#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <cassert>


#include <iostream>

#include "janus_api.h"

#include "dsl_ipc.h"
#include "dsl_debug_utilities.h"
#include "dsl_thread_manager.h"
#include "func.h"
#include "util.h"

/*--- IPC Declarations Start ---*/

CometQueue *COMET_QUEUE;

/*--- IPC Declarations Finish ---*/

//const int DEFAULT_QUEUE_SIZE = 100000000;
const int DEFAULT_QUEUE_SIZE = 2500000;
//const int DEFAULT_QUEUE_SIZE = 2 * (1e5);
//const int DEFAULT_QUEUE_SIZE = 50000;
//const int DEFAULT_QUEUE_SIZE = 5000;

#ifdef SUPPORT_SIMD_REGISTERS
const int INCREMENT = 16;
#else
const int INCREMENT = 8;
#endif

BasicQueue *IPC_QUEUE;
CometQueue *IPC_QUEUE_2;

// If we used a fixed register for the queue pointer, sometimes it may coincide with the register that has
// to be stored in memory (or a source register). The easiest option is to use an alternative register when
// that happens, and the vector below provides a list of potential candidates
std::vector <reg_id_t> INSTRUMENTATION_REGISTERS = {
    DR_REG_R10,
    DR_REG_R11,
    DR_REG_R12,
    DR_REG_R13,
    DR_REG_R9,
    DR_REG_R8,
    DR_REG_RAX,
    DR_REG_RCX,
    DR_REG_RDX,
};

std::vector <instr_t*> instructions_to_remove;


// Index of the AppThread's spill slot where the register that will hold the queue pointer
// will be spilled before loading the queue pointer.
const unsigned QUEUE_PTR_SPILL_SLOT_INDEX = 0;
const unsigned TMP_REG_SPILL_SLOT_INDEX_1 = 1;
const unsigned TMP_REG_SPILL_SLOT_INDEX_2 = 2;

void main_cmp_instr_handler(JANUS_CONTEXT);
void checker_cmp_instr_handler(JANUS_CONTEXT);
void unexpected_dequeue();


BasicQueue* initialise_queue()
{
    std::cout << "Creating basic queue" << std::endl;
        
    return new BasicQueue(DEFAULT_QUEUE_SIZE);
}

CometQueue* initialise_comet_queue()
{
    std::cout << "Creating Comet queue" << std::endl;

    std::cout << "Increment = " << INCREMENT << std::endl;
    return new CometQueue(DEFAULT_QUEUE_SIZE);
}

void add_instrumentation_for_comet_enqueue(JANUS_CONTEXT, CometQueue *queue)
{
    instr_t *trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;

    if (!trigger) { // TODO: remove this check in the future
        return;
    }

    #ifdef PRINT_TRIGGER_INSTR
    std::cout << "    Trigger instruction: " << (void*) instr_get_app_pc(trigger) << std::endl;
    #endif

    if (!instr_num_dsts(trigger)) {
        main_cmp_instr_handler(janus_context);
        return;
    }

    opnd_t dest = instr_get_dst(trigger, 0);
    if (!opnd_is_reg(dest)) {
        return;
    }

    reg_id_t reg = opnd_get_reg(dest);

    if (reg == DR_REG_RBP || reg == DR_REG_RSP) {
        return;
    }

    const reg_id_t queue_ptr_reg = get_free_registers(INSTRUMENTATION_REGISTERS, trigger)[0];

    instr_t *load_enqueue_ptr_instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->enqueue_pointer), OPSZ_8)
    );

    opnd_t enqueue_location = make_mem_opnd_for_reg_from_register(reg, queue_ptr_reg);

    instr_t *enqueue_instr;
    if (reg_is_simd(reg)) {
        enqueue_instr = INSTR_CREATE_movdqu(drcontext, enqueue_location, dest);
    }
    else {
        enqueue_instr = XINST_CREATE_store(drcontext, enqueue_location, dest);
    }

    instr_t *increment_queue_reg_instr = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_INT32(INCREMENT)
    );

    instr_t *store_queue_reg_instr = XINST_CREATE_store(
        drcontext,
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->enqueue_pointer), OPSZ_8),
        opnd_create_reg(queue_ptr_reg)
    );

    // TODO: the spill should only take place when needed indeed (if the register is free, no need to spill)
    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];
    int64_t *spill_slot = &(curr_thread->spill_slots[QUEUE_PTR_SPILL_SLOT_INDEX]);
    instr_t *spill_queue_reg_instr = create_spill_reg_instr(drcontext, queue_ptr_reg, spill_slot);
    instr_t *restore_queue_reg_instr = create_restore_reg_instr(drcontext, queue_ptr_reg, spill_slot);

    if (inRegSet(bitmask, queue_ptr_reg)) {
        instrlist_meta_postinsert(bb, trigger, restore_queue_reg_instr);
    }

    #ifdef PRINT_INSTRUCTION_INSTRUMENTATION_INFO
    std::cout << "Store queue ptr reg: " << inRegSet(bitmask, queue_ptr_reg) << std::endl;
    #endif

    instrlist_postinsert(bb, trigger, store_queue_reg_instr);
    instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
    instrlist_postinsert(bb, trigger, enqueue_instr);
    instrlist_postinsert(bb, trigger, load_enqueue_ptr_instr);
    if (inRegSet(bitmask, queue_ptr_reg)) {
        instrlist_meta_postinsert(bb, trigger, spill_queue_reg_instr);
    }

    #ifdef INSERT_DEBUG_CLEAN_CALLS
    if (!reg_is_simd(reg)) {
        dr_insert_clean_call(drcontext, bb, enqueue_instr, enqueue_debug, 0, 1, dest);
    }
    #endif
}

void main_cmp_instr_handler(JANUS_CONTEXT)
{
    // "free_registers" below refer to registers not used in the trigger instruction
    instr_t * trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;

    //std::cout << "Main handling cmp at " << (void*) instr_get_app_pc(trigger) << std::endl;
    std::vector<reg_id_t> free_registers = get_free_registers(INSTRUMENTATION_REGISTERS, trigger);

    reg_id_t queue_ptr_reg = free_registers[0];

    opnd_t src1 = instr_get_src(trigger, 0);
    opnd_t src2 = instr_get_src(trigger, 1);

    if (!opnd_is_memory_reference(src1) && !opnd_is_memory_register(src1) &&
        !opnd_is_memory_reference(src2) && !opnd_is_memory_register(src2)) {
        //std::cout << "Leave cmp unmodified" << std::endl;
        return;
    }

    // Confirm not both operands are mem references
    assert(!(opnd_is_memory_reference(src1) && opnd_is_memory_reference(src2)));


    opnd_t mem_opnd = opnd_is_memory_reference(src1) ? src1 : src2;
    opnd_size_t mem_opnd_size = opnd_get_size(mem_opnd);
    opnd_t enqueue_location = make_opnd_mem_from_reg_and_size(queue_ptr_reg, mem_opnd_size);

    reg_id_t tmp_reg = reg_resize_to_opsz(free_registers[1], mem_opnd_size);
    instr_t *tmp_load_instr = XINST_CREATE_load(drcontext, opnd_create_reg(tmp_reg), mem_opnd);
    instr_t *enqueue_instr = XINST_CREATE_store(drcontext, enqueue_location, opnd_create_reg(tmp_reg));
        
    instr_t *post_trigger = instr_get_next_app(trigger);
    assert(post_trigger);

    instr_t *load_enqueue_ptr_instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->enqueue_pointer), OPSZ_8)
    );

    instr_t *increment_queue_reg_instr = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_INT32(INCREMENT)
    );
    instr_t *store_queue_reg_instr = XINST_CREATE_store(
        drcontext,
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->enqueue_pointer), OPSZ_8),
        opnd_create_reg(queue_ptr_reg)
    );

    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];

    int64_t *spill_slot1 = &(curr_thread->spill_slots[QUEUE_PTR_SPILL_SLOT_INDEX]);
    instr_t *spill_queue_reg_instr = create_spill_reg_instr(drcontext, queue_ptr_reg, spill_slot1);
    instr_t *restore_queue_reg_instr = create_restore_reg_instr(drcontext, queue_ptr_reg, spill_slot1);

    int64_t *spill_slot2 = &(curr_thread->spill_slots[TMP_REG_SPILL_SLOT_INDEX_1]);
    instr_t *spill_tmp_reg_instr = create_spill_reg_instr(drcontext, tmp_reg, spill_slot2);
    instr_t *restore_tmp_reg_instr = create_restore_reg_instr(drcontext, tmp_reg, spill_slot2);

    instr_set_translation(enqueue_instr, instr_get_app_pc(trigger));

    instrlist_postinsert(bb, trigger, restore_tmp_reg_instr);
    if (inRegSet(bitmask, queue_ptr_reg)) {
        instrlist_postinsert(bb, trigger, restore_queue_reg_instr);
    }
    instrlist_postinsert(bb, trigger, store_queue_reg_instr);
    instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
    instrlist_postinsert(bb, trigger, enqueue_instr);
    instrlist_postinsert(bb, trigger, tmp_load_instr);
    instrlist_postinsert(bb, trigger, load_enqueue_ptr_instr);

    instrlist_meta_postinsert(bb, trigger, spill_tmp_reg_instr);
    if (inRegSet(bitmask, queue_ptr_reg)) {
        instrlist_meta_postinsert(bb, trigger, spill_queue_reg_instr);
    }

    #ifdef INSERT_DEBUG_CLEAN_CALLS
    //dr_insert_clean_call(drcontext, bb, enqueue_instr1, enqueue_debug, 0, 1, src1);
    //dr_insert_clean_call(drcontext, bb, enqueue_instr2, enqueue_debug, 0, 1, src2);
    #endif
}


void add_instrumentation_for_comet_dequeue(JANUS_CONTEXT, CometQueue *queue)
{
    instr_t *trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;

    if (!trigger) {
        return;
    }

    // ignore RSP and RBP

    #ifdef PRINT_TRIGGER_INSTR
    std::cout << "    Trigger instruction: " << (void*) instr_get_app_pc(trigger) << std::endl;
    #endif

    if (!instr_num_dsts(trigger)) {
        #ifdef PRINT_INSTRUCTION_INSTRUMENTATION_INFO
        std::cout << "No dest" << std::endl;
        #endif

        checker_cmp_instr_handler(janus_context);
        return;
    }

    opnd_t dest = instr_get_dst(trigger, 0);

    if (!opnd_is_reg(dest)) {
        #ifdef PRINT_INSTRUCTION_INSTRUMENTATION_INFO
        std::cout << "del: Writing to memory, will remove it:" << std::endl;
        #endif

        instructions_to_remove.push_back(trigger);
        return;
    }


    bool any_src_mem_ref = 0;
    for (int i = 0; i < instr_num_srcs(trigger); ++i) {
        opnd_t src = instr_get_src(trigger, i);
        if (opnd_is_memory_reference(src) && opnd_get_segment(src) != DR_SEG_FS) {
            any_src_mem_ref = 1;
            break;
        }
    }


    reg_id_t reg = opnd_get_reg(dest);


    #ifdef PRINT_INSTRUCTION_INSTRUMENTATION_INFO
    std::cout << "Dest register is " << get_register_name(reg) << std::endl;
    std::cout << "Instruction has any memory references: " << any_src_mem_ref << std::endl;
    #endif

    if (reg == DR_REG_RBP || reg == DR_REG_RSP) {
        return;
    }

    const reg_id_t queue_ptr_reg = get_free_registers(INSTRUMENTATION_REGISTERS, trigger)[0];

    instr_t *load_dequeue_ptr_instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->dequeue_pointer), OPSZ_8)
    );

    int increment = reg_is_simd(reg) ? 16 : 8;
    instr_t *increment_queue_reg_instr = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_INT32(INCREMENT)
    );
    instr_t *store_queue_reg_instr = XINST_CREATE_store(
        drcontext,
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->dequeue_pointer), OPSZ_8),
        opnd_create_reg(queue_ptr_reg)
    );

    opnd_t dequeue_location = make_mem_opnd_for_reg_from_register(reg, queue_ptr_reg);

    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];
    int64_t *spill_slot = &(curr_thread->spill_slots[QUEUE_PTR_SPILL_SLOT_INDEX]);
    instr_t *spill_queue_reg_instr = create_spill_reg_instr(drcontext, queue_ptr_reg, spill_slot);
    instr_t *restore_queue_reg_instr = create_restore_reg_instr(drcontext, queue_ptr_reg, spill_slot);

    if (inRegSet(bitmask, queue_ptr_reg)) {
        instrlist_meta_postinsert(bb, trigger, restore_queue_reg_instr);
    }

    if (any_src_mem_ref) {
        // dequeue and load to reg, remove instruction
        #ifdef PRINT_INSTRUCTION_INSTRUMENTATION_INFO
        std::cout << "del: Memory operands in instruction, will remove it:" << std::endl;
        instr_disassemble(drcontext, trigger, STDOUT);
        std::cout << endl;
        #endif

        instr_t *dequeue_instr;
        if (reg_is_simd(reg)) {
            dequeue_instr = INSTR_CREATE_movdqu(drcontext, dest, dequeue_location);
        }
        else {
            dequeue_instr = XINST_CREATE_load(drcontext, dest, dequeue_location);
        }

        instr_t *pre_trigger = instr_get_prev_app(trigger);
        if (pre_trigger) {
            instr_set_translation(dequeue_instr, instr_get_app_pc(pre_trigger));
        }

        instrlist_postinsert(bb, trigger, store_queue_reg_instr);
        instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
        instrlist_postinsert(bb, trigger, dequeue_instr);
        instrlist_postinsert(bb, trigger, load_dequeue_ptr_instr);

        #ifdef INSERT_DEBUG_CLEAN_CALLS
        if (!reg_is_simd(reg)) {
            dr_insert_clean_call(drcontext, bb, dequeue_instr, dequeue_debug, 0, 2, dest, OPND_CREATE_INT32(0));
        }
        #endif

        // instrlist_remove(bb, trigger);
        instructions_to_remove.push_back(trigger);
    }
    else {
        // cmp against queue, keep instruction
        #ifdef PRINT_INSTRUCTION_INSTRUMENTATION_INFO
        std::cout << "Keep instruction and compare against dequeue" << std::endl;
        #endif

        instr_t *cmp_instr;
        if (reg_is_simd(reg)) {
            // COMISD works on 8 bytes, must readjust the dequeue location
            dequeue_location = opnd_create_base_disp(queue_ptr_reg, DR_REG_NULL, 0, 0, OPSZ_8);
            cmp_instr = INSTR_CREATE_comisd(drcontext, dest, dequeue_location);
        }
        else {
            cmp_instr = XINST_CREATE_cmp(drcontext, dest, dequeue_location);
        }

        instr_t *jmp_instr = INSTR_CREATE_jcc(drcontext, OP_jne, opnd_create_pc((app_pc)unexpected_dequeue));
        instr_set_translation(cmp_instr, instr_get_app_pc(trigger));
        instr_set_translation(jmp_instr, instr_get_app_pc(trigger));

        instrlist_postinsert(bb, trigger, jmp_instr);
        instrlist_postinsert(bb, trigger, store_queue_reg_instr);
        instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
        instrlist_postinsert(bb, trigger, cmp_instr);
        instrlist_postinsert(bb, trigger, load_dequeue_ptr_instr);

        #ifdef INSERT_DEBUG_CLEAN_CALLS
        if (!reg_is_simd(reg)) {
            dr_insert_clean_call(drcontext, bb, cmp_instr, dequeue_debug, 0, 2, dest, OPND_CREATE_INT32(1));
        }
        #endif
    }

    if (inRegSet(bitmask, queue_ptr_reg)) {
        instrlist_meta_postinsert(bb, trigger, spill_queue_reg_instr);
    }
}

void checker_cmp_instr_handler(JANUS_CONTEXT)
{
    instr_t * trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;

    //std::cout << "Checker handling cmp at " << (void*) instr_get_app_pc(trigger) << std::endl;

    opnd_t src1 = instr_get_src(trigger, 0);
    opnd_t src2 = instr_get_src(trigger, 1);

    if (!opnd_is_memory_reference(src1) && !opnd_is_memory_register(src1) &&
        !opnd_is_memory_reference(src2) && !opnd_is_memory_register(src2)) {
        //std::cout << "Leave cmp unmodified" << std::endl;
        return;
    }

    // Confirm not both operands are mem references
    assert(!(opnd_is_memory_reference(src1) && opnd_is_memory_reference(src2)));

    // "free_registers" below refer to registers not used in the trigger instruction
    reg_id_t queue_ptr_reg = get_free_registers(INSTRUMENTATION_REGISTERS, trigger)[0];

    opnd_t mem_opnd = opnd_is_memory_reference(src1) ? src1 : src2;
    opnd_size_t mem_opnd_size = opnd_get_size(mem_opnd);

    opnd_t dequeue_location = make_opnd_mem_from_reg_and_size(queue_ptr_reg, mem_opnd_size);
    if (opnd_is_memory_reference(src1)) {
        src1 = dequeue_location;
    }
    else {
        src2 = dequeue_location;
    }
    instr_t *new_cmp_instr = XINST_CREATE_cmp(drcontext, src1, src2);

    instr_t *prev_trigger = instr_get_prev_app(trigger);
    if (prev_trigger) {
        instr_set_translation(new_cmp_instr, instr_get_app_pc(prev_trigger));
    }


    instr_t *post_trigger = instr_get_next_app(trigger);
    assert(post_trigger);

    instr_t *load_dequeue_ptr_instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->dequeue_pointer), OPSZ_8)
    );
    instr_t *increment_queue_reg_instr = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_INT32(INCREMENT)
    );
    instr_t *store_queue_reg_instr = XINST_CREATE_store(
        drcontext,
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->dequeue_pointer), OPSZ_8),
        opnd_create_reg(queue_ptr_reg)
    );

    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];

    int64_t *spill_slot1 = &(curr_thread->spill_slots[QUEUE_PTR_SPILL_SLOT_INDEX]);
    instr_t *spill_queue_reg_instr = create_spill_reg_instr(drcontext, queue_ptr_reg, spill_slot1);
    instr_t *restore_queue_reg_instr = create_restore_reg_instr(drcontext, queue_ptr_reg, spill_slot1);


    // Add dequeue and replace trigger with new cmp
    if (inRegSet(bitmask, queue_ptr_reg)) {
        instrlist_meta_preinsert(bb, trigger, spill_queue_reg_instr);
    }
    instrlist_preinsert(bb, trigger, load_dequeue_ptr_instr);
    instrlist_preinsert(bb, trigger, new_cmp_instr);
    instrlist_preinsert(bb, trigger, increment_queue_reg_instr);
    instrlist_preinsert(bb, trigger, store_queue_reg_instr);

    if (inRegSet(bitmask, queue_ptr_reg)) {
        instrlist_meta_postinsert(bb, trigger, restore_queue_reg_instr);
    }

    #ifdef INSERT_DEBUG_CLEAN_CALLS
    //dr_insert_clean_call(drcontext, bb, increment_queue_reg_instr1, after_dequeue_debug, 0, 1, instr_get_src(new_cmp, 0));
    //dr_insert_clean_call(drcontext, bb, increment_queue_reg_instr2, after_dequeue_debug, 0, 1, instr_get_src(new_cmp, 1));
    #endif

    instructions_to_remove.push_back(trigger);
}

void unexpected_dequeue()
{
    std::cout << "---->ERROR: dequeue returned unexpected value" << std::endl;
    // Print the message more times in case it gets lost in the STD operations
    for (int i = 1; i <= 5; ++i) {
        std::cout << "---->ERROR: dequeue returned unexpected value" << std::endl;
    }
}

void set_main_queue(CometQueue *queue)
{
    IPC_QUEUE_2 = queue;
}
