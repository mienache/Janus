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

bool REG_PROM_OPT = 1;
bool OFFSET_FUSION_OPT = 1;
bool DYNAMIC_OFFSET_OPT = 1;

//const int DEFAULT_QUEUE_SIZE = 1e8;
//const int DEFAULT_QUEUE_SIZE = 1e7;
//const int DEFAULT_QUEUE_SIZE = 2500000;
//const int DEFAULT_QUEUE_SIZE = 5 * (1e5);
const int DEFAULT_QUEUE_SIZE = 4 * (1e5);
//const int DEFAULT_QUEUE_SIZE = 2 * (1e5);
//const int DEFAULT_QUEUE_SIZE = 1e5;
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
// Ensure there are no duplicates in `INSTRUMENTATION_REGISTERS`
std::vector <reg_id_t> INSTRUMENTATION_REGISTERS = {
    DR_REG_R10,
    DR_REG_R11,
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
void reg_prom_main_handler(JANUS_CONTEXT, CometQueue *queue);
void reg_prom_checker_handler(JANUS_CONTEXT, CometQueue *queue);
void reg_prom_main_cmp_instr_handler(JANUS_CONTEXT);
void reg_prom_checker_cmp_instr_handler(JANUS_CONTEXT);
void unexpected_dequeue();
void adjust_curr_disp(AppThread *curr_thread, opnd_size_t opnd_size);
int get_dynamic_increment(opnd_size_t opnd_size);


BasicQueue* initialise_queue()
{
    std::cout << "Creating basic queue" << std::endl;
        
    return new BasicQueue(DEFAULT_QUEUE_SIZE);
}

CometQueue* initialise_comet_queue()
{
    std::cout << "Creating Comet queue" << std::endl;

    std::cout << "Increment = " << INCREMENT << std::endl;
    return new CometQueue(DEFAULT_QUEUE_SIZE, REG_PROM_OPT, OFFSET_FUSION_OPT, DYNAMIC_OFFSET_OPT);
}

void insert_instrs_for_new_queue_reg(void *drcontext, instrlist_t *bb, instr_t* trigger, reg_id_t new_queue_ptr_reg);

void add_instrumentation_for_comet_enqueue(JANUS_CONTEXT, CometQueue *queue)
{
    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];
    if (IPC_QUEUE_2->bb_reg_prom_opt && curr_thread->curr_queue_reg != DR_REG_NULL) {
        // Run code for register promotion optimisation instead
        reg_prom_main_handler(drcontext, bb, rule, tag, queue);
        return;
    }

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
    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];
    if (IPC_QUEUE_2->bb_reg_prom_opt && curr_thread->curr_queue_reg != DR_REG_NULL) {
        // Run code for register promotion optimisation instead
        reg_prom_checker_handler(drcontext, bb, rule, tag, queue);
        return;
    }

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
    for (int i = 1; i <= 7; ++i) {
        std::cout << "---->ERROR: dequeue returned unexpected value" << std::endl;
    }
}

void set_main_queue(CometQueue *queue)
{
    IPC_QUEUE_2 = queue;
}

void instrument_first_instr_for_reg_prom(void *drcontext, instrlist_t *bb)
{
    pid_t curr_tid = dr_get_thread_id(drcontext);

    AppThread *curr_thread = app_threads[curr_tid];
    const reg_id_t queue_ptr_reg = curr_thread->curr_queue_reg;
    int64_t *spill_slot = &(curr_thread->spill_slots[QUEUE_PTR_SPILL_SLOT_INDEX]);
    instr_t *spill_queue_reg_instr = create_spill_reg_instr(drcontext, queue_ptr_reg, spill_slot);

    void *queue_ptr_addr = curr_thread->threadRole == ThreadRole::MAIN ? &(IPC_QUEUE_2->enqueue_pointer) : &(IPC_QUEUE_2->dequeue_pointer);

    instr_t *load_queue_ptr_instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_ABSMEM((byte*) queue_ptr_addr, OPSZ_8)
    );

    instrlist_prepend(bb, load_queue_ptr_instr); // Second
    instrlist_prepend(bb, spill_queue_reg_instr); // First
}

void instrument_last_instr_for_reg_prom(void*drcontext, instrlist_t *bb)
{
    pid_t curr_tid = dr_get_thread_id(drcontext);

    AppThread *curr_thread = app_threads[curr_tid];
    const reg_id_t queue_ptr_reg = curr_thread->curr_queue_reg;

    int64_t *spill_slot = &(curr_thread->spill_slots[QUEUE_PTR_SPILL_SLOT_INDEX]);
    instr_t *restore_queue_reg_instr = create_restore_reg_instr(drcontext, queue_ptr_reg, spill_slot);

    void *queue_ptr_addr = curr_thread->threadRole == ThreadRole::MAIN ? &(IPC_QUEUE_2->enqueue_pointer) : &(IPC_QUEUE_2->dequeue_pointer);
    instr_t *store_queue_reg_instr = XINST_CREATE_store(
        drcontext,
        OPND_CREATE_ABSMEM((byte*) queue_ptr_addr, OPSZ_8),
        opnd_create_reg(queue_ptr_reg)
    );

    instr_t *last_instr = instrlist_last_app(bb);

    if (IPC_QUEUE_2->addr_offset_fusion_opt && curr_thread->curr_disp) {
        if (IPC_QUEUE_2->dynamic_increment_opt) {
            // std::cout << curr_thread->pid << " - cur_disp before modifying = " << curr_thread->curr_disp << std::endl;
            adjust_curr_disp(curr_thread, opnd_size_from_bytes(INCREMENT));
        }

        // std::cout << curr_thread->pid << " - curr_disp at end of block: " << curr_thread->curr_disp << std::endl;

        instr_t *adjust_queue_reg = XINST_CREATE_add(
            drcontext,
            opnd_create_reg(queue_ptr_reg),
            OPND_CREATE_INT32(curr_thread->curr_disp)
        );

        instrlist_preinsert(bb, last_instr, adjust_queue_reg);
    }

    instrlist_preinsert(bb, last_instr, store_queue_reg_instr); // First
    instrlist_preinsert(bb, last_instr, restore_queue_reg_instr); // Second
}

/*
void insert_instrs_for_new_queue_reg(void *drcontext, instrlist_t *bb, instr_t* trigger, reg_id_t new_queue_ptr_reg)
{
    std::cout << "Start inserting instrs for new queue reg" << std::endl;

    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];
    int64_t *spill_slot1 = &(curr_thread->spill_slots[QUEUE_PTR_SPILL_SLOT_INDEX]);
    int64_t *spill_slot2 = &(curr_thread->spill_slots[TMP_REG_SPILL_SLOT_INDEX_1]);

    instr_t* spill_new_queue_reg_instr = create_spill_reg_instr(drcontext, new_queue_ptr_reg, spill_slot2);
    instr_t *mov_to_new_queue_reg_instr = XINST_CREATE_load(drcontext, opnd_create_reg(new_queue_ptr_reg), opnd_create_reg(QUEUE_PTR_REG));
    instr_t *restore_queue_reg_instr = create_restore_reg_instr(drcontext, QUEUE_PTR_REG, spill_slot1);
    instrlist_preinsert(bb, trigger, spill_new_queue_reg_instr);
    instrlist_preinsert(bb, trigger, mov_to_new_queue_reg_instr);
    instrlist_preinsert(bb, trigger, restore_queue_reg_instr);

    instr_t* spill_queue_reg_instr = create_spill_reg_instr(drcontext, QUEUE_PTR_REG, spill_slot1);
    instr_t* mov_from_new_queue_reg_instr = XINST_CREATE_load(drcontext, opnd_create_reg(QUEUE_PTR_REG), opnd_create_reg(new_queue_ptr_reg));
    instr_t* restore_new_queue_reg_instr = create_restore_reg_instr(drcontext, new_queue_ptr_reg, spill_slot2);
    instrlist_postinsert(bb, trigger, restore_new_queue_reg_instr);
    instrlist_postinsert(bb, trigger, mov_from_new_queue_reg_instr);
    instrlist_postinsert(bb, trigger, spill_queue_reg_instr);

    std::cout << "Finished inserting instrs for new queue reg" << std::endl;


    // TODO: spill/restore new_queue_ptr_reg only if needed
}
*/

void reg_prom_main_handler(JANUS_CONTEXT, CometQueue *queue)
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
        reg_prom_main_cmp_instr_handler(janus_context);
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

    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];
    const reg_id_t new_queue_ptr_reg = curr_thread->curr_queue_reg;

    if (IPC_QUEUE_2->dynamic_increment_opt) {
        adjust_curr_disp(curr_thread, reg_get_size(reg));
    }
    opnd_t enqueue_location = (
        IPC_QUEUE_2->addr_offset_fusion_opt ? 
        make_mem_opnd_for_reg_from_register_and_disp(reg, new_queue_ptr_reg, curr_thread->curr_disp) :
        make_mem_opnd_for_reg_from_register(reg, new_queue_ptr_reg)
    );
    if (IPC_QUEUE_2->addr_offset_fusion_opt) {
        curr_thread->curr_disp += get_dynamic_increment(reg_get_size(reg));
    }

    instr_t *enqueue_instr;
    if (reg_is_simd(reg)) {
        enqueue_instr = INSTR_CREATE_movdqu(drcontext, enqueue_location, dest);
    }
    else {
        enqueue_instr = XINST_CREATE_store(drcontext, enqueue_location, dest);
    }

    instr_t *increment_queue_reg_instr = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(new_queue_ptr_reg),
        OPND_CREATE_INT32(INCREMENT)
    );


    #ifdef PRINT_INSTRUCTION_INSTRUMENTATION_INFO
    std::cout << "Store queue ptr reg: " << inRegSet(bitmask, new_queue_ptr_reg) << std::endl;
    #endif

    if (!IPC_QUEUE_2->addr_offset_fusion_opt) {
        instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
    }
    instrlist_postinsert(bb, trigger, enqueue_instr);

    #ifdef INSERT_DEBUG_CLEAN_CALLS
    if (!reg_is_simd(reg)) {
        dr_insert_clean_call(drcontext, bb, enqueue_instr, enqueue_debug, 0, 1, dest);
    }
    #endif
}

void reg_prom_main_cmp_instr_handler(JANUS_CONTEXT)
{
    instr_t * trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;

    opnd_t src1 = instr_get_src(trigger, 0);
    opnd_t src2 = instr_get_src(trigger, 1);

    if (!opnd_is_memory_reference(src1) && !opnd_is_memory_register(src1) &&
        !opnd_is_memory_reference(src2) && !opnd_is_memory_register(src2)) {
        //std::cout << "Leave cmp unmodified" << std::endl;
        return;
    }

    // Confirm not both operands are mem references
    assert(!(opnd_is_memory_reference(src1) && opnd_is_memory_reference(src2)));

    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];
    const reg_id_t new_queue_ptr_reg = curr_thread->curr_queue_reg;
    //std::cout << "Main handling cmp at " << (void*) instr_get_app_pc(trigger) << std::endl;

    opnd_t mem_opnd = opnd_is_memory_reference(src1) ? src1 : src2;
    opnd_size_t mem_opnd_size = opnd_get_size(mem_opnd);

    if (IPC_QUEUE_2->dynamic_increment_opt) {
        adjust_curr_disp(curr_thread, mem_opnd_size);
    }

    opnd_t enqueue_location = (
        IPC_QUEUE_2->addr_offset_fusion_opt ? 
        make_opnd_mem_from_reg_disp_and_size(new_queue_ptr_reg, curr_thread->curr_disp, mem_opnd_size) :
        make_opnd_mem_from_reg_and_size(new_queue_ptr_reg, mem_opnd_size)
    );

    if (IPC_QUEUE_2->addr_offset_fusion_opt) {
        curr_thread->curr_disp += get_dynamic_increment(mem_opnd_size);
    }

    std::vector<reg_id_t> free_registers = get_free_registers(INSTRUMENTATION_REGISTERS, trigger);
    reg_id_t tmp_reg = free_registers.back();
    while (reg_overlap(tmp_reg, new_queue_ptr_reg)) {
        free_registers.pop_back();
        tmp_reg = free_registers.back();
    }
    tmp_reg = reg_resize_to_opsz(tmp_reg, mem_opnd_size);

    instr_t *tmp_load_instr = XINST_CREATE_load(drcontext, opnd_create_reg(tmp_reg), mem_opnd);
    instr_t *enqueue_instr = XINST_CREATE_store(drcontext, enqueue_location, opnd_create_reg(tmp_reg));

    instr_t *post_trigger = instr_get_next_app(trigger);
    assert(post_trigger);

    instr_t *increment_queue_reg_instr = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(new_queue_ptr_reg),
        OPND_CREATE_INT32(INCREMENT)
    );

    int64_t *spill_slot3 = &(curr_thread->spill_slots[TMP_REG_SPILL_SLOT_INDEX_2]);
    instr_t *spill_tmp_reg_instr = create_spill_reg_instr(drcontext, tmp_reg, spill_slot3);
    instr_t *restore_tmp_reg_instr = create_restore_reg_instr(drcontext, tmp_reg, spill_slot3);

    instr_set_translation(enqueue_instr, instr_get_app_pc(trigger));

    instrlist_postinsert(bb, trigger, restore_tmp_reg_instr);
    if (!IPC_QUEUE_2->addr_offset_fusion_opt) {
        instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
    }
    instrlist_postinsert(bb, trigger, enqueue_instr);
    instrlist_postinsert(bb, trigger, tmp_load_instr);
    instrlist_postinsert(bb, trigger, spill_tmp_reg_instr);

    #ifdef INSERT_DEBUG_CLEAN_CALLS
    //dr_insert_clean_call(drcontext, bb, enqueue_instr1, enqueue_debug, 0, 1, src1);
    //dr_insert_clean_call(drcontext, bb, enqueue_instr2, enqueue_debug, 0, 1, src2);
    #endif
}

void reg_prom_checker_handler(JANUS_CONTEXT, CometQueue *queue)
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

        reg_prom_checker_cmp_instr_handler(janus_context);
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

    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];
    const reg_id_t new_queue_ptr_reg = curr_thread->curr_queue_reg;

    instr_t *increment_queue_reg_instr = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(new_queue_ptr_reg),
        OPND_CREATE_INT32(INCREMENT)
    );

    if (IPC_QUEUE_2->dynamic_increment_opt) {
        adjust_curr_disp(curr_thread, reg_get_size(reg));
    }
    opnd_t dequeue_location = (
        IPC_QUEUE_2->addr_offset_fusion_opt ? 
        make_mem_opnd_for_reg_from_register_and_disp(reg, new_queue_ptr_reg, curr_thread->curr_disp) :
        make_mem_opnd_for_reg_from_register(reg, new_queue_ptr_reg)
    );

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

        if (!IPC_QUEUE_2->addr_offset_fusion_opt) {
            instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
        }
        instrlist_postinsert(bb, trigger, dequeue_instr);

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
            dequeue_location = (
                IPC_QUEUE_2->addr_offset_fusion_opt ? 
                opnd_create_base_disp(new_queue_ptr_reg, DR_REG_NULL, 0, curr_thread->curr_disp, OPSZ_8) :
                opnd_create_base_disp(new_queue_ptr_reg, DR_REG_NULL, 0, 0, OPSZ_8)
            );
            cmp_instr = INSTR_CREATE_comisd(drcontext, dest, dequeue_location);
        }
        else {
            cmp_instr = XINST_CREATE_cmp(drcontext, dest, dequeue_location);
        }

        instr_t *jmp_instr = INSTR_CREATE_jcc(drcontext, OP_jne, opnd_create_pc((app_pc)unexpected_dequeue));
        instr_set_translation(cmp_instr, instr_get_app_pc(trigger));
        instr_set_translation(jmp_instr, instr_get_app_pc(trigger));

        instrlist_postinsert(bb, trigger, jmp_instr);
        if (!IPC_QUEUE_2->addr_offset_fusion_opt) {
            instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
        }
        instrlist_postinsert(bb, trigger, cmp_instr);

        #ifdef INSERT_DEBUG_CLEAN_CALLS
        if (!reg_is_simd(reg)) {
            dr_insert_clean_call(drcontext, bb, cmp_instr, dequeue_debug, 0, 2, dest, OPND_CREATE_INT32(1));
        }
        #endif
    }

    if (IPC_QUEUE_2->addr_offset_fusion_opt) {
        curr_thread->curr_disp += get_dynamic_increment(reg_get_size(reg));
    }
}

void reg_prom_checker_cmp_instr_handler(JANUS_CONTEXT)
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

    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];
    const reg_id_t new_queue_ptr_reg = curr_thread->curr_queue_reg;

    opnd_t mem_opnd = opnd_is_memory_reference(src1) ? src1 : src2;
    opnd_size_t mem_opnd_size = opnd_get_size(mem_opnd);
    if (IPC_QUEUE_2->dynamic_increment_opt) {
        adjust_curr_disp(curr_thread, mem_opnd_size);
    }

    opnd_t dequeue_location = (
        IPC_QUEUE_2->addr_offset_fusion_opt ? 
        make_opnd_mem_from_reg_disp_and_size(new_queue_ptr_reg, curr_thread->curr_disp, mem_opnd_size) :
        make_opnd_mem_from_reg_and_size(new_queue_ptr_reg, mem_opnd_size)
    );
    if (IPC_QUEUE_2->addr_offset_fusion_opt) {
        curr_thread->curr_disp += get_dynamic_increment(mem_opnd_size);
    }

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

    instr_t *increment_queue_reg_instr = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(new_queue_ptr_reg),
        OPND_CREATE_INT32(INCREMENT)
    );


    // Add dequeue and replace trigger with new cmp
    instrlist_preinsert(bb, trigger, new_cmp_instr);
    if (!IPC_QUEUE_2->addr_offset_fusion_opt) {
        instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
    }

    #ifdef INSERT_DEBUG_CLEAN_CALLS
    //dr_insert_clean_call(drcontext, bb, increment_queue_reg_instr1, after_dequeue_debug, 0, 1, instr_get_src(new_cmp, 0));
    //dr_insert_clean_call(drcontext, bb, increment_queue_reg_instr2, after_dequeue_debug, 0, 1, instr_get_src(new_cmp, 1));
    #endif

    instructions_to_remove.push_back(trigger);
}


void adjust_curr_disp(AppThread *curr_thread, opnd_size_t opnd_size)
{
    const int remainder = curr_thread->curr_disp % opnd_size_in_bytes(opnd_size);
    if (remainder) {
        const int required_offest = opnd_size_in_bytes(opnd_size) - remainder;
        curr_thread->curr_disp += required_offest;
    }
}

int get_dynamic_increment(opnd_size_t opnd_size)
{
    return IPC_QUEUE_2->dynamic_increment_opt ? opnd_size_in_bytes(opnd_size) : INCREMENT;
}