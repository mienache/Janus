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

/*--- IPC Declarations Finish ---*/

//const int DEFAULT_QUEUE_SIZE = 100000000;
const int DEFAULT_QUEUE_SIZE = 2500000;
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
    // DR_REG_RDI,
    DR_REG_R10,
    DR_REG_R11,
    DR_REG_R12,
    DR_REG_R13,
    DR_REG_R9,
    DR_REG_R8
};

// Index of the AppThread's spill slot where the register that will hold the queue pointer
// will be spilled before loading the queue pointer.
const unsigned QUEUE_PTR_SPILL_SLOT_INDEX = 0;
const unsigned TMP_REG_SPILL_SLOT_INDEX_1 = 1;
const unsigned TMP_REG_SPILL_SLOT_INDEX_2 = 2;

void main_cmp_instr_handler(JANUS_CONTEXT);


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

    opnd_size_t src1_size = opnd_get_size(src1);
    opnd_size_t src2_size = opnd_get_size(src2);

    opnd_t enqueue_location1 = make_opnd_mem_from_reg_and_size(queue_ptr_reg, src1_size);
    opnd_t enqueue_location2 = make_opnd_mem_from_reg_and_size(queue_ptr_reg, src2_size);

    reg_id_t tmp_reg1 = free_registers[1];
    tmp_reg1 = reg_resize_to_opsz(tmp_reg1, src1_size);
    instr_t *tmp_load_instr1;
    if(opnd_is_immed_int(src1)) {
        tmp_load_instr1 = XINST_CREATE_load_int(drcontext, opnd_create_reg(tmp_reg1), src1);
    }
    else {
        tmp_load_instr1 = XINST_CREATE_load(drcontext, opnd_create_reg(tmp_reg1), src1);
    }
    instr_t *enqueue_instr1 = XINST_CREATE_store(drcontext, enqueue_location1, opnd_create_reg(tmp_reg1));
        
    reg_id_t tmp_reg2 = free_registers[2];
    tmp_reg2 = reg_resize_to_opsz(tmp_reg2, src2_size);
    instr_t *tmp_load_instr2;
    if(opnd_is_immed_int(src2)) {
        tmp_load_instr2 = XINST_CREATE_load_int(drcontext, opnd_create_reg(tmp_reg2), src2);
    }
    else {
        tmp_load_instr2 = XINST_CREATE_load(drcontext, opnd_create_reg(tmp_reg2), src2);
    }
    instr_t *enqueue_instr2 = XINST_CREATE_store(drcontext, enqueue_location2, opnd_create_reg(tmp_reg2));

    instr_t *post_trigger = instr_get_next_app(trigger);
    assert(post_trigger);

    instr_t *load_enqueue_ptr_instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->enqueue_pointer), OPSZ_8)
    );

    instr_t *increment_queue_reg_instr1 = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_INT32(INCREMENT)
    );
    instr_t *increment_queue_reg_instr2 = XINST_CREATE_add(
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
    instr_t *spill_tmp_reg1_instr = create_spill_reg_instr(drcontext, tmp_reg1, spill_slot2);
    instr_t *restore_tmp_reg1_instr = create_restore_reg_instr(drcontext, tmp_reg1, spill_slot2);

    int64_t *spill_slot3 = &(curr_thread->spill_slots[TMP_REG_SPILL_SLOT_INDEX_2]);
    instr_t *spill_tmp_reg2_instr = create_spill_reg_instr(drcontext, tmp_reg2, spill_slot3);
    instr_t *restore_tmp_reg2_instr = create_restore_reg_instr(drcontext, tmp_reg2, spill_slot3);

    instr_set_translation(enqueue_instr1, instr_get_app_pc(trigger));
    instr_set_translation(enqueue_instr2, instr_get_app_pc(trigger));

    if (inRegSet(bitmask, queue_ptr_reg)) {
        instrlist_meta_preinsert(bb, trigger, spill_queue_reg_instr);
    }
    instrlist_meta_preinsert(bb, trigger, spill_tmp_reg1_instr);
    instrlist_meta_preinsert(bb, trigger, spill_tmp_reg2_instr);

    instrlist_postinsert(bb, trigger, restore_tmp_reg2_instr);
    instrlist_postinsert(bb, trigger, restore_tmp_reg1_instr);
    if (inRegSet(bitmask, queue_ptr_reg)) {
        instrlist_postinsert(bb, trigger, restore_queue_reg_instr);
    }
    instrlist_postinsert(bb, trigger, store_queue_reg_instr);
    instrlist_postinsert(bb, trigger, increment_queue_reg_instr2);
    instrlist_postinsert(bb, trigger, enqueue_instr2);
    instrlist_postinsert(bb, trigger, tmp_load_instr2);
    instrlist_postinsert(bb, trigger, increment_queue_reg_instr1);
    instrlist_postinsert(bb, trigger, enqueue_instr1);
    instrlist_postinsert(bb, trigger, tmp_load_instr1);
    instrlist_postinsert(bb, trigger, load_enqueue_ptr_instr);

    #ifdef INSERT_DEBUG_CLEAN_CALLS
    //dr_insert_clean_call(drcontext, bb, enqueue_instr1, enqueue_debug, 0, 1, src1);
    //dr_insert_clean_call(drcontext, bb, enqueue_instr2, enqueue_debug, 0, 1, src2);
    #endif
}

