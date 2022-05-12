/* Header file to implement a JANUS client */
#include <cassert>
#include <iostream>
#include <iomanip>
#include <vector>
#include <unistd.h>

#include "dsl_core.h"
#include "dsl_debug_utilities.h"
#include "dsl_ipc.h"
#include "dsl_thread_manager.h"
#include "func.h"
#include "front_end.h"
#include "janus_api.h"
#include "handler.h"
#include "util.h"

#ifdef SUPPORT_SIMD_REGISTERS
const int INCREMENT = 16;
#else
const int INCREMENT = 8;
#endif

std::vector <instr_t*> instructions_to_remove;

// Index of the AppThread's spill slot where the register that will hold the queue pointer
// will be spilled before loading the queue pointer.
const unsigned QUEUE_PTR_SPILL_SLOT_INDEX = 0;
const unsigned TMP_REG_SPILL_SLOT_INDEX_1 = 1;
const unsigned TMP_REG_SPILL_SLOT_INDEX_2 = 2;

void unexpected_dequeue();
void main_cmp_instr_handler(JANUS_CONTEXT);
void checker_cmp_instr_handler(JANUS_CONTEXT);


/*--- Dynamic Handlers Start ---*/
void count_load_instructions_handler(JANUS_CONTEXT){
    return;
    instr_t * trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;
    dr_save_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_1);
    instrlist_meta_preinsert(bb, trigger, XINST_CREATE_load(drcontext, opnd_create_reg(DR_REG_RAX), OPND_CREATE_ABSMEM((byte *)&inst_count, OPSZ_8)));
    instrlist_meta_preinsert(bb, trigger, XINST_CREATE_add(drcontext, opnd_create_reg(DR_REG_RAX), OPND_CREATE_INT32(1)));
    instrlist_meta_preinsert(bb, trigger, XINST_CREATE_store(drcontext, OPND_CREATE_ABSMEM((byte *)&inst_count, OPSZ_8), opnd_create_reg(DR_REG_RAX)));
    dr_restore_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_1);
} 

void thread_creation_handler(JANUS_CONTEXT){
    #ifdef SKIP_THREAD_CREATION
        std::cout << "Skipping thread creation" << std::endl;
        CHECKER_THREAD_FINISHED = 1;
        return;
    #endif

    std::cout << "Instrumenting through thread creation handler" << std::endl;

    instr_t *trigger = get_trigger_instruction(bb,rule);
    if (!trigger) {
        return;
    }


    if (checker_thread && dr_get_thread_id(drcontext) == checker_thread->pid) {
        std::cout << "CHECKER thread reaches rule for thread creation but will skip instrumenting." << std::endl;
        return;
    }

    std::cout << "MAIN thread now adding instrumentation code for generating CHECKER thread" << std::endl;

    do_pre_thread_creation_maintenance(janus_context);

    // TODO: in the future we will need to save the RDI register on the stack
    // but for now this works as the thread creation only happens at the beginning of the
    // main function. Note that R14 and R15 will also need to be saved as per the
    // instructions of `insert_function_call_as_application`.

    instr_t *instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(DR_REG_RDI),
        OPND_CREATE_ABSMEM((byte *) &checker_thread, OPSZ_8)
    );
    instrlist_meta_preinsert(bb, trigger, instr);

    instr = XINST_CREATE_move(
        drcontext,
        opnd_create_reg(DR_REG_RSI),
        opnd_create_reg(DR_REG_RSP)
    );
    instrlist_meta_preinsert(bb, trigger, instr);

    // IMPORTANT!
    // HERE WE INSERT THE FUNCTION CALL AS APPLICATION, USING THE DYNAMIC/CORE LIBRARY
    insert_function_call_as_application(janus_context, (void*) run_thread);


    // Just printing the modified basic block to identify the file easier
    /*
    app_pc tag_new = instr_get_app_pc(instrlist_first_app(bb));
    file_t output_file = dr_open_file("instructions.txt", DR_FILE_WRITE_OVERWRITE);
    instrlist_disassemble(drcontext, tag_new, bb, output_file);
    dr_close_file(output_file);
    */
}

void main_handler(JANUS_CONTEXT) {
    if (!(main_thread && dr_get_thread_id(drcontext) == main_thread->pid)) {
        return;
    }

    add_instrumentation_for_comet_enqueue(janus_context, IPC_QUEUE_2);
}

void unexpected_dequeue()
{
    std::cout << "---->ERROR: dequeue returned unexpected value" << std::endl;
    for (int i = 1; i <= 5; ++i) {
        std::cout << "---->ERROR: dequeue returned unexpected value" << std::endl;
    }
}


void checker_handler(JANUS_CONTEXT) {
    if (!(checker_thread && dr_get_thread_id(drcontext) == checker_thread->pid)) {
        return;
    }


    // std::cout << "Instrumenting TID " << dr_get_thread_id(drcontext) << " through checker load handler" << std::endl;

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

    // TODO: optimise this
    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];
    int64_t *spill_slot = &(curr_thread->spill_slots[QUEUE_PTR_SPILL_SLOT_INDEX]);
    instr_t *spill_queue_reg_instr = create_spill_reg_instr(drcontext, queue_ptr_reg, spill_slot);
    instr_t *restore_queue_reg_instr = create_restore_reg_instr(drcontext, queue_ptr_reg, spill_slot);

    if (inRegSet(bitmask, queue_ptr_reg)) {
        instrlist_meta_preinsert(bb, trigger, spill_queue_reg_instr);
        instrlist_meta_postinsert(bb, store_queue_reg_instr, restore_queue_reg_instr);
    }
}


void wait_for_checker()
{
    std::cout << "Thread " << gettid() << " now waiting for checker thread" << std::endl;

    // Free all zones in the queue:
    if (IPC_QUEUE_2->enqueue_pointer < IPC_QUEUE_2->z2) {
        IPC_QUEUE_2->is_z1_free = 1;
    }
    else {
        IPC_QUEUE_2->is_z2_free = 1;
    }
    IPC_QUEUE_2->last_thread_changed = 0;

    while (!CHECKER_THREAD_FINISHED);
    std::cout << "Thread " << gettid() << " finished waiting for checker" << std::endl;
}

void mark_checker_thread_finished()
{
    std::cout << "Thread " << gettid() << " now marking completion" << std::endl;
    CHECKER_THREAD_FINISHED = 1;
}

void threads_sync_handler(JANUS_CONTEXT) {
    std::cout << "In threads_sync_handler: TID = " << dr_get_thread_id(drcontext) << std::endl;

    // At the end of main, MAIN thread should wait for CHECKER,
    // whilst CHECKER should mark completion when it's done.
    if (app_threads[dr_get_thread_id(drcontext)]->threadRole == ThreadRole::MAIN) {
        // insert_function_call_as_application(janus_context, wait_for_checker);
        dr_insert_clean_call(drcontext, bb, instrlist_last(bb), (void*) wait_for_checker, 0, 0);
    }
    if (app_threads[dr_get_thread_id(drcontext)]->threadRole == ThreadRole::CHECKER) {
        dr_insert_clean_call(drcontext, bb, instrlist_last(bb), (void*) mark_checker_thread_finished, 0, 0);
    }
}

void create_handler_table(){
    htable[0] = (void*)&count_load_instructions_handler;
    htable[1] = (void*)&thread_creation_handler;
    htable[2] = (void*)&main_handler;
    htable[3] = (void*)&checker_handler;
    htable[4] = (void*)&threads_sync_handler;
}

/*--- Dynamic Handlers Finish ---*/


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

    // "free_registers" below refer to registers not used in the trigger instruction
    std::vector<reg_id_t> free_registers = get_free_registers(INSTRUMENTATION_REGISTERS, trigger);
    reg_id_t queue_ptr_reg = free_registers[0];

    opnd_size_t src1_size = opnd_get_size(src1);
    opnd_size_t src2_size = opnd_get_size(src2);
    opnd_size_t size = max(src1_size, src2_size);
    src1_size = size;
    src2_size = size;

    opnd_t dequeue_location1 = make_opnd_mem_from_reg_and_size(queue_ptr_reg, src1_size);
    opnd_t dequeue_location2 = make_opnd_mem_from_reg_and_size(queue_ptr_reg, src2_size);

    reg_id_t tmp_reg1 = free_registers[1];
    reg_id_t tmp_reg2 = free_registers[2];
    tmp_reg1 = reg_resize_to_opsz(tmp_reg1, src1_size);
    instr_t *dequeue_instr1 = XINST_CREATE_load(drcontext, opnd_create_reg(tmp_reg1), dequeue_location1);
    
    tmp_reg2 = reg_resize_to_opsz(tmp_reg2, src2_size);
    instr_t *dequeue_instr2 = XINST_CREATE_load(drcontext, opnd_create_reg(tmp_reg2), dequeue_location2);
    instr_t *new_cmp = XINST_CREATE_cmp(drcontext, opnd_create_reg(tmp_reg1), opnd_create_reg(tmp_reg2));

    instr_t *prev_trigger = instr_get_prev_app(trigger);

    if (prev_trigger) {
        // instr_set_translation(new_cmp, instr_get_app_pc(prev_trigger));
        instr_set_translation(dequeue_instr1, instr_get_app_pc(prev_trigger));
        instr_set_translation(dequeue_instr2, instr_get_app_pc(prev_trigger));
    }


    instr_t *post_trigger = instr_get_next_app(trigger);
    assert(post_trigger);

    instr_t *load_dequeue_ptr_instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->dequeue_pointer), OPSZ_8)
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
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->dequeue_pointer), OPSZ_8),
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

    // Add dequeue and replace trigger with new cmp
    if (inRegSet(bitmask, queue_ptr_reg)) {
        instrlist_meta_preinsert(bb, trigger, spill_queue_reg_instr);
    }
    instrlist_meta_preinsert(bb, trigger, spill_tmp_reg1_instr);
    instrlist_meta_preinsert(bb, trigger, spill_tmp_reg2_instr);
    instrlist_preinsert(bb, trigger, load_dequeue_ptr_instr);
    instrlist_preinsert(bb, trigger, dequeue_instr1);
    instrlist_preinsert(bb, trigger, increment_queue_reg_instr1);
    instrlist_preinsert(bb, trigger, dequeue_instr2);
    instrlist_preinsert(bb, trigger, increment_queue_reg_instr2);
    instrlist_preinsert(bb, trigger, new_cmp);
    instrlist_preinsert(bb, trigger, store_queue_reg_instr);

    instrlist_meta_postinsert(bb, trigger, restore_tmp_reg2_instr);
    instrlist_meta_postinsert(bb, trigger, restore_tmp_reg1_instr);
    if (inRegSet(bitmask, queue_ptr_reg)) {
        instrlist_meta_postinsert(bb, trigger, restore_queue_reg_instr);
    }

    #ifdef INSERT_DEBUG_CLEAN_CALLS
    //dr_insert_clean_call(drcontext, bb, increment_queue_reg_instr1, after_dequeue_debug, 0, 1, instr_get_src(new_cmp, 0));
    //dr_insert_clean_call(drcontext, bb, increment_queue_reg_instr2, after_dequeue_debug, 0, 1, instr_get_src(new_cmp, 1));
    #endif

    instructions_to_remove.push_back(trigger);
}
