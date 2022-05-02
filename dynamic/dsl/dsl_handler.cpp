/* Header file to implement a JANUS client */
#include <cassert>
#include <iostream>
#include <iomanip>
#include <unistd.h>

#include "dsl_core.h"
#include "dsl_ipc.h"
#include "dsl_thread_manager.h"
#include "func.h"
#include "front_end.h"
#include "janus_api.h"
#include "handler.h"

const reg_id_t QUEUE_PTR_REG = DR_REG_R11;

// Sometimes the QUEUE_PTR_REG coincides with the register that has to be stored in memory
// The easiest option for now is to use an alternative register when that happens.
const reg_id_t QUEUE_PTR_REG_ALTERNATIVE = DR_REG_R10;

// Index of the AppThread's spill slot where the register that will hold the queue pointer
// will be spilled before loading the queue pointer
const unsigned QUEUE_PTR_SPILL_SLOT_INDEX = 0;

instr_t* create_spill_queue_ptr_instr(void *drcontext, reg_id_t queue_ptr_reg, int64_t *spill_slot);
instr_t* create_restore_queue_ptr_instr(void *drcontext, reg_id_t queue_ptr_reg, int64_t *spill_slot);

void print_func_entry_msg(void *drcontext, string func_name)
{
    string thread_role;
    if (app_threads[dr_get_thread_id(drcontext)]->threadRole == ThreadRole::MAIN) {
        thread_role = "MAIN";
    }
    else if (app_threads[dr_get_thread_id(drcontext)]->threadRole == ThreadRole::CHECKER) {
        thread_role = "CHECKER";
    }
    else {
        thread_role = "UNKNOWN";
    }

    std::cout << "Thread " << thread_role << " enters " << func_name << std::endl;
}

/*--- Dynamic Handlers Start ---*/
void handler_1(JANUS_CONTEXT){
    // Uncomment below to monitor when this handler is invoked
    // print_func_entry_msg(drcontext, "handler_1");

    return;
    instr_t * trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;
    dr_save_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_1);
    instrlist_meta_preinsert(bb, trigger, XINST_CREATE_load(drcontext, opnd_create_reg(DR_REG_RAX), OPND_CREATE_ABSMEM((byte *)&inst_count, OPSZ_8)));
    instrlist_meta_preinsert(bb, trigger, XINST_CREATE_add(drcontext, opnd_create_reg(DR_REG_RAX), OPND_CREATE_INT32(1)));
    instrlist_meta_preinsert(bb, trigger, XINST_CREATE_store(drcontext, OPND_CREATE_ABSMEM((byte *)&inst_count, OPSZ_8), opnd_create_reg(DR_REG_RAX)));
    dr_restore_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_1);
} 

void handler_2(JANUS_CONTEXT){
    std::cout << "Instrumenting through handler 2" << std::endl;

    instr_t *trigger = get_trigger_instruction(bb,rule);
    if (!trigger) {
        return;
    }


    // TODO: the above logic will probably need to be moved in a different location but this will do for now
    void *queue_address;
    if (main_thread && dr_get_thread_id(drcontext) == main_thread->pid) {
        queue_address = IPC_QUEUE_2->z1;
    }
    else if (checker_thread && dr_get_thread_id(drcontext) == checker_thread->pid) {
        queue_address = IPC_QUEUE_2->r2;
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

    // IMPORTANT!
    // HERE WE INSERT THE FUNCTION CALL AS APPLICATION, USING THE DYNAMIC/CORE LIBRARY
    insert_function_call_as_application(janus_context, (void*) run_thread);


    // Just printing the modified basic block to identify the file easier
    app_pc tag_new = instr_get_app_pc(instrlist_first_app(bb));
    file_t output_file = dr_open_file("instructions.txt", DR_FILE_WRITE_OVERWRITE);
    instrlist_disassemble(drcontext, tag_new, bb, output_file);
    dr_close_file(output_file);
}


reg_id_t get_64_equivalent_reg(reg_id_t reg)
{
    if (reg_get_size(reg) == OPSZ_8) {
        return reg;
    }
    if (reg_get_size(reg) == OPSZ_4) {
        return reg_32_to_64(reg);
    }
    std::cout << "Warning! Register size is less than 32" << std::endl;
    return reg;
}

void handler_3(JANUS_CONTEXT) {
    if (!(main_thread && dr_get_thread_id(drcontext) == main_thread->pid)) {
        return;
    }

    if (!PAST_THREAD_CREATION_STAGE) {
        return;
    }

    std::cout << "Instrumenting TID " << dr_get_thread_id(drcontext) << " through handler 3" << std::endl;

    instr_t *trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;

    if (!trigger) {
        return;
    }

    if (!instr_num_dsts(trigger)) {
        std::cout << "No dest registers, skipping" << std::endl;
        return;
    }

    opnd_t dest = instr_get_dst(trigger, 0);
    if (!opnd_is_reg(dest)) {
        std::cout << "Operand is not register, skipping" << std::endl;
        return;
    }

    std::cout << "Adding enqueue instruction" << std::endl;

    //add_instrumentation_code_for_queue_communication(janus_context, enqueue, IPC_QUEUE, dest);
    reg_id_t reg = opnd_get_reg(dest);
    std::cout << " Original register is " << get_register_name(reg) << std::endl;

    const reg_id_t queue_ptr_reg = reg_overlap(reg, QUEUE_PTR_REG) ? QUEUE_PTR_REG_ALTERNATIVE : QUEUE_PTR_REG;

    instr_t *load_enqueue_ptr_instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->enqueue_pointer), OPSZ_8)
    );

    instr_t *enqueue_instr = XINST_CREATE_store(
        drcontext,
        reg_is_32bit(reg) ? OPND_CREATE_MEM32(queue_ptr_reg, 0) : OPND_CREATE_MEM64(queue_ptr_reg, 0),
        opnd_create_reg(reg)
    );
    instr_set_translation(enqueue_instr, instr_get_app_pc(trigger));

    instr_t *increment_queue_reg_instr = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_INT32(8)
    );

    instr_t *store_queue_reg_instr = XINST_CREATE_store(
        drcontext,
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->enqueue_pointer), OPSZ_8),
        opnd_create_reg(queue_ptr_reg)
    );

    instrlist_meta_postinsert(bb, trigger, store_queue_reg_instr);
    instrlist_meta_postinsert(bb, trigger, increment_queue_reg_instr);
    instrlist_postinsert(bb, trigger, enqueue_instr);
    instrlist_meta_postinsert(bb, trigger, load_enqueue_ptr_instr);

    if (0 && inRegSet(bitmask, queue_ptr_reg)) {
        std::cout << "Spilling queue ptr reg" << std::endl;
        // If the register is live, must spill and reload before and after the queue operations
        const pid_t tid = dr_get_thread_id(drcontext);

        AppThread *curr_thread = app_threads[tid];
        int64_t *spill_slot = &(curr_thread->spill_slots[QUEUE_PTR_SPILL_SLOT_INDEX]);
        instr_t *spill_queue_reg_instr = create_spill_queue_ptr_instr(drcontext, queue_ptr_reg, spill_slot);
        instr_t *restore_queue_reg_instr = create_restore_queue_ptr_instr(drcontext, queue_ptr_reg, spill_slot) ;

        // Insert the spill before the load ptr instr
        instrlist_meta_preinsert(bb, load_enqueue_ptr_instr, spill_queue_reg_instr);

        // Insert the restore after the queue register pointer is stored
        instrlist_meta_postinsert(bb, store_queue_reg_instr, restore_queue_reg_instr);

        std::cout << "Finished inserting instructions for spilling and restoring" << std::endl;
    }



    /*
    // Uncomment this to print instruction and declare `cnt_inst` before function
    string filename = "instruction_" + to_string(++cnt_inst) + ".txt";
    file_t output_file = dr_open_file(filename.c_str(), DR_FILE_WRITE_OVERWRITE);
    instr_disassemble(drcontext, enqueue_instr, output_file);
    dr_close_file(output_file);
    */
}

void unexpected_dequeue()
{
    std::cout << "ERROR: dequeue returned unexpected value" << std::endl;
}

void handler_4(JANUS_CONTEXT) {
    if (!(checker_thread && dr_get_thread_id(drcontext) == checker_thread->pid)) {
        return;
    }

    std::cout << "Instrumenting TID " << dr_get_thread_id(drcontext) << " through handler 4" << std::endl;

    instr_t *trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;

    if (!trigger) {
        return;
    }

    if (!instr_num_dsts(trigger)) {
        return;
    }

    opnd_t dest = instr_get_dst(trigger, 0);
    if (!opnd_is_reg(dest)) {
        std::cout << "Operand is not register, skipping" << std::endl;
        return;
    }

    std::cout << "Adding dequeue instruction" << std::endl;

    reg_id_t reg = opnd_get_reg(dest);
    std::cout << " Original register is " << get_register_name(reg) << std::endl;

    const reg_id_t queue_ptr_reg = reg_overlap(reg, QUEUE_PTR_REG) ? QUEUE_PTR_REG_ALTERNATIVE : QUEUE_PTR_REG;

    instr_t *load_dequeue_ptr_instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->dequeue_pointer), OPSZ_8)
    );

    instr_t *cmp_instr = XINST_CREATE_cmp(
        drcontext,
        opnd_create_reg(reg),
        reg_is_32bit(reg) ? OPND_CREATE_MEM32(queue_ptr_reg, 0) : OPND_CREATE_MEM64(queue_ptr_reg, 0)
    );

    instr_set_translation(cmp_instr, instr_get_app_pc(trigger));

    instr_t *jmp_instr = INSTR_CREATE_jcc(
        drcontext,
        OP_jne,
        opnd_create_pc((app_pc)unexpected_dequeue)
    );

    instr_t *increment_queue_reg_instr = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_INT32(8)
    );

    instr_t *store_queue_reg_instr = XINST_CREATE_store(
        drcontext,
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->dequeue_pointer), OPSZ_8),
        opnd_create_reg(queue_ptr_reg)
    );

    instrlist_meta_postinsert(bb, trigger, store_queue_reg_instr);
    instrlist_meta_postinsert(bb, trigger, increment_queue_reg_instr);
    instrlist_meta_postinsert(bb, trigger, jmp_instr);
    instrlist_postinsert(bb, trigger, cmp_instr);
    instrlist_meta_postinsert(bb, trigger, load_dequeue_ptr_instr);

    if (0 && inRegSet(bitmask, queue_ptr_reg)) {
        std::cout << "Spilling queue ptr reg" << std::endl;
        // If the register is live, must spill and reload before and after the queue operations
        const pid_t tid = dr_get_thread_id(drcontext);

        AppThread *curr_thread = app_threads[tid];
        int64_t *spill_slot = &(curr_thread->spill_slots[QUEUE_PTR_SPILL_SLOT_INDEX]);
        instr_t *spill_queue_reg_instr = create_spill_queue_ptr_instr(drcontext, queue_ptr_reg, spill_slot);
        instr_t *restore_queue_reg_instr = create_restore_queue_ptr_instr(drcontext, queue_ptr_reg, spill_slot);

        // Insert the spill before the load ptr instr
        instrlist_meta_preinsert(bb, load_dequeue_ptr_instr, spill_queue_reg_instr);

        // Insert the restore after the queue register pointer is stored
        instrlist_meta_postinsert(bb, store_queue_reg_instr, restore_queue_reg_instr);

        std::cout << "Finished inserting instructions for spilling and restoring" << std::endl;
    }
}

void wait_for_checker()
{
    std::cout << "Thread " << gettid() << " now waiting for checker thread" << std::endl;

    // Free all zones in the queue:
    IPC_QUEUE_2->is_z1_free = 1;
    IPC_QUEUE_2->is_z2_free = 1;

    /*
    // Uncomment this to print soome values from the queue
    int *ptr = IPC_QUEUE_2->z1;
    for (int i = 0; i < 4; ++i) {
        //std::cout << "At " << i << " val = " << (void*) (IPC_QUEUE_2->z1[i - 1]) << std::endl;
        std::cout << "At " << i << " val = " << (IPC_QUEUE_2->z1[i - 1]) << std::endl;
    }
    */
    while (!CHECKER_THREAD_FINISHED);
    std::cout << "Thread " << gettid() << " finished waiting for checker" << std::endl;
}

void mark_checker_thread_finished()
{
    std::cout << "Thread " << gettid() << " now marking completion" << std::endl;
    CHECKER_THREAD_FINISHED = 1;
}

void handler_5(JANUS_CONTEXT) {
    std::cout << "In handler_5: TID = " << dr_get_thread_id(drcontext) << std::endl;

    // At the end of main, MAIN thread should wait for CHECKER,
    // whilst CHECKER should mark completion when it's done.
    if (app_threads[dr_get_thread_id(drcontext)]->threadRole == ThreadRole::MAIN) {
        // insert_function_call_as_application(janus_context, wait_for_checker);
        std::cout << "Addres of wait_for_checker: " << (void*) wait_for_checker << std::endl;
        dr_insert_clean_call(drcontext, bb, instrlist_first(bb), (void*) wait_for_checker, false, 0);
    }
    if (app_threads[dr_get_thread_id(drcontext)]->threadRole == ThreadRole::CHECKER) {
        // insert_function_call_as_application(janus_context, mark_checker_thread_finished);
        dr_insert_clean_call(drcontext, bb, instrlist_first(bb), (void*) mark_checker_thread_finished, false, 0);
    }
}

void create_handler_table(){
    htable[0] = (void*)&handler_1;
    htable[1] = (void*)&handler_2;
    htable[2] = (void*)&handler_3;
    htable[3] = (void*)&handler_4;
    htable[4] = (void*)&handler_5;
}

/*--- Dynamic Handlers Finish ---*/

instr_t* create_spill_queue_ptr_instr(void *drcontext, reg_id_t queue_ptr_reg, int64_t *spill_slot)
{
    return XINST_CREATE_store(
        drcontext,
        OPND_CREATE_ABSMEM((byte*) spill_slot, OPSZ_8),
        opnd_create_reg(queue_ptr_reg)
    );

}
instr_t* create_restore_queue_ptr_instr(void *drcontext, reg_id_t queue_ptr_reg, int64_t *spill_slot)
{
    return XINST_CREATE_load(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_ABSMEM((byte*) spill_slot, OPSZ_8)
    );
}