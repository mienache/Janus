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


    // TODO: the above logic will probably need to be moved in a different location but this will do for now
    void *queue_address;
    if (main_thread && dr_get_thread_id(drcontext) == main_thread->pid) {
        queue_address = IPC_QUEUE_2->z1;
    }
    else if (checker_thread && dr_get_thread_id(drcontext) == checker_thread->pid) {
        queue_address = IPC_QUEUE_2->r2;
    }

    // Instruction for loading the enqueue / dequeue ptr in R15
    instr_t *instr = XINST_CREATE_load_int(
        drcontext,
        opnd_create_reg(DR_REG_R13),
        OPND_CREATE_INTPTR(queue_address)
    );
    instrlist_meta_preinsert(bb, trigger, instr);

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

    instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(DR_REG_RDI),
        OPND_CREATE_ABSMEM((byte *) &checker_thread, OPSZ_8)
    );
    instrlist_meta_preinsert(bb, trigger, instr);

    // IMPORTANT!
    // HERE WE INSERT THE FUNCTION CALL AS APPLICATION, USING THE DYNAMIC/CORE LIBRARY
    insert_function_call_as_application(janus_context, run_thread);


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
    reg_id_t reg64 = get_64_equivalent_reg(reg);

    // TODO: OPND_CREATE_MEM32 below should be changed to MEM64 etc. depending on the size of the register

    instr_t *enqueue_instr = XINST_CREATE_store(
        drcontext,
        OPND_CREATE_MEM32(DR_REG_R13, 0),
        opnd_create_reg(reg)
    );

    instr_t *increment_R15_instr = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(DR_REG_R13),
        OPND_CREATE_INT32(4)
    );

    instrlist_postinsert(bb, trigger, increment_R15_instr);
    instrlist_postinsert(bb, trigger, enqueue_instr);
    // TODO: must set translation


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
    reg_id_t reg64 = get_64_equivalent_reg(reg);
    std::cout << " Register that should be compared against dequeue is " << get_register_name(reg64) << std::endl;

    instr_t *cmp_instr = XINST_CREATE_cmp(
        drcontext,
        opnd_create_reg(reg),
        OPND_CREATE_MEM32(DR_REG_R13, 0)
    );

    instr_set_translation(cmp_instr, instr_get_app_pc(trigger));

    instr_t *jmp_instr = INSTR_CREATE_jcc(
        drcontext,
        OP_jne,
        opnd_create_pc((app_pc)unexpected_dequeue)
    );

    // IPC_QUEUE_2->dequeue_ptr++;
    instr_t *increment_R15_instr = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(DR_REG_R13),
        OPND_CREATE_INT32(4)
    );

    instrlist_meta_postinsert(bb, trigger, increment_R15_instr);
    instrlist_meta_postinsert(bb, trigger, jmp_instr);
    instrlist_postinsert(bb, trigger, cmp_instr);
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
        dr_insert_clean_call(drcontext, bb, instrlist_first(bb), wait_for_checker, false, 0);
    }
    if (app_threads[dr_get_thread_id(drcontext)]->threadRole == ThreadRole::CHECKER) {
        // insert_function_call_as_application(janus_context, mark_checker_thread_finished);
        dr_insert_clean_call(drcontext, bb, instrlist_first(bb), mark_checker_thread_finished, false, 0);
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
