/* Header file to implement a JANUS client */
#include <cassert>
#include <iostream>
#include <iomanip>
#include <vector>
#include <unistd.h>

#include "dsl_core.h"
#include "dsl_ipc.h"
#include "dsl_thread_manager.h"
#include "func.h"
#include "front_end.h"
#include "janus_api.h"
#include "handler.h"

std::vector <instr_t*> instructions_to_remove;

const reg_id_t QUEUE_PTR_REG = DR_REG_R11;

// Sometimes the QUEUE_PTR_REG coincides with the register that has to be stored in memory
// The easiest option for now is to use an alternative register when that happens.
const reg_id_t QUEUE_PTR_REG_ALTERNATIVE = DR_REG_R12;

// Index of the AppThread's spill slot where the register that will hold the queue pointer
// will be spilled before loading the queue pointer
const unsigned QUEUE_PTR_SPILL_SLOT_INDEX = 0;

instr_t* create_spill_queue_ptr_instr(void *drcontext, reg_id_t queue_ptr_reg, int64_t *spill_slot);
instr_t* create_restore_queue_ptr_instr(void *drcontext, reg_id_t queue_ptr_reg, int64_t *spill_slot);
void unexpected_dequeue();
void main_cmp_instr_handler(void *drcontext, instrlist_t *bb, instr_t *trigger);
void checker_cmp_instr_handler(void *drcontext, instrlist_t *bb, instr_t *trigger);

opnd_t make_mem_opnd_for_reg(reg_id_t reg, void *address);
opnd_t make_mem_opnd_for_reg_from_register(reg_id_t reg, reg_id_t address_reg);

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
void count_load_instructions_handler(JANUS_CONTEXT){
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

void thread_creation_handler(JANUS_CONTEXT){
    /*
    PAST_THREAD_CREATION_STAGE = 1;
    CHECKER_THREAD_FINISHED = 1;
    return;
    */

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

    // IMPORTANT!
    // HERE WE INSERT THE FUNCTION CALL AS APPLICATION, USING THE DYNAMIC/CORE LIBRARY
    insert_function_call_as_application(janus_context, (void*) run_thread);


    // Just printing the modified basic block to identify the file easier
    app_pc tag_new = instr_get_app_pc(instrlist_first_app(bb));
    file_t output_file = dr_open_file("instructions.txt", DR_FILE_WRITE_OVERWRITE);
    instrlist_disassemble(drcontext, tag_new, bb, output_file);
    dr_close_file(output_file);
}

int get_queue_index(void* ptr);

void main_handler(JANUS_CONTEXT) {
    if (!(main_thread && dr_get_thread_id(drcontext) == main_thread->pid)) {
        return;
    }

    if (!PAST_THREAD_CREATION_STAGE) {
        return;
    }
    std::cout << "Instrumenting TID " << dr_get_thread_id(drcontext) << " through main load /move handler" << std::endl;

    instr_t *trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;

    if (!trigger) {
        return;
    }

    std::cout << "Trigger instruction: " << (void*) instr_get_app_pc(trigger) << std::endl;

    if (!instr_num_dsts(trigger)) {
        main_cmp_instr_handler(drcontext, bb, trigger);
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

    reg_id_t queue_ptr_reg = QUEUE_PTR_REG;

    instr_t *load_enqueue_ptr_instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->enqueue_pointer), OPSZ_8)
    );

    opnd_t enqueue_location = make_mem_opnd_for_reg_from_register(reg, queue_ptr_reg);
    instr_t *enqueue_instr = XINST_CREATE_store(drcontext, enqueue_location, dest);

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

    instrlist_postinsert(bb, trigger, store_queue_reg_instr);
    instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
    instrlist_postinsert(bb, trigger, enqueue_instr);
    instrlist_postinsert(bb, trigger, load_enqueue_ptr_instr);
}

void unexpected_dequeue()
{
    std::cout << "ERROR: dequeue returned unexpected value" << std::endl;
}

void checker_handler(JANUS_CONTEXT) {
    if (!(checker_thread && dr_get_thread_id(drcontext) == checker_thread->pid)) {
        return;
    }


    std::cout << "Instrumenting TID " << dr_get_thread_id(drcontext) << " through checker load handler" << std::endl;

    instr_t *trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;

    if (!trigger) {
        return;
    }

    // ignore RSP and RBP

    std::cout << "Trigger instruction: " << (void*) instr_get_app_pc(trigger) << std::endl;

    if (!instr_num_dsts(trigger)) {
        checker_cmp_instr_handler(drcontext, bb, trigger);
        return;
    }

    opnd_t dest = instr_get_dst(trigger, 0);

    if (!opnd_is_reg(dest)) {
        std::cout << "del: Writing to memory, will remove it:" << std::endl;
        instr_disassemble(drcontext, trigger, STDOUT);
        std::cout << endl;
        instructions_to_remove.push_back(trigger);
        return;
    }


    bool src_all_reg = 1;
    for (int i = 0; i < instr_num_srcs(trigger); ++i) {
        opnd_t src = instr_get_src(trigger, i);
        if (!opnd_is_reg(src)) {
            src_all_reg = 0;
            break;
        }
    }


    reg_id_t reg = opnd_get_reg(dest);

    std::cout << "Dest register is " << get_register_name(reg) << std::endl;

    if (reg == DR_REG_RBP || reg == DR_REG_RSP) {
        return;
    }

    reg_id_t queue_ptr_reg = QUEUE_PTR_REG;

    instr_t *load_dequeue_ptr_instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->dequeue_pointer), OPSZ_8)
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

    opnd_t dequeue_location = make_mem_opnd_for_reg_from_register(reg, queue_ptr_reg);
    instr_t *dequeue_instr;


    if (!src_all_reg) {
        // dequeue and load to reg, remove instruction
        std::cout << "del: Memory operands in instruction, will remove it:" << std::endl;
        instr_disassemble(drcontext, trigger, STDOUT);
        std::cout << endl;

        dequeue_instr = XINST_CREATE_load(drcontext, dest, dequeue_location);

        instr_t *pre_trigger = instr_get_prev_app(trigger);
        if (pre_trigger) {
            instr_set_translation(dequeue_instr, instr_get_app_pc(pre_trigger));
        }

        instrlist_postinsert(bb, trigger, store_queue_reg_instr);
        instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
        instrlist_postinsert(bb, trigger, dequeue_instr);
        instrlist_postinsert(bb, trigger, load_dequeue_ptr_instr);

        // instrlist_remove(bb, trigger);
        instructions_to_remove.push_back(trigger);
    }
    else {
        // cmp against queue, keep instruction
        std::cout << "Keep instruction" << std::endl;
        instr_t *cmp_instr = XINST_CREATE_cmp(drcontext, dest, dequeue_location);
        instr_t *jmp_instr = INSTR_CREATE_jcc(drcontext, OP_jne, opnd_create_pc((app_pc)unexpected_dequeue));
        instr_set_translation(cmp_instr, instr_get_app_pc(trigger));
        instr_set_translation(jmp_instr, instr_get_app_pc(trigger));

        instrlist_postinsert(bb, trigger, jmp_instr);
        instrlist_postinsert(bb, trigger, store_queue_reg_instr);
        instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
        instrlist_postinsert(bb, trigger, cmp_instr);
        instrlist_postinsert(bb, trigger, load_dequeue_ptr_instr);
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

void threads_sync_handler(JANUS_CONTEXT) {
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
    htable[0] = (void*)&count_load_instructions_handler;
    htable[1] = (void*)&thread_creation_handler;
    htable[2] = (void*)&main_handler;
    htable[3] = (void*)&checker_handler;
    htable[4] = (void*)&threads_sync_handler;
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

opnd_t make_mem_opnd_for_reg(reg_id_t reg, void *address)
{
    if (reg_is_64bit(reg)) {
        return OPND_CREATE_ABSMEM(address, OPSZ_8);
    }

    if (reg_is_32bit(reg)) {
        return OPND_CREATE_ABSMEM(address, OPSZ_4);
    }

    if (reg_get_size(reg) == OPSZ_2) {
        return OPND_CREATE_ABSMEM(address, OPSZ_2);
    }

    return OPND_CREATE_ABSMEM(address, OPSZ_1);
}

opnd_t make_mem_opnd_for_reg_from_register(reg_id_t reg, reg_id_t address_reg)
{
    if (reg_is_64bit(reg)) {
        return OPND_CREATE_MEM64(address_reg, 0);
    }

    if (reg_is_32bit(reg)) {
        return OPND_CREATE_MEM32(address_reg, 0);
    }

    if (reg_get_size(reg) == OPSZ_2) {
        return OPND_CREATE_MEM16(address_reg, 0);
    }
    
    return OPND_CREATE_MEM8(address_reg, 0);
}

int get_queue_index(void* ptr)
{
    return ((int) ptr - (int) IPC_QUEUE_2->z1) / 8;
}

void main_cmp_instr_handler(void *drcontext, instrlist_t *bb, instr_t *trigger)
{
    reg_id_t queue_ptr_reg = QUEUE_PTR_REG;

    opnd_t src1 = instr_get_src(trigger, 0);
    opnd_t src2 = instr_get_src(trigger, 1);

    opnd_size_t src1_size = opnd_get_size(src1);
    opnd_size_t src2_size = opnd_get_size(src2);

    opnd_t enqueue_location1 = opnd_create_base_disp(queue_ptr_reg, DR_REG_NULL, 0, 0, src1_size);
    opnd_t enqueue_location2 = opnd_create_base_disp(queue_ptr_reg, DR_REG_NULL, 0, 8, src2_size);

    instr_t *enqueue_instr1;
    instr_t *enqueue_instr2;
    instr_t *tmp_load_instr;
    reg_id_t tmp_reg = DR_REG_R10;
    if (!opnd_is_memory_reference(src1)) {
        enqueue_instr1 = XINST_CREATE_store(drcontext, enqueue_location1, src1);

        tmp_reg = reg_resize_to_opsz(tmp_reg, src2_size);
        tmp_load_instr = XINST_CREATE_load(drcontext, opnd_create_reg(tmp_reg), src2);
        enqueue_instr2 = XINST_CREATE_store(drcontext, enqueue_location2, opnd_create_reg(tmp_reg));
    }
    else {
        tmp_reg = reg_resize_to_opsz(tmp_reg, src1_size);
        tmp_load_instr = XINST_CREATE_load(drcontext, opnd_create_reg(tmp_reg), src1);
        enqueue_instr1 = XINST_CREATE_store(drcontext, enqueue_location1, opnd_create_reg(tmp_reg));

        enqueue_instr2 = XINST_CREATE_store(drcontext, enqueue_location2, src2);
    }

    instr_set_translation(tmp_load_instr, instr_get_app_pc(trigger));
    instr_set_translation(enqueue_instr1, instr_get_app_pc(trigger));
    instr_set_translation(enqueue_instr2, instr_get_app_pc(trigger));


    instr_t *post_trigger = instr_get_next_app(trigger);
    assert(post_trigger);
    assert(instr_is_cti(post_trigger));

    instr_t *load_enqueue_ptr_instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->enqueue_pointer), OPSZ_8)
    );

    instr_t *increment_queue_reg_instr = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_INT32(16) // Must increment twice
    );

    instr_t *store_queue_reg_instr = XINST_CREATE_store(
        drcontext,
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->enqueue_pointer), OPSZ_8),
        opnd_create_reg(queue_ptr_reg)
    );


    instrlist_postinsert(bb, trigger, store_queue_reg_instr);
    instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
    instrlist_postinsert(bb, trigger, enqueue_instr2);
    instrlist_postinsert(bb, trigger, enqueue_instr1);
    instrlist_postinsert(bb, trigger, tmp_load_instr);
    instrlist_postinsert(bb, trigger, load_enqueue_ptr_instr);
}

void checker_cmp_instr_handler(void *drcontext, instrlist_t *bb, instr_t *trigger)
{
    reg_id_t queue_ptr_reg = QUEUE_PTR_REG;

    std::cout << "No dest " << std::endl;

    opnd_t src1 = instr_get_src(trigger, 0);
    opnd_t src2 = instr_get_src(trigger, 1);

    opnd_size_t src1_size = opnd_get_size(src1);
    opnd_size_t src2_size = opnd_get_size(src2);
    opnd_size_t size = max(src1_size, src2_size);
    src1_size = size;
    src2_size = size;

    opnd_t dequeue_location1 = opnd_create_base_disp(queue_ptr_reg, DR_REG_NULL, 0, 0, src1_size);
    opnd_t dequeue_location2 = opnd_create_base_disp(queue_ptr_reg, DR_REG_NULL, 0, 8, src1_size);

    instr_t *dequeue_instr;
    reg_id_t tmp_reg = DR_REG_R10;
    instr_t *new_cmp;
    bool src1_is_mem_ref = 1;
    if (opnd_is_memory_reference(src1)) {
        tmp_reg = reg_resize_to_opsz(tmp_reg, src2_size);
        dequeue_instr = XINST_CREATE_load(drcontext, opnd_create_reg(tmp_reg), dequeue_location2);
        new_cmp = XINST_CREATE_cmp(drcontext, dequeue_location1, opnd_create_reg(tmp_reg));
    }
    else {
        src1_is_mem_ref = 0;
        tmp_reg = reg_resize_to_opsz(tmp_reg, src1_size);
        dequeue_instr = XINST_CREATE_load(drcontext, opnd_create_reg(tmp_reg), dequeue_location1);
        new_cmp = XINST_CREATE_cmp(drcontext, opnd_create_reg(tmp_reg), dequeue_location2);
    }

    std::cout << "Old: " << std::endl;
    instr_disassemble(drcontext, trigger, STDOUT);
    std::cout << endl;
    std::cout << "New: " << std::endl;
    instr_disassemble(drcontext, new_cmp, STDOUT);
    std::cout << endl;

    instr_t *prev_trigger = instr_get_prev_app(trigger);

    if (prev_trigger) {
        instr_set_translation(new_cmp, instr_get_app_pc(prev_trigger));
        instr_set_translation(dequeue_instr, instr_get_app_pc(prev_trigger));
    }


    instr_t *post_trigger = instr_get_next_app(trigger);
    assert(post_trigger);
    assert(instr_is_cti(post_trigger));

    instr_t *load_dequeue_ptr_instr = XINST_CREATE_load(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->dequeue_pointer), OPSZ_8)
    );
    instr_t *increment_queue_reg_instr = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_INT32(16) // Must increment twice
    );
    instr_t *store_queue_reg_instr = XINST_CREATE_store(
        drcontext,
        OPND_CREATE_ABSMEM((byte*) &(IPC_QUEUE_2->dequeue_pointer), OPSZ_8),
        opnd_create_reg(queue_ptr_reg)
    );

    // Add dequeue and replace trigger with new cmp
    instrlist_preinsert(bb, trigger, load_dequeue_ptr_instr);
    instrlist_preinsert(bb, trigger, dequeue_instr);
    instrlist_preinsert(bb, trigger, new_cmp);
    instrlist_preinsert(bb, trigger, increment_queue_reg_instr);
    instrlist_preinsert(bb, trigger, store_queue_reg_instr);

    instructions_to_remove.push_back(trigger);
}