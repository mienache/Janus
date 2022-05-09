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
#include "util.h"

//#define INSERT_DEBUG_CLEAN_CALLS
//#define PRINT_TRIGGER_INSTR
//#define SHOW_INFO_ABOUT_CMP
//#define SKIP_THREAD_CREATION

std::vector <instr_t*> instructions_to_remove;

// If we used a fixed register for the queue pointer, sometimes it may coincide with the register that has
// to be stored in memory (or a source register). The easiest option is to use an alternative register when
// that happens, and the vector below provides a list of potential candidates
std::vector <reg_id_t> INSTRUMENTATION_REGISTERS = {DR_REG_R10, DR_REG_R11, DR_REG_R12, DR_REG_R13, DR_REG_R9};

// Index of the AppThread's spill slot where the register that will hold the queue pointer
// will be spilled before loading the queue pointer.
const unsigned QUEUE_PTR_SPILL_SLOT_INDEX = 0;
const unsigned TMP_REG_SPILL_SLOT_INDEX_1 = 1;
const unsigned TMP_REG_SPILL_SLOT_INDEX_2 = 2;

instr_t* create_spill_reg_instr(void *drcontext, reg_id_t queue_ptr_reg, int64_t *spill_slot);
instr_t* create_restore_reg_instr(void *drcontext, reg_id_t queue_ptr_reg, int64_t *spill_slot);
void unexpected_dequeue();
void main_cmp_instr_handler(JANUS_CONTEXT);
void checker_cmp_instr_handler(JANUS_CONTEXT);

opnd_t make_mem_opnd_for_reg(reg_id_t reg, void *address);
opnd_t make_mem_opnd_for_reg_from_register(reg_id_t reg, reg_id_t address_reg);
opnd_t make_opnd_mem_from_reg_and_size(reg_id_t reg, opnd_size_t size);

bool opnd_is_memory_register(opnd_t o)
{
    return (
        opnd_get_reg(o) == DR_REG_RSP
     || opnd_get_reg(o) == DR_REG_RBP
    );
}

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
    #ifdef SKIP_THREAD_CREATION
        PAST_THREAD_CREATION_STAGE = 1;
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

int get_queue_index(void* ptr);

void enqueue_debug(int64_t enqueued_value)
{
    std::cout << "In enqueue_debug" << std::endl;

    const int index = get_queue_index(IPC_QUEUE_2->enqueue_pointer);
    std::cout << "Enqueing to index: " << index << std::endl;
    std::cout << "Enqueued value = " << enqueued_value << std::endl;
}

void main_handler(JANUS_CONTEXT) {
    if (!(main_thread && dr_get_thread_id(drcontext) == main_thread->pid)) {
        return;
    }

    if (!PAST_THREAD_CREATION_STAGE) {
        return;
    }
    // std::cout << "Instrumenting TID " << dr_get_thread_id(drcontext) << " through main load /move handler" << std::endl;

    instr_t *trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;

    if (!trigger) {
        return;
    }

    #ifdef PRINT_TRIGGER_INSTR
    std::cout << "Trigger instruction: " << (void*) instr_get_app_pc(trigger) << std::endl;
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

    // TODO: the spill should only take place when needed indeed (if the register is free, no need to spill)
    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];
    int64_t *spill_slot = &(curr_thread->spill_slots[QUEUE_PTR_SPILL_SLOT_INDEX]);
    instr_t *spill_queue_reg_instr = create_spill_reg_instr(drcontext, queue_ptr_reg, spill_slot);
    instr_t *restore_queue_reg_instr = create_restore_reg_instr(drcontext, queue_ptr_reg, spill_slot);

    instrlist_meta_postinsert(bb, trigger, restore_queue_reg_instr);
    instrlist_postinsert(bb, trigger, store_queue_reg_instr);
    instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
    instrlist_postinsert(bb, trigger, enqueue_instr);
    instrlist_postinsert(bb, trigger, load_enqueue_ptr_instr);
    instrlist_meta_postinsert(bb, trigger, spill_queue_reg_instr);

    #ifdef INSERT_DEBUG_CLEAN_CALLS
    dr_insert_clean_call(drcontext, bb, enqueue_instr, enqueue_debug, 0, 1, dest);
    #endif
}

void unexpected_dequeue()
{
    std::cout << "---->ERROR: dequeue returned unexpected value" << std::endl;
    for (int i = 1; i <= 50; ++i) {
        std::cout << "---->ERROR: dequeue returned unexpected value" << std::endl;
    }
}

void dequeue_debug(int64_t expected_value, int asserting)
{
    std::cout << "In dequeue_debug" << std::endl;

    if (IPC_QUEUE_2->dequeue_pointer >= IPC_QUEUE_2->r2) {
        std::cout << "R zone" << std::endl;
        return;
    }

    const int index = get_queue_index(IPC_QUEUE_2->dequeue_pointer);
    const int64_t curr_value = *((int64_t*) (IPC_QUEUE_2->dequeue_pointer));
    std::cout << "Dequeing from index: " << index << std::endl;
    std::cout << "Current value: " << curr_value << std::endl;

    if (asserting) {
        std::cout << "Expected value: " << expected_value << std::endl;
    }
    else {
        std::cout << "Not asserting" << std::endl;
    }

    if (asserting && curr_value != expected_value) {
        dump_registers();
    }
}

void after_dequeue_debug(int64_t dequeued_val)
{
    std::cout << "In after dequeue_debug" << std::endl;

    if (IPC_QUEUE_2->dequeue_pointer >= IPC_QUEUE_2->r2) {
        std::cout << "R zone" << std::endl;
        return;
    }

    const int index = get_queue_index(IPC_QUEUE_2->dequeue_pointer);
    std::cout << "Dequeued from index: " << index << std::endl;
    std::cout << "Current value: " << *((int64_t*) (IPC_QUEUE_2->dequeue_pointer)) << std::endl;
    std::cout << "Dequeued value: " << dequeued_val << std::endl;
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
    std::cout << "Trigger instruction: " << (void*) instr_get_app_pc(trigger) << std::endl;
    #endif

    if (!instr_num_dsts(trigger)) {
        //std::cout << "No dest" << std::endl;
        checker_cmp_instr_handler(janus_context);
        return;
    }

    opnd_t dest = instr_get_dst(trigger, 0);

    if (!opnd_is_reg(dest)) {
        //std::cout << "del: Writing to memory, will remove it:" << std::endl;
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

    // std::cout << "Dest register is " << get_register_name(reg) << std::endl;

    if (reg == DR_REG_RBP || reg == DR_REG_RSP) {
        return;
    }

    const reg_id_t queue_ptr_reg = get_free_registers(INSTRUMENTATION_REGISTERS, trigger)[0];

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

    if (any_src_mem_ref) {
        // dequeue and load to reg, remove instruction
        // std::cout << "del: Memory operands in instruction, will remove it:" << std::endl;
        // instr_disassemble(drcontext, trigger, STDOUT);
        // std::cout << endl;

        instr_t *dequeue_instr = XINST_CREATE_load(drcontext, dest, dequeue_location);

        instr_t *pre_trigger = instr_get_prev_app(trigger);
        if (pre_trigger) {
            instr_set_translation(dequeue_instr, instr_get_app_pc(pre_trigger));
        }

        instrlist_postinsert(bb, trigger, store_queue_reg_instr);
        instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
        instrlist_postinsert(bb, trigger, dequeue_instr);
        instrlist_postinsert(bb, trigger, load_dequeue_ptr_instr);

        #ifdef INSERT_DEBUG_CLEAN_CALLS
        dr_insert_clean_call(drcontext, bb, dequeue_instr, dequeue_debug, 0, 2, dest, OPND_CREATE_INT32(0));
        #endif

        // instrlist_remove(bb, trigger);
        instructions_to_remove.push_back(trigger);
    }
    else {
        // cmp against queue, keep instruction
        // std::cout << "Keep instruction" << std::endl;
        instr_t *cmp_instr = XINST_CREATE_cmp(drcontext, dest, dequeue_location);
        instr_t *jmp_instr = INSTR_CREATE_jcc(drcontext, OP_jne, opnd_create_pc((app_pc)unexpected_dequeue));
        instr_set_translation(cmp_instr, instr_get_app_pc(trigger));
        instr_set_translation(jmp_instr, instr_get_app_pc(trigger));

        instrlist_postinsert(bb, trigger, jmp_instr);
        instrlist_postinsert(bb, trigger, store_queue_reg_instr);
        instrlist_postinsert(bb, trigger, increment_queue_reg_instr);
        instrlist_postinsert(bb, trigger, cmp_instr);
        instrlist_postinsert(bb, trigger, load_dequeue_ptr_instr);

        #ifdef INSERT_DEBUG_CLEAN_CALLS
        dr_insert_clean_call(drcontext, bb, cmp_instr, dequeue_debug, 0, 2, dest, OPND_CREATE_INT32(1));
        #endif
    }

    // TODO: optimise this
    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];
    int64_t *spill_slot = &(curr_thread->spill_slots[QUEUE_PTR_SPILL_SLOT_INDEX]);
    instr_t *spill_queue_reg_instr = create_spill_reg_instr(drcontext, queue_ptr_reg, spill_slot);
    instr_t *restore_queue_reg_instr = create_restore_reg_instr(drcontext, queue_ptr_reg, spill_slot);

    instrlist_meta_preinsert(bb, trigger, spill_queue_reg_instr);
    instrlist_meta_postinsert(bb, store_queue_reg_instr, restore_queue_reg_instr);
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

instr_t* create_spill_reg_instr(void *drcontext, reg_id_t reg, int64_t *spill_slot)
{
    return XINST_CREATE_store(
        drcontext,
        OPND_CREATE_ABSMEM((byte*) spill_slot, reg_get_size(reg)),
        opnd_create_reg(reg)
    );

}
instr_t* create_restore_reg_instr(void *drcontext, reg_id_t reg, int64_t *spill_slot)
{
    return XINST_CREATE_load(
        drcontext,
        opnd_create_reg(reg),
        OPND_CREATE_ABSMEM((byte*) spill_slot, reg_get_size(reg))
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

opnd_t make_opnd_mem_from_reg_and_size(reg_id_t reg, opnd_size_t size)
{
    if (size == OPSZ_8) {
        return OPND_CREATE_MEM64(reg, 0);
    }
    else if (size == OPSZ_4) {
        return OPND_CREATE_MEM32(reg, 0);
    }
    else if (size == OPSZ_2) {
        return OPND_CREATE_MEM16(reg, 0);
    }

    return OPND_CREATE_MEM8(reg, 0);
}

int get_queue_index(void* ptr)
{
    return ((int) ptr - (int) IPC_QUEUE_2->z1) / 8;
}

void main_cmp_instr_handler(JANUS_CONTEXT)
{
    // "free_registers" below refer to registers not used in the trigger instruction
    instr_t * trigger = get_trigger_instruction(bb,rule);

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
        OPND_CREATE_INT32(8)
    );
    instr_t *increment_queue_reg_instr2 = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_INT32(8)
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

    instrlist_meta_preinsert(bb, trigger, spill_queue_reg_instr);
    instrlist_meta_preinsert(bb, trigger, spill_tmp_reg1_instr);
    instrlist_meta_preinsert(bb, trigger, spill_tmp_reg2_instr);

    instrlist_postinsert(bb, trigger, restore_tmp_reg2_instr);
    instrlist_postinsert(bb, trigger, restore_tmp_reg1_instr);
    instrlist_postinsert(bb, trigger, restore_queue_reg_instr);
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

void checker_cmp_instr_handler(JANUS_CONTEXT)
{
    instr_t * trigger = get_trigger_instruction(bb,rule);

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
        OPND_CREATE_INT32(8)
    );
    instr_t *increment_queue_reg_instr2 = XINST_CREATE_add(
        drcontext,
        opnd_create_reg(queue_ptr_reg),
        OPND_CREATE_INT32(8)
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
    instrlist_meta_preinsert(bb, trigger, spill_queue_reg_instr);
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
    instrlist_meta_postinsert(bb, trigger, restore_queue_reg_instr);

    #ifdef INSERT_DEBUG_CLEAN_CALLS
    dr_insert_clean_call(drcontext, bb, increment_queue_reg_instr, after_dequeue_debug, 0, 1, instr_get_src(new_cmp, 0));
    dr_insert_clean_call(drcontext, bb, increment_queue_reg_instr, after_dequeue_debug, 0, 1, instr_get_src(new_cmp, 1));
    #endif

    instructions_to_remove.push_back(trigger);
}
