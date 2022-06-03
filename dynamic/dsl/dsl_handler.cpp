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

// Index of the AppThread's spill slot where the register that will hold the queue pointer
// will be spilled before loading the queue pointer.
const unsigned QUEUE_PTR_SPILL_SLOT_INDEX = 0;
const unsigned TMP_REG_SPILL_SLOT_INDEX_1 = 1;
const unsigned TMP_REG_SPILL_SLOT_INDEX_2 = 2;


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

    add_instrumentation_for_thread_creation(janus_context);
}

void main_handler(JANUS_CONTEXT) {
    if (!(main_thread && dr_get_thread_id(drcontext) == main_thread->pid)) {
        return;
    }

    add_instrumentation_for_comet_enqueue(janus_context, IPC_QUEUE_2);
}


void checker_handler(JANUS_CONTEXT) {
    if (!(checker_thread && dr_get_thread_id(drcontext) == checker_thread->pid)) {
        return;
    }

    add_instrumentation_for_comet_dequeue(janus_context, IPC_QUEUE_2);
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
