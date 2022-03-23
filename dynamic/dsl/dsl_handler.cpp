/* Header file to implement a JANUS client */
#include <cassert>
#include <iostream>
#include <iomanip>
#include <unistd.h>

#include "dsl_core.h"
#include "dsl_ipc.h"
#include "dsl_thread_manager.h"
#include "func.h"
#include "janus_api.h"
#include "handler.h"



/*--- Dynamic Handlers Start ---*/
void handler_1(JANUS_CONTEXT){
    if (app_threads[gettid()]->threadRole == ThreadRole::CHECKER) {
        std::cout << "Checker thread in handler_1" << std::endl;
    }
    instr_t * trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;
    dr_save_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_1);
    instrlist_meta_preinsert(bb, trigger, XINST_CREATE_load(drcontext, opnd_create_reg(DR_REG_RAX), OPND_CREATE_ABSMEM((byte *)&inst_count, OPSZ_8)));
    instrlist_meta_preinsert(bb, trigger, XINST_CREATE_add(drcontext, opnd_create_reg(DR_REG_RAX), OPND_CREATE_INT32(1)));
    instrlist_meta_preinsert(bb, trigger, XINST_CREATE_store(drcontext, OPND_CREATE_ABSMEM((byte *)&inst_count, OPSZ_8), opnd_create_reg(DR_REG_RAX)));
    dr_restore_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_1);

    std::cout << "in handler 1" << std::endl;
} 

void msg() {
    std::cout << "Just before clean call" << std::endl;
}
void handler_2(JANUS_CONTEXT){
    if (app_threads[gettid()]->threadRole == ThreadRole::CHECKER) {
        std::cout << "Checker thread in handler_2" << std::endl;
    }
    if (CHECKER_THREAD_REGISTERED) {
        return;
    }

    instr_t *first = instrlist_first(bb);
    std::cout << "First instruction is at " << (void*) instr_get_app_pc(first) << std::endl;

    instr_t * trigger = get_trigger_instruction(bb,rule);
    app_pc pc = instr_get_app_pc(trigger);
    std::cout << "In handler 2 PC is " << std::hex << (void*) pc << std::dec << std::endl;
    std::cout << std::resetiosflags(std::ios::showbase);


    /*
    uint64_t bitmask = rule->reg1;
    if(inRegSet(bitmask,11)) dr_save_reg(drcontext,bb,trigger,DR_REG_R10,SPILL_SLOT_1);
    if(inRegSet(bitmask,12)) dr_save_reg(drcontext,bb,trigger,DR_REG_R11,SPILL_SLOT_2);
    if(inRegSet(bitmask,9)) dr_save_reg(drcontext,bb,trigger,DR_REG_R8,SPILL_SLOT_4);
    if(inRegSet(bitmask,10)) dr_save_reg(drcontext,bb,trigger,DR_REG_R9,SPILL_SLOT_5);
    dr_save_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_6);
    if(inRegSet(bitmask,2)) dr_save_reg(drcontext,bb,trigger,DR_REG_RCX,SPILL_SLOT_7);
    if(inRegSet(bitmask,8)) dr_save_reg(drcontext,bb,trigger,DR_REG_RDI,SPILL_SLOT_8);
    if(inRegSet(bitmask,3)) dr_save_reg(drcontext,bb,trigger,DR_REG_RDX,SPILL_SLOT_9);
    if(inRegSet(bitmask,7)) dr_save_reg(drcontext,bb,trigger,DR_REG_RSI,SPILL_SLOT_10);
    dr_save_arith_flags(drcontext,bb,trigger,SPILL_SLOT_11);
    dr_save_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_11);
    dr_restore_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_6);
    instrlist_meta_preinsert(bb, trigger,INSTR_CREATE_push(drcontext, opnd_create_reg(DR_REG_RAX)));
    //dr_insert_clean_call(drcontext, bb, instrlist_first(bb), create_checker_thread, false, 1, OPND_CREATE_INT64(val));

    dr_save_reg(drcontext,bb,trigger, DR_REG_RAX, SPILL_SLOT_13);
    dr_save_reg(drcontext,bb,trigger, DR_REG_R14, SPILL_SLOT_12);
    dr_save_reg(drcontext,bb,trigger, DR_REG_R15, SPILL_SLOT_3);

    */
    insert_function_call_as_application(janus_context, create_checker_thread);

    /*
    dr_restore_reg(drcontext,bb,trigger,DR_REG_R14,SPILL_SLOT_12);
    dr_restore_reg(drcontext,bb,trigger,DR_REG_R15,SPILL_SLOT_3);
    dr_restore_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_14);

    instrlist_meta_preinsert(bb, trigger, INSTR_CREATE_pop(drcontext, opnd_create_reg(DR_REG_RAX)));
    if(inRegSet(bitmask,11)) dr_restore_reg(drcontext,bb,trigger,DR_REG_R10,SPILL_SLOT_1);
    if(inRegSet(bitmask,12)) dr_restore_reg(drcontext,bb,trigger,DR_REG_R11,SPILL_SLOT_2);
    if(inRegSet(bitmask,16)) dr_restore_reg(drcontext,bb,trigger,DR_REG_R15,SPILL_SLOT_3);
    if(inRegSet(bitmask,9)) dr_restore_reg(drcontext,bb,trigger,DR_REG_R8,SPILL_SLOT_4);
    if(inRegSet(bitmask,10)) dr_restore_reg(drcontext,bb,trigger,DR_REG_R9,SPILL_SLOT_5);
    dr_restore_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_6);
    if(inRegSet(bitmask,2)) dr_restore_reg(drcontext,bb,trigger,DR_REG_RCX,SPILL_SLOT_7);
    if(inRegSet(bitmask,8)) dr_restore_reg(drcontext,bb,trigger,DR_REG_RDI,SPILL_SLOT_8);
    if(inRegSet(bitmask,3)) dr_restore_reg(drcontext,bb,trigger,DR_REG_RDX,SPILL_SLOT_9);
    if(inRegSet(bitmask,7)) dr_restore_reg(drcontext,bb,trigger,DR_REG_RSI,SPILL_SLOT_10);
    dr_restore_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_11);
    dr_restore_arith_flags(drcontext,bb,trigger,SPILL_SLOT_11);
    dr_restore_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_6);
    */

    app_pc tag_new = instr_get_app_pc(instrlist_first_app(bb));

    file_t output_file = dr_open_file("instructions.txt", DR_FILE_WRITE_OVERWRITE);

    instrlist_disassemble(drcontext, tag_new, bb, output_file);

    dr_close_file(output_file);
}


void handler_3(JANUS_CONTEXT) {
    if (app_threads[gettid()]->threadRole == ThreadRole::CHECKER) {
        std::cout << "Checker thread in handler_3" << std::endl;
    }
    return;
    std::cout << getpid() << " in handler 3" << std::endl;

    instr_t *trigger = get_trigger_instruction(bb,rule);

    std::cout << getpid() << ": trigger instruction " << (void*) instr_get_app_pc(trigger) << std::endl;
    instr_t *post_trigger = instr_get_next(trigger);

    dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
    dr_get_mcontext(drcontext, &mc);

    assert(post_trigger);

    // Get the number of destination operands 
    int num_dest_opnds = instr_num_dsts(trigger);

    if (num_dest_opnds > 1) {
        std::cout << "Instructions with more than 1 dest operands found" << std::endl;
    }
    
    // Iterate over each dest operands
    for (int i = 0; i < num_dest_opnds; ++i) {
        opnd_t dest = instr_get_dst(trigger, i); 

        // If dest operand is not reigster, skip it
        if (!opnd_is_reg(dest)) {
            continue;
        }

        // Debug info
        reg_id_t reg = opnd_get_reg(dest);
        std::cout << " Passing register " << get_register_name(reg) << " to clean call" << std::endl;

        // Insert the value in the queue
        dr_insert_clean_call(drcontext, bb, post_trigger, (void*) communicate, false, 1, dest);

        std::cout << "Clean call inserted" << std::endl;
    }
}

void create_handler_table(){
    htable[0] = (void*)&handler_1;
    htable[1] = (void*)&handler_2;
    htable[2] = (void*)&handler_3;
}

/*--- Dynamic Handlers Finish ---*/
