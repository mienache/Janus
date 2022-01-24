/* Header file to implement a JANUS client */
#include <iostream>
#include "janus_api.h"
#include "dsl_core.h"
#include "dsl_thread_manager.h"

#include "func.h"

/*--- Dynamic Handlers Start ---*/
void handler_1(JANUS_CONTEXT){
    instr_t * trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;
    dr_save_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_1);
    instrlist_meta_preinsert(bb, trigger, XINST_CREATE_load(drcontext, opnd_create_reg(DR_REG_RAX), OPND_CREATE_ABSMEM((byte *)&inst_count, OPSZ_8)));
    instrlist_meta_preinsert(bb, trigger, XINST_CREATE_add(drcontext, opnd_create_reg(DR_REG_RAX), OPND_CREATE_INT32(1)));
    instrlist_meta_preinsert(bb, trigger, XINST_CREATE_store(drcontext, OPND_CREATE_ABSMEM((byte *)&inst_count, OPSZ_8), opnd_create_reg(DR_REG_RAX)));
    dr_restore_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_1);
}

// #define JANUS_CONTEXT void *drcontext, instrlist_t *bb, RRule *rule, void *tag
void handler_2(JANUS_CONTEXT) {
    rsched_info.number_of_threads = 2;
    create_threads();
}

void old_handler_2(JANUS_CONTEXT){
    instr_t * trigger = get_trigger_instruction(bb,rule);
    uint64_t bitmask = rule->reg1;
    if(inRegSet(bitmask,8)) dr_save_reg(drcontext,bb,trigger,DR_REG_RDI,SPILL_SLOT_1);
    if(inRegSet(bitmask,11)) dr_save_reg(drcontext,bb,trigger,DR_REG_R10,SPILL_SLOT_2);
    if(inRegSet(bitmask,12)) dr_save_reg(drcontext,bb,trigger,DR_REG_R11,SPILL_SLOT_3);
    if(inRegSet(bitmask,16)) dr_save_reg(drcontext,bb,trigger,DR_REG_R15,SPILL_SLOT_4);
    if(inRegSet(bitmask,9)) dr_save_reg(drcontext,bb,trigger,DR_REG_R8,SPILL_SLOT_5);
    if(inRegSet(bitmask,10)) dr_save_reg(drcontext,bb,trigger,DR_REG_R9,SPILL_SLOT_6);
    dr_save_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_7);
    if(inRegSet(bitmask,2)) dr_save_reg(drcontext,bb,trigger,DR_REG_RCX,SPILL_SLOT_8);
    if(inRegSet(bitmask,3)) dr_save_reg(drcontext,bb,trigger,DR_REG_RDX,SPILL_SLOT_9);
    if(inRegSet(bitmask,7)) dr_save_reg(drcontext,bb,trigger,DR_REG_RSI,SPILL_SLOT_10);
    dr_save_arith_flags(drcontext,bb,trigger,SPILL_SLOT_11);
    dr_save_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_11);
    dr_restore_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_7);
    instrlist_meta_preinsert(bb, trigger,INSTR_CREATE_push(drcontext, opnd_create_reg(DR_REG_RAX)));
    instrlist_meta_preinsert(bb, trigger, XINST_CREATE_load_int(drcontext, opnd_create_reg(DR_REG_RDI), OPND_CREATE_INT64((uint64_t)L_3)));
    instrlist_meta_preinsert(bb, trigger, XINST_CREATE_call(drcontext, opnd_create_pc((byte *)&print_str)));
    instrlist_meta_preinsert(bb, trigger, INSTR_CREATE_pop(drcontext, opnd_create_reg(DR_REG_RAX)));
    if(inRegSet(bitmask,8)) dr_restore_reg(drcontext,bb,trigger,DR_REG_RDI,SPILL_SLOT_1);
    if(inRegSet(bitmask,11)) dr_restore_reg(drcontext,bb,trigger,DR_REG_R10,SPILL_SLOT_2);
    if(inRegSet(bitmask,12)) dr_restore_reg(drcontext,bb,trigger,DR_REG_R11,SPILL_SLOT_3);
    if(inRegSet(bitmask,16)) dr_restore_reg(drcontext,bb,trigger,DR_REG_R15,SPILL_SLOT_4);
    if(inRegSet(bitmask,9)) dr_restore_reg(drcontext,bb,trigger,DR_REG_R8,SPILL_SLOT_5);
    if(inRegSet(bitmask,10)) dr_restore_reg(drcontext,bb,trigger,DR_REG_R9,SPILL_SLOT_6);
    dr_restore_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_7);
    if(inRegSet(bitmask,2)) dr_restore_reg(drcontext,bb,trigger,DR_REG_RCX,SPILL_SLOT_8);
    if(inRegSet(bitmask,3)) dr_restore_reg(drcontext,bb,trigger,DR_REG_RDX,SPILL_SLOT_9);
    if(inRegSet(bitmask,7)) dr_restore_reg(drcontext,bb,trigger,DR_REG_RSI,SPILL_SLOT_10);
    dr_restore_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_11);
    dr_restore_arith_flags(drcontext,bb,trigger,SPILL_SLOT_11);
    dr_restore_reg(drcontext,bb,trigger,DR_REG_RAX,SPILL_SLOT_7);
}
void create_handler_table(){
    htable[0] = (void*)&handler_1;
    htable[1] = (void*)&handler_2;
}

/*--- Dynamic Handlers Finish ---*/
