#ifndef _DSL_UTIL_
#define _DSL_UTIL_

#include "dr_api.h"
#include "janus.h"
#include "janus_api.h"
#include <fstream>
#include <list>
#include <map>
#include <vector>


#define f.open(var)                 f.open(var, ios::in | ios::out)
#define get_return_val(I)           opnd_create_reg((reg_id_t)DR_REG_RAX)
#define get_arg1(I)                 opnd_create_reg((reg_id_t)DR_REG_RDI)
#define get_arg2(I)                 opnd_create_reg((reg_id_t)DR_REG_RSI)
#define get_arg3(I)                 opnd_create_reg((reg_id_t)DR_REG_RDX)
#define get_arg4(I)                 opnd_create_reg((reg_id_t)DR_REG_RCX)
#define get_arg5(I)                 opnd_create_reg((reg_id_t)DR_REG_R8)
#define get_arg6(I)                 opnd_create_reg((reg_id_t)DR_REG_R9)
#define get_value(opnd)             get_val(drcontext, bb, opnd, trigger)
#define get_value_opnd(opnd)        OPND_CREATE_INTPTR(get_value_exp(drcontext, bb, opnd, trigger))
#define get_addr(opnd)              get_addr_full(drcontext, bb,opnd, I) 
#define is_type(a,b)                OPND_CREATE_INT64(is_type_opnd(a,b))

void get_mem_rw_addr_full(void *dr_context, instrlist_t *bb, instr_t * instr);
#define get_mem_rw_addr(I)          get_mem_rw_addr_full(drcontext, bb, trigger)

app_pc get_nextaddr_full(void *dr_context, instr_t *instr);
#define get_nextaddr(I)             OPND_CREATE_INTPTR(get_nextaddr_full(drcontext, trigger))

opnd_t get_target_addr_indcall(instr_t * instr);
uintptr_t get_target_addr_call(instr_t * instr);
#define get_target_addr(I)          (instr_is_return(trigger)? OPND_CREATE_MEMPTR(DR_REG_XSP,0) : (instr_is_call_direct(trigger)? OPND_CREATE_INTPTR(get_target_addr_call(trigger)) : get_target_addr_indcall(trigger))) 

opnd_t get_src1(instr_t *instr);
opnd_t get_src2(instr_t *instr);
opnd_t get_dest(instr_t *instr);
opnd_t opnd(int x);
opnd_t opnd(uint64_t x);
opnd_t opnd(uint32_t x);
opnd_t opnd(opnd_t x);
opnd_t opnd(opnd_t x, int offset, int size);
opnd_t opnd(struct instr &x);
opnd_t opnd_null();
int get_opcode(instr_t *instr);
void replace(void *drcontext, instrlist_t *bb, instr_t *trigger, struct instr x);
void insert_before(void *drcontext, instrlist_t *bb, instr_t *trigger, struct instr x);
void insert_after(void *drcontext, instrlist_t *bb, instr_t *trigger, struct instr x);
void replace(void *drcontext, instrlist_t *bb, instr_t *trigger);
void delete_instr(void *drcontext, instrlist_t *bb, instr_t *trigger);
void clear_bb(void *drcontext, instrlist_t *bb, instr_t *trigger);
void clear_bb_but_last(void *drcontext, instrlist_t *bb, instr_t *trigger);
void bb_append(void *drcontext, instrlist_t *bb, struct basicblock &sbb, struct instr &x);
void bb_prepend(void *drcontext, instrlist_t *bb, struct basicblock &sbb, struct instr &x);
void bb_append(void *drcontext, instrlist_t *bb, instr_t *trigger, struct instr x);
void bb_prepend(void *drcontext, instrlist_t *bb, instr_t *trigger, struct instr x);
void bb_append(void *drcontext, instrlist_t *bb, instr_t *trigger, struct basicblock sbb);
void bb_prepend(void *drcontext, instrlist_t *bb, instr_t *trigger, struct basicblock sbb);
void replace_bb(void *drcontext, instrlist_t *bb, instr_t *trigger, struct basicblock sbb);
void replace_bb_but_last(void *drcontext, instrlist_t *bb, instr_t *trigger, struct basicblock sbb);
void print_bb(void *drcontext, instrlist_t *bb, instr_t *trigger);
bool mem_to_reg(instr_t *instr, opnd_t opnd);
void print_u64(uint64_t x);
void print_u32(uint32_t x);
void print_i(int x);
void print_str(char* x);
void print_test();
void fileOpen(std::fstream* s, char* name);
void fileClose(std::fstream *s);
void fileWrite(std::fstream *s, char* str);
opnd_t get_mem_opnd(instr_t *instr);
uint64_t get_val(void *dr_context, instrlist_t *bb, opnd_t opnd, instr_t * instr);
uint64_t get_value_exp(void *dr_context, instrlist_t *bb, opnd_t opnd, instr_t * instr);
uint64_t get_addr_exp(void *dr_context, instrlist_t *bb, opnd_t opnd, instr_t * instr);
void get_addr_full(void *dr_context, instrlist_t *bb, opnd_t opnd, instr_t * instr);
uint64_t get_size(opnd_t opnd);
uint64_t is_type_opnd(opnd_t opnd, int type);
extern uint64_t vars[20];
extern uint64_t var_count;
struct instr{
    opnd_t src;
    opnd_t src2 = opnd_create_null();
    opnd_t dst;
    int opcode;
    instr_t* inst = NULL; //in case of a label, store the instr
};
struct basicblock{
    std::list<instr_t *> instrs;
};
extern void* dr_ctext;

// Given a target instruction and a list of wanted registers, return those registers from the list
// that are not used in the target instruction
std::vector<reg_id_t> get_free_registers(std::vector<reg_id_t> wanted_registers, instr_t* target_instr);


// Given a register and a memory location, create a store using XINST_CREATE_store which spills
// the specified register into the specified spill slot
instr_t* create_spill_reg_instr(void *drcontext, reg_id_t queue_ptr_reg, int64_t *spill_slot);

// Given a register and a memory location, create a load using XINST_CREATE_load which loads 
// the specified register from the specified spill slot
instr_t* create_restore_reg_instr(void *drcontext, reg_id_t queue_ptr_reg, int64_t *spill_slot);


// Given a register and an address, create a memory operand which references the specified address
// and has the same size as the specified register
opnd_t make_mem_opnd_for_reg(reg_id_t reg, void *address);

// Given a register `reg` and an address register, create a memory operand which references the address
// held by the specified address register and has the same size as the specified register `reg`.
// (i.e., it uses the `address_reg` as the base and a 0 displacement)
opnd_t make_mem_opnd_for_reg_from_register(reg_id_t reg, reg_id_t address_reg);

// Given a register `reg`, an address register and a disposition, create a memory operand which references the address
// held by the specified address register + `disp` and has the same size as the specified register `reg`.
// (i.e., it uses the `address_reg` as the base and a `disp` displacement)
opnd_t make_mem_opnd_for_reg_from_register_and_disp(reg_id_t reg, reg_id_t address_reg, int disp);

// Given a register `reg` and a `size`, create a memory reference operand whose base register is the
// specified register `reg` (and displacement is zero), and whose size is the specifid `size`.
opnd_t make_opnd_mem_from_reg_and_size(reg_id_t reg, opnd_size_t size);

// Given a register `reg`, a disp `disp` and a `size`, create a memory reference operand whose base register is the
// specified register `reg` (and displacement is `disp`), and whose size is the specifid `size`.
opnd_t make_opnd_mem_from_reg_disp_and_size(reg_id_t reg, int disp, opnd_size_t size);

// Check if the specified operand `o` is a memory register (RBP or RSP on x86-64)
bool opnd_is_memory_register(opnd_t o);

// Given a target basic block and a list of wanted registers, return those registers from the list
// that are not used in the target basic block
std::vector<reg_id_t> get_free_registers_for_bb(std::vector<reg_id_t> wanted_registers, instrlist_t* bb);

// Given a basic block, returns the number of instructions that have the destination as a register
int get_num_instr_with_reg_dsts(instrlist_t *bb);

// Given a basic block, returns the instruction that has the destination as a register
// and is placed at `index` (among only the insturctions that have the destination as register)
// To be used in conjunction with `get_num_instr_with_reg_dsts`
int get_instr_with_reg_dsts_at_idx(instrlist_t *bb, int index);


#endif


