#ifndef __DSL_ERROR_INSERTION__
#define __DSL_ERROR_INSERTION__

#include "dr_api.h"
#include "dsl_thread_manager.h"

/*
EXPECTED_*_BB_CNT variables must be defined in the dsl_error_insertion.cpp file
They represent the number of expected basic blocks for each thread and will be
used to generate the uniform distribution from which the erroneous basic block is
sampled.
*/
extern const int EXPECTED_MAIN_BB_CNT;
extern const int EXPECTED_CHECKER_BB_CNT;

extern int EXPECTED_BB_CNT; // One of MAIN / CHECKER_BB_CNT

extern int MAIN_BB_CNT; // Counter for the BBs in main thread
extern int CHECKER_BB_CNT; // Counter for the BBs in checker thread

extern ThreadRole ERRONEOUS_THREAD_ROLE; // Role of thread that will have error
extern int BB_WITH_ERROR; // Number of basic block that will have the error

extern bool ERROR_INSERTED; // Global boolean representing whether the error was successfully inserted

// Inserts an error in the basic block `bb`. The error is generated for an instruction
// that has a register as the destination operand.
// For example: I = dest_reg = dest_reg + 10
// `dest_reg = dest_reg xor t` is inserted after I.
// `t` is a power of 2 randomly generated using the number of bits of `dest_reg`
bool insert_error(void *drcontext, instrlist_t *bb);

// Return the role of the thread that will have the error
// Also set the `EXPECTED_BB_CNT` variable to be that of MAIN or CHECKER, depending
// on which one was selected to be erroneous.
ThreadRole gen_thread_with_error();

// Return the number of the bassic block that will have the error
int gen_bb_with_error();

#endif