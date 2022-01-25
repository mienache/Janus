#ifndef _DSL_FUNC_
#define _DSL_FUNC_
#include "dr_api.h"
#include "util.h"
#include <map>
using namespace std;
/*--- Global Var Decl Start ---*/
/*--- Global Var Decl End ---*/

/*--- Function Global Declaration Start ---*/
#include <fstream>
#include <iostream>
#include <stdint.h>
void func_1();
void func_2();
extern uint64_t inst_count ;

/*--- Function Global Declaration Finish ---*/
void exit_routine();
void init_routine();
bool inRegSet(uint64_t bits, uint32_t reg);
#endif
