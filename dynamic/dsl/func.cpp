#include <cassert>
#include <iostream>
#include "func.h"
#include "util.h"
using namespace std;
/*--- Global Var Decl Start ---*/
#include <fstream>
#include <iostream>
#include <stdint.h>
uint64_t inst_count = 0;
char L_3[] = "-------> Starting new function.";
/*--- Global Var Decl End ---*/


/*--- DSL Function Start ---*/
void func_1(){
    inst_count = inst_count + 1;
}
void func_2(){
    print_str("-------> Starting new function.");
}

/*--- DSL Function Finish ---*/

void exit_routine(){
    /*--- Termination Start ---*/
    print_u64(inst_count);

/*--- Termination End ---*/
}
void init_routine(){
    /*--- Init Start ---*/

/*--- Init End ---*/
}

bool inRegSet(uint64_t bits, uint32_t reg)
{
    if((bits >> (reg-1)) & 1)
        return true;
    if(bits == 0 || bits == 1)
        return true;
    return false;
}
