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

/*--- Global Var Decl End ---*/



void exit_routine(){
    /*--- Termination Start ---*/
    print_str("Num instructions:");
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
