/* Note that this file is automatic generated */
#include "DSLGen.h"
#include "DSLGenUtil.h"
#include "Analysis.h"
/*--- Global Var Decl Start ---*/
#include <fstream>
#include <iostream>
#include <iomanip>
#include <stdint.h>

/*--- Global Var Decl End ---*/

using namespace std;
using namespace janus;

uint64_t bitmask;

void ruleGenerationTemplate(JanusContext &jc) {
/*--- Static RuleGen Start ---*/

std::cout << "LOAD IS " << Instruction::Load << std::endl;
std::cout << "STORE IS " << Instruction::Store << std::endl;
for (auto &func: jc.functions){
    livenessAnalysis(&func);
    for (auto &I: func.instrs){
        if(get_opcode(I) == Instruction::Load) {
            bitmask = func.liveRegIn[I.id].bits;
            insertCustomRule<Instruction>(3,I,1, true, 0, bitmask);
            insertCustomRule<Instruction>(4,I,1, true, 0, bitmask);
        }
        else if (get_opcode(I) == Instruction::Store) {
            bitmask = func.liveRegIn[I.id].bits;
            insertCustomRule<Instruction>(3,I,1, true, 0, bitmask);
            insertCustomRule<Instruction>(4,I,1, true, 0, bitmask);
        }
        else if (get_opcode(I) == Instruction::Mov) {
            bitmask = func.liveRegIn[I.id].bits;
            insertCustomRule<Instruction>(3,I,1, true, 0, bitmask);
            insertCustomRule<Instruction>(4,I,1, true, 0, bitmask);
        }
        /*
        else if (get_opcode(I) == Instruction::GetPointer) {
            bitmask = func.liveRegIn[I.id].bits;
            insertCustomRule<Instruction>(3,I,1, true, 0, bitmask);
            insertCustomRule<Instruction>(4,I,1, true, 0, bitmask);
        }
        */
    }
}
for (auto &F: jc.functions){
    if( is_main_func(jc, F)){
        
        std::cout << "Inserting thread create rule at " << std::hex << F.startAddress << std::endl;
        insertCustomRule<Function>(2,F,4, true, 0, bitmask);


        // F.endAddress = 0x40182b;
        std::cout << "Inserting thread wait rule at " << std::hex << F.endAddress<< std::endl;
        insertCustomRule<Function>(5,F,5, true, 0, bitmask);

        std::cout << std::resetiosflags(std::ios::showbase);
    }
}

/*--- Static RuleGen Finish ---*/

}

