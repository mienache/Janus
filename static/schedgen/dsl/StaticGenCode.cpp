/* Note that this file is automatic generated */
#include "DSLGen.h"
#include "DSLGenUtil.h"
#include "Analysis.h"
/*--- Global Var Decl Start ---*/
#include <algorithm>
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

bool instr_should_be_instrumented_for_comet(Instruction instr);

std::cout << "LOAD IS " << Instruction::Load << std::endl;
std::cout << "STORE IS " << Instruction::Store << std::endl;
for (auto &func: jc.functions){
    livenessAnalysis(&func);
    for (auto &I: func.instrs){
        // std::cout << "Instruction " << (void*) I.pc << ": " << I << std::endl;

        if(instr_should_be_instrumented_for_comet(I)) {
            bitmask = func.liveRegIn[I.id].bits;
            insertCustomRule<Instruction>(3,I,1, true, 0, bitmask);
            insertCustomRule<Instruction>(4,I,1, true, 0, bitmask);
        }
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


bool instr_should_be_instrumented_for_comet(Instruction instr) {
    std::vector<Instruction::Opcode> target_opcodes = {
        Instruction::Load,
        Instruction::Store,
        Instruction::Mov,

        Instruction::Add,
        Instruction::Sub,
        Instruction::Mul,
        Instruction::Div,
        Instruction::Rem,
        Instruction::Shl,
        Instruction::LShr,
        Instruction::AShr,
        Instruction::And,
        Instruction::Or,
        Instruction::Xor,

        Instruction::Neg,

        Instruction::Compare,

        Instruction::GetPointer
    };

    return std::find(target_opcodes.begin(), target_opcodes.end(), get_opcode(instr)) != target_opcodes.end();
}