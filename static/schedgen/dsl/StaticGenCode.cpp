/* Note that this file is automatic generated */
#include "DSLGen.h"
#include "DSLGenUtil.h"
#include "Analysis.h"
/*--- Global Var Decl Start ---*/
#include <fstream>
#include <iostream>
#include <stdint.h>

/*--- Global Var Decl End ---*/

using namespace std;
using namespace janus;

uint64_t bitmask;

void ruleGenerationTemplate(JanusContext &jc) {
/*--- Static RuleGen Start ---*/
for (auto &func: jc.functions){
    livenessAnalysis(&func);
    for (auto &I: func.instrs){
        if( get_opcode(I) == Instruction::Load){
            bitmask = func.liveRegIn[I.id].bits;
            insertCustomRule<Instruction>(1,I,1, true, 0, bitmask);
        }
    }
}
for (auto &F: jc.functions){
    if (&F == jc.main) {
        cout << "Found main\n";
        insertCustomRule<Function>(2,F,4, true, 0, bitmask);
    }
}

/*--- Static RuleGen Finish ---*/

}

