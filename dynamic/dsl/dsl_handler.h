#ifndef __DSL_HANDLER__
#define __DSL_HANDLER__

/* Header file to implement a JANUS client */
#include "janus_api.h"

#include <vector>

// If instructions are to be removed, they should be removed after
// all instrumentation has been performed in a given basic block.
// Otherwise, if they are removed while instrumenting the basic block,
// the PC of the rest of the instructions will be readjusted hence
// the mappings from PC -> rule won't be valid anymore.
extern std::vector <instr_t*> instructions_to_remove;

/* Fill up handler tables */
void create_handler_table();

#endif
