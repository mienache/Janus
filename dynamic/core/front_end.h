#ifndef _JANUS_FRONT_END_
#define _JANUS_FRONT_END_

/* Frontend library for JANUS framework */
#include "janus.h"
#include "dr_api.h"

#ifdef __cplusplus
extern "C" {
#endif
//Initialise JANUS system in the dynamoRIO client
//Returns the rule type read from the rule file
//Pass in the pointer to number of threads to be updated by the front end
void janus_init(client_id_t id);

void         load_static_rules(char *rule_path, uint64_t base);
//Find the corresponding static rule from specified address
RRule *get_static_rule(PCAddress addr);

// Copies the rules from the rule table entry of the source basic block to the
// entry belonging to the destination basic block. This can be used for example
// when an original basic block is split into multiple ones by inserting a jump
// instruction executed as application instruction. If a basic block A is split
// into B and C, this function will also copy rules that should be triggered
// before the end of B to the entry of C. Thus care must be taken when processing
// the rules for C to ensure that all rules coming from the rule table are relevant.
// TODO: the above will probably need to be changed (currently rules are stored as linked
// lists in each entry in the hashtable which makes it non-trivial to split).
void copy_rules_to_new_bb(void *dest_bb_start, void *source_bb_start);

#ifdef __cplusplus
}
#endif
#endif
