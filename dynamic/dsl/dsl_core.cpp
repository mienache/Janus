#include <sys/types.h>
#include <unistd.h>

#include <iostream>

#include "dsl_core.h"
#include "dsl_handler.h"
#include "dsl_ipc.h"
#include "dsl_thread_manager.h"
#include "func.h"

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating);

static void
new_janus_thread(void *drcontext);

static void
exit_janus_thread(void *drcontext);

static void
call_rule_handler(RuleOp rule_opcode, JANUS_CONTEXT);

/* Handler table */
void **htable = NULL;

void create_shared_memory_area();

DR_EXPORT void 
dr_init(client_id_t id)
{
#ifdef JANUS_VERBOSE
    dr_fprintf(STDOUT,"\n---------------------------------------------------------------\n");
    dr_fprintf(STDOUT,"               Janus Custom DSL Interpreter\n");
    dr_fprintf(STDOUT,"---------------------------------------------------------------\n\n");
#endif
    /* Register event callbacks. */
    dr_register_bb_event(event_basic_block);    
    dr_register_thread_init_event(new_janus_thread);
    dr_register_thread_exit_event(exit_janus_thread);

    /* Initialise Janus components and file Janus global info */
    janus_init(id);

    /* Initialise handler table */
    htable = (void **)malloc(sizeof(void *)*MAX_HANDLER_TABLE_LENGTH);
    for (int i=0; i<MAX_HANDLER_TABLE_LENGTH; i++)
        htable[i] = NULL;

    /* Fill up handler tables */
    create_handler_table();

    if(rsched_info.mode != JCUSTOM) {
        dr_fprintf(STDOUT,"Rewrite rules not intended for %s!\n",print_janus_mode(rsched_info.mode));
        return;
    }
    IF_VERBOSE(dr_fprintf(STDOUT,"DynamoRIO client initialised\n"));

    create_shared_memory_area();
}

void new_janus_thread(void *drcontext) {
    printf("New Janus TID = %d\n", gettid());
    init_routine();
    if (!MAIN_THREAD_REGISTERED) {
        register_thread(ThreadRole::MAIN);
        MAIN_THREAD_REGISTERED = 1;
    }
    else {
        register_thread(ThreadRole::CHECKER);
    }
}

void exit_janus_thread(void *drcontext) {
    exit_routine();
}

/* Main execution loop: this will be executed at every initial encounter of new basic block */
static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    RuleOp rule_opcode;
    //get current basic block starting address
    PCAddress bbAddr = (PCAddress)dr_fragment_app_pc(tag);

    //lookup in the hashtable to check if there is any rule attached to the block
    RRule *rule = get_static_rule(bbAddr);

    //if it is a normal basic block, then omit it.
    if(rule == NULL) return DR_EMIT_DEFAULT;

    printf("Current TID = %d\n", gettid());

    do {
        rule_opcode = rule->opcode;
        // cout << "Rule opcode is: " << rule->opcode << "\n";

        call_rule_handler(rule_opcode, janus_context);

        //This basic block may be annotated with more rules
        rule = rule->next;
    }while(rule);


    return DR_EMIT_DEFAULT;
}

static void
call_rule_handler(RuleOp rule_opcode, JANUS_CONTEXT) {
    int id = (int)rule_opcode - 1;

    if (id < 0 || id > MAX_HANDLER_TABLE_LENGTH-1) return;

    void *handler = htable[id];

    void (*fhandler)(JANUS_CONTEXT) = (void (*)(JANUS_CONTEXT))(handler);

    //call the corresponding handler
    fhandler(janus_context);
}
