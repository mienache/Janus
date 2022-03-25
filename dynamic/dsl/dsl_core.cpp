#include <sys/types.h>
#include <unistd.h>

#include <iostream>

#include "dsl_core.h"
#include "dsl_handler.h"
#include "dsl_ipc.h"
#include "dsl_thread_manager.h"
#include "func.h"
#include "handler.h"

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

    std::cout << "Confirm thread private caches: " << dr_using_all_private_caches() << std::endl;

    // Must be called to initialise the call func template
    create_call_func_code_cache();

    // Can skip this for now until we figure out the thread synchronization issue
    // create_shared_memory_area();
}

int total_num_threads;

// This is a a callback invoked whenever DynamoRIO identifies a new thread
void new_janus_thread(void *drcontext) {
    init_routine();
    std::cout << "A new thread is registered. Total threads: " << ++total_num_threads << std::endl;
    std::cout << "The new Janus TID: " << dr_get_thread_id(drcontext) << std::endl;

    if (!MAIN_THREAD_REGISTERED) {
        // If it is the first thread, register it as the main thread
        std::cout << "Registering MAIN thread" << std::endl;
        MAIN_THREAD_REGISTERED = 1;
        register_thread(ThreadRole::MAIN, drcontext);
    }
    else {
        // Otherwise register as checker thread
        std::cout << "Registering CHECKER thread" << std::endl;
        CHECKER_THREAD_REGISTERED = 1;
        register_thread(ThreadRole::CHECKER, drcontext);
    }

}

// This is a a callback invoked whenever DynamoRIO observes a thread is about to leave
void exit_janus_thread(void *drcontext) {
    std::cout << "Thread leaving: TID = " << dr_get_thread_id(drcontext) << std::endl;

    if (app_threads[dr_get_thread_id(drcontext)]->threadRole == ThreadRole::MAIN) {
        std::cout << "MAIN thread leaving." << std::endl;
    }
    else if (app_threads[dr_get_thread_id(drcontext)]->threadRole == ThreadRole::CHECKER) {
        std::cout << "CHECKER thread leaving." << std::endl;
    }
    else {
        std::cout << "UNKNOWN thread leaving." << std::endl;
    }
    exit_routine();
}

// Helper variables to print the basic block files with unique names.
int cnt1 = 0;
int cnt2 = 0;


// Helper method for generating the name of a file used to print the current basic block
string get_basic_block_filename(void *drcontext, bool is_original_bb)
{
    string filename;
    if (app_threads[dr_get_thread_id(drcontext)]->threadRole == ThreadRole::MAIN) {
        if (is_original_bb) {
            ++cnt1; // Only increment counter if we're printing the original BB (to keep 1-1 mapping between filenames)
        }
        filename = "main_basic_block_" + std::to_string(cnt1);
    }
    else {
        if (is_original_bb) {
            ++cnt2;
        }
        filename = "checker_basic_block_" + std::to_string(cnt2);
    }

    if (!is_original_bb) {
        // Generate different names for the original and the instrumented basic blocks
        filename += is_original_bb ? ".txt" : "_modified.txt";
    }

    return filename;
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

    std::cout << "Processing basic block for TID = " << dr_get_thread_id(drcontext) << std::endl;

    // Next 5 lines just print the original basic block instructions (before it the rules are applied)
    string filename = get_basic_block_filename(drcontext, 1);
    app_pc tag_new = instr_get_app_pc(instrlist_first_app(bb));
    file_t output_file = dr_open_file(filename.c_str(), DR_FILE_WRITE_OVERWRITE);
    instrlist_disassemble(drcontext, tag_new, bb, output_file);
    dr_close_file(output_file);

    do {
        rule_opcode = rule->opcode;
        // cout << "Rule opcode is: " << rule->opcode << "\n";

        call_rule_handler(rule_opcode, janus_context);

        //This basic block may be annotated with more rules
        rule = rule->next;
    }while(rule);

    // Next 5 lines just print the original basic block instructions (before it the rules are applied)
    filename = get_basic_block_filename(drcontext, 1);
    tag_new = instr_get_app_pc(instrlist_first_app(bb));
    output_file = dr_open_file(filename.c_str(), DR_FILE_WRITE_OVERWRITE);
    instrlist_disassemble(drcontext, tag_new, bb, output_file);
    dr_close_file(output_file);

    std::cout << "Thread " << dr_get_thread_id(drcontext) << " finished appliying rules - code will be now executed:" << std::endl;

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
