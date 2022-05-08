#include <set>

#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>

#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
#include <cstdlib>

#include "dsl_core.h"
#include "dsl_handler.h"
#include "dsl_ipc.h"
#include "dsl_thread_manager.h"
#include "func.h"
#include "handler.h"

//#define PRINT_SIG_HANDLER_INFO
//#define PRINT_PROCESSING_BASIC_BLOCK
//#define PRINT_QUEUE_PTRS
//#define PRINT_BB_TO_FILE

extern std::vector <instr_t*> instructions_to_remove;

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating);

static void
new_janus_thread(void *drcontext);

static void
exit_janus_thread(void *drcontext);

static void
call_rule_handler(RuleOp rule_opcode, JANUS_CONTEXT);

dr_signal_action_t signal_handler(void *drcontext, dr_siginfo_t *siginfo);

// Helper function - TODO: move to another file
void print_first_n_elements_from_queue(int n);

void restore_state_handler(void *drcontext, void *tag, dr_mcontext_t *mcontext, bool restore_memory, bool app_code_consistent);


/* Handler table */
void **htable = NULL;

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
    dr_register_signal_event(signal_handler);
    // dr_register_restore_state_event(restore_state_handler);

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

    init_routine();
}

int total_num_threads;

// This is a a callback invoked whenever DynamoRIO identifies a new thread
void new_janus_thread(void *drcontext) {
    std::cout << "A new thread is registered. Total threads: " << ++total_num_threads << std::endl;
    std::cout << "The new Janus TID: " << dr_get_thread_id(drcontext) << std::endl;

/*--- Janus Thread Init Start ---*/

    if (!main_thread) {
        // If it is the first thread, register it as the main thread
        std::cout << "Registering MAIN thread" << std::endl;
        main_thread = register_thread("main", drcontext);
        IPC_QUEUE_2->last_thread_changed = main_thread->pid;
    }
    else {
        // Otherwise register as checker thread
        std::cout << "Registering CHECKER thread" << std::endl;
        checker_thread = register_thread("worker", drcontext);
        // std::cout << "CHECKER THREAD SLEEPING 2 sec." << std::endl;
        // sleep(2);
    }

/*--- Janus Thread Init Finish ---*/
}

// This is a a callback invoked whenever DynamoRIO observes a thread is about to leave
void exit_janus_thread(void *drcontext) {
    std::cout << "Thread leaving: TID = " << dr_get_thread_id(drcontext) << std::endl;

    IPC_QUEUE_2->is_z1_free = 1;
    IPC_QUEUE_2->is_z2_free = 1;

    if (app_threads[dr_get_thread_id(drcontext)]->threadRole == ThreadRole::MAIN) {
        std::cout << "MAIN thread leaving." << std::endl;
    }
    else if (app_threads[dr_get_thread_id(drcontext)]->threadRole == ThreadRole::CHECKER) {
        std::cout << "CHECKER thread leaving." << std::endl;
        CHECKER_THREAD_FINISHED = 1;
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
            filename = "main_basic_block_" + std::to_string(cnt1);
        }
        else {
            filename = "main_basic_block_modified_" + std::to_string(cnt1);
        }
    }
    else {
        if (is_original_bb) {
            ++cnt2;
            filename = "checker_basic_block_" + std::to_string(cnt2);
        }
        else {
            filename = "checker_basic_block_modified_" + std::to_string(cnt2);
        }
    }

    filename += is_original_bb ? ".txt" : "_modified.txt";

    std::cout << "file: " << filename << std::endl;

    return filename;
}



/* Main execution loop: this will be executed at every initial encounter of new basic block */
static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    RuleOp rule_opcode;
    //get current basic block starting address
    PCAddress bbAddr = (PCAddress)dr_fragment_app_pc(tag);

    const long long tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];
    curr_thread->curr_bb = bbAddr;

    if (curr_thread->bb_to_required_rules.find(bbAddr) != curr_thread->bb_to_required_rules.end()) {
        for (auto fromBBAddr : curr_thread->bb_to_required_rules[bbAddr])  {
            std::cout << "Forwarding rules from " << (void*) fromBBAddr << " to " << (void*) bbAddr << std::endl;
            copy_rules_to_new_bb(bbAddr, fromBBAddr);
        }
    }

    //lookup in the hashtable to check if there is any rule attached to the block
    RRule *rule = get_static_rule(bbAddr);

    if (rule == NULL && instr_is_nop(instrlist_first_app(bb))) {
        // First instruction is a NOP - iterate until we find the first non-NOP.
        // We need this because the static analyser does not allow basic blocks to start with NOP
        // instructions. This is different from DynamoRIO's definition of basic blocks, which may start with NOPs.
        // Hence, if a rewrite rule was registered at the start of a basic block and the underlying instruction is right after a NOP,
        // the `get_static_rule` call above would not retrive it, so we have to iterate until the first non-NOP.
        // TODO: probably the solution is to modify the static analyser

        instr_t *curr = instr_get_next_app(instrlist_first_app(bb));

        while (curr && instr_is_nop(curr)) {
            curr = instr_get_next_app(curr);
        }

        if (curr) {
            rule = get_static_rule((PCAddress) instr_get_app_pc(curr));
        }

        if (rule) {
            std::cout << "New rule found at " << (void*) instr_get_app_pc(curr) << std::endl;
        }
    }

    //if it is a normal basic block, then omit it.
    if(rule == NULL) return DR_EMIT_DEFAULT;

    #ifdef PRINT_PROCESSING_BASIC_BLOCK
    std::cout << "Processing basic block at " << (void*) bbAddr << " for TID = " << dr_get_thread_id(drcontext) << std::endl;
    #endif

    // Next 5 lines just print the original basic block instructions (before the rules are applied)

    #ifdef PRINT_BB_TO_FILE
    string filename = get_basic_block_filename(drcontext, 1);
    app_pc tag_new = instr_get_app_pc(instrlist_first_app(bb));
    file_t output_file = dr_open_file(filename.c_str(), DR_FILE_WRITE_OVERWRITE);
    instrlist_disassemble(drcontext, tag_new, bb, output_file);
    dr_close_file(output_file);
    #endif


    instructions_to_remove.clear();
    do {
        // The while below is needed because a linked list of rules might belong to different
        // basic blocks if an original basic block was split. This is because the PC of some
        // rules may be in the second block but currently there is no mechanism to redistribute
        // the rules in the rule table so we keep a copy in the entries of both of the resulting
        // basic blocks. (see `copy_rules_to_new_bb` in front_end.h)

        while (rule && rule->pc < bbAddr) {
            // Rule actually belongs to a preivous block, skip it
            rule = rule->next;
        }

        if (!rule) {
            break;
        }

        rule_opcode = rule->opcode;
        // cout << "Rule opcode is: " << rule->opcode << "\n";

        call_rule_handler(rule_opcode, janus_context);

        //This basic block may be annotated with more rules
        rule = rule->next;
    }while(rule);

    for (auto i: instructions_to_remove) {
        instrlist_remove(bb, i);
    }

    // Next 5 lines just print the modified basic block instructions (after the rules are applied)
    #ifdef PRINT_BB_TO_FILE
    filename = get_basic_block_filename(drcontext, 0);
    tag_new = instr_get_app_pc(instrlist_first_app(bb));
    output_file = dr_open_file(filename.c_str(), DR_FILE_WRITE_OVERWRITE);
    instrlist_disassemble(drcontext, tag_new, bb, output_file);
    dr_close_file(output_file);
    #endif

    #ifdef PRINT_PROCESSING_BASIC_BLOCK
    std::cout << "Thread " << dr_get_thread_id(drcontext) << " finished appliying rules - code will be now executed:" << std::endl;
    #endif

    #ifdef PRINT_QUEUE_PTRS
    std::cout << "Enq ptr = " << IPC_QUEUE_2->enqueue_pointer << std::endl;
    std::cout << "Deq ptr = " << IPC_QUEUE_2->dequeue_pointer << std::endl;
    #endif
    // print_first_n_elements_from_queue(15);


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

void spinlock()
{
    std::cout << "In spinlock" << std::endl;
    sleep(3);
    std::cout << "Spinlock done" << std::endl;
}

dr_signal_action_t signal_handler(void *drcontext, dr_siginfo_t *siginfo) 
{
    // TODO: this will need to make one thread sleep while the other one completes its part of the queue
    // TODO: check this the signal is SIGSEGV otherwise deliver it

    const pid_t tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];

    #ifdef PRINT_SIG_HANDLER_INFO
    std::cout << tid << " Error caught" << std::endl;
    std::cout << tid << " Error at " << (void*) siginfo->access_address << std::endl;
    #endif

    if (siginfo->sig != SIGSEGV) {
        std::cout << "NON SIGSEGV signal found" << std::endl;
        return DR_SIGNAL_DELIVER;
    }

    #ifdef PRINT_SIG_HANDLER_INFO
    std::cout << tid << " PC = " << (void*) siginfo->mcontext->pc << std::endl;
    std::cout << tid << " Curr bb = " << (void*) curr_thread->curr_bb << std::endl;
    std::cout << tid << " Raw PC = " << (void*) siginfo->raw_mcontext->pc << std::endl;

    std::cout << tid << " In TID = " << tid << std::endl;
    std::cout << tid << " Z1 free: " << IPC_QUEUE_2->is_z1_free<< std::endl;
    std::cout << tid << " Z2 free: " << IPC_QUEUE_2->is_z2_free<< std::endl;
    std::cout << tid << " Last thread changed: " << IPC_QUEUE_2->last_thread_changed << std::endl;
    #endif

    void *error_address = siginfo->access_address;
    if (error_address < IPC_QUEUE_2->r1 || error_address > IPC_QUEUE_2->r2 + 8) {
        std::cout << "Non-comet ERROR " << std::endl;
        return DR_SIGNAL_DELIVER;
    }
        
    /*
    siginfo->raw_mcontext->pc = (void*) spinlock;
    return DR_SIGNAL_SUPPRESS;
    */

    const uint64_t pc = siginfo->mcontext->pc;

    if (pc != curr_thread->curr_bb) {
        curr_thread->bb_to_required_rules[pc].insert(curr_thread->curr_bb);
    }


    if (error_address < IPC_QUEUE_2->z2) {
        #ifdef PRINT_SIG_HANDLER_INFO
        std::cout << tid << " trying to enter Z2" << std::endl;
        #endif
        IPC_QUEUE_2->is_z1_free = 1;

        while (!IPC_QUEUE_2->is_z2_free || IPC_QUEUE_2->last_thread_changed == tid) {
            // TODO: investigate if usleep is needed indeed.
            // This was added because on some runs the execution does not finish and the thread
            // keeps waiting in the while loop even though the condition is modified by the other thread
            usleep(500);
            //return DR_SIGNAL_SUPPRESS;
        }

        IPC_QUEUE_2->is_z2_free = 0;
        IPC_QUEUE_2->last_thread_changed = tid;
        #ifdef PRINT_SIG_HANDLER_INFO
        std::cout << tid << " Marked z2 as non-free" << std::endl;
        #endif

        // Must also make the enqueue / dequeue pointer field of the CometQueue point to the right zone
        if (app_threads[tid]->threadRole == ThreadRole::MAIN) {
            #ifdef PRINT_SIG_HANDLER_INFO
            std::cout << tid << " Setting enqueue pointer to z2" << std::endl;
            #endif
            IPC_QUEUE_2->enqueue_pointer = IPC_QUEUE_2->z2;
            memset(IPC_QUEUE_2->z2, 0, IPC_QUEUE_2->bytes_per_zone);
        }
        else {
            #ifdef PRINT_SIG_HANDLER_INFO
            std::cout << tid << "Setting dequeue pointer to z2" << std::endl;
            #endif
            IPC_QUEUE_2->dequeue_pointer = IPC_QUEUE_2->z2;
        }

        //assert (llabs(siginfo->raw_mcontext->r10 - (uint64_t) error_address) <= 16);
        if (llabs(siginfo->raw_mcontext->r10 - (uint64_t) error_address) <= 16) {
            siginfo->raw_mcontext->r10 = IPC_QUEUE_2->z2;
        }
        if (llabs(siginfo->raw_mcontext->r11 - (uint64_t) error_address) <= 16) {
            while(1) {
                std::cout << "Unexpected reg" << std::endl;
            }
            siginfo->raw_mcontext->r11 = IPC_QUEUE_2->z2;
        }
        if (llabs(siginfo->raw_mcontext->r12 - (uint64_t) error_address) <= 16) {
            while(1) {
                std::cout << "Unexpected reg" << std::endl;
            }
            siginfo->raw_mcontext->r12 = IPC_QUEUE_2->z2;
        }
        if (llabs(siginfo->raw_mcontext->r13 - (uint64_t) error_address) <= 16){
            while(1) {
                std::cout << "Unexpected reg" << std::endl;
            }
            siginfo->raw_mcontext->r13 = IPC_QUEUE_2->z2;
        }

        #ifdef PRINT_SIG_HANDLER_INFO
        std::cout << tid << " Thread " << tid << " finished spinlocking and entering Z2" << std::endl;
        #endif

    }
    else {
        #ifdef PRINT_SIG_HANDLER_INFO
        std::cout << tid << " trying to enter Z1" << std::endl;
        #endif
        IPC_QUEUE_2->is_z2_free = 1;
        while (!IPC_QUEUE_2->is_z1_free || IPC_QUEUE_2->last_thread_changed == tid) {
            usleep(500);
            //sleep(2);
            //return DR_SIGNAL_SUPPRESS;
        }

        IPC_QUEUE_2->is_z1_free = 0;
        IPC_QUEUE_2->last_thread_changed = tid;

        #ifdef PRINT_SIG_HANDLER_INFO
        std::cout << tid << " Marked z1 as non-free" << std::endl;
        #endif

        // Must also make the enqueue / dequeue pointer field of the CometQueue point to the right zone
        if (app_threads[tid]->threadRole == ThreadRole::MAIN) {
            #ifdef PRINT_SIG_HANDLER_INFO
            std::cout << tid << " Setting enqueue pointer to z1" << std::endl;
            #endif
            IPC_QUEUE_2->enqueue_pointer = IPC_QUEUE_2->z1;
            memset(IPC_QUEUE_2->z1, 0, IPC_QUEUE_2->bytes_per_zone);
        }
        else {
            #ifdef PRINT_SIG_HANDLER_INFO
            std::cout << tid << " Setting dequeue pointer to z1" << std::endl;
            #endif
            IPC_QUEUE_2->dequeue_pointer = IPC_QUEUE_2->z1;
        }

        assert (llabs(siginfo->raw_mcontext->r10 - (uint64_t) error_address) <= 16);
        if (llabs(siginfo->raw_mcontext->r10 - (uint64_t) error_address) <= 16) {
            siginfo->raw_mcontext->r10 = IPC_QUEUE_2->z1;
        }
        if (llabs(siginfo->raw_mcontext->r11 - (uint64_t)error_address) <= 16) {
            siginfo->raw_mcontext->r11 = IPC_QUEUE_2->z1;
            while(1) {
                std::cout << "Unexpected reg" << std::endl;
            }
        }
        if (llabs(siginfo->raw_mcontext->r12 - (uint64_t) error_address) <= 16) {
            siginfo->raw_mcontext->r12 = IPC_QUEUE_2->z1;
            while(1) {
                std::cout << "Unexpected reg" << std::endl;
            }
        }
        if (llabs(siginfo->raw_mcontext->r13 - (uint64_t) error_address) <= 16) {
            siginfo->raw_mcontext->r13 = IPC_QUEUE_2->z1;
            while(1) {
                std::cout << "Unexpected reg" << std::endl;
            }
        }

        #ifdef PRINT_SIG_HANDLER_INFO
        std::cout << "Thread " << tid << " finished spinlocking and entering Z1" << std::endl;
        #endif
    }

    #ifdef PRINT_SIG_HANDLER_INFO
    std::cout << tid << " Z1 free: " << IPC_QUEUE_2->is_z1_free<< std::endl;
    std::cout << tid << " Z2 free: " << IPC_QUEUE_2->is_z2_free<< std::endl;
    std::cout << tid << " IPC_POINTERS: " << IPC_QUEUE_2->enqueue_pointer << " | " << IPC_QUEUE_2->dequeue_pointer << std::endl;
    #endif

    return DR_SIGNAL_SUPPRESS;
}


void print_first_n_elements_from_queue(int n)
{
    std::cout << "First " << n << " elements of the queue are: " << std::endl;
    int64_t *ptr = IPC_QUEUE_2->z1;
    for (int i = 0; i < n; ++i) {
        std::cout << i << ": " << (void*) *ptr << std::endl;
        ++ptr;
    }
}

void restore_state_handler(void *drcontext, void *tag, dr_mcontext_t *mcontext, bool restore_memory, bool app_code_consistent)
{
    // std::cout << "Should restore memory: " << restore_memory << std::endl;
}