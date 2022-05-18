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
#include "dsl_debug_utilities.h"
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

std::atomic<int> sigsegv_cnt;

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating);

static void
new_janus_thread(void *drcontext);

static void
exit_janus_thread(void *drcontext);

static void
call_rule_handler(RuleOp rule_opcode, JANUS_CONTEXT);

dr_signal_action_t signal_handler(void *drcontext, dr_siginfo_t *siginfo);

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

    std::cout << "Enq ptr = " << IPC_QUEUE_2->enqueue_pointer << std::endl;
    std::cout << "Deq ptr = " << IPC_QUEUE_2->dequeue_pointer << std::endl;

    exit_routine();

    std::cout << "SIGSEGV_cnt = " << sigsegv_cnt << std::endl;
}


/* Main execution loop: this will be executed at every initial encounter of new basic block */
static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{

    if (translating) {
        return DR_EMIT_DEFAULT;
    }

    RuleOp rule_opcode;
    //get current basic block starting address
    PCAddress bbAddr = (PCAddress)dr_fragment_app_pc(tag);

    const long long tid = dr_get_thread_id(drcontext);
    AppThread *curr_thread = app_threads[tid];
    curr_thread->curr_bb = bbAddr;

    if (IPC_QUEUE_2->bb_reg_prom_opt) {
        curr_thread->instrumented_start_and_end_of_bb = 0;
        std::vector<reg_id_t> free_registers = get_free_registers_for_bb(INSTRUMENTATION_REGISTERS, bb);
        curr_thread->curr_queue_reg = (
            free_registers.size() ? get_free_registers_for_bb(INSTRUMENTATION_REGISTERS, bb)[0] : DR_REG_NULL
        );

        if (IPC_QUEUE_2->addr_offset_fusion_opt) {
            curr_thread->curr_disp = 0;
        }
    }

    if (curr_thread->bb_to_required_rules.find(bbAddr) != curr_thread->bb_to_required_rules.end()) {
        assert (false);
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

    #ifdef PRINT_BB_TO_FILE
        print_bb_to_file(drcontext, bb, 1);
    #endif


    // There is (probably) a bug in the static analyser which sometimes inserts the same (PC, ruleID) into the rewrite table.
    // An easy temporary fix is to keep track of which pairs of (PC, ruleID) have been applied to make sure instrumentation
    // is done only once for each rule.
    std::set<std::pair<int, int> > applied_rules;

    instructions_to_remove.clear();


    if (IPC_QUEUE_2->bb_reg_prom_opt) {
        instrument_first_instr_for_reg_prom(drcontext, bb);
    }

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

        const std::pair<int, int> p = std::make_pair(rule->pc, rule_opcode);
        if (applied_rules.find(p) == applied_rules.end()) {
            call_rule_handler(rule_opcode, janus_context);
            applied_rules.insert(p);
        }

        //This basic block may be annotated with more rules
        rule = rule->next;
    }while(rule);

    if (IPC_QUEUE_2->bb_reg_prom_opt) {
        instrument_last_instr_for_reg_prom(drcontext, bb);
    }

    if (curr_thread->threadRole == ThreadRole::CHECKER) {
        for (auto i: instructions_to_remove) {
            instrlist_remove(bb, i);
        }
    }

    #ifdef PRINT_BB_TO_FILE
        print_bb_to_file(drcontext, bb, 0);
    #endif

    #ifdef PRINT_PROCESSING_BASIC_BLOCK
    std::cout << "Thread " << dr_get_thread_id(drcontext) << " finished appliying rules - code will be now executed:" << std::endl;
    #endif

    #ifdef PRINT_QUEUE_PTRS
    std::cout << "Enq ptr = " << IPC_QUEUE_2->enqueue_pointer << std::endl;
    std::cout << "Deq ptr = " << IPC_QUEUE_2->dequeue_pointer << std::endl;
    #endif

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

    // A cmp instruction can push 2 values into the restricted zone, hence error margin should be 2 x INCREMENT
    // INCREMENT is 16 when SIMD registers are supported
    int ZONE_ERROR_MARGIN = 32;

    void *error_address = siginfo->access_address;
    if (error_address < IPC_QUEUE_2->r1 || error_address > IPC_QUEUE_2->r2 + ZONE_ERROR_MARGIN) {
        std::cout << "Non-comet ERROR " << std::endl;
        return DR_SIGNAL_DELIVER;
    }

    // TODO: think about this
    ZONE_ERROR_MARGIN += 4000;
        
    /*
    siginfo->raw_mcontext->pc = (void*) spinlock;
    return DR_SIGNAL_SUPPRESS;
    */

    const uint64_t pc = siginfo->mcontext->pc;

    if (pc != curr_thread->curr_bb) {
        curr_thread->bb_to_required_rules[pc].insert(curr_thread->curr_bb);
    }

    assert (error_address == IPC_QUEUE_2->r1 || error_address == IPC_QUEUE_2->r2);


    int disp_offset = -1;
    int num_updated_registers = 0;
    if (error_address < IPC_QUEUE_2->z2) {
        #ifdef PRINT_SIG_HANDLER_INFO
        std::cout << tid << " trying to enter Z2" << std::endl;
        #endif
        IPC_QUEUE_2->is_z1_free = 1;

        while (!IPC_QUEUE_2->is_z2_free || IPC_QUEUE_2->last_thread_changed == tid) {
            // TODO: investigate if usleep is needed indeed.
            // This was added because on some runs the execution does not finish and the thread
            // keeps waiting in the while loop even though the condition is modified by the other thread
            //usleep(500);
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
            //IPC_QUEUE_2->enqueue_pointer = IPC_QUEUE_2->z2;
            //memset(IPC_QUEUE_2->z2, 0, IPC_QUEUE_2->bytes_per_zone);
        }
        else {
            #ifdef PRINT_SIG_HANDLER_INFO
            std::cout << tid << "Setting dequeue pointer to z2" << std::endl;
            #endif
            //IPC_QUEUE_2->dequeue_pointer = IPC_QUEUE_2->z2;
        }

        //assert (llabs(siginfo->raw_mcontext->r10 - (uint64_t) error_address) <= ZONE_ERROR_MARGIN);
        if (llabs(siginfo->raw_mcontext->rax - (uint64_t) error_address) <= ZONE_ERROR_MARGIN) {
            disp_offset = error_address - siginfo->raw_mcontext->rax;
            siginfo->raw_mcontext->rax = IPC_QUEUE_2->z2 - disp_offset;
            ++num_updated_registers;
        }
        if (llabs(siginfo->raw_mcontext->rcx - (uint64_t) error_address) <= ZONE_ERROR_MARGIN) {
            disp_offset = error_address - siginfo->raw_mcontext->rcx;
            siginfo->raw_mcontext->rcx = IPC_QUEUE_2->z2 - disp_offset;
            ++num_updated_registers;
        }
        if (llabs(siginfo->raw_mcontext->rdx - (uint64_t) error_address) <= ZONE_ERROR_MARGIN) {
            disp_offset = error_address - siginfo->raw_mcontext->rdx;
            siginfo->raw_mcontext->rdx = IPC_QUEUE_2->z2 - disp_offset;
            ++num_updated_registers;
        }
        if (llabs(siginfo->raw_mcontext->r10 - (uint64_t) error_address) <= ZONE_ERROR_MARGIN) {
            disp_offset = error_address - siginfo->raw_mcontext->r10;
            siginfo->raw_mcontext->r10 = IPC_QUEUE_2->z2 - disp_offset;
            ++num_updated_registers;
        }
        if (llabs(siginfo->raw_mcontext->r11 - (uint64_t) error_address) <= ZONE_ERROR_MARGIN) {
            disp_offset = error_address - siginfo->raw_mcontext->r11;
            siginfo->raw_mcontext->r11 = IPC_QUEUE_2->z2 - disp_offset;
            ++num_updated_registers;
        }
        if (llabs(siginfo->raw_mcontext->r12 - (uint64_t) error_address) <= ZONE_ERROR_MARGIN) {
            disp_offset = error_address - siginfo->raw_mcontext->r12;
            siginfo->raw_mcontext->r12 = IPC_QUEUE_2->z2 - disp_offset;
            ++num_updated_registers;
        }
        if (llabs(siginfo->raw_mcontext->r13 - (uint64_t) error_address) <= ZONE_ERROR_MARGIN){
            disp_offset = error_address - siginfo->raw_mcontext->r13;
            siginfo->raw_mcontext->r13 = IPC_QUEUE_2->z2 - disp_offset;
            ++num_updated_registers;
        }
        if (llabs(siginfo->raw_mcontext->rdi - (uint64_t) error_address) <= ZONE_ERROR_MARGIN){
            disp_offset = error_address - siginfo->raw_mcontext->rdi;
            siginfo->raw_mcontext->rdi = IPC_QUEUE_2->z2 - disp_offset;
            ++num_updated_registers;
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
            //usleep(500);
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
            // IPC_QUEUE_2->enqueue_pointer = IPC_QUEUE_2->z1;
            //memset(IPC_QUEUE_2->z1, 0, IPC_QUEUE_2->bytes_per_zone);
        }
        else {
            #ifdef PRINT_SIG_HANDLER_INFO
            std::cout << tid << " Setting dequeue pointer to z1" << std::endl;
            #endif
            // IPC_QUEUE_2->dequeue_pointer = IPC_QUEUE_2->z1;
        }

        if (llabs(siginfo->raw_mcontext->rax - (uint64_t) error_address) <= ZONE_ERROR_MARGIN) {
            disp_offset = error_address - siginfo->raw_mcontext->rax;
            siginfo->raw_mcontext->rax = IPC_QUEUE_2->z1 - disp_offset;
            ++num_updated_registers;
        }
        if (llabs(siginfo->raw_mcontext->rcx - (uint64_t) error_address) <= ZONE_ERROR_MARGIN) {
            disp_offset = error_address - siginfo->raw_mcontext->rcx;
            siginfo->raw_mcontext->rcx = IPC_QUEUE_2->z1 - disp_offset;
            ++num_updated_registers;
        }
        if (llabs(siginfo->raw_mcontext->rdx - (uint64_t) error_address) <= ZONE_ERROR_MARGIN) {
            disp_offset = error_address - siginfo->raw_mcontext->rdx;
            siginfo->raw_mcontext->rdx = IPC_QUEUE_2->z1 - disp_offset;
            ++num_updated_registers;
        }
        if (llabs(siginfo->raw_mcontext->r10 - (uint64_t) error_address) <= ZONE_ERROR_MARGIN) {
            disp_offset = error_address - siginfo->raw_mcontext->r10;
            siginfo->raw_mcontext->r10 = IPC_QUEUE_2->z1 - disp_offset;
            ++num_updated_registers;
        }
        if (llabs(siginfo->raw_mcontext->r11 - (uint64_t)error_address) <= ZONE_ERROR_MARGIN) {
            disp_offset = error_address - siginfo->raw_mcontext->r11;
            siginfo->raw_mcontext->r11 = IPC_QUEUE_2->z1 - disp_offset;
            ++num_updated_registers;
        }
        if (llabs(siginfo->raw_mcontext->r12 - (uint64_t) error_address) <= ZONE_ERROR_MARGIN) {
            disp_offset = error_address - siginfo->raw_mcontext->r12;
            siginfo->raw_mcontext->r12 = IPC_QUEUE_2->z1 - disp_offset;
            ++num_updated_registers;
        }
        if (llabs(siginfo->raw_mcontext->r13 - (uint64_t) error_address) <= ZONE_ERROR_MARGIN) {
            disp_offset = error_address - siginfo->raw_mcontext->r13;
            siginfo->raw_mcontext->r13 = IPC_QUEUE_2->z1 - disp_offset;
            ++num_updated_registers;
        }
        if (llabs(siginfo->raw_mcontext->rdi - (uint64_t) error_address) <= ZONE_ERROR_MARGIN) {
            disp_offset = error_address - siginfo->raw_mcontext->rdi;
            siginfo->raw_mcontext->rdi = IPC_QUEUE_2->z1 - disp_offset;
            ++num_updated_registers;
        }

        #ifdef PRINT_SIG_HANDLER_INFO
        std::cout << "Thread " << tid << " finished spinlocking and entering Z1" << std::endl;
        #endif

    }

    assert (disp_offset <= 4000);
    assert (num_updated_registers == 1);

    #ifdef PRINT_SIG_HANDLER_INFO
    std::cout << tid << " Z1 free: " << IPC_QUEUE_2->is_z1_free<< std::endl;
    std::cout << tid << " Z2 free: " << IPC_QUEUE_2->is_z2_free<< std::endl;
    std::cout << tid << " IPC_POINTERS: " << IPC_QUEUE_2->enqueue_pointer << " | " << IPC_QUEUE_2->dequeue_pointer << std::endl;
    #endif

    ++sigsegv_cnt;

    return DR_SIGNAL_SUPPRESS;
}
