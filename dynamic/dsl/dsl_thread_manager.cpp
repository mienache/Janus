#include "dsl_thread_manager.h"

#include <atomic>
#include <cassert>
#include <exception>
#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <sys/mman.h>  /* for mmap */
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>

#include "dsl_ipc.h"
#include "handler.h"
#include "janus_api.h"

std::map <pid_t, AppThread*> app_threads;
AppThread *main_thread;
AppThread *checker_thread;
int NUM_THREADS;
std::atomic<bool> CHECKER_THREAD_FINISHED;
std::atomic<bool> PAST_THREAD_CREATION_STAGE;
void *NEW_THREAD_START_PTR;

void* alloc_thread_stack(size_t size);

ThreadRole get_thread_role_from_str(char *thread_role_as_str);

void run_thread(void *raw_app_thread) {
    // IMPORTANT: This should be executed as application code
    // NOTE: here we should use gettid rather than dr_get_thread_id as the app code should not rely on drcontext
    // IMPORTANT: Confirm that the TID printed below corresponds to the dr_get_thread_id of the MAIN thread

    std::cout << "In run_thread (TID = " << gettid() << ")" << std::endl;
    std::cout << "Address of run_thread: " << (void*) run_thread << std::endl;
    if (checker_thread) {
        std::cout << "Checker thread already registered - THIS SHOULD NEVER BE REACHED" << std::endl;
        return;
    }

    AppThread *app_thread = (AppThread*) raw_app_thread;

    // The AppThread pointer must be NULL when create thread is called
    if (app_thread) {
        std::cout << "ERROR: raw_app_thread pointer must be NULL when the thread is created" << std::endl;
        std::cout << "raw_app_thread = " << raw_app_thread << std::endl;
    }

    int (*main_ptr)(int, char*) = (int (*)(int, char*)) NEW_THREAD_START_PTR;
    std::cout << "Main func ptr in the original binary is: " << std::hex << (void*) main_ptr << std::dec << std::endl;

    std::cout << "Allocating stack" << std::endl;
    void *thread_stack = alloc_thread_stack(8 * 1024 * 1024);

    int flags = (CLONE_THREAD | CLONE_VM | CLONE_PARENT |
             CLONE_FS | CLONE_FILES  | CLONE_IO | CLONE_SIGHAND);

    std::cout << "Calling clone" << std::endl;

    int newpid = clone(main_ptr, thread_stack, flags, NULL, NULL, NULL, NULL);
    std::cout << "(From TID = " << gettid() << "): New pid = " << newpid << std::endl;

    PAST_THREAD_CREATION_STAGE = 1;
}

void* alloc_thread_stack(size_t size)
{
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    // TODO: assert

    // stack grows from high to low addresses 
    size_t sp = (size_t)p + size;

    return (void*) sp;
}

AppThread* register_thread(char *thread_role_as_str, void *drcontext)
{
    // This is executed as DynamoRIO code, so we should call dr_get_thread_id not gettid
    pid_t tid = dr_get_thread_id(drcontext);

    ThreadRole thread_role = get_thread_role_from_str(thread_role_as_str);

    AppThread *app_thread = new AppThread(tid);
    app_thread->threadRole = thread_role;
    app_threads.insert(std::make_pair(tid, app_thread));

    std::cout << dr_get_thread_id(drcontext) << ": Thread registered" << std::endl;

    switch (thread_role) {
        case MAIN: {
            std::cout << "role = MAIN" << std::endl;
            break;
        }
        case CHECKER: {
            std::cout << "role = CHECKER" << std::endl;
            break;
        }
        default: {
            std::cout << "role = UNKNOWN" << std::endl;
        }
    }

    return app_thread;
}

void init_num_threads(int num_threads)
{
    std::cout << "Num threads initialised to " << num_threads << std::endl;
    NUM_THREADS = num_threads;
}

void do_pre_thread_creation_maintenance(JANUS_CONTEXT)
{
    instr_t *trigger = get_trigger_instruction(bb,rule);
    app_pc pc = instr_get_app_pc(trigger);
    std::cout << "APP PC of trigger is" << (void*) pc << std::endl;

    NEW_THREAD_START_PTR = (void*) pc;
    // TODO: maybe replace the above and pass it via registers
    // as otherwise if more threads are created it is prone to race conditions

    // The jump inserted by insert_function_call_as_application will split the current basic blocks
    // into two. Thus the rules that should be applied after that jump (i.e., starting from the instruction
    // right after `trigger`) must be copied to the new basic block, otherwise they won't be applied.
    instr_t *post_trigger = instr_get_next_app(trigger);
    app_pc post_trigger_pc = instr_get_app_pc(post_trigger);
    copy_rules_to_new_bb(post_trigger_pc, pc);
}

ThreadRole get_thread_role_from_str(char *thread_role_as_str)
{
    if (thread_role_as_str == "main") {
        return ThreadRole::MAIN;
    }

    if (thread_role_as_str == "worker") {
        return ThreadRole::CHECKER;
    }

    return ThreadRole::UNKNOWN;
}