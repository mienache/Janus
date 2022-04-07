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

#include "janus_api.h"
#include "dsl_ipc.h"

std::map <pid_t, AppThread*> app_threads;
AppThread *main_thread;
AppThread *checker_thread;
int NUM_THREADS;
std::atomic<bool> CHECKER_THREAD_FINISHED;
std::atomic<bool> PAST_THREAD_CREATION_STAGE;
void *NEW_THREAD_START_PTR;

void* alloc_thread_stack(size_t size);

void create_checker_thread(void *raw_app_thread) {
    // IMPORTANT: This should be executed as application code
    // NOTE: here we should use gettid rather than dr_get_thread_id as the app code should not rely on drcontext
    // IMPORTANT: Confirm that the TID printed below corresponds to the dr_get_thread_id of the MAIN thread

    std::cout << "In create_checker_thread (TID = " << gettid() << ")" << std::endl;
    std::cout << "Address of create_checker_thread: " << (void*) create_checker_thread << std::endl;
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

AppThread* register_thread(ThreadRole threadRole, void *drcontext)
{
    // This is executed as DynamoRIO code, so we should call dr_get_thread_id not gettid
    pid_t tid = dr_get_thread_id(drcontext);

    AppThread *app_thread = new AppThread(tid);
    app_thread->threadRole = threadRole;
    app_threads.insert(std::make_pair(tid, app_thread));

    std::cout << dr_get_thread_id(drcontext) << ": Thread registered" << std::endl;

    switch (threadRole) {
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