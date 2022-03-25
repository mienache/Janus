#include "dsl_thread_manager.h"

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
bool MAIN_THREAD_REGISTERED;
bool CHECKER_THREAD_REGISTERED;

void* alloc_thread_stack(size_t size);

//void create_checker_thread(uint64_t pc) {
void create_checker_thread() {
    // IMPORTANT: This should be executed as application code
    // NOTE: here we should use gettid rather than dr_get_thread_id as the app code should not rely on drcontext
    // IMPORTANT: Confirm that the TID printed below correspond to the dr_get_thread_id of the MAIN checker

    std::cout << "In create_checker_thread (TID = " << gettid() << ")" << std::endl;
    std::cout << "Address of create_checker_thread: " << (void*) create_checker_thread << std::endl;
    if (CHECKER_THREAD_REGISTERED) {
        std::cout << "Checker thread already registered - THIS SHOULD NEVER BE REACHED" << std::endl;
        return;
    }


    // Encode manually the address to the beginning of the main function - don't forget to update this
    // if recompiling the binary or using a different one.
    int (*main_ptr)(int, char*) = (int (*)(int, char*)) 0x0000000000401156;

    // int (*main_ptr)(int, char*) = (int (*)(int, char*)) pc;
    // TODO: see how to convert PC above to the real address


    std::cout << "Main func ptr in the original binary is: " << std::hex << (void*) main_ptr << std::dec << std::endl;

    std::cout << "Allocating stack" << std::endl;
    void *thread_stack = alloc_thread_stack(8 * 1024 * 1024);

    int flags = (CLONE_THREAD | CLONE_VM | CLONE_PARENT |
             CLONE_FS | CLONE_FILES  | CLONE_IO | CLONE_SIGHAND);

    std::cout << "Calling clone" << std::endl;

    CHECKER_THREAD_REGISTERED = 1;
    int newpid = clone(main_ptr, thread_stack, flags, NULL, NULL, NULL, NULL);

    // VERY IMPORTANT: MUST FORCE THE MAIN THREAD TO SLEEP RIGHT AFTER CLONE IS CALLED
    // OTHERWISE THE MAIN THREAD WILL MOST LIKELY FINISH BEFORE THE SECOND THREAD AND
    // DYNAMORIO EXECUTION WILL BE STOPPED
    sleep(3);

    std::cout << "(From TID = " << gettid() << "): New pid = " << newpid << std::endl;
}

void* alloc_thread_stack(size_t size)
{
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    // TODO: assert

    // stack grows from high to low addresses 
    size_t sp = (size_t)p + size;

    return (void*) sp;
}

void register_thread(ThreadRole threadRole, void *drcontext)
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
}