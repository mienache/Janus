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

void* alloc_thread_stack(size_t size);

void create_checker_thread(uint64_t pc) {
    std::cout << "In create_checker_thread PC is " << std::hex << pc << std::endl;

    // int (*main_ptr)(int, char*) = (int (*)(int, char*)) pc;
    // TODO: see how to convert PC above to the real address
    int (*main_ptr)(int, char*) = (int (*)(int, char*)) 0x0000000000401156;


    // Needs to be converted to (void*) for printing
    std::cout << "Func ptr is: " << std::hex << (void*) main_ptr << std::dec << std::endl;

    std::cout << "Allocating stack" << std::endl;
    void *thread_stack = alloc_thread_stack(8 * 1024 * 1024);

    int flags = (CLONE_THREAD | CLONE_VM | CLONE_PARENT |
             CLONE_FS | CLONE_FILES  | CLONE_IO | CLONE_SIGHAND);

    std::cout << "Calling clone" << std::endl;

    int newpid = clone(main_ptr, thread_stack, flags, NULL, NULL, NULL, NULL);
    std::cout << "New pid = " << newpid << std::endl;
}

void* alloc_thread_stack(size_t size)
{
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    // TODO: assert

    // stack grows from high to low addresses 
    size_t sp = (size_t)p + size;

    return (void*) sp;
}

void register_thread(ThreadRole threadRole)
{
    pid_t pid = getpid();

    AppThread *app_thread = new AppThread(pid);

    app_thread->threadRole = threadRole;

    app_threads.insert(std::make_pair(pid, app_thread));

    std::cout << "Thread registered" << std::endl;

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