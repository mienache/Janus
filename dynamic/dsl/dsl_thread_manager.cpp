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

void* alloc_thread_stack(size_t size);

void create_checker_thread(uint64_t pc) {
    std::cout << "In create checker thread"<< std::endl;

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

    if (newpid) {
        pidToRole.insert(std::make_pair(getpid(), ThreadRole::MAIN));
    }
    else {
        pidToRole.insert(std::make_pair(getpid(), ThreadRole::CHECKER));
    }
}

void* alloc_thread_stack(size_t size)
{
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    // TODO: assert

    // stack grows from high to low addresses 
    size_t sp = (size_t)p + size;

    return (void*) sp;
}
