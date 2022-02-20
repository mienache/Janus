#include <exception>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "janus_api.h"
#include "dsl_ipc.h"

extern bool MAIN_THREAD;

bool CHECKER_THREAD_CREATED;

void check_shared_memory();

void create_checker_thread() {
    std::cout << "In create checker thread\n";

    const pid_t new_pid = fork();
    if (new_pid) {
        std::cout << "Process with PID = " << new_pid << " created\n";
        std::cout << "Checker thread created!\n";

        CHECKER_THREAD_CREATED = 1;

        return;
    }

    CHECKER_THREAD_CREATED = 1;
    MAIN_THREAD = 0;
}
