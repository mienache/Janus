#include <iostream>
#include <unistd.h>
#include <sys/types.h>

#include "janus_api.h"


void create_checker_thread() {
    std::cout << "In create checker thread\n";

    const pid_t new_pid = fork();
    if (new_pid) {
        std::cout << "Process with PID = " << new_pid << " created\n";
    }

    std::cout << "Check thread created!\n";
}