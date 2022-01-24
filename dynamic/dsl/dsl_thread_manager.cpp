#include <iostream>
#include <unistd.h>
#include <sys/types.h>

#include "janus_api.h"


void create_threads() {
    const int num_threads = rsched_info.number_of_threads;
    std::cout << "Creating " << num_threads << "threads\n";

    for (int i = 0; i < rsched_info.number_of_threads - 1; ++i) {
        const pid_t new_pid = fork();
        if (!new_pid) {
            // Stop child processes from creating others
            break;
        }

        std::cout << "Process with PID = " << new_pid << " created\n";
    }

    std::cout << num_threads << " threads created\n";
}