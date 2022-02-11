#include <exception>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "janus_api.h"

void check_shared_memory();

void create_checker_thread() {
    std::cout << "In create checker thread\n";

    const pid_t new_pid = fork();
    if (new_pid) {
        std::cout << "Process with PID = " << new_pid << " created\n";
        std::cout << "Checker thread created!\n";

        return;
    }

    try {
        check_shared_memory();
    }
    catch (std::exception &e) {
        std::cout << "Exception caught: " << e.what() << std::endl;
    }

}

void check_shared_memory()
{
    std::cout << "Checking shared memory" << std::endl;

    key_t key = ftok("/janus", 22);

    // shmget returns an identifier in shmid
    int shmid = shmget(key,1024,0666|IPC_CREAT);

    // shmat to attach to shared memory
    char *str = (char*) shmat(shmid,(void*)0,0);

    printf("Data read from memory: %s\n",str);

    //detach from shared memory
    shmdt(str);

    // destroy the shared memory
    shmctl(shmid,IPC_RMID,NULL);
}