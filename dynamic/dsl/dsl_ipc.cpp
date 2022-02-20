#include <sys/ipc.h>
#include <sys/shm.h>

#include <iostream>

#include "dsl_ipc.h"

BasicQueue *IPC_QUEUE;

bool MAIN_THREAD = 1;
extern bool CHECKER_THREAD_CREATED;

void create_shared_memory_area()
{
    std::cout << "Creating shared memory" << std::endl;
        
    // ftok to generate unique key
    key_t key = ftok("/janus", 22);

    // shmget returns an identifier in shmid
    int shmid = shmget(key,1024,0666|IPC_CREAT);

    // acquire the memory
    IPC_QUEUE = (BasicQueue*) shmat(shmid, (void*) 0, 0);

    // create the basic queue at the specified location 
    new(IPC_QUEUE) BasicQueue;

    //detach from shared memory
    // shmdt(IPC_QUEUE);
}


void append_value(int val)
{
    std::cout << "Adding value at IPC_QUEUE->end = " << IPC_QUEUE->end << std::endl;

    *(IPC_QUEUE->end) = val;
    IPC_QUEUE->end++;

    std::cout << "Value added" << val << std::endl;
}

int consume_value()
{
    std::cout << "Consuming value at IPC_QUEUE->begin = " << IPC_QUEUE->begin << std::endl;

    while(IPC_QUEUE->begin == IPC_QUEUE->end); // The queue is empty, must wait

    int ret = *(IPC_QUEUE->begin);
    IPC_QUEUE->begin++;

    std::cout << "Consumed value " << ret << std::endl;

    return ret;
}


void communicate(uint64_t register_value) {
    // TODO: rewrite this in enqueue / dequeue and use those as separate clean calls
    std::cout << "---> In clean call: register_value = " << register_value << std::endl;

    static int cnt = 0;
    if (!CHECKER_THREAD_CREATED) {
        return;
    }

    if (MAIN_THREAD) {
        append_value(register_value);
    }
    else {
        const int expected_value = consume_value();
        if (expected_value != register_value) {
            std::cout << "DIFF: " << expected_value << " != " << register_value << std::endl;
        }
        else {
            std::cout << "EQ: " << expected_value << " == " << register_value << std::endl;
        }
    }
}
