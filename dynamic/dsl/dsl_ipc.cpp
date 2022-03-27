#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>


#include <iostream>

#include "dsl_ipc.h"
#include "dsl_thread_manager.h"

BasicQueue *IPC_QUEUE;

void create_shared_memory_area()
{
    std::cout << "Creating shared memory" << std::endl;
        
    IPC_QUEUE = new BasicQueue;
}


void append_value(int val)
{
    std::cout << "Adding value at IPC_QUEUE->end = " << IPC_QUEUE->end << std::endl;

    *(IPC_QUEUE->end) = val;
    IPC_QUEUE->end++;

    std::cout << "Value added " << val << std::endl;
}

int consume_value()
{
    std::cout << "Reading value at IPC_QUEUE->begin = " << IPC_QUEUE->begin << std::endl;

    while(IPC_QUEUE->begin == IPC_QUEUE->end); // The queue is empty, must wait

    int ret = *(IPC_QUEUE->begin);
    IPC_QUEUE->begin++;

    std::cout << "Value read" << ret << std::endl;

    return ret;
}


void communicate(uint64_t register_value) {
    // TODO: rewrite this in enqueue / dequeue and use those as separate clean calls
    std::cout << gettid() << " in clean call: register_value = " << register_value << std::endl;

    if (!PAST_THREAD_CREATION_STAGE) {
        std::cout << "Not yet past thread creation stage, skipping any communication" << std::endl;
        return;
    }

    static int cnt = 0;

    //std::cout << dr_get_thread_id(drcontext) << " communicating " << std::endl;

    AppThread *app_thread = app_threads[gettid()];

    if (app_thread->threadRole == ThreadRole::MAIN) {
        std::cout << gettid() << " appending value " << register_value << std::endl;
        append_value(register_value);
    }
    else {
        std::cout << gettid() << " consuming value " << register_value << std::endl;

        int expected_value = consume_value();
        if (expected_value != register_value) {
            std::cout << "DIFF: " << expected_value << " != " << register_value << std::endl;
        }
        else {
            std::cout << "EQ: " << expected_value << " == " << register_value << std::endl;
        }
    }
}
