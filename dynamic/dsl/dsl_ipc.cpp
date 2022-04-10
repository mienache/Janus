#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <cassert>


#include <iostream>

#include "janus_api.h"

#include "dsl_ipc.h"
#include "dsl_thread_manager.h"

/*--- IPC Declarations Start ---*/

/*--- IPC Declarations Finish ---*/

BasicQueue *IPC_QUEUE;

BasicQueue* create_shared_memory_area()
{
    std::cout << "Creating shared memory" << std::endl;
        
    return new BasicQueue;
}


void append_value(BasicQueue *queue, int val)
{
    std::cout << "Adding value at queue->end = " << queue->end << std::endl;

    *(queue->end) = val;
    queue->end++;

    std::cout << "Value added " << val << std::endl;
}

int consume_value(BasicQueue *queue)
{
    std::cout << "Reading value at queue->begin = " << queue->begin << std::endl;

    while(queue->begin == queue->end); // The queue is empty, must wait

    int ret = *(queue->begin);
    queue->begin++;

    std::cout << "Value read" << ret << std::endl;

    return ret;
}


void communicate(BasicQueue *queue, uint64_t register_value) {
    // TODO: rewrite this in enqueue / dequeue and use those as separate clean calls
    std::cout << gettid() << " in clean call: register_value = " << register_value << std::endl;
    std::cout << "Queue pointer is: " << (void*) queue << std::endl;

    if (!PAST_THREAD_CREATION_STAGE) {
        std::cout << "Not yet past thread creation stage, skipping any communication" << std::endl;
        return;
    }

    static int cnt = 0;

    //std::cout << dr_get_thread_id(drcontext) << " communicating " << std::endl;

    AppThread *app_thread = app_threads[gettid()];

    if (app_thread->threadRole == ThreadRole::MAIN) {
        std::cout << gettid() << " appending value " << register_value << std::endl;
        append_value(queue, register_value);
    }
    else {
        std::cout << gettid() << " consuming value " << register_value << std::endl;

        int expected_value = consume_value(queue);
        if (expected_value != register_value) {
            std::cout << "DIFF: " << expected_value << " != " << register_value << std::endl;
        }
        else {
            std::cout << "EQ: " << expected_value << " == " << register_value << std::endl;
        }
    }
}

void add_instrumentation_code_for_communication(JANUS_CONTEXT, BasicQueue *queue, opnd_t dest)
{
    instr_t *trigger = get_trigger_instruction(bb,rule);
    instr_t *post_trigger = instr_get_next(trigger);

    assert(post_trigger);

    if (!opnd_is_reg(dest)) {
        return;
    }

    std::cout << "Passing queue pointer: " << (void*) queue << std::endl;
    dr_insert_clean_call(drcontext, bb, post_trigger, (void*) communicate, false, 2, OPND_CREATE_INT64(queue), dest);
}
