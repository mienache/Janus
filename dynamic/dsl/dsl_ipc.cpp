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

BasicQueue* initialise_queue()
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


void enqueue(BasicQueue *queue, uint64_t register_value)
{
    if (!PAST_THREAD_CREATION_STAGE) {
        std::cout << "Not yet past thread creation stage, skipping any communication" << std::endl;
        return;
    }

    append_value(queue, register_value);
}

void dequeue(BasicQueue *queue, uint64_t register_value)
{
    int expected_value = consume_value(queue);
    if (expected_value != register_value) {
        std::cout << "DIFF: " << expected_value << " != " << register_value << std::endl;
    }
    else {
        std::cout << "EQ: " << expected_value << " == " << register_value << std::endl;
    }

}

void add_instrumentation_code_for_queue_communication(JANUS_CONTEXT, void *func, BasicQueue *queue, opnd_t dest)
{
    instr_t *trigger = get_trigger_instruction(bb,rule);
    instr_t *post_trigger = instr_get_next(trigger);

    assert(post_trigger);

    if (!opnd_is_reg(dest)) {
        return;
    }

    std::cout << "Passing queue pointer: " << (void*) queue << std::endl;
    dr_insert_clean_call(drcontext, bb, post_trigger, (void*) func, false, 2, OPND_CREATE_INT64(queue), dest);
}
