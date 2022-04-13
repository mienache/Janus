#ifndef __DSL_IPC__
#define __DSL_IPC__

#include <map>

#include <cstdint>

#include "janus_api.h"

struct BasicQueue;

/*--- IPC Declarations Start ---*/

/*--- IPC Declarations Finish ---*/

struct BasicQueue {
    int *begin; 
    int *end;
    int *v;

    BasicQueue(size_t queue_size)
    {
        v = new int[queue_size];
        begin = v;
        end = v;
    }
};

extern BasicQueue *IPC_QUEUE;

BasicQueue* initialise_queue();

void append_value(BasicQueue *queue, int val);
int consume_value(BasicQueue *queue);
void add_instrumentation_code_for_queue_communication(JANUS_CONTEXT, void *func, BasicQueue *queue, opnd_t dest);
void enqueue(BasicQueue *queue, uint64_t register_value);
void dequeue(BasicQueue *queue, uint64_t register_value);

#endif