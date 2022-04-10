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
    int v[10];

    BasicQueue()
    {
        begin = v;
        end = v;
    }
};

extern BasicQueue *IPC_QUEUE;

BasicQueue* create_shared_memory_area();

void append_value(int val);
int consume_value();
void communicate(uint64_t register_value);
void add_instrumentation_code_for_communication(JANUS_CONTEXT, opnd_t dest);

#endif