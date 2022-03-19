#ifndef __DSL_IPC__
#define __DSL_IPC__

#include <map>

#include <cstdint>

enum ThreadRole {
    MAIN,
    CHECKER
};

extern std::map<pid_t, ThreadRole> pidToRole;

void create_shared_memory_area();

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

void append_value(int val);
int consume_value();
void communicate(uint64_t register_value);

#endif