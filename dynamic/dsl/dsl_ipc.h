#ifndef __DSL_IPC__
#define __DSL_IPC__

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

#endif