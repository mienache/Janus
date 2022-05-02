#ifndef __DSL_IPC__
#define __DSL_IPC__

#include <atomic>
#include <iostream>
#include <map>

#include <sys/mman.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>

#include "janus_api.h"

struct BasicQueue;

struct CometQueue;

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

struct CometQueue {
    void *z1;
    void *z2;
    void *r1;
    void *r2;
    void *enqueue_pointer;
    void *dequeue_pointer;
    std::atomic<bool> is_z1_free;
    std::atomic<bool> is_z2_free;
    std::atomic<pid_t> z1_last_thread;
    std::atomic<pid_t> z2_last_thread;

    CometQueue(size_t num_items_per_zone)
    {
        std::cout<< "Num items per zone: " << num_items_per_zone << std::endl;

        const int prot = PROT_READ | PROT_WRITE;
        const int flags = MAP_PRIVATE | MAP_ANONYMOUS;
        const int fd = -1;
        const size_t offset = 0;

        const int page_size = getpagesize();
        size_t item_size = sizeof(uint64_t);
        size_t num_items_per_page = page_size / item_size;
        std::cout<< "Size of a queue item is: " << item_size << std::endl;

        std::cout<< "Size of a page = " << page_size << std::endl;
        std::cout<< "Num items per page: " << num_items_per_page << std::endl;

        const size_t pages_per_zone = (num_items_per_zone * item_size) / page_size + (((num_items_per_zone * item_size) % page_size) ? 1 : 0);
        const size_t zone_size = pages_per_zone * page_size;
        num_items_per_zone = zone_size / item_size;

        std::cout<< "Readjusted num items per zone: " << num_items_per_zone << std::endl;

        std::cout<< "Allocating " << pages_per_zone << " pages per zone" << std::endl;

        const int total_pages = 2 * (pages_per_zone + 1);
        const size_t total_size = total_pages * page_size;

        z1 = mmap(0, total_size, prot, flags, fd, offset);
        memset(z1, 0, total_size);

        std::cout<< "Allocated Z1 at " << (void*) z1 << std::endl;

        r1 = z1 + num_items_per_zone * item_size;

        std::cout<< "Trying to deallocate at " << (void*) r1 << std::endl;
        std::cout<< "munmap successful? : " << munmap(r1, page_size) << std::endl;

        r2 = z1 + 2 * num_items_per_zone * item_size + num_items_per_page * item_size;
        std::cout<< "Trying to deallocate at " << (void*) r2 << std::endl;
        std::cout<< "munmap successful? : " << munmap(r2, page_size) << std::endl;

        z2 = z1 + (num_items_per_zone + num_items_per_page) * item_size;

        std::cout<< "Z1 at " << (void*) z1 << std::endl;
        std::cout<< "Z2 at " << (void*) z2 << std::endl;

        enqueue_pointer = z1;
        dequeue_pointer = r2;

        is_z1_free = 0;
        is_z2_free = 0;

        std::cout << "Enqueue pointer allocated at: " << (void*) &enqueue_pointer << std::endl;
        std::cout << "Dequeue pointer allocated at: " << (void*) &dequeue_pointer << std::endl;

        // TODO: complete signal_handler
    }

};

extern BasicQueue *IPC_QUEUE;
extern CometQueue *IPC_QUEUE_2;

BasicQueue* initialise_queue();
CometQueue* initialise_comet_queue();

void append_value(BasicQueue *queue, int val);
int consume_value(BasicQueue *queue);
void add_instrumentation_code_for_queue_communication(JANUS_CONTEXT, void *func, BasicQueue *queue, opnd_t dest);
void enqueue(BasicQueue *queue, uint64_t register_value);
void dequeue(BasicQueue *queue, uint64_t register_value);

#endif