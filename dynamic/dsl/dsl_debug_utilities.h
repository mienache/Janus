#ifndef __DSL_DEBUG_UTILITIES__
#define __DSL_DEBUG_UTILITIES__

#include <string>

#include "dsl_ipc.h"
#include "janus_api.h"

#define SUPPORT_SIMD_REGISTERS

//#define INSERT_DEBUG_CLEAN_CALLS
#define SKIP_ENQUEUE_DEBUG
//#define SKIP_DEQUEUE_DEBUG

//#define PRINT_TRIGGER_INSTR
//#define PRINT_INSTRUCTION_INSTRUMENTATION_INFO
//#define SHOW_INFO_ABOUT_CMP
//#define SKIP_THREAD_CREATION


void print_first_n_elements_from_queue(CometQueue *queue, int n);

std::string get_basic_block_filename(void *drcontext, bool is_original_bb);

void print_bb_to_file(void *drcontext, instrlist_t *bb, bool is_original_bb);

void enqueue_debug(int64_t enqueued_value);
void dequeue_debug(int64_t expected_value, int asserting);
void after_dequeue_debug(int64_t dequeued_val);

int get_queue_index(void* ptr);


#endif