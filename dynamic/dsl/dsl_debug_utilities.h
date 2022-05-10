#ifndef __DSL_DEBUG_UTILITIES__
#define __DSL_DEBUG_UTILITIES__

#include <string>

#include "dsl_ipc.h"
#include "janus_api.h"

void print_first_n_elements_from_queue(CometQueue *queue, int n);

std::string get_basic_block_filename(void *drcontext, bool is_original_bb);

void print_bb_to_file(void *drcontext, instrlist_t *bb, bool is_original_bb);

#endif