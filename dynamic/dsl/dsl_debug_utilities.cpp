#include <string>

#include "dsl_debug_utilities.h"
#include "dsl_thread_manager.h"


#ifdef SUPPORT_SIMD_REGISTERS
const int INCREMENT = 16;
#else
const int INCREMENT = 8;
#endif

void print_first_n_elements_from_queue(CometQueue *queue, int n)
{
    std::cout << "First " << n << " elements of the queue are: " << std::endl;
    int64_t *ptr = queue->z1;
    for (int i = 0; i < n; ++i) {
        std::cout << i << ": " << (void*) *ptr << std::endl;
        ++ptr;
    }
}

// Helper variables to print the basic block files with unique names.
int bb_cnt1 = 0;
int bb_cnt2 = 0;

// Helper method for generating the name of a file used to print the current basic block
std::string get_basic_block_filename(void *drcontext, bool is_original_bb)
{
    std::string filename;
    if (app_threads[dr_get_thread_id(drcontext)]->threadRole == ThreadRole::MAIN) {
        if (is_original_bb) {
            ++bb_cnt1; // Only increment counter if we're printing the original BB (to keep 1-1 mapping between filenames)
            filename = "main_basic_block_" + std::to_string(bb_cnt1);
        }
        else {
            filename = "main_basic_block_modified_" + std::to_string(bb_cnt1);
        }
    }
    else {
        if (is_original_bb) {
            ++bb_cnt2;
            filename = "checker_basic_block_" + std::to_string(bb_cnt2);
        }
        else {
            filename = "checker_basic_block_modified_" + std::to_string(bb_cnt2);
        }
    }

    filename += is_original_bb ? ".txt" : "_modified.txt";

    std::cout << "file: " << filename << std::endl;

    return filename;
}

void print_bb_to_file(void *drcontext, instrlist_t *bb, bool is_original_bb)
{
    std::string filename = get_basic_block_filename(drcontext, is_original_bb);
    app_pc tag_new = instr_get_app_pc(instrlist_first_app(bb));
    file_t output_file = dr_open_file(filename.c_str(), DR_FILE_WRITE_OVERWRITE);
    instrlist_disassemble(drcontext, tag_new, bb, output_file);
    dr_close_file(output_file);
}

void enqueue_debug(int64_t enqueued_value)
{
    #ifdef SKIP_ENQUEUE_DEBUG
        return;
    #endif

    std::cout << "In enqueue_debug" << std::endl;

    const int index = get_queue_index(IPC_QUEUE_2->enqueue_pointer);
    std::cout << "Enqueing to index: " << index << std::endl;
    std::cout << "Enqueued value = " << (void*) enqueued_value << std::endl;
}

void dequeue_debug(int64_t expected_value, int asserting)
{
    #ifdef SKIP_DEQUEUE_DEBUG
        return;
    #endif

    std::cout << "In dequeue_debug" << std::endl;

    if (IPC_QUEUE_2->dequeue_pointer >= IPC_QUEUE_2->r2) {
        std::cout << "R zone" << std::endl;
        return;
    }

    const int index = get_queue_index(IPC_QUEUE_2->dequeue_pointer);
    const int64_t curr_value = *((int64_t*) (IPC_QUEUE_2->dequeue_pointer));
    std::cout << "Dequeing from index: " << index << std::endl;
    std::cout << "Current value: " << (void*) curr_value << std::endl;

    if (asserting) {
        std::cout << "Expected value: " << (void*) expected_value << std::endl;
    }
    else {
        std::cout << "Not asserting" << std::endl;
    }

    if (asserting && curr_value != expected_value) {
        dump_registers();
    }
}

void after_dequeue_debug(int64_t dequeued_val)
{
    std::cout << "In after dequeue_debug" << std::endl;

    if (IPC_QUEUE_2->dequeue_pointer >= IPC_QUEUE_2->r2) {
        std::cout << "R zone" << std::endl;
        return;
    }

    const int index = get_queue_index(IPC_QUEUE_2->dequeue_pointer);
    std::cout << "Dequeued from index: " << index << std::endl;
    std::cout << "Current value: " << *((int64_t*) (IPC_QUEUE_2->dequeue_pointer)) << std::endl;
    std::cout << "Dequeued value: " << dequeued_val << std::endl;
}

int get_queue_index(void* ptr)
{
    return ((int) ptr - (int) IPC_QUEUE_2->z1) / INCREMENT;
}