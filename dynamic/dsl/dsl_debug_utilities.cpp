#include <string>

#include "dsl_debug_utilities.h"
#include "dsl_thread_manager.h"


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