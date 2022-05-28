#include <chrono>
#include <iostream>
#include <random>

#include <cassert>

#include "dr_api.h"
#include "dsl_error_insertion.h"
#include "dsl_thread_manager.h"
#include "util.h"

const int EXPECTED_MAIN_BB_CNT = 59;
const int EXPECTED_CHECKER_BB_CNT = 38;
int EXPECTED_BB_CNT; 

int MAIN_BB_CNT;
int CHECKER_BB_CNT;
ThreadRole ERRONEOUS_THREAD_ROLE;
int BB_WITH_ERROR;
bool ERROR_INSERTED = 0;

void insert_error(void *drcontext, instrlist_t *bb)
{
    int seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine generator(seed);

    const int cnt = get_num_instr_with_reg_dsts(bb);

    if (cnt < 1) {
        // Basic block does not have instructions with destination as register, can't
        // insert error error
        return;
    }

    std::uniform_int_distribution<int> distribution(1, cnt);
    const int index = distribution(generator); // Index of instruction with error
    instr_t *i = get_instr_with_reg_dsts_at_idx(bb, index);
    assert(i);

    opnd_t dest = instr_get_dst(i, 0);
    const int num_bits = opnd_size_in_bits(opnd_get_size(dest));

    std::uniform_int_distribution<int> distribution2(1, num_bits);
    int err_bit = distribution(generator);

    if (err_bit >= 32) {
        err_bit = 31;
    }
    
    std::cout << "Err bit = " << err_bit << std::endl;

    // Create instruction that flips bit of dest
    instr_t *xor_instr = INSTR_CREATE_xor(
        drcontext,
        dest,
        opnd_create_immed_int(1 << err_bit, OPSZ_4)
    );

    // Insert the instruction
    instrlist_postinsert(bb, i, xor_instr);

    ERROR_INSERTED = 1;
}

ThreadRole gen_thread_with_error()
{
    int seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine generator(seed);
    std::uniform_int_distribution<int> distribution(1, 2);

    // Also set the EXPECTED_BB_CNT variable to be the correct thread
    if (ERRONEOUS_THREAD_ROLE == ThreadRole::MAIN) {
        EXPECTED_BB_CNT = EXPECTED_MAIN_BB_CNT;
    }
    else {
        EXPECTED_BB_CNT = EXPECTED_CHECKER_BB_CNT;
    }
    return (distribution(generator) == 1) ? ThreadRole::MAIN : ThreadRole::CHECKER;
}


int gen_bb_with_error()
{
    int seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine generator(seed);
    std::uniform_int_distribution<int> distribution(1, EXPECTED_BB_CNT);
    return distribution(generator);
}
