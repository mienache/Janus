#!/usr/bin/python3

import os
import pickle
import sys

from typing import Dict

PATH_TO_OUTPUT_DIR = "/janus_project/all_output_error_detection/"

NUM_ITERATIONS = 3

assert os.path.isdir(PATH_TO_OUTPUT_DIR)

KEY_SIGSEGV_CNT = "sigsegv_cnt"
KEY_TIME = "time"
KEY_MEAN_TIME = "mean_time"
KEY_STD_TIME = "std_time"

INDEX_SIGSEGV = 0
INDEX_TIME = 1

MAIN_DIRECTORIES = [
    "con_comps",
    "expr_evaluator",
    "file_system_interaction",
    "matrix_mult",
    "merge_sort",
    "pi_approximation",
    "prime_numbers",
    "vector"
]

N = int(2 * 1e5)

def parse_results(file_path: str) -> Dict:
    cnt = 0
    results = {}
    with open(file_path) as input_file:
        for line in input_file:
            line = line.strip()
            if line not in results:
                results[line] = 0
            results[line] += 1

            if cnt == NUM_ITERATIONS: # Only read max NUM_ITERATIONS entries from the file
                break

    return results


def parse_results_for_error_detection(ed: int) -> None:
    ec = "EC" if ed else "NO_EC"

    results = {}

    for main_dir in MAIN_DIRECTORIES:
        results_filename = f"results_{main_dir}_{N}_{ec}.txt"
        results_file_path = f"{PATH_TO_OUTPUT_DIR}/{main_dir}/{N}/{results_filename}"

        results[main_dir] = parse_results(results_file_path)
    
    return results


def main():
    all_results = {}
    for ed in [0, 1]:
        all_results[ed] = parse_results_for_error_detection(ed)

    save_dict_to_file(all_results, "results_error_detection_200k.dict")
    
    # return all_results

if __name__ == "__main__":
    main()
