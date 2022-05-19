#!/usr/bin/python3

import math
import os
import pickle
import sys
from collections import namedtuple

from timeit import default_timer as timer
from typing import Dict, List

PATH_TO_BENCHMARK = "/janus_project/comet_benchmark/"
PATH_TO_OUTPUT_DIR = "/janus_project/all_output/"

#QUEUE_SIZE_RANGE = [200000, 400000, 1000000, 800000, 1500000, 2000000] 
#QUEUE_SIZE_RANGE = [i for i in range(int(1e5), 2 * int(1e6) + 1, int(1e5))] # This will be multiplied by 2 in Janus

QUEUE_SIZE_RANGE = [
    65024,
    130560,
    196096,
    261632,
    327168,
    392704,
    458240,
    523776,
    589312,
    654848,
    720384,
    785920,
    851456,
    916992,
    982528,
    1048064,
    1113600,
    1179136,
    1244672,
    1310208,
    1375744,
    1441280,
    1506816,
    1572352,
    1637888,
    1703424,
    1768960,
    1834496,
    1900032,
    1965568
]

OPTIMISATION_LEVELS = ["O0", "O1", "O2", "O3"]

NUM_ITERATIONS = 13

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

N_RANGE = [2 * int(1e6)]

#N_START = 2 * int(1e5)
#N_END = 1 + 2 * int(1e6)
#N_STEP = 2 * int(1e5)
#N_RANGE = list(i for i in range(N_START, N_END, N_STEP))

IterResults = namedtuple("IterResults", ["sigsegv_cnt", "time"])
InputSizeResults = namedtuple("InputSizeResults", ["sigsegv_cnt", "median_time", "mean_time", "std_time"])
MainDirResults = namedtuple("MainDirResults", ["input_size_to_results"])
OptResults = namedtuple("OptResults", ["main_dir_to_results", "agg_dir_results"])
QueueSizeResults = namedtuple("QueueSizeResults", ["opt_to_results"])

AggDirResults = namedtuple("AggDirResults", "input_size_to_agg_results")

def aggregate_iterations(iter_results: List[IterResults]) -> InputSizeResults:
    all_sigsegv = [ir.sigsegv_cnt for ir in iter_results]
    all_times = list(sorted(ir.time for ir in iter_results))

    assert len(all_times) == NUM_ITERATIONS
    assert len(all_sigsegv) == NUM_ITERATIONS
    assert len(set(all_sigsegv)) == 1 # Must have the same number of sigsegv across the same input size and queue size

    sigsegv_cnt = all_sigsegv[0]
    median_time = all_times[NUM_ITERATIONS // 2] # Take median for time
    mean_time = sum(all_times) / len(all_times)
    std_time = math.sqrt(sum((t - mean_time) ** 2 for t in all_times) / len(all_times))

    return InputSizeResults(sigsegv_cnt, median_time, mean_time, std_time)

def aggregate_dirs(main_dir_to_results: Dict[str, MainDirResults]) -> AggDirResults:
    agg = {}
    for main_dir in main_dir_to_results:
        r = main_dir_to_results[main_dir]
        for input_size in r.input_size_to_results:
            r_ = r.input_size_to_results[input_size]
            if input_size not in agg:
                agg[input_size] = {
                    KEY_SIGSEGV_CNT: 0,
                    KEY_TIME: 0,
                    KEY_MEAN_TIME: 0,
                    KEY_STD_TIME: 0,
                }

            agg[input_size][KEY_SIGSEGV_CNT] += r_.sigsegv_cnt
            agg[input_size][KEY_TIME] += r_.median_time
            agg[input_size][KEY_MEAN_TIME] += r_.mean_time
            agg[input_size][KEY_STD_TIME] += r_.std_time

        agg[input_size][KEY_MEAN_TIME] /= len(r.input_size_to_results)
        agg[input_size][KEY_STD_TIME] /= len(r.input_size_to_results)


    return AggDirResults(agg) # TODO: make `agg_dir_results` also a named tuple

def parse_results_for_iter(curr_path: str, main_dir: str, n: int, num_iter: int) -> IterResults:
    file_path = f"{curr_path}{main_dir}_{n}_{num_iter}.txt"

    iter_time = None
    iter_sigsegv_cnt = None
    with open(file_path, "r") as input_file:
        for line in input_file:
            if "TOTAL_TIME" in line:
                iter_time = float(line.split()[1])
            elif "SIGSEGV_cnt" in line:
                iter_sigsegv_cnt = int(line.split()[2])
    
    try:
        assert iter_time is not None
        assert iter_sigsegv_cnt is not None
    except Exception:
        print(file_path)
        assert False

    return IterResults(iter_sigsegv_cnt, iter_time)

def parse_results_for_input_size(curr_path: str, main_dir: str, n: int) -> InputSizeResults:
    curr_path += f"{n}/"

    all_iter_results = []
    for num_iter in range(NUM_ITERATIONS):
        iter_results = parse_results_for_iter(curr_path, main_dir, n, num_iter)
        all_iter_results.append(iter_results)

    return aggregate_iterations(all_iter_results)


def parse_results_for_main_dir(curr_path, main_dir: str) -> MainDirResults:
    curr_path += f"{main_dir}/"

    input_size_to_results = {}
    for n in N_RANGE:
        input_size_to_results[n] = parse_results_for_input_size(curr_path, main_dir, n)
    
    return MainDirResults(input_size_to_results) 

def parse_results_for_opt_level(curr_path: str, opt_level: str) -> OptResults:
    curr_path += f"{opt_level}/"

    main_dir_to_results = {}
    for main_dir in MAIN_DIRECTORIES:
        main_dir_to_results[main_dir] = parse_results_for_main_dir(curr_path, main_dir)

    agg_results = aggregate_dirs(main_dir_to_results)

    return OptResults(main_dir_to_results, agg_results) 

def parse_results_for_queue_size(curr_path: str, queue_size: int) -> QueueSizeResults:
    curr_path += f"{queue_size}/"

    opt_to_results = {}
    for opt_level in OPTIMISATION_LEVELS:
        opt_to_results[opt_level] = parse_results_for_opt_level(curr_path, opt_level)

    return QueueSizeResults(opt_to_results)

def save_dict_to_file(my_dict: Dict, filename: str) -> None:
    with open(filename, "wb") as output_file:
        pickle.dump(my_dict, output_file)
    
    print(f"Results saved to {filename}")

def main():
    all_results = {}
    for queue_size in QUEUE_SIZE_RANGE:
        all_results[queue_size] = parse_results_for_queue_size(PATH_TO_OUTPUT_DIR, queue_size)

    save_dict_to_file(all_results, "results_ITER13_Q_ranging.dict")
    
    # return all_results

if __name__ == "__main__":
    main()
