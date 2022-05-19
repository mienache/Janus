#!/usr/bin/python3

import os
import subprocess
from timeit import default_timer as timer
import sys

PATH_TO_BENCHMARK = "/janus_project/comet_benchmark/"
PATH_TO_OUTPUT_DIR = "/janus_project/all_output/"
JDSL_RUN_PATH = "/janus_project/janus/jdsl_run"

QUEUE_SIZE = sys.argv[1]

OPT_LEVEL = sys.argv[2] # O0, O1, O2, O3 - must be a string
assert OPT_LEVEL in ["NO-COMET", "O0", "O1", "O2", "O3"]

NUM_ITERATIONS = int(sys.argv[3])

# Make sure "all_output" directory exists
if not os.path.isdir(PATH_TO_OUTPUT_DIR):
    os.mkdir(PATH_TO_OUTPUT_DIR)

# Update PATH_TO_OUTPUT_DIR based on the parameters and make sure subidrectories exist
PATH_TO_OUTPUT_DIR += f"{QUEUE_SIZE}/"
if not os.path.isdir(PATH_TO_OUTPUT_DIR):
    os.mkdir(PATH_TO_OUTPUT_DIR)

PATH_TO_OUTPUT_DIR += f"{OPT_LEVEL}/"
if not os.path.isdir(PATH_TO_OUTPUT_DIR):
    os.mkdir(PATH_TO_OUTPUT_DIR)


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

#N_START = 2 * int(1e5)
#N_END = 2 * int(1e6)
#N_STEP = 2 * int(1e5)
#N_RANGE = list(i for i in range(N_START, N_END, N_STEP))

N_RANGE = [2 * int(1e6)]

def create_output_dir(main_dir: str) -> None:
    output_dir_path = f"{PATH_TO_OUTPUT_DIR}{main_dir}"
    if not os.path.isdir(output_dir_path):
        os.mkdir(output_dir_path)

def create_output_dir_for_size(main_dir: str, size: int) -> None:
    output_dir_path_for_size = f"{PATH_TO_OUTPUT_DIR}{main_dir}/{size}/"
    if not os.path.isdir(output_dir_path_for_size):
        os.mkdir(output_dir_path_for_size)

def remove_fs_interaction_output() -> None:
    os.remove("/janus_project/comet_evaluator/fs_interaction_files/output.txt")

def run_test_for_dir(main_dir: str, size: int) -> None:
    create_output_dir_for_size(main_dir, size)

    curr_path = PATH_TO_BENCHMARK + main_dir
    bin_path = curr_path + "/bin/"
    bin_file_path = f"{bin_path}_generated_{size}_{main_dir}"

    for num_iter in range(NUM_ITERATIONS):
        jdsl_command = f"/usr/bin/time {JDSL_RUN_PATH} {bin_file_path}"
        jdsl_command = jdsl_command.split()

        done = False
        while not done:
            try:
                output_filename = f"{main_dir}_{size}_{num_iter}.txt"
                output_file_path = f"{PATH_TO_OUTPUT_DIR}{main_dir}/{size}/{output_filename}"
                output_file = open(output_file_path, "w")

                start_time = timer()
                results = subprocess.run(jdsl_command, stdout=output_file, stderr=output_file, timeout=55)
                end_time = timer()
                output_file.close()

                results.check_returncode()
                done = True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                print(f"Error! Retrying")
                done = False

        with open(output_file_path, "a") as output_file:
            total_time = round(end_time - start_time, 4)
            print(f"Iteration {num_iter} total time: {total_time} (sec.)")
            output_file.write(f"TOTAL_TIME: {total_time} (sec.)")


        if main_dir == "file_system_interaction":
            remove_fs_interaction_output()


def run_tests_for_dir(main_dir: str) -> None:
    create_output_dir(main_dir)
    print(f"    ===== Running tests for {main_dir} ==== ")
    for n in N_RANGE:
        print(f"Running tests for N = {n}")
        run_test_for_dir(main_dir, n)


def main():
    for main_dir in MAIN_DIRECTORIES:
        run_tests_for_dir(main_dir)

if __name__ == "__main__":
    print(f"Running {NUM_ITERATIONS} iterations per (binary, input_size) pair")
    print(f"Optimisations: {OPT_LEVEL}")
    main()
