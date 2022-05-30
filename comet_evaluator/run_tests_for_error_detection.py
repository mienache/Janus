#!/usr/bin/python3

import os
import subprocess
from timeit import default_timer as timer
import sys

PATH_TO_BENCHMARK = "/janus_project/comet_benchmark/"
PATH_TO_OUTPUT_DIR = "/janus_project/all_output_error_detection/"
JDSL_RUN_PATH = "/janus_project/janus/jdsl_run"

MAIN_DIR_TO_EXPECTED_OUTPUT = {
    "con_comps": "100\n",
    "expr_evaluator": "4787\n",
    "file_system_interaction": "200000\n",
    "matrix_mult": "396\n",
    "merge_sort": "OK: 1\n",
    "pi_approximation": "3.14159\n",
    "prime_numbers": "33860\n",
    "vector": "80000200000\n",
}


MAIN_DIR = sys.argv[1]
ERROR_DETECTION = "EC" if int(sys.argv[2]) else "NO_EC"
EXPECTED_CNT = 2 if ERROR_DETECTION == "EC" else 1
NUM_ITERATIONS = int(sys.argv[3])

# Make sure "all_output" directory exists
if not os.path.isdir(PATH_TO_OUTPUT_DIR):
    os.mkdir(PATH_TO_OUTPUT_DIR)

N_RANGE = [4 * int(1e5)]


def find_content(file_path: str, content: str) -> int:
    cnt = 0
    with open(file_path) as input_file:
        for line in input_file:
            if content in line:
                cnt += 1

    return cnt 


def was_error_inserted(file_path: str) -> bool:
    with open(file_path) as input_file:
        for line in input_file:
            if "ERROR INSERTED" in line:
                val = int(line.strip().split()[-1])
                if val:
                    return True
                else:
                    return False

    return True

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

    max_timeout = 15 if main_dir == "mult_matrix" else 5

    curr_path = PATH_TO_BENCHMARK + main_dir
    bin_path = curr_path + "/bin/"
    bin_file_path = f"{bin_path}_generated_{size}_{main_dir}"

    for num_iter in range(NUM_ITERATIONS):
        print(f"Iter {num_iter}...")
        jdsl_command = f"/usr/bin/time {JDSL_RUN_PATH} {bin_file_path}"
        jdsl_command = jdsl_command.split()

        output_filename = f"{main_dir}_{size}_{ERROR_DETECTION}_{num_iter}.txt"
        output_file_path = f"{PATH_TO_OUTPUT_DIR}{main_dir}/{size}/{output_filename}"
        output_file = open(output_file_path, "w")

        result = None
        try:
            result = "Masked"
            results = subprocess.run(jdsl_command, stdout=output_file, stderr=output_file, timeout=max_timeout)
            results.check_returncode()
        except Exception as e:
            if type(e) == subprocess.CalledProcessError:
                result = "Exception"
            elif type(e) == subprocess.TimeoutExpired:
                result = "Timeout"

        
        try:
            if find_content(output_file_path, "unexpected"):
                result = "Detected"
            elif (
                result == "Masked" and find_content(output_file_path, MAIN_DIR_TO_EXPECTED_OUTPUT[main_dir]) < EXPECTED_CNT
            ):
                print(f"                ==== WRONG OUTPUT at {num_iter=}")
                result = "Wrong output"
            if was_error_inserted(output_file_path):
                is_valid = True
            else:
                is_valid = False
        except Exception as e:
            assert type(e) == UnicodeDecodeError
            is_valid = True
            result = "Corrupted"

        if is_valid:
            results_filename = f"results_{main_dir}_{size}_{ERROR_DETECTION}.txt"
            results_file_path = f"{PATH_TO_OUTPUT_DIR}{main_dir}/{size}/{results_filename}"
            results_file = open(results_file_path, "a")
            results_file.write(result + "\n")

            print(result)
        else:
            print("Skipping")

        if main_dir == "file_system_interaction":
            try:
                remove_fs_interaction_output()
            except:
                pass


def run_tests_for_dir(main_dir: str) -> None:
    create_output_dir(main_dir)
    print(f"    ===== Running tests for {main_dir} ==== ")
    for n in N_RANGE:
        print(f"Running tests for N = {n}")
        run_test_for_dir(main_dir, n)


def main():
    run_tests_for_dir(MAIN_DIR)

if __name__ == "__main__":
    main()
