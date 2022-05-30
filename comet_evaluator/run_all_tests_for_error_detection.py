#!/usr/bin/python3

import subprocess
import sys

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

NUM_ITERATIONS = 3

def build_and_run(main_dir: str) -> None:
    print(f"Building for {main_dir=}")
    rebuild_command = f"./rebuild_for_error_detection.py {main_dir}".split()
    cp = subprocess.run(rebuild_command)
    cp.check_returncode()

    print(f"Running tests for {main_dir=}")
    run_tests_command = f"./run_error_detection_tests.py {main_dir} {NUM_ITERATIONS}".split()
    cp = subprocess.run(run_tests_command)
    cp.check_returncode()



def main():
    for main_dir in MAIN_DIRECTORIES:
        build_and_run(main_dir)

if __name__ == "__main__":
    main()
