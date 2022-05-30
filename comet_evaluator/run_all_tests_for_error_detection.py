#!/usr/bin/python3

import subprocess

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

NUM_ITERATIONS = 110

def build_and_run(main_dir: str, with_error_detection: int) -> None:
    print(f"Building for {main_dir=}")
    rebuild_command = f"./rebuild_for_error_detection.py {main_dir} {with_error_detection}".split()
    cp = subprocess.run(rebuild_command)
    cp.check_returncode()

    print(f"Running tests for {main_dir=}, {with_error_detection=}")
    run_tests_command = f"./run_tests_for_error_detection.py {main_dir} {with_error_detection} {NUM_ITERATIONS}".split()
    cp = subprocess.run(run_tests_command)
    cp.check_returncode()



def main():
    for with_error_detection in [0]:
        for main_dir in MAIN_DIRECTORIES:
            build_and_run(main_dir, with_error_detection)

if __name__ == "__main__":
    main()
