#!/usr/bin/python3

import subprocess
import sys


# QUEUE_SIZES = [i for i in range(int(1e6) + int(1e5), 2 * int(1e6) + 1, int(1e5))] # This will be multiplied by 2 in Janus

QUEUE_SIZES = [
    # 65024,
    # 130560,
    # 196096,
    # 261632,
    # 327168,
    # 392704,
    # 458240,
    # 523776,
    # 589312,
    # 654848,
    # 720384,
    # 785920,
    # 851456,
    # 916992,
    # 982528,
    # 1048064,
    # 1113600,
    # 1179136,
    # 1244672,
    # 1310208,
    1375744,
    # 1441280,
    # 1506816,
    # 1572352,
    # 1637888,
    # 1703424,
    # 1768960,
    # 1834496,
    # 1900032,
    # 1965568
]

OPTIMISATIONS_LEVELS = [0]

# OPTIMISATIONS_LEVELS = [0, 1, 2, 3]
NUM_ITERATIONS = 1

def opt_level_as_str(opt_level: int) -> str:
    if opt_level == -1:
        return "NO-COMET"

    return f"O{opt_level}"

def build_and_run(queue_size: int, opt_level: int):
    print(f"Building for {queue_size=}, {opt_level=}")
    rebuild_command = f"./rebuild.py {queue_size} {opt_level}".split()
    cp = subprocess.run(rebuild_command)
    cp.check_returncode()

    print(f"Running tests for {queue_size=}, {opt_level=}")
    run_tests_command = f"./run_tests.py {queue_size} {opt_level_as_str(opt_level)} {NUM_ITERATIONS}".split()
    cp = subprocess.run(run_tests_command)
    cp.check_returncode()



def main():
    for queue_size in QUEUE_SIZES:
        for opt_level in OPTIMISATIONS_LEVELS:
            build_and_run(queue_size, opt_level)

if __name__ == "__main__":
    main()
