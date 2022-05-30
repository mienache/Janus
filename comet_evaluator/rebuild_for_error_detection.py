#!/usr/bin/python3

import os
import subprocess
from timeit import default_timer as timer
import sys

MAIN_DIR = sys.argv[1]

WITH_ERROR_DETECTION = int(sys.argv[2])

MAIN_DIR_TO_MAIN_CNT = {
    "con_comps": 48,
    "expr_evaluator": 60,
    "file_system_interaction": 40,
    "matrix_mult": 45,
    "merge_sort": 214,
    "pi_approximation": 44,
    "prime_numbers": 59,
    "vector": 120,
}

MAIN_DIR_TO_CHECKER_CNT = {
    "con_comps": 27,
    "expr_evaluator": 39,
    "file_system_interaction": 19,
    "matrix_mult": 24,
    "merge_sort": 193,
    "pi_approximation": 23,
    "prime_numbers": 38,
    "vector": 76,
}

JANUS_PROJECT_PATH = "/janus_project/"
DSL_ERROR_INSERTION_CPP_PATH = "/janus_project/dynamic/dsl/dsl_error_insertion.cpp"
DSL_CORE_CPP_PATH = "/janus_project/dynamic/dsl/dsl_core.cpp"


def update_dsl_error_insertion_file() -> None:
    print(f"Updating dsl_error_insertion.cpp")
    new_file_content = ""
    bb_cnt_decls = [
        f"const int EXPECTED_MAIN_BB_CNT",
        f"const int EXPECTED_CHECKER_BB_CNT",
    ]

    with open(DSL_ERROR_INSERTION_CPP_PATH) as error_insertion_file:
        for line in error_insertion_file:
            new_line = line
            for bb_cnt_decl in bb_cnt_decls:
                if bb_cnt_decl in line:
                    if "MAIN" in bb_cnt_decl:
                        new_line = f"{bb_cnt_decl} = {MAIN_DIR_TO_MAIN_CNT[MAIN_DIR]};\n"
                    elif "CHECKER" in bb_cnt_decl:
                        new_line = f"{bb_cnt_decl} = {MAIN_DIR_TO_CHECKER_CNT[MAIN_DIR]};\n"

            new_file_content += new_line

    with open(DSL_ERROR_INSERTION_CPP_PATH, "w") as error_insertion_file:
        error_insertion_file.write(new_file_content)

    print(f"File updated")

def update_dsl_core_file() -> None:
    print(f"Updating dsl_core.cpp")
    new_file_content = ""
    call_rule_handler_decl = "call_rule_handler"

    with open(DSL_CORE_CPP_PATH) as core_file:
        for line in core_file:
            new_line = line
            if call_rule_handler_decl in line and ";" not in line:
                new_line += "    return;\n"

            new_file_content += new_line

    with open(DSL_CORE_CPP_PATH, "w") as core_file:
        core_file.write(new_file_content)

    print(f"File updated")
    
        
def build_janus():
    cwd = os.getcwd()

    os.chdir(JANUS_PROJECT_PATH)
    build_command = "./run_make"
    subprocess.run(build_command)

    os.chdir(cwd)

    print(f"Back to {os.getcwd()}")


def main():
    update_dsl_error_insertion_file()
    if not WITH_ERROR_DETECTION:
        update_dsl_core_file()
    build_janus()

if __name__ == "__main__":
    main()