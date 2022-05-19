#!/usr/bin/python3

import os
import math
import subprocess
from typing import List

PATH_TO_BENCHMARK = "/janus_project/comet_benchmark/"

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

MAIN_DIR_TO_MAIN_PARAMS = {
    "con_comps": ["N"],
    "expr_evaluator": ["N", "filename"],
    "file_system_interaction": ["N"],
    "matrix_mult": ["N"],
    "merge_sort": ["N"],
    "pi_approximation": ["N"],
    "prime_numbers": ["N"],
    "vector": ["N"]
}


N_START = 2 * int(1e5)
N_END = 1 + 2 * int(1e6)
N_STEP = 2 * int(1e5)

PARAM_TO_RANGES = {
    "N": list(i for i in range(N_START, N_END, N_STEP)),
    "filename": list(
        f'"/janus_project/comet_evaluator/expr_input/{i}_expr.txt"'
        for i in range(N_START, N_END, N_STEP)
    ),
}

PARAM_TO_DECL = {
    "N": "const int N = ",
    "filename": "const char *filename = "
}

MAIN_DIR_TO_MAIN_PARAM_RANGES = {} # TODO

def generate_src_file(main_dir: str, src_path: str, template_file: str, param_vals: int) -> str:
    new_file_content = ""
    params = MAIN_DIR_TO_MAIN_PARAMS[main_dir]

    if len(param_vals) > 1:
        print(f"Param vals are: {param_vals}")

    with open(src_path + template_file, "r") as f:
        for line in f:
            replaced_line = False
            for param, param_val in zip(params, param_vals):
                param_decl = PARAM_TO_DECL[param]

                # N Must be sqrt for matrix multiplication
                if main_dir == "matrix_mult" and param == "N":
                    param_val = int(math.sqrt(param_val)) + 1
                
                if param_decl in line:
                    new_line = f"{param_decl}{param_val};\n"
                    if "filename" in new_line:
                        print(f"NEW LINE: {new_line}")
                    new_file_content += new_line
                    replaced_line = True
            if not replaced_line: 
                new_file_content += line

    print(params, param_vals)

    N_val = list(v for p, v in zip(params, param_vals) if p == "N")[0]
    new_file_name = f"_generated_{N_val}_{main_dir}.cpp"
    print(f"Generating {new_file_name}")
    with open(src_path + new_file_name, "w") as f:
        f.write(new_file_content)

    return new_file_name

def generate_src_files(main_dir: str, src_path: str, template_file: str) -> List[str]:
    curr_path = PATH_TO_BENCHMARK + main_dir

    params = MAIN_DIR_TO_MAIN_PARAMS[main_dir]
    param_vals = []
    for param in params:
        param_vals.append(PARAM_TO_RANGES[param])

    # Param_vals is a list of lists (usually 1 x 20 but 2 x 20 for expr_evaluator)
    

    if len(param_vals) > 1:
        assert len(param_vals[0]) == len(param_vals[1])

    NUM_TESTS = len(param_vals[0])

    generated_file_names = []
    for num_test in range(NUM_TESTS):
        curr_param_vals = []
        for i in range(len(params)):
            curr_param_vals.append(param_vals[i][num_test])

        generated_file_names.append(
            generate_src_file(main_dir, src_path, template_file, curr_param_vals)
        )

    return generated_file_names


def compile_src_file(main_dir: str, src_file_name: str) -> None:
    curr_path = PATH_TO_BENCHMARK + main_dir
    src_path = curr_path + "/src/"
    bin_path = curr_path + "/bin/"

    src_file_path = src_path + src_file_name
    bin_file_path = bin_path + src_file_name.split(".")[0] # Remove ".cpp"

    print(f"Compiling {src_file_path} to {bin_file_path}")

    compile_command = f"g++ -no-pie -o {bin_file_path} {src_file_path}".split()

    print(f"Compile command: {compile_command}")
    cp = subprocess.run(compile_command)
    cp.check_returncode()


def compile_src_files(main_dir: str, src_file_names: List[str]) -> None:
    for src_file_name in src_file_names:
        compile_src_file(main_dir, src_file_name)


def process_main_dir(main_dir: str) -> None:
    curr_path = PATH_TO_BENCHMARK + main_dir
    src_path = curr_path + "/src/"

    src_files = os.listdir(src_path)
    src_files = [src_file for src_file in src_files if src_file.endswith(".cpp") and not src_file.startswith("_")]
    if not src_files[0].endswith(".cpp"):
        raise RuntimeError(f"Can't find template file for dir {main_dir}")

    template_file = src_files[0]

    src_file_names = generate_src_files(main_dir, src_path, template_file)

    compile_src_files(main_dir, src_file_names)



def main():
    for main_dir in MAIN_DIRECTORIES:
        process_main_dir(main_dir)

if __name__ == "__main__":
    main()