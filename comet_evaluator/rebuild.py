#!/usr/bin/python3

import os
import subprocess
from timeit import default_timer as timer
import sys


JANUS_PROJECT_PATH = "/janus_project/"
DSL_IPC_CPP_PATH = "/janus_project/dynamic/dsl/dsl_ipc.cpp"
DSL_CORE_CPP_PATH = "/janus_project/dynamic/dsl/dsl_core.cpp"


QUEUE_SIZE = int(sys.argv[1])
OPT_LEVEL = int(sys.argv[2]) # OPT_LEVEL -1 is "NO-COMET"

def update_dsl_core_file():
    new_file_content = ""

    print(f"Updating for NO-COMET")

    prev_line_is_bb_handler_def = None
    with open(DSL_CORE_CPP_PATH) as core_file:
        for line in core_file:
            if prev_line_is_bb_handler_def:
                print(f"---{line}")
                assert "{" in line # Must be at the beginning of the BB event handler
                new_line = "    return;\n"
            else:
                new_line = None

            if "event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)" in line and ";" not in line:
                prev_line_is_bb_handler_def = True
            else:
                prev_line_is_bb_handler_def = False
            
            new_file_content += line
            if new_line:
                new_file_content += new_line

    with open(DSL_CORE_CPP_PATH, "w") as ipc_file:
        ipc_file.write(new_file_content)

    print(f"File updated")


def update_dsl_ipc_file(queue_size: int, opt_level: int) -> None:
    new_file_content = ""
    opt_decls = [
        "bool REG_PROM_OPT",
        "bool OFFSET_FUSION_OPT",
        "bool DYNAMIC_OFFSET_OPT"
    ]

    queue_decl = "const int DEFAULT_QUEUE_SIZE"

    print(f"Updating file with {opt_level=}")

    with open(DSL_IPC_CPP_PATH) as ipc_file:
        for line in ipc_file:
            curr_opt = "1" if opt_level > 0 else "0"

            new_line = line
            for opt_decl in opt_decls:
                if opt_decl in line:
                    new_line = f"{opt_decl} = {curr_opt};\n"
                    opt_level -= 1
                    break

            if queue_decl in line and not line.startswith("//"):
                new_line = f"{queue_decl} = {queue_size};\n"

            new_file_content += new_line

    with open(DSL_IPC_CPP_PATH, "w") as ipc_file:
        ipc_file.write(new_file_content)

    print(f"File updated")
    
        
def build_janus():
    cwd = os.getcwd()

    os.chdir(JANUS_PROJECT_PATH)
    build_command = "./run_make"
    subprocess.run(build_command)

    os.chdir(cwd)

    print(f"Back to {os.getcwd()}")


def main():
    if OPT_LEVEL == -1:
        update_dsl_core_file()
    else:
        update_dsl_ipc_file(QUEUE_SIZE, OPT_LEVEL)
    build_janus()

if __name__ == "__main__":
    main()