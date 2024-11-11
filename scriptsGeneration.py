import os
import subprocess

# Directory to store generated C scripts and executables
output_dir = "generated_syscall_scripts"
os.makedirs(output_dir, exist_ok=True)

# Path to your header file containing all syscall functions
header_file = "syscalls.h"

# Sample GAN outputs with sets of syscalls to use
gan_outputs = [
    ["read", "write", "getpid"],
    ["open", "close", "fork"],
    ["getpid", "fork", "write"]
    # Add more sets of syscalls from GAN output here
]

# Template for the C program structure
c_program_template = """\
#include <stdio.h>
#include "{header_file}"

int main() {{
{syscalls_code}
    return 0;
}}
"""

def generate_c_code(syscall_list, script_name):
    # Generate code to call each syscall function
    syscalls_code = ""
    for syscall in syscall_list:
        function_call = f"    template_{syscall}();\n"
        syscalls_code += function_call

    # Format the full C program by including the header and syscall code
    c_code = c_program_template.format(header_file=header_file, syscalls_code=syscalls_code)

    # Write the generated C code to a file
    c_file_path = os.path.join(output_dir, f"{script_name}.c")
    with open(c_file_path, "w") as c_file:
        c_file.write(c_code)
    print(f"Generated C code file: {c_file_path}")
    return c_file_path

def compile_c_code(c_file_path):
    # Compile the C file into an executable
    executable_path = c_file_path.replace(".c", "")
    compile_cmd = ["gcc", c_file_path, "-o", executable_path]
    try:
        subprocess.run(compile_cmd, check=True)
        print(f"Compiled {c_file_path} to {executable_path}")
        return executable_path
    except subprocess.CalledProcessError:
        print(f"Compilation failed for {c_file_path}")
        return None

def run_executable(executable_path):
    # Run the compiled executable and capture output
    try:
        result = subprocess.run([executable_path], capture_output=True, text=True)
        print(f"Execution output:\n{result.stdout}")
        print(f"Execution errors:\n{result.stderr}")
    except Exception as e:
        print(f"Execution failed for {executable_path}: {e}")

# Main process: generate, compile, and run each set of syscalls from GAN output
for idx, syscall_set in enumerate(gan_outputs):
    script_name = f"syscall_script_{idx + 1}"
    # Step 1: Generate C code
    c_file_path = generate_c_code(syscall_set, script_name)
    # Step 2: Compile the generated C code
    # if c_file_path:
    #     executable_path = compile_c_code(c_file_path)
        # Step 3: Run the executable if compilation was successful
        # if executable_path:
        #     run_executable(executable_path)