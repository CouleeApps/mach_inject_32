import os
import subprocess

# Xcode provides us this environment variable with the root directory of the project
project_dir = os.environ["PROJECT_DIR"]
proc1 = subprocess.run(["scc", "--platform", "mac", "--arch", "x86", project_dir+"/mach_inject_32/shellcode.c", "--stdout"], stdout=subprocess.PIPE)
proc2 = subprocess.run(["scc", "--platform", "mac", "--arch", "x86", project_dir+"/mach_inject_32/shellcode2.c", "--stdout"], stdout=subprocess.PIPE)

# Pad shellcodes with interrupts, just in case
proc1_output = proc1.stdout
proc1_output = proc1_output.ljust((len(proc1_output) + 0xf) & ~0xf, b'\xcc')
proc2_output = proc2.stdout
proc2_output = proc2_output.ljust((len(proc2_output) + 0xf) & ~0xf, b'\xcc')

# Combine shellcode into a C-style array
shellcodes = proc1_output + proc2_output
formatted = "unsigned char shellcode[] = {" + ", ".join("0x{:02X}".format(b) for b in shellcodes) + "};\n"

# Page align
code_size = len(shellcodes) + 0x100
code_size = (code_size + 0xfff) & ~0xfff

# Write to a C header file for main.m to include
with open(project_dir + "/mach_inject_32/shellcode.h", "w") as f:
	f.write(formatted)
	f.write("uint32_t sc1_length = 0x{:x};\n".format(len(proc1_output)))
	f.write("#define CODE_SIZE 0x{:x}\n".format(code_size))
