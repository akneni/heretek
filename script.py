import os
import time

print(os.getpid())
z = input("block: ")

# 1. Full path to the executable file
path = "/bin/ls"

# 2. List of arguments (The first must be the program name by convention)
args = ["ls", "-l", "/tmp"]

# 3. Dictionary of environment variables
env = os.environ  # Use current environment or create a custom dict

# This replaces the current Python process with 'ls'
os.execve(path, args, env)
