# Heretek
- Heretek is a endpoint detection and response (EDR) solution for linux. It's primarily targeted towards desktop linux. 

## Architecture
- The core part of this is an ebpf program that pushed relevant syscalls to a per CPU ring buffer. 
- The second half of this is a user space daemon that will drain these buffers and analyze the raw data to detect malicious processes. 

