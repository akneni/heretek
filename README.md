# Heretek
- Heretek is a endpoint detection and response (EDR) solution for linux. It's primarily targeted towards desktop linux. 

## Architecture
- The core part of this is an ebpf program that pushed relevant syscalls to a per CPU ring buffer. 
- The second half of this is a user space daemon that will drain these buffers and analyze the raw data to detect malicious processes. 





## CLI 
### Main Loop
- The main loop for the daemon will be doing 4 things in sequence perpetually. 
    1) Drain the ring buffers and update it's internal pgraph structure with the events just pulled
    2) Run checks against the ACL to check for violations
    3) Check for IPC RPCs from CLI invocations of this tool (like `htek desc <pid>`)
    4) Sleep for an alloted amount of time. 

### Process Model
- We will think of all processes of having an ID of (pid, start_ktime). 