# Heretek
- Heretek is an endpoint detection and response (EDR) solution for linux. It's primarily targeted towards desktop linux. 

## About

## Install && Setup
- In order to build from source, do the following. 
```bash 
git clone https://github.com/akneni/heretek.git
cd heretek 
sudo make install_deps
make build
sudo make install
```
- Providing prebuild binaries (and publishing to each distro's package manager) is still a WIP.

## Usage
- To start the service, run the following. 
```
sudo htek up
```



## Architecture
- The core part of this is an ebpf program that pushed relevant syscalls to a per CPU ring buffer. 
- The second half of this is a user space daemon that will drain these buffers and analyze the raw data to detect malicious processes. 

## Userspace Layout
- `htek_cli` builds the `htek` command-line client.
- `htek_daemon` builds the `htekd` daemon and owns the eBPF, detection, process graph, response, and tracing code.
- `htek_lib` contains the configuration and RPC code shared by both binaries.

## CLI
### Main Loop
- The main loop for the daemon will be doing 4 things in sequence perpetually. 
    1) Drain the ring buffers and update it's internal pgraph structure with the events just pulled
    2) Run checks against the ACL to check for violations
    3) Check for IPC RPCs from CLI invocations of this tool (like `htek summary <pid>`)
    4) Sleep for an alloted amount of time. 

### Process Model
- We will think of all processes of having an ID of (pid, start_ktime). 

### Docs
- We can start the daemon by doing the following. 
```bash
# Need to be root. This loads the eBPF objects and starts htekd.
htek up
```

- The daemon can also be run directly after the eBPF objects are loaded:
```bash
sudo htekd
```

- We can query a processes summary by doing the following
```bash
htek summary <pid | executable_path>
```
