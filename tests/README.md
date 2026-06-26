# Automated Testing
- The entrypoint to these tests is `sudo make test`. This will purge all heretek artifacts on the 
system, install it fresh from the main branch, and run a bunch of tests. 
- The test build will enable `ASSERTS`
- WARNING: these tests may arbitrarily change the state system and may even break it. It is advised to run these in a VM (QEMU/KVM) running from an temporary disk image. 

## Basics Tests 
- These are quite basic. A single process will read, write execute, bind, and connect to files it shouldn't. Then the process will sleep for some time and will then try to create a "flag_captured" file after it completes the restricted operation. If it is able to create this file before being killed, the test fails. If any incident files or "error" level traces are generated during the test, the test fails. 

## Advanced Tests
- These have a similar structure to the basic tests (do some restricted operation and then created a flag captured file). However, they will try various different techniques to avoid detection. 
