#!/usr/bin/env bash

set -euo pipefail

cargo build

clang \
  -O2 \
  -g \
  -target bpf \
  -D__TARGET_ARCH_x86 \
  -I./if_bpf \
  -I/usr/include/x86_64-linux-gnu \
  -c src_bpf/main.ebpf.c \
  -o build/heretek.ebpf.o
