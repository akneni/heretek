#!/usr/bin/env bash

set -euo pipefail

mkdir -p build

clang \
  -O2 \
  -g \
  -target bpf \
  -D__TARGET_ARCH_x86 \
  -I./if \
  -I/usr/include/x86_64-linux-gnu \
  -c src/main.ebpf.c \
  -o build/heretek.ebpf.o
