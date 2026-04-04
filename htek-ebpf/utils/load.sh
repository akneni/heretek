#!/usr/bin/env bash

set -euo pipefail

readonly PROG_PIN_DIR="/sys/fs/bpf/heretek"
readonly MAP_PIN_DIR="/sys/fs/bpf/heretek-maps"

sudo bash -lc "
set -euo pipefail
ulimit -l unlimited
mkdir -p '${PROG_PIN_DIR}' '${MAP_PIN_DIR}'
bpftool prog loadall build/heretek.ebpf.o '${PROG_PIN_DIR}' pinmaps '${MAP_PIN_DIR}' autoattach
"
