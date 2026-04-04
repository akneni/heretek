#!/usr/bin/env bash

set -euo pipefail

readonly PROG_PIN_DIR="/sys/fs/bpf/heretek"
readonly MAP_PIN_DIR="/sys/fs/bpf/heretek-maps"

sudo bash -lc "
set -euo pipefail
rm -f '${PROG_PIN_DIR}'/* || true
rm -f '${MAP_PIN_DIR}'/* || true
rmdir '${PROG_PIN_DIR}' || true
rmdir '${MAP_PIN_DIR}' || true
"
