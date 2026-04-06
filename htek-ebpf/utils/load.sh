#!/usr/bin/env bash

set -euo pipefail

readonly PROG_PIN_DIR="/sys/fs/bpf/heretek"
readonly MAP_PIN_DIR="/sys/fs/bpf/heretek-maps"

sudo bash -lc "
set -euo pipefail
ulimit -l unlimited
if [ -w /proc/sys/kernel/perf_event_paranoid ]; then
  echo -1 > /proc/sys/kernel/perf_event_paranoid || true
fi
mkdir -p '${PROG_PIN_DIR}' '${MAP_PIN_DIR}'
if command -v capsh >/dev/null 2>&1; then
  capsh \
    --caps='cap_perfmon,cap_bpf,cap_sys_admin,cap_ipc_lock=eip' \
    --keep=1 \
    --addamb=cap_perfmon,cap_bpf,cap_sys_admin,cap_ipc_lock \
    -- -c \"bpftool prog loadall build/heretek.ebpf.o '${PROG_PIN_DIR}' pinmaps '${MAP_PIN_DIR}' autoattach\"
else
  bpftool prog loadall build/heretek.ebpf.o '${PROG_PIN_DIR}' pinmaps '${MAP_PIN_DIR}' autoattach
fi
"
