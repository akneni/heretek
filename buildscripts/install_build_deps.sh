#!/usr/bin/env bash

set -euo pipefail

if [[ ${EUID} -eq 0 ]]; then
    SUDO=()
elif command -v sudo >/dev/null 2>&1; then
    SUDO=(sudo)
else
    echo "Error: sudo is required to install system packages." >&2
    exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
    "${SUDO[@]}" apt-get update
    "${SUDO[@]}" apt-get install -y \
        ca-certificates \
        clang \
        curl \
        gcc \
        libbpf-dev \
        llvm \
        make \
        "linux-headers-$(uname -r)"
elif command -v pacman >/dev/null 2>&1; then
    "${SUDO[@]}" pacman -S --needed --noconfirm \
        bpf \
        clang \
        curl \
        gcc \
        libbpf \
        linux-headers \
        llvm \
        make
else
    echo "Error: unsupported package manager. Expected apt or pacman." >&2
    exit 1
fi

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
