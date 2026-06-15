#!/usr/bin/env bash

set -euo pipefail

readonly REQUIRED_COMMAND="bpftool"

if command -v "${REQUIRED_COMMAND}" >/dev/null 2>&1; then
  printf '%s is already installed at %s\n' \
    "${REQUIRED_COMMAND}" \
    "$(command -v "${REQUIRED_COMMAND}")"
  exit 0
fi

if ((EUID == 0)); then
  ROOT=()
elif command -v sudo >/dev/null 2>&1; then
  ROOT=(sudo)
else
  echo "Root privileges are required. Run this script as root or install sudo." >&2
  exit 1
fi

install_with_apt() {
  "${ROOT[@]}" apt-get update

  if apt-cache show bpftool >/dev/null 2>&1; then
    "${ROOT[@]}" apt-get install --yes bpftool
    return
  fi

  # Ubuntu packages bpftool with its kernel-specific linux-tools package.
  local kernel_tools="linux-tools-$(uname -r)"
  if apt-cache show "${kernel_tools}" >/dev/null 2>&1; then
    "${ROOT[@]}" apt-get install --yes linux-tools-common "${kernel_tools}"
    return
  fi

  echo "Could not find a package providing bpftool in the configured apt repositories." >&2
  echo "Tried: bpftool and ${kernel_tools}" >&2
  exit 1
}

install_with_pacman() {
  # On Arch Linux, bpftool is provided by the bpf package.
  "${ROOT[@]}" pacman --sync --needed --noconfirm bpf
}

if command -v apt-get >/dev/null 2>&1; then
  install_with_apt
elif command -v pacman >/dev/null 2>&1; then
  install_with_pacman
else
  echo "Unsupported package manager. Heretek currently supports apt and pacman." >&2
  exit 1
fi

if ! command -v "${REQUIRED_COMMAND}" >/dev/null 2>&1; then
  echo "Installation completed, but bpftool is not available on PATH." >&2
  exit 1
fi

printf 'Installed %s at %s\n' \
  "${REQUIRED_COMMAND}" \
  "$(command -v "${REQUIRED_COMMAND}")"
