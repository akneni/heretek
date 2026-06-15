#!/usr/bin/env python3
"""Build all Heretek artifacts into the repository build directory."""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List

REPO_ROOT = Path.cwd()
BUILD_DIR = REPO_ROOT / "build"
DAEMON_DIR = REPO_ROOT / "htek_daemon"


def run(command: List[str], cwd=REPO_ROOT):
    print("+ {}".format(" ".join(command)), flush=True)
    subprocess.run(command, cwd=str(cwd), check=True)


def require_command(command: str):
    if shutil.which(command) is None:
        raise RuntimeError(
            "Required build command is not installed: {}".format(command)
        )


def cpy_to_build(source: Path):
    if not source.is_file():
        raise RuntimeError("Expected build artifact was not created: {}".format(source))

    destination = BUILD_DIR / source.name
    shutil.copy2(str(source), str(destination))

    if source.stat().st_size != destination.stat().st_size:
        raise RuntimeError(
            "Copied artifact length does not match source: {}".format(source)
        )

    return destination


def build_daemon(profile):
    command = [
        "cargo",
        "build",
    ]
    if profile == "release":
        command.append("--release")

    run(command, cwd=DAEMON_DIR)

    bin_path = REPO_ROOT / "target" / profile / "htekd"
    return cpy_to_build(bin_path)


def build_ebpf():
    machine = platform.machine().lower()
    if machine not in ("x86_64", "amd64"):
        raise RuntimeError(
            "The eBPF build currently supports x86_64 only, not {}".format(machine)
        )

    destination = (BUILD_DIR / "heretek.ebpf.o").absolute()

    command = [
        "clang",
        "-O2",
        "-g",
        "-target",
        "bpf",
        "-D__TARGET_ARCH_x86",
        "-I./if_bpf",
    ]

    multiarch_include = Path("/usr/include/x86_64-linux-gnu")
    if multiarch_include.is_dir():
        command.append("-I{}".format(multiarch_include))

    command.extend(
        [
            "-c",
            "src_bpf/main.ebpf.c",
            "-o",
            str(destination),
        ]
    )

    run(command, cwd=DAEMON_DIR)

    return destination


def build_cli(profile):
    command = [
        "cargo",
        "build",
    ]
    if profile == "release":
        command.append("--release")

    run(command, cwd=(REPO_ROOT / "htek_cli"))

    bin_path = REPO_ROOT / "target" / profile / "htek"
    return cpy_to_build(bin_path)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Build htek, htekd, and the Heretek eBPF object."
    )
    parser.add_argument(
        "--profile",
        choices=("debug", "release"),
        default="release",
        help="Rust build profile (default: release)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        require_command("cargo")
        require_command("clang")
        BUILD_DIR.mkdir(parents=True, exist_ok=True)

        artifacts = [
            build_daemon(args.profile),
            build_ebpf(),
            build_cli(args.profile),
        ]
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print("build failed: {}".format(error), file=sys.stderr)
        return 1

    print("\nBuilt artifacts:")
    for artifact in artifacts:
        print("  {}".format(artifact.relative_to(REPO_ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
