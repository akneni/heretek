import sys
import shutil
import time
import os
import subprocess
import json
from pathlib import Path

import unit_tests

# Required system dependencies
# Note, these are dependencies required by the testing code, deps required by heretek and
# the heretek build process are explicitly not included here so `make install_deps` gets
# tested as well
REQ_BINS = [
    "python3",
    "git",
    "make",
    "lscpu",
    "kill",
    "pgrep",
]

TARGETS = {
    "/root/HeretekTargets/read": "r----",
    "/root/HeretekTargets/write": "-w---",
    "/root/HeretekTargets/execute": "--x--",
    "/root/HeretekTargets/bind": "---b-",
    "/root/HeretekTargets/connect": "----c",
}


def preflight():
    if os.environ.get("USER", "") != "root":
        print("Must run tests as root")
        exit(1)

    status = subprocess.run(
        f"lscpu",
        stdout=subprocess.PIPE,
        shell=True,
        check=True,
    )

    lscpu_out = status.stdout.decode()

    if "hypervisor" not in lscpu_out.lower():
        print("Could not guarantee the current system is a VM, continue tests anyway?")
        print("WARNING: these tests may break your system")
        res = input("[y/N]: ")
        if res.lower().strip() != "y":
            exit(0)


def purge_htek():
    # Kill all htek processess
    subprocess.run(f"htek down", shell=True)
    time.sleep(1)
    subprocess.run(f"pgrep htek | xargs kill -9", shell=True)

    # remove all htek files
    shutil.rmtree("/usr/local/bin/heretek/")
    shutil.rmtree("/root/HtekTestWorkDir")
    shutil.rmtree("/root/HetkTestResults")
    shutil.rmtree("/root/HeretekTargets")


def git_install_heretek():
    workdir = Path("/root/HtekTestWorkDir")
    repo_dir = workdir / "heretek"
    sudo_user = os.environ.get("SUDO_USER")

    if repo_dir.exists():
        shutil.rmtree(repo_dir)

    workdir.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [
            "git",
            "clone",
            "--branch",
            "main",
            "--single-branch",
            "https://github.com/akneni/heretek.git",
            str(repo_dir),
        ],
        check=True,
    )

    subprocess.run(["make", "install_deps"], cwd=repo_dir, check=True)

    if sudo_user:
        subprocess.run(
            ["sudo", "-u", sudo_user, "make", "build"], cwd=repo_dir, check=True
        )
    else:
        subprocess.run(["make", "build"], cwd=repo_dir, check=True)

    subprocess.run(["make", "install"], cwd=repo_dir, check=True)


def setup_tst_env():
    """
    Creates all the target files listed in `TARGETS` and sets them to 0o777
    Modifies ACL.json file from the hretek to include the appropriate permissions for `TARGETS`
    """
    lscpu = shutil.which("lscpu")
    if lscpu is None:
        raise FileNotFoundError("Could not find required executable: lscpu")

    for target in TARGETS:
        target_path = Path(target)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        if target_path.name == "execute":
            shutil.copy2(lscpu, target_path)
        else:
            target_path.touch(exist_ok=True)

        os.chmod(target_path, 0o777)

    acl_path = Path("/usr/local/bin/heretek/config/ACL.json")
    with acl_path.open("r") as acl_file:
        acl = json.load(acl_file)

    hardened_profile = acl.setdefault("hardened", {})
    rules = hardened_profile.setdefault("rules", {})
    rules.update(TARGETS)

    with acl_path.open("w") as acl_file:
        json.dump(acl, acl_file, indent=2)
        acl_file.write("\n")


def spawn_htekd():
    subprocess.run(f"htek up", shell=True, check=True)


def run_all_tests():
    htek_dir = Path("/usr/local/bin/heretek")
    trace_path = htek_dir / "daemon_traces.log"
    results_dir = Path("/root/HetkTestResults")
    results_dir.mkdir(parents=True, exist_ok=True)

    seen_incidents = set(htek_dir.glob("*.incident"))
    seen_trace_lines = []
    if trace_path.exists():
        seen_trace_lines = trace_path.read_text(errors="replace").splitlines()

    def append_dif(test_name: str, msg: str):
        dif_path = results_dir / f"{test_name}.dif"
        with dif_path.open("a") as dif_file:
            dif_file.write(msg)
            if not msg.endswith("\n"):
                dif_file.write("\n")

    for name in unit_tests.alltests:
        subprocess.run([sys.executable, __file__, name], check=False)

        cf_path = results_dir / f"{name}.cf"
        if cf_path.exists():
            append_dif(
                name,
                f"{cf_path} was created; the process was not killed when it should have been.\n",
            )

        current_incidents = set(htek_dir.glob("*.incident"))
        new_incidents = sorted(current_incidents - seen_incidents)
        seen_incidents = current_incidents

        if new_incidents:
            incident_msg = "New incident files were created:\n"
            for incident in new_incidents:
                incident_msg += f"\n--- {incident} ---\n"
                incident_msg += incident.read_text(errors="replace")
                if not incident_msg.endswith("\n"):
                    incident_msg += "\n"
            append_dif(name, incident_msg)

        current_trace_lines = []
        if trace_path.exists():
            current_trace_lines = trace_path.read_text(errors="replace").splitlines()

        new_trace_lines = current_trace_lines[len(seen_trace_lines) :]
        seen_trace_lines = current_trace_lines
        new_errors = [line for line in new_trace_lines if "ERROR" in line]

        if new_errors:
            append_dif(
                name,
                "New ERROR level trace messages were generated:\n"
                + "\n".join(new_errors)
                + "\n",
            )

        htek_status = subprocess.run(
            ["pgrep", "htek"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if htek_status.returncode != 0:
            append_dif(name, "htek is not running after this test.\n")
            sys.exit(1)


def exec_test(test: str):
    target_dir = "/root/HeretekTargets"
    results_dir = "/root/HetkTestResults"
    ttfc = 100  # Time (ms) to wait to create the <test>.fc file

    unit_tests.alltests[test](target_dir, results_dir, ttfc)


def main():
    if len(sys.argv) > 1:
        target_test = sys.argv[1]
        exec_test(target_test)
    else:
        preflight()
        purge_htek()

        git_install_heretek()

        setup_tst_env()

        spawn_htekd()

        time.sleep(1)
        run_all_tests()


if __name__ == "__main__":
    main()
