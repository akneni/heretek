import time
from pathlib import Path


def get_target_path(target_path: str, atype: str) -> Path:
    map = {
        "r": "read",
        "w": "write",
        "x": "execute",
        "b": "bind",
        "c": "connect",
    }
    return Path(target_path) / map[atype]


def create_flag_capture(results_dir: str, ttcf: float, context=None):
    filename = __file__
    filename = filename[:-3] + ".diff"
    filepath = Path(results_dir) / filename

    time.sleep(ttcf)
    filepath.write_text(f"Capture file created. (ttcf = {ttcf})\n\n{context}")


def create_dif(results_dir: str, context=None):
    filename = __file__
    filename = filename[:-3] + ".diff"
    filepath = Path(results_dir) / filename

    filepath.write_text(f"Context:\n\n{context}")
