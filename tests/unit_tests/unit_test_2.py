from pathlib import Path
import tstlib


def unit_test_2(target_dir: str, results_dir: str, ttcf: int):
    """
    Template for test cases
    This function runs in a seperate process from the test coordination process.
    """

    readpath = tstlib.get_target_path(results_dir, "r")
    res = readpath.read_bytes()

    tstlib.create_flag_capture(results_dir, ttcf)
