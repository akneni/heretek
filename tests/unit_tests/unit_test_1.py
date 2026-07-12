from pathlib import Path
import tstlib


def unit_test_1(target_dir: str, results_dir: str, ttcf: int):
    """
    Template for test cases
    This function runs in a seperate process from the test coordination process.
    """

    # test case here

    tstlib.create_flag_capture(results_dir, ttcf)
