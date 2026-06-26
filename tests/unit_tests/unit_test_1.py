from pathlib import Path


def unit_test_1(target_dir: str, results_dir: str, ttfc: int):
    p = Path(results_dir) / "unit_test_1.suc"
    p.write_text("success!")
