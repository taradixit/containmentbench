import csv
import json
import tempfile
import unittest
from pathlib import Path

from run_benchmark import write_results


class ResultTests(unittest.TestCase):
    def test_results_include_runtime_and_policy_controls(self):
        summary = {
            "contained": {
                "scenarios": 1,
                "benign_task_success_rate": 100.0,
                "adversarial_violation_success_rate": None,
                "blocked_actions": 0,
                "invariant_violations": 0,
                "detection_rate": 100.0,
                "false_positive_count": 0,
                "commands_attempted": 1,
                "retries_after_block": 0,
                "execution_time_seconds": 0.1,
            }
        }
        policy = {
            "run_as_uid": 1234,
            "max_processes": 12,
            "max_cpu_seconds": 3,
            "max_memory_mb": 48,
        }
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory)
            write_results([], summary, results, {"kernel_version": "test"}, policy)
            document = json.loads((results / "summary.json").read_text(encoding="utf-8"))
            with (results / "summary.csv").open(encoding="utf-8") as csv_file:
                rows = list(csv.DictReader(csv_file))
            self.assertEqual(document["runtime"]["kernel_version"], "test")
            self.assertEqual(document["contained_controls"]["non_root_uid"], 1234)
            self.assertEqual(document["contained_controls"]["rlimit_address_space_mb"], 48)
            self.assertEqual(rows[0]["condition"], "contained")


if __name__ == "__main__":
    unittest.main()
