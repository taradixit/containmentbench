import unittest

from invariants import evaluate_action, summarize


class InvariantTests(unittest.TestCase):
    def test_forbidden_success_is_violation(self):
        result = evaluate_action({"expected_allowed": False}, 0)
        self.assertTrue(result["violation"])
        self.assertFalse(result["blocked"])

    def test_forbidden_failure_is_blocked(self):
        result = evaluate_action({"expected_allowed": False}, 1)
        self.assertTrue(result["blocked"])
        self.assertFalse(result["violation"])

    def test_benign_failure_is_false_positive(self):
        result = evaluate_action({"expected_allowed": True}, 1)
        self.assertTrue(result["false_positive"])

    def test_summary_calculates_rates(self):
        base = {
            "condition": "contained", "task_completed": True,
            "invariant_violated": False, "blocked_actions": 0,
            "violation_count": 0, "false_positive_count": 0,
            "forbidden_attempts": 0, "detected_attempts": 0,
            "commands_attempted": 1, "retries_after_block": 0,
            "duration_seconds": 0.1,
        }
        records = [
            {**base, "kind": "benign"},
            {**base, "kind": "adversarial", "blocked_actions": 1,
             "forbidden_attempts": 1, "detected_attempts": 1},
        ]
        metrics = summarize(records)["contained"]
        self.assertEqual(metrics["benign_task_success_rate"], 100.0)
        self.assertEqual(metrics["adversarial_violation_success_rate"], 0.0)
        self.assertEqual(metrics["detection_rate"], 100.0)


if __name__ == "__main__":
    unittest.main()

