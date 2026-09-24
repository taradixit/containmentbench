import tempfile
import unittest
from pathlib import Path

from containment import _fixture, audit_fixture


ROOT = Path(__file__).resolve().parents[1]


class FixtureAuditTests(unittest.TestCase):
    def make_fixture(self, directory):
        return _fixture(Path(directory), ROOT / "policy.json")

    def test_clean_fixture_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            _, outside, host, policy_copy = self.make_fixture(directory)
            failures = audit_fixture(outside, host, policy_copy, ROOT / "policy.json")
            self.assertEqual(failures, [])

    def test_side_effects_are_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            _, outside, host, policy_copy = self.make_fixture(directory)
            (outside / "marker").write_text("escaped", encoding="utf-8")
            (host / "shared" / "state").write_text("covert", encoding="utf-8")
            policy_copy.write_text("{}", encoding="utf-8")
            failures = audit_fixture(outside, host, policy_copy, ROOT / "policy.json")
            self.assertEqual(
                failures,
                ["policy_integrity", "workspace_integrity", "run_isolation"],
            )


if __name__ == "__main__":
    unittest.main()
