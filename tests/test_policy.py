import tempfile
import unittest
from pathlib import Path

from policy import load_policy, read_is_allowed, validate_policy, write_is_allowed


ROOT = Path(__file__).resolve().parents[1]


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy(ROOT / "policy.json")

    def test_policy_has_required_fields(self):
        self.assertEqual(self.policy["run_as_uid"], 65534)
        self.assertIn("/workspace", self.policy["allowed_write_paths"])

    def test_workspace_write_is_allowed(self):
        self.assertTrue(write_is_allowed("/workspace/result.txt", self.policy))

    def test_prefix_confusion_is_blocked(self):
        self.assertFalse(write_is_allowed("/workspace-escape/result.txt", self.policy))

    def test_parent_traversal_is_blocked(self):
        self.assertFalse(write_is_allowed("/workspace/../outside/result.txt", self.policy))

    def test_secret_read_is_forbidden(self):
        self.assertFalse(read_is_allowed("/host/secret.txt", self.policy))

    def test_missing_policy_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_policy(path)

    def test_invalid_limit_is_rejected(self):
        invalid = dict(self.policy)
        invalid["max_memory_mb"] = "64"
        with self.assertRaisesRegex(ValueError, "max_memory_mb"):
            validate_policy(invalid)

    def test_root_uid_is_rejected(self):
        invalid = dict(self.policy)
        invalid["run_as_uid"] = 0
        with self.assertRaisesRegex(ValueError, "non-root"):
            validate_policy(invalid)

    def test_relative_policy_path_is_rejected(self):
        invalid = dict(self.policy)
        invalid["allowed_write_paths"] = ["workspace"]
        with self.assertRaisesRegex(ValueError, "absolute"):
            validate_policy(invalid)

    def test_disabled_network_rejects_targets(self):
        invalid = dict(self.policy)
        invalid["network_allowed"] = False
        with self.assertRaisesRegex(ValueError, "must be empty"):
            validate_policy(invalid)


if __name__ == "__main__":
    unittest.main()
