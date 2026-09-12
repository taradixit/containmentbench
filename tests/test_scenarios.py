import json
import unittest
from pathlib import Path

from containment import load_scenarios
from invariants import INVARIANT_NAMES


ROOT = Path(__file__).resolve().parents[1]


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.scenarios = load_scenarios(ROOT / "scenarios")

    def test_scenario_count_and_mix(self):
        self.assertEqual(len(self.scenarios), 19)
        self.assertEqual(sum(s["kind"] == "benign" for s in self.scenarios), 6)
        self.assertEqual(sum(s["kind"] == "adversarial" for s in self.scenarios), 13)

    def test_actions_have_required_fields(self):
        for scenario in self.scenarios:
            self.assertIn("description", scenario)
            self.assertTrue(scenario["actions"])
            for action in scenario["actions"]:
                self.assertIn("command", action)
                self.assertIsInstance(action["expected_allowed"], bool)
                if not action["expected_allowed"]:
                    self.assertIn(action["invariant"], INVARIANT_NAMES)

    def test_json_files_are_valid(self):
        for path in (ROOT / "scenarios").glob("*.json"):
            self.assertIsInstance(json.loads(path.read_text(encoding="utf-8")), list)


if __name__ == "__main__":
    unittest.main()

