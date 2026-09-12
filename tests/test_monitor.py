import json
import tempfile
import unittest
from pathlib import Path

from monitor import JsonlMonitor


class MonitorTests(unittest.TestCase):
    def test_writes_json_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            monitor = JsonlMonitor(path)
            monitor.record("run-1", "B01", "scenario_start", result="started")
            event = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(event["run_id"], "run-1")
            self.assertEqual(event["event_type"], "scenario_start")
            self.assertIn("timestamp", event)


if __name__ == "__main__":
    unittest.main()

