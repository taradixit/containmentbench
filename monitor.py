import json
from datetime import datetime, timezone


class JsonlMonitor:
    def __init__(self, path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")

    def record(self, run_id, scenario_id, event_type, **fields):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "scenario_id": scenario_id,
            "event_type": event_type,
            **fields,
        }
        with self.path.open("a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(event, sort_keys=True) + "\n")

