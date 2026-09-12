import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from invariants import evaluate_action


IMAGE = "containmentbench:local"


def docker(*args, check=True, capture_output=True, timeout=60):
    return subprocess.run(
        ["docker", *args],
        check=check,
        capture_output=capture_output,
        text=True,
        timeout=timeout,
    )


def check_environment():
    if shutil.which("docker") is None:
        raise RuntimeError("Docker is required")
    result = docker("info", check=False)
    if result.returncode:
        raise RuntimeError("Docker is installed, but the daemon is not running")
    if result.stdout and "OSType: linux" not in result.stdout:
        info = docker("info", "--format", "{{.OSType}}")
        if info.stdout.strip() != "linux":
            raise RuntimeError("Docker must use Linux containers")


def build_image(project_root):
    docker("build", "-t", IMAGE, str(project_root), capture_output=False, timeout=300)


class NetworkLab:
    def __init__(self):
        token = uuid.uuid4().hex[:8]
        self.baseline_network = f"cb-baseline-{token}"
        self.contained_network = f"cb-contained-{token}"
        self.services = []

    def __enter__(self):
        docker("network", "create", self.baseline_network)
        docker("network", "create", "--internal", self.contained_network)
        self._start_service(self.baseline_network, "allowed.local")
        self._start_service(self.baseline_network, "forbidden.local")
        self._start_service(self.contained_network, "allowed.local")
        time.sleep(0.3)
        return self

    def _start_service(self, network, alias):
        name = f"cb-service-{uuid.uuid4().hex[:10]}"
        docker(
            "run", "-d", "--rm", "--name", name, "--network", network,
            "--network-alias", alias, IMAGE, "python3", "-m", "http.server", "8000",
        )
        self.services.append(name)

    def __exit__(self, *_):
        for service in self.services:
            docker("rm", "-f", service, check=False)
        docker("network", "rm", self.baseline_network, check=False)
        docker("network", "rm", self.contained_network, check=False)


def _fixture(root, policy_source):
    workspace = root / "workspace"
    outside = root / "outside"
    host = root / "host"
    workspace.mkdir()
    outside.mkdir()
    host.mkdir()
    os.chmod(workspace, 0o777)
    (workspace / "project.txt").write_text("hello\n", encoding="utf-8")
    (host / "secret.txt").write_text("FAKE_SECRET_FOR_TESTING\n", encoding="utf-8")
    (host / "shared").mkdir()
    policy_copy = root / "policy.json"
    shutil.copy(policy_source, policy_copy)
    return workspace, outside, host, policy_copy


def _docker_args(condition, workspace, outside, host, policy_copy, network, policy):
    args = ["run", "--rm", "--network", network, "-w", "/workspace"]
    args += ["-v", f"{workspace}:/workspace:rw"]
    if condition == "baseline":
        args += [
            "--pid=host",
            "-v", f"{outside}:/outside:rw",
            "-v", f"{host}:/host:rw",
            "-v", f"{policy_copy}:/policy/policy.json:rw",
        ]
    else:
        args += [
            "--read-only",
            "--user", str(policy["run_as_uid"]),
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--security-opt", f"seccomp={Path(__file__).resolve().parent / 'seccomp.json'}",
            "--pids-limit", str(policy["max_processes"]),
            "--memory", f"{policy['max_memory_mb']}m",
            "--cpus", "0.5",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "-v", f"{policy_copy}:/policy/policy.json:ro",
        ]
    return args


def run_scenario(scenario, condition, monitor, network_lab, policy, policy_source):
    run_id = uuid.uuid4().hex
    started = time.monotonic()
    monitor.record(run_id, scenario["id"], "scenario_start", result="started", details={"condition": condition})
    action_results = []
    previous_blocked = False

    with tempfile.TemporaryDirectory(prefix="containmentbench-") as temp_dir:
        workspace, outside, host, policy_copy = _fixture(Path(temp_dir), policy_source)
        network = network_lab.baseline_network if condition == "baseline" else network_lab.contained_network
        base_args = _docker_args(condition, workspace, outside, host, policy_copy, network, policy)

        for action in scenario["actions"]:
            monitor.record(
                run_id, scenario["id"], action["event_type"], command=action["command"],
                result="attempted", exit_code=None,
                allowed_or_blocked="allowed" if action["expected_allowed"] else "policy_violation_attempt",
                invariant=action.get("invariant"), details={"condition": condition},
            )
            process_started = time.monotonic()
            command = action["command"]
            container_command = [IMAGE, "sh", "-c", command]
            if condition == "contained":
                container_command = [
                    IMAGE, "sh", "-c",
                    f'ulimit -t {policy["max_cpu_seconds"]}; exec sh -c "$1"',
                    "containmentbench", command,
                ]
            try:
                result = docker(
                    *base_args, *container_command,
                    check=False, timeout=action.get("timeout_seconds", 15),
                )
                exit_code = result.returncode
                output = (result.stdout + result.stderr).strip()[-500:]
            except subprocess.TimeoutExpired:
                exit_code = 124
                output = "command timed out"
            evaluation = evaluate_action(action, exit_code)
            evaluation.update({
                "id": action["id"],
                "exit_code": exit_code,
                "output": output,
                "invariant": action.get("invariant"),
                "duration_seconds": round(time.monotonic() - process_started, 3),
                "retry_after_block": bool(action.get("retry") and previous_blocked),
            })
            action_results.append(evaluation)
            previous_blocked = evaluation["blocked"]
            monitor.record(
                run_id, scenario["id"], "process_exit", command=action["command"],
                result="succeeded" if exit_code == 0 else "failed", exit_code=exit_code,
                allowed_or_blocked="blocked" if evaluation["blocked"] else "allowed",
                invariant=action.get("invariant"), details={"output": output, "condition": condition},
            )
            if evaluation["violation"]:
                monitor.record(
                    run_id, scenario["id"], "invariant_failure", command=action["command"],
                    result="violated", exit_code=exit_code, allowed_or_blocked="allowed",
                    invariant=action.get("invariant"), details={"condition": condition},
                )

    benign = scenario["kind"] == "benign"
    record = {
        "run_id": run_id,
        "scenario_id": scenario["id"],
        "name": scenario["name"],
        "category": scenario["category"],
        "kind": scenario["kind"],
        "condition": condition,
        "task_completed": all(r["succeeded"] for r in action_results) if benign else True,
        "invariant_violated": any(r["violation"] for r in action_results),
        "violation_count": sum(r["violation"] for r in action_results),
        "blocked_actions": sum(r["blocked"] for r in action_results),
        "false_positive_count": sum(r["false_positive"] for r in action_results),
        "forbidden_attempts": sum(not a["expected_allowed"] for a in scenario["actions"]),
        "detected_attempts": sum(not a["expected_allowed"] for a in scenario["actions"]),
        "commands_attempted": len(action_results),
        "retries_after_block": sum(r["retry_after_block"] for r in action_results),
        "duration_seconds": round(time.monotonic() - started, 3),
        "actions": action_results,
    }
    monitor.record(
        run_id, scenario["id"], "scenario_end", result="completed", exit_code=None,
        allowed_or_blocked=None, invariant=None,
        details={"condition": condition, "invariant_violated": record["invariant_violated"]},
    )
    return record


def load_scenarios(directory):
    scenarios = []
    for path in sorted(Path(directory).glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        scenarios.extend(data)
    ids = [scenario["id"] for scenario in scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError("scenario IDs must be unique")
    return scenarios
