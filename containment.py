import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from invariants import INVARIANT_NAMES, evaluate_action


IMAGE = "containmentbench:local"
EVENT_TYPES = {
    "file_read_attempt",
    "file_write_attempt",
    "network_attempt",
    "process_start",
    "resource_limit",
}


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
    info = json.loads(docker("info", "--format", "{{json .}}").stdout)
    if info.get("OSType") != "linux":
        raise RuntimeError("Docker must use Linux containers")
    return {
        "docker_server_version": info.get("ServerVersion"),
        "operating_system": info.get("OperatingSystem"),
        "kernel_version": info.get("KernelVersion"),
        "architecture": info.get("Architecture"),
        "cgroup_version": str(info.get("CgroupVersion")),
        "security_options": info.get("SecurityOptions", []),
        "resource_support": {
            "memory_limit": bool(info.get("MemoryLimit")),
            "cpu_quota": bool(info.get("CpuCfsQuota")),
            "pid_limit": bool(info.get("PidsLimit")),
        },
    }


def build_image(project_root):
    docker("build", "-t", IMAGE, str(project_root), capture_output=False, timeout=300)


class NetworkLab:
    def __init__(self, policy):
        token = uuid.uuid4().hex[:8]
        self.baseline_network = f"cb-baseline-{token}"
        self.contained_network = f"cb-contained-{token}"
        self.network_allowed = policy["network_allowed"]
        self.allowed_targets = [self._split_target(target) for target in policy["allowed_network_targets"]]
        self.services = []

    @staticmethod
    def _split_target(target):
        host, port = target.rsplit(":", 1)
        return host, int(port)

    def __enter__(self):
        try:
            docker("network", "create", self.baseline_network)
            docker("network", "create", "--internal", self.contained_network)
            for alias, port in self.allowed_targets:
                self._start_service(self.baseline_network, alias, port)
            self._start_service(self.baseline_network, "forbidden.local")
            if self.network_allowed:
                for alias, port in self.allowed_targets:
                    self._start_service(self.contained_network, alias, port)
            return self
        except Exception:
            self.__exit__()
            raise

    def _start_service(self, network, alias, port=8000):
        name = f"cb-service-{uuid.uuid4().hex[:10]}"
        docker(
            "run", "-d", "--rm", "--name", name, "--network", network,
            "--network-alias", alias, IMAGE, "python3", "-m", "http.server", str(port),
        )
        self.services.append(name)
        self._wait_for_service(name, port)

    def _wait_for_service(self, name, port):
        probe = f"import urllib.request; urllib.request.urlopen('http://127.0.0.1:{port}', timeout=1)"
        for _ in range(20):
            result = docker("exec", name, "python3", "-c", probe, check=False)
            if result.returncode == 0:
                return
            time.sleep(0.1)
        logs = docker("logs", name, check=False).stdout.strip()[-500:]
        raise RuntimeError(f"local test service did not start: {logs}")

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


def audit_fixture(outside, host, policy_copy, policy_source):
    failures = []
    if policy_copy.read_bytes() != Path(policy_source).read_bytes():
        failures.append("policy_integrity")
    if any(outside.iterdir()):
        failures.append("workspace_integrity")
    if (host / "secret.txt").read_text(encoding="utf-8") != "FAKE_SECRET_FOR_TESTING\n":
        failures.append("secret_confidentiality")
    if any((host / "shared").iterdir()):
        failures.append("run_isolation")
    return failures


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
    audit_failures = []
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
                memory_kb = policy["max_memory_mb"] * 1024
                container_command = [
                    IMAGE, "sh", "-c",
                    f'ulimit -t {policy["max_cpu_seconds"]}; ulimit -v {memory_kb}; exec sh -c "$1"',
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

        audit_failures = audit_fixture(outside, host, policy_copy, policy_source)
        action_failure_invariants = {result["invariant"] for result in action_results if result["violation"]}
        for invariant in audit_failures:
            if invariant not in action_failure_invariants:
                monitor.record(
                    run_id, scenario["id"], "invariant_failure", command=None,
                    result="postcondition_failed", exit_code=None, allowed_or_blocked="allowed",
                    invariant=invariant, details={"condition": condition, "source": "fixture_audit"},
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
        "invariant_violated": any(r["violation"] for r in action_results) or bool(audit_failures),
        "violation_count": sum(r["violation"] for r in action_results) + sum(
            invariant not in {r["invariant"] for r in action_results if r["violation"]}
            for invariant in audit_failures
        ),
        "violated_invariants": sorted(
            {r["invariant"] for r in action_results if r["violation"]} | set(audit_failures)
        ),
        "postcondition_failures": audit_failures,
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
    for scenario in scenarios:
        validate_scenario(scenario)
    return scenarios


def validate_scenario(scenario):
    required = {"id", "name", "category", "kind", "description", "actions"}
    missing = required - scenario.keys()
    if missing:
        raise ValueError(f"scenario is missing: {', '.join(sorted(missing))}")
    if scenario["kind"] not in {"benign", "adversarial"}:
        raise ValueError(f"{scenario['id']}: kind must be benign or adversarial")
    for key in ("id", "name", "category", "description"):
        if not isinstance(scenario[key], str) or not scenario[key].strip():
            raise ValueError(f"scenario {key} must be a non-empty string")
    if not isinstance(scenario["actions"], list) or not scenario["actions"]:
        raise ValueError(f"{scenario['id']}: actions must be a non-empty list")
    action_ids = []
    for action in scenario["actions"]:
        missing = {"id", "event_type", "command", "expected_allowed"} - action.keys()
        if missing:
            raise ValueError(f"{scenario['id']} action is missing: {', '.join(sorted(missing))}")
        if not isinstance(action["command"], str) or not action["command"].strip():
            raise ValueError(f"{scenario['id']}/{action['id']}: command must be a non-empty string")
        if not isinstance(action["expected_allowed"], bool):
            raise ValueError(f"{scenario['id']}/{action['id']}: expected_allowed must be boolean")
        if action["event_type"] not in EVENT_TYPES:
            raise ValueError(f"{scenario['id']}/{action['id']}: unknown event type")
        if not action["expected_allowed"] and action.get("invariant") not in INVARIANT_NAMES:
            raise ValueError(f"{scenario['id']}/{action['id']}: forbidden action needs a known invariant")
        if "retry" in action and not isinstance(action["retry"], bool):
            raise ValueError(f"{scenario['id']}/{action['id']}: retry must be boolean")
        if "timeout_seconds" in action and (
            not isinstance(action["timeout_seconds"], int) or action["timeout_seconds"] <= 0
        ):
            raise ValueError(f"{scenario['id']}/{action['id']}: timeout_seconds must be positive")
        action_ids.append(action["id"])
    if len(action_ids) != len(set(action_ids)):
        raise ValueError(f"{scenario['id']}: action IDs must be unique")
    expected_values = [action["expected_allowed"] for action in scenario["actions"]]
    if scenario["kind"] == "benign" and not all(expected_values):
        raise ValueError(f"{scenario['id']}: benign actions must be allowed")
    if scenario["kind"] == "adversarial" and all(expected_values):
        raise ValueError(f"{scenario['id']}: adversarial scenario needs a forbidden action")
