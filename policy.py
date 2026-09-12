import json
from pathlib import PurePosixPath


REQUIRED_POLICY_KEYS = {
    "allowed_read_paths",
    "allowed_write_paths",
    "blocked_paths",
    "network_allowed",
    "allowed_network_targets",
    "max_processes",
    "max_cpu_seconds",
    "max_memory_mb",
    "run_as_uid",
}


def load_policy(path="policy.json"):
    with open(path, encoding="utf-8") as policy_file:
        policy = json.load(policy_file)
    missing = REQUIRED_POLICY_KEYS - policy.keys()
    if missing:
        raise ValueError(f"policy is missing: {', '.join(sorted(missing))}")
    return policy


def path_is_within(path, roots):
    candidate = PurePosixPath(path)
    return any(candidate == PurePosixPath(root) or PurePosixPath(root) in candidate.parents for root in roots)


def write_is_allowed(path, policy):
    return path_is_within(path, policy["allowed_write_paths"]) and not path_is_within(
        path, policy["blocked_paths"]
    )


def read_is_allowed(path, policy):
    return path_is_within(path, policy["allowed_read_paths"]) and not path_is_within(
        path, policy["blocked_paths"]
    )

