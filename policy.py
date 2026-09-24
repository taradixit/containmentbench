import json
import posixpath
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


def _require_string_list(policy, key, allow_empty=False):
    value = policy[key]
    valid_items = isinstance(value, list) and all(isinstance(item, str) and item for item in value)
    if not valid_items or (not allow_empty and not value):
        qualifier = "a list" if allow_empty else "a non-empty list"
        raise ValueError(f"{key} must be {qualifier} of strings")


def validate_policy(policy):
    missing = REQUIRED_POLICY_KEYS - policy.keys()
    if missing:
        raise ValueError(f"policy is missing: {', '.join(sorted(missing))}")

    for key in ("allowed_read_paths", "allowed_write_paths", "blocked_paths"):
        _require_string_list(policy, key)
    _require_string_list(policy, "allowed_network_targets", allow_empty=True)
    for key in ("allowed_read_paths", "allowed_write_paths", "blocked_paths"):
        if not all(PurePosixPath(item).is_absolute() for item in policy[key]):
            raise ValueError(f"{key} must contain absolute Linux paths")
    for target in policy["allowed_network_targets"]:
        try:
            host, port = target.rsplit(":", 1)
            valid_target = bool(host) and 1 <= int(port) <= 65535
        except ValueError:
            valid_target = False
        if not valid_target:
            raise ValueError(f"invalid network target: {target}")
    if not isinstance(policy["network_allowed"], bool):
        raise ValueError("network_allowed must be true or false")
    if not policy["network_allowed"] and policy["allowed_network_targets"]:
        raise ValueError("allowed_network_targets must be empty when networking is disabled")
    for key in ("max_processes", "max_cpu_seconds", "max_memory_mb"):
        if not isinstance(policy[key], int) or isinstance(policy[key], bool) or policy[key] <= 0:
            raise ValueError(f"{key} must be a positive integer")
    if not isinstance(policy["run_as_uid"], int) or isinstance(policy["run_as_uid"], bool) or policy["run_as_uid"] <= 0:
        raise ValueError("run_as_uid must be a positive non-root user ID")
    return policy


def load_policy(path="policy.json"):
    with open(path, encoding="utf-8") as policy_file:
        policy = json.load(policy_file)
    return validate_policy(policy)


def path_is_within(path, roots):
    candidate = PurePosixPath(posixpath.normpath(path))
    normalized_roots = [PurePosixPath(posixpath.normpath(root)) for root in roots]
    return any(candidate == root or root in candidate.parents for root in normalized_roots)


def write_is_allowed(path, policy):
    return path_is_within(path, policy["allowed_write_paths"]) and not path_is_within(
        path, policy["blocked_paths"]
    )


def read_is_allowed(path, policy):
    return path_is_within(path, policy["allowed_read_paths"]) and not path_is_within(
        path, policy["blocked_paths"]
    )
