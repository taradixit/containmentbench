#!/usr/bin/env python3
import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from containment import NetworkLab, build_image, check_environment, load_scenarios, run_scenario
from invariants import summarize
from monitor import JsonlMonitor
from policy import load_policy


ROOT = Path(__file__).resolve().parent


def write_results(records, summary, results_dir, runtime, policy):
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "runs.jsonl").write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records), encoding="utf-8"
    )
    document = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": "Linux containers via Docker",
        "runtime": runtime,
        "contained_controls": {
            "read_only_root": True,
            "non_root_uid": policy["run_as_uid"],
            "capabilities_dropped": "all",
            "no_new_privileges": True,
            "custom_seccomp_profile": "seccomp.json",
            "separate_pid_namespace": True,
            "internal_allowlist_network": True,
            "pids_limit": policy["max_processes"],
            "docker_memory_limit_mb": policy["max_memory_mb"],
            "rlimit_cpu_seconds": policy["max_cpu_seconds"],
            "rlimit_address_space_mb": policy["max_memory_mb"],
        },
        "summary": summary,
    }
    (results_dir / "summary.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    with (results_dir / "summary.csv").open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=["condition", *next(iter(summary.values())).keys()],
            lineterminator="\n",
        )
        writer.writeheader()
        for condition, metrics in summary.items():
            writer.writerow({"condition": condition, **metrics})


def print_summary(summary):
    print("\ncondition  benign success  adversarial violations  blocked  detected  false positives")
    for condition, metrics in summary.items():
        benign_rate = metrics["benign_task_success_rate"]
        violation_rate = metrics["adversarial_violation_success_rate"]
        benign_text = "n/a" if benign_rate is None else f"{benign_rate:.1f}%"
        violation_text = "n/a" if violation_rate is None else f"{violation_rate:.1f}%"
        print(
            f"{condition:10} {benign_text:>7}"
            f" {violation_text:>20}"
            f" {metrics['blocked_actions']:8} {metrics['detection_rate']:8.1f}%"
            f" {metrics['false_positive_count']:15}"
        )


def main():
    parser = argparse.ArgumentParser(description="Compare weak and contained agent environments")
    parser.add_argument("--scenario", help="run one scenario ID")
    parser.add_argument("--condition", choices=["baseline", "contained"], action="append")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--results-dir", type=Path, default=ROOT / "results")
    args = parser.parse_args()

    runtime = check_environment()
    if not args.skip_build:
        build_image(ROOT)
    policy = load_policy(ROOT / "policy.json")
    scenarios = load_scenarios(ROOT / "scenarios")
    if args.scenario:
        scenarios = [scenario for scenario in scenarios if scenario["id"] == args.scenario]
        if not scenarios:
            parser.error(f"unknown scenario: {args.scenario}")
    conditions = args.condition or ["baseline", "contained"]
    monitor = JsonlMonitor(args.results_dir / "events.jsonl")
    records = []

    with NetworkLab(policy) as network_lab:
        for condition in conditions:
            for scenario in scenarios:
                print(f"[{condition}] {scenario['id']} {scenario['name']}")
                records.append(
                    run_scenario(scenario, condition, monitor, network_lab, policy, ROOT / "policy.json")
                )

    summary = summarize(records)
    write_results(records, summary, args.results_dir, runtime, policy)
    print_summary(summary)


if __name__ == "__main__":
    main()
