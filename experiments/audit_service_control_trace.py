"""Independently validate frozen Windows SCM transitions captured by V16."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def audit(run_dir: Path) -> dict[str, Any]:
    freeze = read_json(run_dir / "source-freeze.json")
    experiment_id = freeze["experiment_id"]
    assignment = read_json(run_dir / "assignment.json")
    capture_dir = run_dir / "remote-capture" / experiment_id
    cohort = read_json(capture_dir / "cohort-execution.json")
    postflight = read_json(capture_dir / "postflight-final.json")
    failures: list[str] = []
    trial_checks: list[dict[str, Any]] = []

    if len(assignment["trials"]) != 30:
        failures.append("assignment denominator is not 30")
    if len(cohort.get("completed_slots", [])) != 30:
        failures.append("cohort does not contain 30 completed slots")
    if not postflight.get("postflight_pass"):
        failures.append("Windows postflight did not pass")

    for trial in assignment["trials"]:
        trial_id = trial["trial_id"]
        raw_path = capture_dir / "trials" / trial_id / "run.json"
        if not raw_path.is_file():
            failures.append(f"{trial_id}: raw run artifact missing")
            continue
        raw = read_json(raw_path)
        expected_control = trial["condition"] == "target_event_drop"
        attempts = raw.get("service_control_attempts", [])
        local_failures: list[str] = []
        if expected_control and len(attempts) != 4:
            local_failures.append(f"expected 4 service transitions, got {len(attempts)}")
        if not expected_control and attempts:
            local_failures.append("unexpected service transition in non-drop arm")

        expected_states = ["Stopped", "Running", "Stopped", "Running"] if expected_control else []
        transition_summaries = []
        for index, attempt in enumerate(attempts):
            wanted = expected_states[index] if index < len(expected_states) else None
            poll = attempt.get("state_poll") or {}
            final = poll.get("final") or {}
            pid_ok = final.get("process_id") == (0 if wanted == "Stopped" else final.get("process_id"))
            if wanted == "Running":
                pid_ok = isinstance(final.get("process_id"), int) and final["process_id"] > 0
            if (
                attempt.get("requested_state") != wanted
                or not attempt.get("completed")
                or attempt.get("command_exit_code") != 0
                or not poll.get("reached")
                or final.get("state") != wanted
                or not pid_ok
            ):
                local_failures.append(f"transition {index + 1} did not satisfy SCM state/PID/exit gates")

            health = attempt.get("health_check")
            if wanted == "Running" and not (
                health
                and health.get("api_ok")
                and health.get("indexer_ok")
                and health.get("wazuh_service_status") == "Running"
                and int(health.get("wazuh_service_pid") or 0) > 0
                and health.get("agent", {}).get("status") == "active"
            ):
                local_failures.append(f"transition {index + 1} lacks a healthy post-start check")

            transition_summaries.append(
                {
                    "requested_state": attempt.get("requested_state"),
                    "command": attempt.get("command"),
                    "command_exit_code": attempt.get("command_exit_code"),
                    "before_state": (attempt.get("before") or {}).get("state"),
                    "before_pid": (attempt.get("before") or {}).get("process_id"),
                    "final_state": final.get("state"),
                    "final_pid": final.get("process_id"),
                    "observations": len(poll.get("observations", [])),
                    "completed": attempt.get("completed"),
                    "health_checked": bool(health),
                }
            )

        if expected_control:
            original_hash = (raw.get("preflight") or {}).get("agent_config_sha256")
            restored_hash = (raw.get("restoration") or {}).get("restored_hash")
            if not (raw.get("restoration") or {}).get("exact_hash_match") or original_hash != restored_hash:
                local_failures.append("Wazuh configuration was not restored byte-for-byte")
        if local_failures:
            failures.extend(f"{trial_id}: {message}" for message in local_failures)
        trial_checks.append(
            {
                "trial_id": trial_id,
                "condition": trial["condition"],
                "transition_count": len(attempts),
                "transitions": transition_summaries,
                "passed": not local_failures,
                "failures": local_failures,
            }
        )

    result = {
        "schema_version": "csg-service-control-trace-audit-v1",
        "experiment_id": experiment_id,
        "audit_method": "Independent JSON re-read of assigned raw run files, SCM transition records, health checks, and postflight.",
        "assigned_trials": len(assignment["trials"]),
        "completed_slots": len(cohort.get("completed_slots", [])),
        "drop_trials": sum(item["condition"] == "target_event_drop" for item in assignment["trials"]),
        "recorded_service_transitions": sum(item["transition_count"] for item in trial_checks),
        "passed_trials": sum(item["passed"] for item in trial_checks),
        "postflight_pass": bool(postflight.get("postflight_pass")),
        "audit_pass": not failures and len(trial_checks) == len(assignment["trials"]),
        "failures": failures,
        "trials": trial_checks,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.run_dir)
    output_path = args.run_dir / "analysis" / "service-control-audit.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(
        "SERVICE_CONTROL_AUDIT={}; TRIALS={}/{}; DROP_TRANSITIONS={}; POSTFLIGHT={}".format(
            "PASS" if result["audit_pass"] else "FAIL",
            result["passed_trials"],
            result["assigned_trials"],
            result["recorded_service_transitions"],
            result["postflight_pass"],
        )
    )
    if result["failures"]:
        print("FAILURES=" + " | ".join(result["failures"]))
    return 0 if result["audit_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
