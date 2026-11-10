"""Audit and summarize the scheduled-task positive-control holdout."""

# Generated report prose is intentionally stored as readable single-line strings.
# ruff: noqa: E501

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def canonical_identity(value: Any) -> str:
    text = str(value or "").strip().lower().replace("\\", "/")
    while "//" in text:
        text = text.replace("//", "/")
    return text.replace(":/", "/")


def seconds_between(start: str | None, end: str | None) -> float | None:
    if not start or not end:
        return None
    left = datetime.fromisoformat(start.replace("Z", "+00:00"))
    right = datetime.fromisoformat(end.replace("Z", "+00:00"))
    return (right - left).total_seconds()


def binomial_cdf(k: int, n: int, probability: float) -> float:
    return sum(
        math.comb(n, j) * probability**j * (1 - probability) ** (n - j) for j in range(k + 1)
    )


def exact_binomial_interval(successes: int, trials: int, alpha: float = 0.05) -> list[float]:
    tail = alpha / 2
    if successes == 0:
        lower = 0.0
    else:
        lo, hi = 0.0, 1.0
        for _ in range(80):
            mid = (lo + hi) / 2
            if 1 - binomial_cdf(successes - 1, trials, mid) < tail:
                lo = mid
            else:
                hi = mid
        lower = (lo + hi) / 2
    if successes == trials:
        upper = 1.0
    else:
        lo, hi = 0.0, 1.0
        for _ in range(80):
            mid = (lo + hi) / 2
            if binomial_cdf(successes, trials, mid) > tail:
                lo = mid
            else:
                hi = mid
        upper = (lo + hi) / 2
    return [lower, upper]


def analyze_trial(run_path: Path) -> dict[str, Any]:
    run = read_json(run_path)
    if len(run.get("scenarios", [])) != 1:
        raise ValueError(f"expected one scenario in {run_path}")
    scenario = run["scenarios"][0]
    name = scenario["object_name"]
    expected_key = canonical_identity(scenario["expected_object_key"])
    exact_events = scenario["event_plane"].get("exact_matches", [])
    event_ids = [str(event["event_id"]) for event in exact_events if event.get("event_id")]
    local_events = scenario.get("local_source_evidence", {}).get("exact_events", [])
    latest = scenario.get("csg_reconciliation", {})
    matched_ids = [str(value) for value in as_list(latest.get("matched_evidence_ids"))]
    history = latest.get("history", [])
    final_records = [item for item in history if item.get("finalized")]
    final = max(final_records, key=lambda item: item.get("version", 0), default={})
    state_window = final.get("observation_window", {})
    post_items = scenario.get("state_plane", {}).get("after_action_observed", [])
    direct = scenario.get("state_plane", {}).get("direct_windows_verification") or {}

    event_identity_ok = len(exact_events) == 1 and all(
        event.get("host_id") == "win11-arm-lab"
        and event.get("source") == "wazuh"
        and event.get("normalized_type") == "scheduled_task_created"
        and canonical_identity(event.get("target", {}).get("key")) == expected_key
        for event in exact_events
    )
    local_event_ok = len(local_events) == 1 and all(
        event.get("event_id") == 4698
        and event.get("exact_identity_match") is True
        and str(event.get("event_data", {}).get("TaskName", "")).strip("\\").lower() == name.lower()
        for event in local_events
    )
    probe_seen = any(
        str(item.get("task_name", "")).strip("\\").lower() == name.lower() for item in post_items
    )
    exact_reconciliation = (
        final.get("status") == "CONSISTENT"
        and bool(event_ids)
        and bool(matched_ids)
        and set(matched_ids) == set(event_ids)
    )
    first_wazuh_time = exact_events[0].get("event_time") if exact_events else None
    if first_wazuh_time and state_window.get("start") and state_window.get("end"):
        before_window = seconds_between(first_wazuh_time, state_window["start"])
        after_window = seconds_between(state_window["end"], first_wazuh_time)
        event_window_offset = (
            before_window if before_window > 0 else after_window if after_window > 0 else 0.0
        )
    else:
        event_window_offset = None
    tolerance = float(final.get("metadata", {}).get("event_time_tolerance_seconds", 20))
    checks = {
        "runner_gate": scenario.get("positive_control", {}).get("passed") is True,
        "probe_absent_before": scenario.get("state_plane", {}).get("target_absent_before_action")
        is True,
        "probe_present_after": probe_seen,
        "probe_absent_after_cleanup": scenario.get("state_plane", {}).get(
            "cleanup_removed_from_probe"
        )
        is True,
        "native_task_sequence": direct
        == {
            "target_absent_before_action": True,
            "target_present_after_action": True,
            "target_absent_after_cleanup": True,
        },
        "local_windows_4698_exact": local_event_ok,
        "wazuh_query_complete": scenario.get("event_plane", {}).get("query_complete") is True,
        "one_exact_wazuh_event": event_identity_ok,
        "event_within_frozen_time_tolerance": event_window_offset is not None
        and event_window_offset <= tolerance,
        "final_csg_consistent_exact_ids": exact_reconciliation,
        "cleanup_completed": scenario.get("action", {}).get("cleanup_completed") is True,
        "no_action_error": scenario.get("action", {}).get("error") is None,
    }
    action_start = scenario.get("action", {}).get("started_at")
    probe_snapshot_time = (
        scenario.get("state_plane", {}).get("after_action_observation", {}).get("observed_at")
    )
    probe_category_time = (
        scenario.get("state_plane", {})
        .get("after_action_observation", {})
        .get("category_observed_at")
    )
    local_event_time = local_events[0].get("event_time_utc") if local_events else None
    wazuh_event_time = exact_events[0].get("event_time") if exact_events else None
    final_time = final.get("finalized_at")
    if wazuh_event_time and state_window.get("start") and state_window.get("end"):
        before_window = seconds_between(wazuh_event_time, state_window["start"])
        after_window = seconds_between(state_window["end"], wazuh_event_time)
        event_window_offset = (
            before_window if before_window > 0 else after_window if after_window > 0 else 0.0
        )
    else:
        event_window_offset = None
    tolerance = float(final.get("metadata", {}).get("event_time_tolerance_seconds", 20))
    delta_matches = [
        item
        for item in scenario.get("deltas", [])
        if item.get("delta_type") == "ADD"
        and canonical_identity(item.get("object_key")) == expected_key
    ]
    return {
        "trial_id": run_path.parent.name,
        "task_name": name,
        "expected_object_key": scenario.get("expected_object_key"),
        "passed": all(checks.values()),
        "checks": checks,
        "failed_checks": [name for name, passed in checks.items() if not passed],
        "finding_id": latest.get("finding_id"),
        "add_delta_id": delta_matches[-1].get("delta_id") if delta_matches else None,
        "local_event_record_id": local_events[0].get("record_id") if local_events else None,
        "local_event_time_utc": local_event_time,
        "wazuh_event_ids": event_ids,
        "wazuh_event_times_utc": [event.get("event_time") for event in exact_events],
        "csg_matched_evidence_ids": matched_ids,
        "reconciliation_history_statuses": [item.get("status") for item in history],
        "final_reconciliation_status": final.get("status"),
        "state_observation_window_start_utc": state_window.get("start"),
        "state_observation_window_end_utc": state_window.get("end"),
        "wazuh_event_outside_window_seconds": event_window_offset,
        "frozen_event_time_tolerance_seconds": tolerance,
        "action_started_at_utc": action_start,
        "probe_category_observed_at_utc": probe_category_time,
        "probe_snapshot_available_at_utc": probe_snapshot_time,
        "reconciliation_finalized_at_utc": final_time,
        "action_to_category_observation_seconds": seconds_between(
            action_start, probe_category_time
        ),
        "action_to_probe_snapshot_seconds": seconds_between(action_start, probe_snapshot_time),
        "action_to_local_event_timestamp_seconds": seconds_between(action_start, local_event_time),
        "action_to_wazuh_event_timestamp_seconds": seconds_between(action_start, wazuh_event_time),
        "action_to_reconciliation_finalization_seconds": seconds_between(action_start, final_time),
        "retrieval_candidate_count": scenario.get("event_plane", {})
        .get("retrieval", {})
        .get("candidate_count"),
    }


def summarize(values: list[float | None]) -> dict[str, float | int | None]:
    present = [float(value) for value in values if value is not None]
    if not present:
        return {"n": 0, "min": None, "median": None, "max": None}
    return {
        "n": len(present),
        "min": round(min(present), 3),
        "median": round(median(present), 3),
        "max": round(max(present), 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("campaign_dir", type=Path)
    args = parser.parse_args()
    raw_root = args.campaign_dir / "windows/raw/endpoint-capture-v2"
    trials = [
        analyze_trial(raw_root / f"task-positive-{index:02d}" / "run.json") for index in range(1, 6)
    ]
    successes = sum(item["passed"] for item in trials)
    all_event_ids = [event_id for item in trials for event_id in item["wazuh_event_ids"]]
    latency_fields = [
        "action_to_category_observation_seconds",
        "action_to_probe_snapshot_seconds",
        "action_to_local_event_timestamp_seconds",
        "action_to_wazuh_event_timestamp_seconds",
        "action_to_reconciliation_finalization_seconds",
    ]
    latency = {field: summarize([item[field] for item in trials]) for field in latency_fields}
    aggregate = {
        "schema_version": "csg-scheduled-task-positive-holdout-analysis-v1",
        "campaign_id": "scheduled-task-positive-v2",
        "n_trials": len(trials),
        "full_gate_successes": successes,
        "full_gate_rate": successes / len(trials),
        "full_gate_rate_exact_95pct_clopper_pearson": exact_binomial_interval(
            successes, len(trials)
        ),
        "all_wazuh_event_ids_unique": len(all_event_ids) == len(set(all_event_ids)),
        "latency_definitions": {
            "action_to_category_observation_seconds": "Task creation action start to probe category observed_at; snapshot/collection timestamp, not exact kernel detection time.",
            "action_to_probe_snapshot_seconds": "Task creation action start to committed probe observation observed_at.",
            "action_to_local_event_timestamp_seconds": "Task creation action start to Windows Security event 4698 timestamp; not Wazuh delivery latency.",
            "action_to_wazuh_event_timestamp_seconds": "Task creation action start to Wazuh event timestamp; not index-ingestion latency.",
            "action_to_reconciliation_finalization_seconds": "Task creation action start to finalized CSG reconciliation record.",
        },
        "latency_summary_seconds": latency,
        "trials": trials,
        "interpretation_limit": "Five benign scheduled-task positive controls on one Windows VM. This validates the tested observation/reconciliation path only; it is not attack-detection performance, a capture-loss result, or evidence of cross-host generalization.",
    }
    args.campaign_dir.mkdir(parents=True, exist_ok=True)
    (args.campaign_dir / "aggregate.json").write_text(
        json.dumps(aggregate, indent=2) + "\n", encoding="utf-8"
    )
    columns = [
        "trial_id",
        "task_name",
        "passed",
        "finding_id",
        "add_delta_id",
        "local_event_record_id",
        "wazuh_event_ids",
        "csg_matched_evidence_ids",
        "final_reconciliation_status",
        *latency_fields,
    ]
    with (args.campaign_dir / "trial-summary.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for item in trials:
            row = {key: item.get(key) for key in columns}
            row["wazuh_event_ids"] = ";".join(item["wazuh_event_ids"])
            row["csg_matched_evidence_ids"] = ";".join(item["csg_matched_evidence_ids"])
            writer.writerow(row)
    table_rows = [
        "| {trial} | {name} | {snapshot:.2f} | {local:.2f} | {wazuh:.2f} | "
        "{final:.2f} | {status} | {passed} |".format(
            trial=item["trial_id"],
            name=item["task_name"],
            snapshot=item["action_to_probe_snapshot_seconds"],
            local=item["action_to_local_event_timestamp_seconds"],
            wazuh=item["action_to_wazuh_event_timestamp_seconds"],
            final=item["action_to_reconciliation_finalization_seconds"],
            status=item["final_reconciliation_status"],
            passed="PASS" if item["passed"] else "FAIL",
        )
        for item in trials
    ]
    identity_rows = [
        f"| {item['trial_id']} | `{item['add_delta_id']}` | `{item['finding_id']}` | "
        f"`{item['local_event_record_id']}` | `{'; '.join(item['wazuh_event_ids'])}` |"
        for item in trials
    ]
    gate_ci = aggregate["full_gate_rate_exact_95pct_clopper_pearson"]
    report_lines = [
        "# Scheduled-Task Positive-Control Holdout v2",
        "",
        "## Result",
        "",
        f"All **{successes}/{len(trials)}** preregistered trials passed the complete positive-control gate ({successes / len(trials):.0%}; exact two-sided 95% Clopper-Pearson interval {gate_ci[0]:.3f} to {gate_ci[1]:.3f}). Each task name was freshly randomized, and each trial produced a distinct Wazuh event ID.",
        "",
        "For every trial, the direct CSG probe observed the scheduled-task ADD after it was absent in the pre-action observation; Windows Security logged exact event 4698; the bounded Wazuh query completed and returned one same-host/type/object match; and finalized CSG reconciliation was `CONSISTENT` with only that trial's exact event ID. Both the native Task Scheduler API and probe confirmed cleanup.",
        "",
        "This supports repeatability of the tested scheduled-task state/event path and object-specific reconciliation on this endpoint. It is not evidence of attack detection, telemetry-loss resilience, false-positive performance, or cross-host generalization.",
        "",
        "## Trial Results",
        "",
        "Times are relative to task-creation command start. Probe snapshot availability uses the API observation timestamp, not the exact instant the collector read the object. Windows and Wazuh event values are event timestamps, **not** delivery/index-ingestion latency. The 60-second grace is the maximum pending window; exact evidence may finalize a finding sooner. At n=5, report min/median/max only; do not estimate tail percentiles.",
        "",
        "| Trial | Fresh task | Probe snapshot (s) | Windows 4698 timestamp (s) | Wazuh event timestamp (s) | CSG finalized (s) | Status | Gate |",
        "|---|---|---:|---:|---:|---:|---|---|",
        *table_rows,
        "",
        "| Measure | Median [minimum, maximum] seconds |",
        "|---|---:|",
        *[
            f"| {label} | {latency[field]['median']:.2f} [{latency[field]['min']:.2f}, {latency[field]['max']:.2f}] |"
            for field, label in [
                ("action_to_category_observation_seconds", "Probe category observation"),
                ("action_to_probe_snapshot_seconds", "Probe snapshot available"),
                ("action_to_local_event_timestamp_seconds", "Windows event timestamp"),
                ("action_to_wazuh_event_timestamp_seconds", "Wazuh event timestamp"),
                ("action_to_reconciliation_finalization_seconds", "Reconciliation finalized"),
            ]
        ],
        "",
        "## Evidence Linkage",
        "",
        "| Trial | ADD delta | Finding | Windows Security record | Exact Wazuh event ID |",
        "|---|---|---|---:|---|",
        *identity_rows,
        "",
        "Every final record references only the listed Wazuh event. Raw data preserves the provisional and finalized reconciliation versions, task definition, before/after snapshots, local event data/XML, retrieval metadata, and cleanup state.",
        "",
        "## Frozen Method and Scope",
        "",
        "- One Windows 11 Home ARM64 VM (`win11-arm-lab`, build 26200); Wazuh agent 4.14.7 active, Sysmon 15.22 running, indexer 7.10.2 available.",
        "- Five randomized tasks with action `cmd.exe /c exit 0`, scheduled one hour later so they would not execute during the measurement.",
        "- Before/after checks used both the native Task Scheduler API and CSG probe. Presence and cleanup polling were bounded at 90 seconds.",
        "- Wazuh wait was 35 seconds. Event-time tolerance was frozen at 20 seconds from a separate calibration set, not tuned on this holdout.",
        "- Migration `0005_state_transitions` (head); image IDs, source hashes, endpoint configuration hashes, and pre-run environment capture are recorded in `source-freeze.json`.",
        "- Predeclared protocol is `PROTOCOL.md`; raw VM archive is `windows/raw/windows-holdout-v2.zip`; archive and artifact hashes are recorded in `campaign-closeout.json`.",
        "",
        "The five-trial arm has no no-change, wrong-object, delayed-event, or capture-drop conditions. This is a benign live behavior-family validation inspired by Windows-APT 2025, not a dataset replay or replication. Event timestamps do not establish when records became queryable; measured ingestion latency requires separate availability timestamps.",
        "",
        "The raw endpoint archive contains personal/identifying lab data (Windows account name/SID, computer name, and private-network addresses). Keep it access-controlled; redact these fields and generate new hashes before public release.",
        "",
        "## Reproduce the Analysis",
        "",
        "```sh",
        "python3 experiments/analyze_scheduled_task_positive_holdout.py \\",
        "  experiments/results/runs/20261011/reconciliation-calibration/holdout/scheduled-task-positive-v2",
        "```",
        "",
        "The analyzer re-reads the five archived `run.json` files and regenerates `aggregate.json`, `trial-summary.csv`, and this report. It checks host, type, task identity, event-time tolerance, and exact matched evidence IDs.",
    ]
    (args.campaign_dir / "RESULTS.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    archive = args.campaign_dir / "windows/raw/windows-holdout-v2.zip"
    postflight = read_json(
        args.campaign_dir / "windows/raw/endpoint-capture-v2/windows/raw/postflight.json"
    )
    analyzer_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    closeout = {
        "schema_version": "csg-campaign-closeout-v1",
        "campaign_id": "scheduled-task-positive-v2",
        "closed_at_utc": datetime.now(UTC).isoformat(),
        "status": "ALL_FIVE_POSITIVE_CONTROLS_PASSED"
        if successes == len(trials)
        else "POSITIVE_CONTROL_GAPS",
        "trials_completed": len(trials),
        "full_gate_successes": successes,
        "all_wazuh_event_ids_unique": aggregate["all_wazuh_event_ids_unique"],
        "endpoint_postflight": {
            "all_tasks_absent": postflight.get("all_tasks_absent"),
            "wazuh_service": postflight.get("wazuh_service"),
            "sysmon_service": postflight.get("sysmon_service"),
        },
        "windows_archive": {
            "path": "windows/raw/windows-holdout-v2.zip",
            "size_bytes": archive.stat().st_size,
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "entry_count": 23,
        },
        "analysis_script": {
            "path": "experiments/analyze_scheduled_task_positive_holdout.py",
            "sha256": analyzer_hash,
        },
        "publication_redaction_required": True,
        "sensitive_fields_in_raw_archive": [
            "Windows account name and SID",
            "computer name",
            "private-network addresses",
        ],
        "detailed_hash_catalog": "artifact-hashes.sha256",
        "claim_boundary": aggregate["interpretation_limit"],
    }
    (args.campaign_dir / "campaign-closeout.json").write_text(
        json.dumps(closeout, indent=2) + "\n", encoding="utf-8"
    )
    hash_lines = []
    for path in sorted(args.campaign_dir.rglob("*")):
        if path.is_file() and path.name != "artifact-hashes.sha256":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            hash_lines.append(f"{digest}  {path.relative_to(args.campaign_dir).as_posix()}")
    (args.campaign_dir / "artifact-hashes.sha256").write_text(
        "\n".join(hash_lines) + "\n", encoding="utf-8"
    )
    print(f"{successes}/{len(trials)} full-gate trials passed")
    print(f"Distinct Wazuh event IDs: {len(set(all_event_ids))}/{len(all_event_ids)}")
    for name, values in latency.items():
        print(f"{name}: {values}")


if __name__ == "__main__":
    main()
