#!/usr/bin/env python3
"""Independently validate raw service-dwell trial evidence and identity boundaries."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8-sig") as handle:
        return json.load(handle)


def utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def mode(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return {"automatic": "auto", "demand": "manual"}.get(normalized, normalized)


def summarize(campaign_dir: Path) -> dict[str, Any]:
    manifest = read_json(campaign_dir / "campaign-manifest.json")
    paths = sorted(campaign_dir.glob("trial-*/run.json"))
    runs = [read_json(path) for path in paths]
    findings: list[str] = []
    by_condition: dict[str, Counter[str]] = defaultdict(Counter)
    services: set[str] = set()
    transition_owner: dict[str, str] = {}
    evidence_owner: dict[str, set[str]] = defaultdict(set)
    system_record_owner: dict[int, set[str]] = defaultdict(set)
    status_counts: Counter[str] = Counter()
    event_7040_counts: Counter[str] = Counter()

    expected_plan = manifest.get("planned_trials", [])
    if len(expected_plan) != manifest.get("scheduled_trials"):
        findings.append("manifest planned_trials length differs from scheduled_trials")
    if len(runs) != len(paths) or len(runs) != manifest.get("completed_trials"):
        findings.append("per-trial run file count differs from manifest completed_trials")

    for index, run in enumerate(runs, start=1):
        trial_id = run.get("trial_id", f"trial-{index:03d}")
        target = run.get("target") or {}
        service_name = str(target.get("service_name", ""))
        object_key = str(target.get("object_key", ""))
        condition = str(run.get("condition", "unknown"))
        validation = run.get("validation") or {}
        outcome = str(validation.get("outcome", "MISSING"))
        by_condition[condition][outcome] += 1
        if index <= len(expected_plan):
            plan = expected_plan[index - 1]
            if (
                plan.get("condition"),
                float(plan.get("dwell_seconds", 0)),
                plan.get("replicate"),
            ) != (
                condition,
                float(run.get("planned_dwell_seconds", 0)),
                run.get("replicate"),
            ):
                findings.append(
                    f"{trial_id}: observed trial does not match scheduled plan row {index}"
                )
        expected_key = f"service:{service_name.lower()}"
        if not service_name or object_key != expected_key:
            findings.append(f"{trial_id}: service name/object_key mismatch")
        if service_name in services:
            findings.append(f"{trial_id}: randomized service name reused")
        services.add(service_name)
        if run.get("host_id") != manifest.get("host_id"):
            findings.append(f"{trial_id}: host_id differs from campaign host")

        for label in ("snapshot_before", "snapshot_after"):
            snapshot = run.get(label) or {}
            objects = [
                obj for obj in snapshot.get("objects", []) if obj.get("object_key") == object_key
            ]
            if (
                len(objects) != 1
                or mode((objects[0].get("attributes") or {}).get("start_mode")) != "manual"
            ):
                findings.append(
                    f"{trial_id}: {label} lacks exactly one target service in Manual mode"
                )

        for label in ("monitor_health_before", "monitor_health_after"):
            if ((run.get(label) or {}).get("status")) != "HEALTHY":
                findings.append(f"{trial_id}: {label} is not HEALTHY")
        for label in ("wazuh_service_before", "wazuh_service_after"):
            if ((run.get(label) or {}).get("status")) != "Running":
                findings.append(f"{trial_id}: {label} is not Running")
        cleanup = run.get("cleanup") or {}
        if not cleanup.get("completed") or not cleanup.get("service_absent"):
            findings.append(f"{trial_id}: cleanup did not confirm target service absence")

        transitions = run.get("transition_records", [])
        for record in transitions:
            if (
                record.get("host_id") != run.get("host_id")
                or record.get("object_key") != object_key
            ):
                findings.append(f"{trial_id}: transition record has wrong host or object")
            transition_id = str(record.get("transition_id", ""))
            if transition_id in transition_owner:
                findings.append(f"{trial_id}: transition ID is duplicated in the raw campaign")
            transition_owner[transition_id] = service_name

        auto_start = auto_restore = None
        for action in run.get("action_timeline", []):
            if action.get("action") == "manual_to_auto":
                auto_start = utc(action["completed_at_utc"])
                if action.get("exit_code") != 0:
                    findings.append(f"{trial_id}: Manual-to-Auto command failed")
            elif action.get("action") == "auto_to_manual":
                auto_restore = utc(action["invoked_at_utc"])
                if action.get("exit_code") != 0:
                    findings.append(f"{trial_id}: Auto-to-Manual command failed")

        auto_records = [
            record
            for record in transitions
            if record.get("transition_type") == "SERVICE_START_MODE_CHANGED"
            and mode((record.get("new_state") or {}).get("start_mode")) == "auto"
            and auto_start is not None
            and auto_restore is not None
            and auto_start <= utc(record["observed_at"]) <= auto_restore
        ]
        mode_transitions = [
            record
            for record in transitions
            if record.get("transition_type") == "SERVICE_START_MODE_CHANGED"
        ]
        if condition == "dwell":
            recomputed = "CAPTURED" if auto_records else "NOT_CAPTURED"
            if auto_start is None or auto_restore is None:
                findings.append(f"{trial_id}: dwell action timestamps are missing")
            if outcome in {"CAPTURED", "NOT_CAPTURED"} and outcome != recomputed:
                findings.append(
                    f"{trial_id}: stored primary outcome disagrees with raw transition timestamps"
                )
            if auto_start is not None and auto_restore is not None and auto_restore < auto_start:
                findings.append(f"{trial_id}: negative or reversed dwell interval")
            if run.get("actual_dwell_seconds", 0) <= 0:
                findings.append(f"{trial_id}: actual dwell is not positive")
        elif condition == "stable_no_change" and mode_transitions:
            findings.append(f"{trial_id}: stable control contains a service start-mode transition")

        windows_events = run.get("windows_system_7040", [])
        event_7040_counts[condition] += len(windows_events)
        for event in windows_events:
            if service_name.lower() not in str(event.get("message", "")).lower():
                findings.append(
                    f"{trial_id}: Windows 7040 event message does not name the target service"
                )
            if event.get("record_id") is not None:
                system_record_owner[int(event["record_id"])].add(service_name)

        for attempt in run.get("reconciliation_attempts", []):
            reconciliation_status = str(
                attempt.get("status", attempt.get("query_status", "MISSING"))
            )
            status_counts[reconciliation_status] += 1
            if reconciliation_status == "CORROBORATED":
                reasons = [str(item.get("reason", "")) for item in attempt.get("match_reasons", [])]
                if not any("exact service object" in reason.lower() for reason in reasons):
                    findings.append(
                        f"{trial_id}: CORROBORATED status lacks an explicit exact-object reason"
                    )
            for evidence_id in attempt.get("matched_evidence_ids", []) or []:
                evidence_owner[str(evidence_id)].add(service_name)

    duplicate_evidence = {
        evidence_id: sorted(owners)
        for evidence_id, owners in evidence_owner.items()
        if len(owners) > 1
    }
    duplicate_system_records = {
        str(record_id): sorted(owners)
        for record_id, owners in system_record_owner.items()
        if len(owners) > 1
    }
    if duplicate_evidence:
        findings.append("Wazuh evidence IDs are reused across different randomized service objects")
    if duplicate_system_records:
        findings.append(
            "Windows System event record IDs are reused across randomized service objects"
        )

    return {
        "schema_version": "1.0",
        "campaign_id": manifest.get("campaign_id"),
        "campaign_status": manifest.get("status"),
        "host_id": manifest.get("host_id"),
        "scheduled_trials": manifest.get("scheduled_trials"),
        "manifest_completed_trials": manifest.get("completed_trials"),
        "raw_run_files": len(runs),
        "unique_service_objects": len(services),
        "transition_records": len(transition_owner),
        "unique_wazuh_evidence_ids": len(evidence_owner),
        "duplicate_wazuh_evidence_across_objects": duplicate_evidence,
        "duplicate_windows_system_record_ids_across_objects": duplicate_system_records,
        "reconciliation_status_counts": dict(sorted(status_counts.items())),
        "windows_system_7040_counts_by_condition": dict(sorted(event_7040_counts.items())),
        "outcomes_by_condition": {
            key: dict(sorted(value.items())) for key, value in sorted(by_condition.items())
        },
        "findings": findings,
        "integrity_status": "PASS" if not findings else "REVIEW_REQUIRED",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("campaign_dir", type=Path)
    args = parser.parse_args()
    report = summarize(args.campaign_dir)
    output_dir = args.campaign_dir / "analysis"
    output_dir.mkdir(exist_ok=True)
    (output_dir / "raw-evidence-audit.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
