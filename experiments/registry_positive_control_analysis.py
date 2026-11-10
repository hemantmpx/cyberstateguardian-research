"""Analyze a Windows registry positive-control campaign with source-aware evidence checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

WILSON_Z_95 = 1.959963984540054


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _normalize_identity(value: Any) -> str:
    text = str(value or "").strip().casefold().replace("\\", "/")
    while "//" in text:
        text = text.replace("//", "/")
    return text.replace(":/", "/")


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _inside_action_window(timestamp: Any, action: dict[str, Any]) -> bool:
    event_time = _parse_time(timestamp)
    started_at = _parse_time(action.get("started_at"))
    ended_at = _parse_time(action.get("ended_at"))
    if event_time is None or started_at is None or ended_at is None:
        return False
    return started_at - timedelta(minutes=2) <= event_time <= ended_at + timedelta(minutes=2)


def _seconds_outside_window(timestamp: Any, window: dict[str, Any]) -> float | None:
    event_time = _parse_time(timestamp)
    start = _parse_time(window.get("start"))
    end = _parse_time(window.get("end"))
    if event_time is None or start is None or end is None:
        return None
    if event_time < start:
        return (start - event_time).total_seconds()
    if event_time > end:
        return (event_time - end).total_seconds()
    return 0.0


def _index_class(event: dict[str, Any]) -> str:
    source = event.get("source_reference") or {}
    index_name = str(source.get("index") or "").casefold()
    if index_name.startswith("wazuh-alerts-"):
        return "alert_index"
    if index_name.startswith("wazuh-archives-"):
        return "archive_index"
    return "unclassified_index"


def wilson_interval(successes: int, total: int) -> list[float] | None:
    if total <= 0:
        return None
    proportion = successes / total
    z_squared = WILSON_Z_95**2
    denominator = 1 + z_squared / total
    center = (proportion + z_squared / (2 * total)) / denominator
    margin = (
        WILSON_Z_95
        * math.sqrt(proportion * (1 - proportion) / total + z_squared / (4 * total**2))
        / denominator
    )
    return [max(0.0, center - margin), min(1.0, center + margin)]


def _trial_result(
    campaign_dir: Path, schedule_entry: dict[str, Any], run: dict[str, Any]
) -> dict[str, Any]:
    scenario = next(
        (
            row
            for row in run.get("scenarios", [])
            if row.get("scenario_id") == "registry-autorun-persistence"
        ),
        None,
    )
    if scenario is None:
        raise ValueError(f"{schedule_entry['trial_id']}: missing registry scenario")

    expected_key = _normalize_identity(scenario.get("expected_object_key"))
    object_name = str(scenario.get("object_name") or "")
    action = scenario.get("action") or {}
    state_rows = scenario.get("state_plane", {}).get("after_action_observed") or []
    state_matches = [
        row
        for row in state_rows
        if _normalize_identity(row.get("object_key")) == expected_key
        or str(row.get("name") or "").casefold() == object_name.casefold()
    ]

    local = scenario.get("local_source_evidence") or {}
    local_rows = local.get("exact_events") or []
    local_exact = [
        row
        for row in local_rows
        if row.get("event_id") == 13
        and row.get("exact_identity_match") is True
        and row.get("log_name") == "Microsoft-Windows-Sysmon/Operational"
        and _inside_action_window(row.get("event_time_utc"), action)
    ]

    event_plane = scenario.get("event_plane") or {}
    event_matches = event_plane.get("exact_matches") or []
    exact_events = [
        row
        for row in event_matches
        if row.get("source") == "wazuh"
        and row.get("host_id") == run.get("environment", {}).get("host_id")
        and row.get("normalized_type") == "registry_value_modified"
        and _inside_action_window(row.get("event_time"), action)
        and (
            _normalize_identity((row.get("target") or {}).get("key")) == expected_key
            or _normalize_identity((row.get("attributes") or {}).get("target_object"))
            == expected_key.removeprefix("registry:")
        )
    ]
    sources = {_index_class(row) for row in exact_events}
    exact_ids = {str(row.get("event_id")) for row in exact_events if row.get("event_id")}

    deltas = scenario.get("deltas") or []
    add_deltas = [
        row
        for row in deltas
        if row.get("delta_type") == "ADD"
        and _normalize_identity(row.get("object_key")) == expected_key
    ]
    findings = scenario.get("findings") or []
    add_findings = [
        row
        for row in findings
        if row.get("delta_id") in {delta.get("delta_id") for delta in add_deltas}
        and _normalize_identity(row.get("object_key")) == expected_key
    ]
    reconciliation = max(
        (row.get("reconciliation") or {} for row in add_findings),
        key=lambda row: int(row.get("version") or 0),
        default={},
    )
    matched_ids = {str(value) for value in reconciliation.get("matched_evidence_ids") or []}
    reconciliation_exact = (
        reconciliation.get("status") == "CONSISTENT"
        and bool(exact_ids)
        and bool(matched_ids.intersection(exact_ids))
    )
    reconciliation_window = reconciliation.get("observation_window") or {}
    exact_event_window_checks = [
        {
            "event_id": row.get("event_id"),
            "event_time": row.get("event_time"),
            "source_class": _index_class(row),
            "seconds_outside_csg_reconciliation_window": _seconds_outside_window(
                row.get("event_time"), reconciliation_window
            ),
        }
        for row in exact_events
    ]
    if reconciliation_exact:
        linkage_diagnosis = "EXACT_EVENT_LINKED"
    elif not add_findings:
        linkage_diagnosis = "NO_TARGET_ADD_FINDING"
    elif not exact_events:
        linkage_diagnosis = "NO_EXACT_WAZUH_EVENT"
    elif any(
        item["seconds_outside_csg_reconciliation_window"] is None
        for item in exact_event_window_checks
    ):
        linkage_diagnosis = "CSG_RECONCILIATION_WINDOW_UNAVAILABLE"
    elif any(
        item["seconds_outside_csg_reconciliation_window"] == 0
        for item in exact_event_window_checks
    ):
        linkage_diagnosis = "EXACT_EVENT_WITHIN_WINDOW_NOT_LINKED"
    else:
        linkage_diagnosis = "EXACT_EVENT_OUTSIDE_CSG_RECONCILIATION_WINDOW"
    cleanup_confirmed = scenario.get("state_plane", {}).get("cleanup_removed_from_probe") is True
    query_completed = event_plane.get("query_completed") is True
    positive_control_passed = all(
        (
            bool(state_matches),
            local.get("query_status") == "COMPLETE",
            bool(local_exact),
            bool(exact_events),
            cleanup_confirmed,
            query_completed,
            reconciliation_exact,
        )
    )
    return {
        "trial_id": schedule_entry["trial_id"],
        "schedule_status": schedule_entry.get("status"),
        "target_name": object_name,
        "target_object_key": scenario.get("expected_object_key"),
        "ground_truth": "controlled_reversible_registry_mutation_performed; intent_not_labeled",
        "state_observed": bool(state_matches),
        "state_observation_ids": [
            scenario.get("state_plane", {}).get("after_action_observation_id")
        ],
        "local_query_status": local.get("query_status"),
        "exact_local_sysmon_event_count": len(local_exact),
        "exact_local_sysmon_record_ids": [row.get("record_id") for row in local_exact],
        "wazuh_query_completed": query_completed,
        "exact_wazuh_event_count": len(exact_events),
        "exact_wazuh_event_ids": sorted(exact_ids),
        "exact_wazuh_source_classes": sorted(sources),
        "exact_wazuh_alert_count": sum(_index_class(row) == "alert_index" for row in exact_events),
        "exact_wazuh_archive_count": sum(
            _index_class(row) == "archive_index" for row in exact_events
        ),
        "unclassified_index_event_count": sum(
            _index_class(row) == "unclassified_index" for row in exact_events
        ),
        "csg_add_finding_count": len(add_findings),
        "csg_add_reconciliation_status": reconciliation.get("status"),
        "csg_event_time_tolerance_seconds": (
            (reconciliation.get("metadata") or {}).get("event_time_tolerance_seconds")
        ),
        "csg_add_reconciliation_evidence_ids": sorted(matched_ids),
        "csg_add_reconciliation_window": reconciliation_window,
        "exact_wazuh_event_window_checks": exact_event_window_checks,
        "reconciliation_linkage_diagnosis": linkage_diagnosis,
        "reconciliation_linked_to_exact_event": reconciliation_exact,
        "cleanup_confirmed_by_probe": cleanup_confirmed,
        "strict_positive_control_passed": positive_control_passed,
    }


def analyze_campaign(campaign_dir: Path, campaign_label: str | None = None) -> dict[str, Any]:
    manifest_path = campaign_dir / "campaign-manifest.json"
    manifest = _load(manifest_path)
    if manifest.get("schema_version") != "csg-windows-registry-positive-campaign-v1":
        raise ValueError("unsupported registry positive-control campaign schema")
    if manifest.get("status") not in {"COMPLETED", "COMPLETED_WITH_GAPS"}:
        raise ValueError("campaign must be finalized before analysis")

    input_hashes = {"campaign-manifest.json": _sha256(manifest_path)}
    environment_path = campaign_dir / str(
        manifest.get("environment") or "pretrial-environment.json"
    )
    if environment_path.is_file():
        input_hashes[environment_path.name] = _sha256(environment_path)

    trials: list[dict[str, Any]] = []
    retained_failures: list[dict[str, Any]] = []
    schedule = manifest.get("schedule") or []
    for row in schedule:
        trial_id = str(row["trial_id"])
        run_path = campaign_dir / trial_id / "run.json"
        if row.get("status", "").startswith("COMPLETED") and run_path.is_file():
            input_hashes[f"{trial_id}/run.json"] = _sha256(run_path)
            run = _load(run_path)
            trials.append(_trial_result(campaign_dir, row, run))
        else:
            failure_path = campaign_dir / trial_id / "failure.json"
            if failure_path.is_file():
                input_hashes[f"{trial_id}/failure.json"] = _sha256(failure_path)
                retained_failures.append(_load(failure_path))

    completed = len(trials)
    passed = sum(row["strict_positive_control_passed"] for row in trials)
    source_counts = {
        source: sum(source in row["exact_wazuh_source_classes"] for row in trials)
        for source in ("alert_index", "archive_index", "unclassified_index")
    }
    stage_counts = {
        "state_observed": sum(row["state_observed"] for row in trials),
        "exact_local_sysmon_event": sum(
            row["exact_local_sysmon_event_count"] > 0 for row in trials
        ),
        "exact_wazuh_event_any_index": sum(row["exact_wazuh_event_count"] > 0 for row in trials),
        "exact_wazuh_event_alert_index": sum(row["exact_wazuh_alert_count"] > 0 for row in trials),
        "exact_wazuh_event_archive_index": sum(
            row["exact_wazuh_archive_count"] > 0 for row in trials
        ),
        "csg_reconciled_exact_wazuh_event": sum(
            row["reconciliation_linked_to_exact_event"] for row in trials
        ),
        "cleanup_confirmed": sum(row["cleanup_confirmed_by_probe"] for row in trials),
    }
    duplicate_event_ids: dict[str, list[str]] = {}
    for trial in trials:
        for event_id in trial["exact_wazuh_event_ids"]:
            duplicate_event_ids.setdefault(event_id, []).append(trial["trial_id"])
    duplicate_event_ids = {
        event_id: trial_ids
        for event_id, trial_ids in duplicate_event_ids.items()
        if len(trial_ids) > 1
    }
    return {
        "schema_version": "csg-windows-registry-positive-analysis-v1",
        "analysis_type": "prospective_live_positive_control_pilot",
        "analysis_source": {
            "path": "experiments/registry_positive_control_analysis.py",
            "sha256": _sha256(Path(__file__)),
        },
        "campaign_id": campaign_label or manifest.get("experiment_id"),
        "source_campaign_id": manifest.get("experiment_id"),
        "campaign_status": manifest.get("status"),
        "assigned_trials": len(schedule),
        "completed_trials": completed,
        "retained_failure_count": len(retained_failures),
        "strict_positive_controls_passed": passed,
        "strict_positive_control_rate": passed / completed if completed else None,
        "strict_positive_control_wilson_95": wilson_interval(passed, completed),
        "stage_counts": stage_counts,
        "stage_rates": {
            name: {
                "successes": count,
                "denominator": completed,
                "rate": count / completed if completed else None,
                "wilson_95": wilson_interval(count, completed),
            }
            for name, count in stage_counts.items()
        },
        "trials_with_exact_wazuh_source": source_counts,
        "duplicate_exact_wazuh_event_ids_across_trials": duplicate_event_ids,
        "limitations": [
            "A positive trial is a harmless controlled registry mutation, not malicious activity.",
            "This positive-control-only campaign has no negative class and cannot estimate "
            "specificity, precision, or false-positive rate.",
            "Trials share one Windows 11 ARM64 VM and do not establish cross-host reliability.",
            "Alert-index versus archive-index evidence is reported separately; neither alone "
            "establishes malicious intent.",
            "The 10-trial pilot is a calibration/replication step, not a conference-ready "
            "final study.",
        ],
        "retained_failures": retained_failures,
        "input_sha256": dict(sorted(input_hashes.items())),
        "trials": trials,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--campaign-label")
    args = parser.parse_args()
    result = analyze_campaign(args.campaign_dir, campaign_label=args.campaign_label)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "campaign_id",
                    "source_campaign_id",
                    "campaign_status",
                    "assigned_trials",
                    "completed_trials",
                    "retained_failure_count",
                    "strict_positive_controls_passed",
                    "strict_positive_control_rate",
                    "strict_positive_control_wilson_95",
                    "trials_with_exact_wazuh_source",
                )
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
