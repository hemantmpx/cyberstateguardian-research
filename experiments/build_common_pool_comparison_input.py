"""Build a conservative comparator input from a Windows campaign and common-pool capture."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

MAX_COMMON_POOL_POLL_LAG_SECONDS = 30


def _read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8-sig") as stream:
        return json.load(stream)


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"timestamp must include a timezone: {value}")
    return parsed.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _latest_usable_poll(
    capture: dict[str, Any], cutoff: datetime, window_start: datetime, window_end: datetime
) -> tuple[dict[str, Any] | None, str | None]:
    eligible = [
        poll
        for poll in capture["polls"]
        if poll.get("query_complete") is True
        and poll.get("coverage_status") == "COMPLETE"
        and poll.get("retrieval_metadata", {}).get("complete") is True
        and _time(poll["response_received_at"]) <= cutoff
    ]
    if not eligible:
        return None, "no complete common-pool query completed by target cutoff"
    covering = [
        poll
        for poll in eligible
        if _time(poll["retrieval_metadata"]["start"]) <= window_start
        and _time(poll["retrieval_metadata"]["end"]) >= window_end
    ]
    if not covering:
        poll = max(eligible, key=lambda row: row["response_received_at"])
        return poll, "no complete common-pool query covered the full target observation window"
    poll = max(covering, key=lambda row: row["response_received_at"])
    lag = (cutoff - _time(poll["response_received_at"])).total_seconds()
    max_lag = max(
        MAX_COMMON_POOL_POLL_LAG_SECONDS,
        2 * float(capture["poll_interval_seconds"]),
    )
    if lag > max_lag:
        return poll, f"latest complete poll was {lag:.3f}s before cutoff (limit {max_lag:.3f}s)"
    return poll, None


def _event_record(row: dict[str, Any]) -> dict[str, Any]:
    event = row["event"]
    metadata = event.get("metadata") or {}
    attributes = event.get("attributes") or {}
    return {
        "event_id": event["event_id"],
        "host_id": event["host_id"],
        "object_key": (event.get("target") or {}).get("key"),
        "normalized_type": event["normalized_type"],
        "source": event["source"],
        "source_kind": metadata.get("source_kind", "unknown"),
        "event_time": event["event_time"],
        "first_observed_at": row.get("first_seen_upper_bound") or row["first_observed_at"],
        "rule_id": attributes.get("rule_id") or (metadata.get("rule") or {}).get("id"),
        "source_document_id": (event.get("source_reference") or {}).get("document_id"),
        "synthetic": bool(event.get("synthetic", False)),
    }


def _as_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    return []


def _trial_observation(
    run: dict[str, Any],
    capture: dict[str, Any],
    trial_status: str,
    comparison_window_tolerance_seconds: int,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    trial_id = run["trial_id"]
    details = run["same_host_distractor_proof"]["details"]
    target_key = f"service:{run['service_name'].casefold()}"
    add_deltas = [
        delta
        for delta in run.get("target_state_deltas", [])
        if delta.get("delta_type") == "ADD" and delta.get("object_key", "").casefold() == target_key
    ]
    remove_deltas = [
        delta
        for delta in run.get("target_state_deltas", [])
        if delta.get("delta_type") == "REMOVE"
        and delta.get("object_key", "").casefold() == target_key
    ]
    add_findings = [
        finding
        for finding in _as_list(details.get("add_bounded_finding"))
        if finding.get("object_key", "").casefold() == target_key
    ]
    if not add_deltas or not add_findings:
        return None, {
            "trial_id": trial_id,
            "status": "MISSING_OBSERVATION",
            "reason": "target ADD delta/finding missing",
        }

    delta = add_deltas[0]
    finding = add_findings[0]
    reconciliation = finding.get("reconciliation") or {}
    interval = reconciliation.get("observation_window") or delta.get("observation_window") or {}
    cutoff_text = details.get("add_bounded_snapshot_time")
    if not interval.get("start") or not interval.get("end") or not cutoff_text:
        return None, {
            "trial_id": trial_id,
            "status": "MISSING_OBSERVATION",
            "reason": "bounded observation interval/cutoff missing",
        }
    window_start = _time(interval["start"])
    window_end = _time(interval["end"])
    cutoff = _time(cutoff_text)
    poll, poll_issue = _latest_usable_poll(capture, cutoff, window_start, window_end)

    captured_events = [_event_record(row) for row in capture.get("events", {}).values()]
    event_start = window_start - timedelta(seconds=comparison_window_tolerance_seconds)
    event_end = window_end + timedelta(seconds=comparison_window_tolerance_seconds)
    as_of_events = [
        event
        for event in captured_events
        if event["host_id"] == run["host_id"]
        and event_start <= _time(event["event_time"]) <= event_end
        and _time(event["first_observed_at"]) <= cutoff
    ]
    distractor_name = str(details.get("distractor_service_name", ""))
    distractor_key = f"service:{distractor_name.casefold()}"
    distractor_seen = any(
        event["object_key"]
        and event["object_key"].casefold() == distractor_key
        and event["normalized_type"] == "service_created"
        for event in as_of_events
    )
    target_create_events = [
        event
        for event in as_of_events
        if event["object_key"]
        and event["object_key"].casefold() == target_key
        and event["normalized_type"] == "service_created"
    ]
    distractor_create_events = [
        event
        for event in as_of_events
        if event["object_key"]
        and event["object_key"].casefold() == distractor_key
        and event["normalized_type"] == "service_created"
    ]
    source_state = details.get("source_during_target_add") or {}
    source_stopped = (
        source_state.get("status") == "Stopped"
        and source_state.get("command_exit_code") == 0
        and source_state.get("process_id") == 0
    )
    windows_events = (run.get("windows_source_evidence") or {}).get("events", [])
    target_windows_creation_events = [
        event
        for event in windows_events
        if event.get("event_id") == 7045
        and run["service_name"].casefold() in event.get("message", "").casefold()
    ]
    exact_service_creation = bool(target_windows_creation_events)
    state_observed = (
        bool(delta.get("after"))
        and delta.get("after", {}).get("metadata", {}).get("source") == "direct_probe"
    )
    action_verified = state_observed and exact_service_creation
    condition_attained = source_stopped and distractor_seen
    cleanup_verified = (
        bool(remove_deltas) and (run.get("state_transition") or {}).get("cleanup_present") is False
    )
    matched_ids = reconciliation.get("matched_evidence_ids", [])
    recovery_sync = details.get("add_recovery_sync") or {}
    exact_wazuh = run.get("verified_exact_wazuh_evidence") or {}
    csg_decision = {
        "status": reconciliation.get("status", "UNKNOWN"),
        "finalized": bool(reconciliation.get("finalized", False)),
        "finding_present": True,
        "matched_event_ids": matched_ids,
        "source_coverage_status": "DEGRADED" if source_stopped else "AVAILABLE",
    }
    observation = {
        "trial_id": trial_id,
        "host_id": run["host_id"],
        "target_object_key": target_key,
        "expected_event_types": ["service_created"],
        "window_start": _iso(window_start),
        "window_end": _iso(window_end),
        "cutoff_at": _iso(cutoff),
        "time_tolerance_seconds": comparison_window_tolerance_seconds,
        "event_query_complete": poll is not None and poll_issue is None,
        "action_verified": action_verified,
        "condition_attained": condition_attained,
        "cleanup_verified": cleanup_verified,
        "state_observed": state_observed,
        "expected_reconciliation_status": reconciliation.get("status"),
        "truth_supporting_occurrence_ids": [],
        "events": as_of_events,
        "full_csg": csg_decision,
    }
    audit = {
        "trial_id": trial_id,
        "campaign_status": trial_status,
        "status": "OBSERVED",
        "latest_complete_poll_at_or_before_cutoff": poll.get("response_received_at")
        if poll
        else None,
        "poll_lag_seconds": round((cutoff - _time(poll["response_received_at"])).total_seconds(), 3)
        if poll
        else None,
        "common_pool_query_complete_at_cutoff": observation["event_query_complete"],
        "coverage_issue": poll_issue,
        "exact_target_windows_event_7045": exact_service_creation,
        "native_probe_add_observed": state_observed,
        "wazuh_service_stopped_during_target_add": source_stopped,
        "same_host_distractor_visible_by_cutoff": distractor_seen,
        "same_host_distractor_service_created_event_ids_by_cutoff": [
            event["event_id"] for event in distractor_create_events
        ],
        "target_service_created_event_ids_by_cutoff": [
            event["event_id"] for event in target_create_events
        ],
        "target_windows_7045_records": [
            {"record_id": event.get("record_id"), "event_time": event.get("event_time")}
            for event in target_windows_creation_events
        ],
        "target_reconciliation": reconciliation.get("status"),
        "target_reconciliation_finalized": csg_decision["finalized"],
        "post_restore_query_complete": recovery_sync.get("query_complete"),
        "post_restore_target_service_created_event_ids": recovery_sync.get(
            "exact_target_event_ids", []
        ),
        "post_restore_target_service_modified_event_ids": [
            event.get("event_id") for event in exact_wazuh.get("service_modified", [])
        ],
        "cleanup_verified": cleanup_verified,
    }
    return observation, audit


def merge_captures(captures: list[dict[str, Any]]) -> dict[str, Any]:
    if not captures:
        raise ValueError("at least one common-pool capture is required")
    merged = dict(captures[0])
    merged["polls"] = sorted(
        (poll for capture in captures for poll in capture.get("polls", [])),
        key=lambda poll: poll["response_received_at"],
    )
    merged["poll_interval_seconds"] = min(
        float(capture["poll_interval_seconds"]) for capture in captures
    )
    merged_events: dict[str, dict[str, Any]] = {}
    for capture in captures:
        for event_id, row in capture.get("events", {}).items():
            previous = merged_events.get(event_id)
            if previous is None or _time(
                row.get("first_seen_upper_bound") or row["first_observed_at"]
            ) < _time(previous.get("first_seen_upper_bound") or previous["first_observed_at"]):
                merged_events[event_id] = row
    merged["events"] = merged_events
    merged["unique_event_count"] = len(merged_events)
    merged["capture_status"] = (
        "COMPLETE"
        if all(capture.get("capture_status") == "COMPLETE" for capture in captures)
        else "INCOMPLETE_OR_QUERY_ERRORS"
    )
    return merged


def build_input(
    manifest: dict[str, Any], capture: dict[str, Any], raw_dir: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    runs = {
        path.parent.name: _read_json(path)
        for path in raw_dir.glob("same_host_distractor-*/run.json")
    }
    assignments = []
    observations = []
    audit_rows = []
    for row in manifest.get("runs", []):
        trial_id = row["trial_id"]
        assignments.append(
            {
                "trial_id": trial_id,
                "session_id": manifest["experiment_id"],
                "family": "service",
                "condition": row["condition"],
                "status": row["status"],
                "target_changed": True,
            }
        )
        run = runs.get(trial_id)
        if run is None:
            audit_rows.append(
                {
                    "trial_id": trial_id,
                    "status": "MISSING_OBSERVATION",
                    "reason": "raw run file missing",
                }
            )
            continue
        observation, audit = _trial_observation(
            run,
            capture,
            row["status"],
            int(manifest["declared_event_time_tolerance_seconds"]),
        )
        audit_rows.append(audit)
        if observation is not None:
            observations.append(observation)
    return (
        {
            "campaign_id": manifest["experiment_id"],
            "config": {"wazuh_alert_rule_ids": ["61138"], "wazuh_fim_rule_ids": []},
            "assignments": assignments,
            "observations": observations,
        },
        {
            "schema_version": "csg-common-pool-input-audit-v1",
            "max_common_pool_poll_lag_seconds": MAX_COMMON_POOL_POLL_LAG_SECONDS,
            "assignment_count": len(assignments),
            "observation_count": len(observations),
            "trials": audit_rows,
            "interpretation": (
                "An incomplete as-of common-pool observation is retained as assigned, but is "
                "not eligible for event-absence or event-link scoring."
            ),
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument(
        "--capture",
        required=True,
        action="append",
        type=Path,
        help="Common-pool capture JSON; repeat for adjacent capture windows.",
    )
    parser.add_argument("--raw-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    manifest = _read_json(args.manifest)
    capture = merge_captures([_read_json(path) for path in args.capture])
    campaign_input, audit = build_input(manifest, capture, args.raw_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "comparison-input.json").write_text(
        json.dumps(campaign_input, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.output_dir / "input-audit.json").write_text(
        json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "assignments": audit["assignment_count"],
                "observations": audit["observation_count"],
                "output": str(args.output_dir),
            }
        )
    )


if __name__ == "__main__":
    main()
