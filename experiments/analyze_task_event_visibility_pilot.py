"""Audit the frozen scheduled-task provider-visibility timing pilot."""

# ruff: noqa: E501

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import statistics
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from analyze_scheduled_task_positive_holdout import exact_binomial_interval


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)


def seconds(left: Any, right: Any) -> float | None:
    start, end = timestamp(left), timestamp(right)
    return (end - start).total_seconds() if start and end else None


def task_identity(value: Any) -> str:
    return str(value or "").replace("\\", "").strip().casefold()


def event_time_in_window(value: Any, window: Any) -> bool | None:
    event_at = timestamp(value)
    start = timestamp(window.get("start")) if isinstance(window, dict) else None
    end = timestamp(window.get("end")) if isinstance(window, dict) else None
    return start <= event_at <= end if event_at and start and end else None


def metric_value(row: dict[str, Any], path: str) -> Any:
    value: Any = row
    for part in path.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


def padded_window(start_value: Any, end_value: Any, tolerance: float) -> dict[str, str] | None:
    start, end = timestamp(start_value), timestamp(end_value)
    if not start or not end:
        return None
    return {
        "start": (start - timedelta(seconds=tolerance)).isoformat().replace("+00:00", "Z"),
        "end": (end + timedelta(seconds=tolerance)).isoformat().replace("+00:00", "Z"),
    }


def latest_record(value: Any) -> dict[str, Any]:
    records = [item for item in as_list(value) if isinstance(item, dict)]
    if not records:
        return {}
    return max(records, key=lambda item: int(item.get("version") or 0))


def evidence_ids(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return sorted({str(item) for item in value if isinstance(item, (str, int)) and item})
    if isinstance(value, dict):
        return sorted(
            {
                str(item)
                for items in value.values()
                for item in as_list(items)
                if isinstance(item, (str, int)) and item
            }
        )
    return []


def read_campaign(archive_path: Path) -> tuple[list[dict[str, Any]], str]:
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    trials: list[dict[str, Any]] = []
    pattern = re.compile(r"visibility-(?:(v2)-)?(\d{2})/run\.json$")
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.namelist():
            normalized = member.replace("\\", "/")
            match = pattern.search(normalized)
            if not match:
                continue
            run = json.loads(archive.read(member))
            scenarios = run.get("scenarios", [])
            if len(scenarios) != 1:
                raise ValueError(f"expected one scenario in {member}")
            version_prefix = f"{match.group(1)}-" if match.group(1) else ""
            trials.append(
                {
                    "trial_number": int(match.group(2)),
                    "trial_label": f"visibility-{version_prefix}{match.group(2)}",
                    "run": run,
                    "scenario": scenarios[0],
                }
            )
    trials.sort(key=lambda item: item["trial_number"])
    if len(trials) != 5:
        raise ValueError(f"expected five frozen run artifacts, found {len(trials)}")
    return trials, digest


def summarize_trial(item: dict[str, Any], poll_events: dict[str, Any]) -> dict[str, Any]:
    run, scenario = item["run"], item["scenario"]
    name = scenario.get("object_name")
    key = task_identity(name)
    state = scenario.get("state_plane", {})
    before = state.get("before_action_observation", {})
    after = state.get("after_action_observation", {})
    action = scenario.get("action", {})
    direct_check = state.get("direct_windows_verification", {})
    was_observed_after = any(
        isinstance(record, dict) and task_identity(record.get("task_name")) == key
        for record in as_list(state.get("after_action_observed"))
    )
    local_evidence = scenario.get("local_source_evidence", {})
    local_events = [
        event
        for event in as_list(local_evidence.get("exact_events"))
        if isinstance(event, dict) and event.get("exact_identity_match")
    ]
    event_plane = scenario.get("event_plane", {})
    exact_events = [event for event in as_list(event_plane.get("exact_matches")) if isinstance(event, dict)]
    exact_ids = sorted({str(event["event_id"]) for event in exact_events if event.get("event_id")})
    matching = [
        event
        for event in exact_events
        if event.get("host_id") == "win11-arm-lab"
        and event.get("normalized_type") == scenario.get("expected_event_type")
        and str(event.get("attributes", {}).get("event_code")) == "4698"
        and task_identity(event.get("target", {}).get("task_name")) == key
    ]
    reconciliation = scenario.get("csg_reconciliation", {})
    history = latest_record(reconciliation.get("history"))
    raw_matched_ids = history.get("matched_evidence_ids")
    if raw_matched_ids is None:
        raw_matched_ids = reconciliation.get("matched_evidence_ids")
    matched_ids = evidence_ids(raw_matched_ids)
    add_delta = next(
        (
            delta
            for delta in scenario.get("deltas", [])
            if delta.get("delta_type") == "ADD" and task_identity(delta.get("object_key", "").split(":", 1)[-1]) == key
        ),
        {},
    )
    windows_event = local_events[0] if local_events else {}
    wazuh_event = matching[0] if matching else {}
    source_event = poll_events.get(key, {})
    poll_time = source_event.get("event_time_utc")
    wazuh_time = wazuh_event.get("event_time")
    source_ref = wazuh_event.get("source_reference", {})
    previous_absence = source_event.get("previous_complete_absence_query", {})
    first_seen = source_event.get("first_seen_query", {})
    source_signature_agrees = bool(
        source_event
        and wazuh_event
        and timestamp(poll_time) == timestamp(wazuh_time)
        and source_event.get("host_id") == wazuh_event.get("host_id")
        and source_event.get("normalized_type") == wazuh_event.get("normalized_type")
        and task_identity(source_event.get("task_name")) == key
        and task_identity(wazuh_event.get("target", {}).get("task_name")) == key
    )
    status = reconciliation.get("status")
    finalized = bool(reconciliation.get("finalized"))
    matching_ids = {str(event.get("event_id")) for event in matching if event.get("event_id")}
    gate = bool(
        direct_check.get("target_absent_before_action")
        and direct_check.get("target_present_after_action")
        and was_observed_after
        and direct_check.get("target_absent_after_cleanup")
        and action.get("cleanup_completed")
        and not action.get("error")
        and windows_event.get("event_id") == 4698
        and windows_event.get("exact_identity_match")
        and event_plane.get("query_complete")
        and len(matching) == 1
        and status == "CONSISTENT"
        and finalized
        and set(matched_ids) == matching_ids
    )
    delta_window = add_delta.get("observation_window", {})
    reconciliation_window = history.get("observation_window", {})
    delta_quality = add_delta.get("source_quality", {})
    category_window = {
        "start": delta_quality.get("previous", {}).get("observed_at"),
        "end": delta_quality.get("current", {}).get("observed_at"),
    }
    tolerance = float(history.get("metadata", {}).get("event_time_tolerance_seconds") or 0)
    category_padded_window = padded_window(
        category_window["start"], category_window["end"], tolerance
    )
    direct_bracket = {"start": before.get("observed_at"), "end": after.get("observed_at")}
    local_event_time = windows_event.get("event_time_utc")
    event_time = wazuh_time or poll_time
    first_visible_delay = {
        "lower_seconds": seconds(event_time, previous_absence.get("response_completed_at_utc")),
        "upper_seconds": seconds(event_time, first_seen.get("response_completed_at_utc")),
        "outer_bracket_width_seconds": seconds(
            previous_absence.get("response_completed_at_utc"), first_seen.get("response_completed_at_utc")
        ),
    }
    return {
        "trial_id": item["trial_label"],
        "object_name": name,
        "run_status": run.get("status"),
        "action_started_at_utc": action.get("started_at"),
        "before_probe_observed_at_utc": before.get("observed_at"),
        "after_probe_observed_at_utc": after.get("observed_at"),
        "probe_interval_contains_action_time": bool(
            timestamp(before.get("observed_at"))
            and timestamp(action.get("started_at"))
            and timestamp(after.get("observed_at"))
            and timestamp(before.get("observed_at")) <= timestamp(action.get("started_at")) <= timestamp(after.get("observed_at"))
        ),
        "probe_target_observed_after_action": was_observed_after,
        "delta_observation_window": delta_window,
        "category_sample_observation_window": category_window,
        "category_sample_window_with_frozen_tolerance": category_padded_window,
        "snapshot_envelope_start_lag_after_category_sample_seconds": seconds(
            category_window["start"], delta_window.get("start")
        ),
        "snapshot_envelope_end_lag_after_category_sample_seconds": seconds(
            category_window["end"], delta_window.get("end")
        ),
        "reconciliation_observation_window": reconciliation_window,
        "event_time_utc": event_time,
        "local_security_4698_time_utc": local_event_time,
        "local_security_4698_record_id": windows_event.get("record_id"),
        "local_security_4698_exact_identity": bool(windows_event.get("exact_identity_match")),
        "state_detection_seconds_from_action_to_category_observation": seconds(
            action.get("started_at"), after.get("category_observed_at")
        ),
        "state_detection_seconds_from_action_to_observation_upload": seconds(
            action.get("started_at"), after.get("observed_at")
        ),
        "event_action_to_wazuh_event_timestamp_seconds": seconds(action.get("started_at"), event_time),
        "event_inside_direct_probe_bracket": event_time_in_window(event_time, direct_bracket),
        "event_inside_delta_interval": event_time_in_window(event_time, delta_window),
        "event_inside_category_sample_window_with_frozen_tolerance": event_time_in_window(
            event_time, category_padded_window
        ),
        "event_inside_padded_reconciliation_window": event_time_in_window(event_time, reconciliation_window),
        "provider_archive_event_id": source_event.get("event_id"),
        "provider_archive_index": source_event.get("source_reference", {}).get("index"),
        "provider_archive_document_id": source_event.get("source_reference", {}).get("document_id"),
        "provider_poll_number": first_seen.get("poll_number"),
        "provider_previous_absence_poll_number": previous_absence.get("poll_number"),
        "provider_visibility_delay_bracket": first_visible_delay,
        "wazuh_alert_event_id": wazuh_event.get("event_id"),
        "wazuh_alert_index": source_ref.get("index"),
        "wazuh_alert_document_id": source_ref.get("document_id"),
        "archive_alert_signature_agrees": source_signature_agrees,
        "exact_wazuh_match_count": len(matching),
        "wazuh_query_complete": bool(event_plane.get("query_complete")),
        "csg_status": status,
        "csg_finalized": finalized,
        "csg_matched_evidence_ids": matched_ids,
        "exact_target_event_ids": exact_ids,
        "cleanup_completed": bool(action.get("cleanup_completed") and direct_check.get("target_absent_after_cleanup")),
        "full_positive_control_gate_passed": gate,
    }


def write_outputs(
    rows: list[dict[str, Any]], archive_hash: str, poll_data: dict[str, Any], out_dir: Path
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0])
    with (out_dir / "trial-summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    key: json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value
                    for key, value in row.items()
                }
            )
    passed = sum(bool(row["full_positive_control_gate_passed"]) for row in rows)
    counters = {
        "state_probe_before_after_and_cleanup": sum(
            bool(row["probe_interval_contains_action_time"] and row["cleanup_completed"]) for row in rows
        ),
        "exact_local_security_4698": sum(bool(row["local_security_4698_exact_identity"]) for row in rows),
        "exact_wazuh_event": sum(bool(row["exact_wazuh_match_count"] == 1) for row in rows),
        "archive_alert_signature_agreement": sum(bool(row["archive_alert_signature_agrees"]) for row in rows),
        "final_consistent_csg": sum(bool(row["csg_status"] == "CONSISTENT" and row["csg_finalized"]) for row in rows),
        "full_gate": passed,
    }
    metric_fields = (
        "state_detection_seconds_from_action_to_category_observation",
        "state_detection_seconds_from_action_to_observation_upload",
        "event_action_to_wazuh_event_timestamp_seconds",
        "provider_visibility_delay_bracket.lower_seconds",
        "provider_visibility_delay_bracket.upper_seconds",
    )
    timing = {
        field: {
            "n": len(
                values := [
                    value
                    for row in rows
                    if isinstance(value := metric_value(row, field), (int, float)) and value >= 0
                ]
            ),
            "median_seconds": statistics.median(values) if values else None,
            "min_seconds": min(values) if values else None,
            "max_seconds": max(values) if values else None,
        }
        for field in metric_fields
    }
    visibility_intervals = [row["provider_visibility_delay_bracket"] for row in rows]
    summary = {
        "schema_version": 1,
        "analysis_label": "single-host scheduled-task provider-visibility timing pilot; descriptive only",
        "archive_sha256": archive_hash,
        "poller_status": poll_data.get("status"),
        "provider_queries": len(poll_data.get("polls", [])),
        "complete_provider_queries": sum(bool(poll.get("query_complete") and poll.get("coverage_status") == "COMPLETE") for poll in poll_data.get("polls", [])),
        "baseline_matching_event_count": len(poll_data.get("baseline_task_event_ids", [])),
        "trials": len(rows),
        "outcome_counts": counters,
        "full_gate_rate_exact_two_sided_95pct_clopper_pearson": exact_binomial_interval(passed, len(rows)),
        "descriptive_latency": timing,
        "provider_visibility_delay_brackets_seconds": visibility_intervals,
        "pilot_trial_results": rows,
        "interpretation_limits": [
            "Five benign scheduled-task registrations on one Windows 11 ARM VM; not independent host replication.",
            "Provider first-seen bounds are query-observation intervals, not exact index-ingestion timestamps.",
            "The poller queried every two seconds and therefore adds query load.",
            "A Wazuh alert-index document and archive-index document for one event are not independent Windows events.",
            "A timing-window mismatch is reported as a gate failure; no trial is excluded or retroactively reclassified.",
            "This is not a malicious-activity detection, capture-drop, or no-change-control evaluation.",
        ],
    }
    (out_dir / "timing-analysis.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    gate_ci = summary["full_gate_rate_exact_two_sided_95pct_clopper_pearson"]
    report = [
        "# Scheduled-Task Provider-Visibility Timing Pilot",
        "",
        "## Design and Data",
        "",
        f"This frozen pilot ran {len(rows)} uniquely named, benign scheduled-task registrations on one Windows 11 ARM endpoint. The Windows event log, CSG direct-probe observations, Wazuh provider query, and CSG reconciliation were retained per trial. The Windows archive SHA-256 is `{archive_hash}`. The read-only provider poller completed {summary['complete_provider_queries']}/{summary['provider_queries']} complete queries; the initial baseline contained {summary['baseline_matching_event_count']} matching task events.",
        "",
        "## Results",
        "",
        f"The complete positive-control gate passed {passed}/{len(rows)} trials ({passed / len(rows):.0%}; exact two-sided 95% Clopper-Pearson interval {gate_ci[0]:.3f} to {gate_ci[1]:.3f}). Subchecks: state before/after/cleanup {counters['state_probe_before_after_and_cleanup']}/{len(rows)}; exact Windows Security event 4698 {counters['exact_local_security_4698']}/{len(rows)}; exact Wazuh object event {counters['exact_wazuh_event']}/{len(rows)}; archive/alert event signature agreement {counters['archive_alert_signature_agreement']}/{len(rows)}; finalized CSG CONSISTENT {counters['final_consistent_csg']}/{len(rows)}.",
        f"Provider-visibility delay brackets relative to the Wazuh source timestamp: median lower bound {timing['provider_visibility_delay_bracket.lower_seconds']['median_seconds']:.2f}s, median upper bound {timing['provider_visibility_delay_bracket.upper_seconds']['median_seconds']:.2f}s; these are observed-query bounds, not exact ingestion times.",
        "",
        "| Trial | Task | Local 4698 (UTC) | Wazuh source time (UTC) | Probe category latency (s) | Event in CSG window? | Category-time diagnostic? | CSG final | Archive / alert IDs | Gate |",
        "|---|---|---|---|---:|---|---|---|---|---|",
    ]
    for row in rows:
        ids = f"{row['provider_archive_event_id']} / {row['wazuh_alert_event_id']}"
        latency = row["state_detection_seconds_from_action_to_category_observation"]
        report.append(
            f"| {row['trial_id']} | `{row['object_name']}` | {row['local_security_4698_time_utc']} | {row['event_time_utc']} | {latency if latency is not None else 'NA'} | {row['event_inside_padded_reconciliation_window']} | {row['event_inside_category_sample_window_with_frozen_tolerance']} | {row['csg_status']} ({'final' if row['csg_finalized'] else 'provisional'}) | `{ids}` | {'PASS' if row['full_positive_control_gate_passed'] else 'FAIL'} |"
        )
    report.extend(
        [
            "",
            "## Timing Interpretation",
            "",
            "For each task, the poller recorded the last complete query that did not contain the exact task event and the first complete query that did. The interval in `trial-summary.csv` bounds when the provider query first exposed the archive-index record. It does not claim the index's exact ingestion time. The bounded CSG event retrieval also returned an alert-index document; when its host, task, type, event code, and timestamp agree with the archive record, these are treated as two indexed representations of one Windows event, not two independent events.",
            "",
            "The `Category-time diagnostic?` column is a post-hoc diagnostic only: it recomputes the frozen tolerance around the previous/current category timestamps stored in each delta's source-quality record. It does not overwrite or reclassify the observed CSG result. This comparison tests whether snapshot-envelope times differ from the collector's category sampling times; the corrected delta-time implementation must still pass a new frozen live rerun.",
            "",
            "## Limits",
            "",
            *[f"- {item}" for item in summary["interpretation_limits"]],
            "",
            "Artifacts: `timing-analysis.json`, `trial-summary.csv`, `wazuh-provider-polling.json`, and `windows/raw/windows-pilot.zip`. Raw VM artifacts contain identifying host/account metadata and must be redacted before public release.",
        ]
    )
    (out_dir / "RESULTS.md").write_text("\n".join(report) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--polls", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    campaign, archive_hash = read_campaign(args.archive)
    poll_data = json.loads(args.polls.read_text(encoding="utf-8"))
    poll_events = {
        task_identity(event.get("task_name") or key): event
        for key, event in poll_data.get("events", {}).items()
        if isinstance(event, dict)
    }
    rows = [summarize_trial(item, poll_events) for item in campaign]
    write_outputs(rows, archive_hash, poll_data, args.output_dir)


if __name__ == "__main__":
    main()
