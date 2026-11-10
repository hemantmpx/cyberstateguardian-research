#!/usr/bin/env python3
"""Analyze exact-object Wazuh visibility alongside the frozen CSG dwell outcomes."""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from experiments.analyze_service_dwell_campaign import wilson_interval


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8-sig") as handle:
        return json.load(handle)


def utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * quantile + 0.5)))
    return ordered[index]


def summarize(campaign_dir: Path) -> dict[str, Any]:
    campaign = read_json(campaign_dir / "campaign-manifest.json")
    query_dir = campaign_dir / "analysis" / "wazuh-visibility-posthoc"
    runs = [read_json(path) for path in sorted(campaign_dir.glob("trial-*/run.json"))]
    queries = {path.stem: read_json(path) for path in sorted(query_dir.glob("trial-*.json"))}
    groups: dict[tuple[str, float], list[dict[str, Any]]] = defaultdict(list)
    all_exact_ids: dict[str, set[str]] = defaultdict(set)
    csg_delays: list[float] = []
    event_timestamp_offsets: list[float] = []
    trial_audit: list[dict[str, Any]] = []
    for run in runs:
        trial_id = str(run["trial_id"])
        condition = str(run["condition"])
        dwell = float(run["planned_dwell_seconds"])
        groups[(condition, dwell)].append(run)
        query = queries.get(trial_id, {})
        query_events = query.get("exact_target_events", [])
        validation = run.get("validation") or {}
        windows_events = run.get("windows_system_7040", [])
        exact_keys = [
            (
                event.get("attributes", {}).get("old_start_mode"),
                event.get("attributes", {}).get("new_start_mode"),
            )
            for event in query_events
        ]
        windows_keys = []
        for event in windows_events:
            text = str(event.get("message", "")).lower().rstrip(".")
            if " changed from " in text and " to " in text:
                phrase = text.split(" changed from ", 1)[1]
                old_mode, new_mode = phrase.split(" to ", 1)
                windows_keys.append((old_mode, new_mode))
        event_pairs_match = Counter(exact_keys) == Counter(windows_keys)

        for event in query_events:
            evidence_id = str(event.get("event_id", ""))
            if evidence_id:
                all_exact_ids[evidence_id].add(str(run["target"]["service_name"]))
        if condition == "dwell" and validation.get("primary_capture"):
            action = next(
                item
                for item in run.get("action_timeline", [])
                if item.get("action") == "manual_to_auto"
            )
            transition = next(
                record
                for record in run.get("transition_records", [])
                if record.get("transition_type") == "SERVICE_START_MODE_CHANGED"
                and str((record.get("new_state") or {}).get("start_mode", "")).lower() == "auto"
                and utc(action["completed_at_utc"]) <= utc(record["observed_at"])
            )
            csg_delays.append(
                (utc(transition["observed_at"]) - utc(action["completed_at_utc"])).total_seconds()
            )
        for record in windows_events:
            windows_time = utc(record["time_created_utc"])
            match = next(
                (
                    event
                    for event in query_events
                    if event.get("attributes", {}).get("old_start_mode", "").casefold()
                    in str(record.get("message", "")).casefold()
                    and event.get("attributes", {}).get("new_start_mode", "").casefold()
                    in str(record.get("message", "")).casefold()
                ),
                None,
            )
            if match and match.get("event_time"):
                event_timestamp_offsets.append(
                    (utc(match["event_time"]) - windows_time).total_seconds()
                )

        trial_audit.append(
            {
                "trial_id": trial_id,
                "condition": condition,
                "planned_dwell_seconds": dwell,
                "query_status": query.get("query_status", "MISSING"),
                "query_complete": (query.get("retrieval") or {}).get("query_complete"),
                "exact_wazuh_service_modified_events": len(query_events),
                "windows_system_7040_events": len(windows_events),
                "event_pairs_match": event_pairs_match,
                "csg_primary_outcome": validation.get("outcome"),
                "snapshot_start_modes": [
                    validation.get("snapshot_a_start_mode"),
                    validation.get("snapshot_b_start_mode"),
                ],
                "reconciliation_event_id_overlap": len(
                    query.get("query_evidence_id_overlap_with_reconciliation", [])
                ),
            }
        )

    by_condition: list[dict[str, Any]] = []
    for (condition, dwell), trials in sorted(groups.items()):
        query_complete = sum(
            queries.get(run["trial_id"], {}).get("query_status") == "COMPLETE" for run in trials
        )
        exact_per_trial = [
            len(queries.get(run["trial_id"], {}).get("exact_target_events", [])) for run in trials
        ]
        if condition == "dwell":
            captured = sum(
                bool((run.get("validation") or {}).get("primary_capture")) for run in trials
            )
            csg_rate = captured / len(trials) if trials else None
            csg_ci = wilson_interval(captured, len(trials))
            expected_wazuh = sum(count == 2 for count in exact_per_trial)
            control_false = None
        else:
            captured = sum(count == 0 for count in exact_per_trial)
            csg_rate = None
            csg_ci = None
            expected_wazuh = None
            control_false = sum(count > 0 for count in exact_per_trial)
        by_condition.append(
            {
                "condition": condition,
                "planned_dwell_seconds": dwell,
                "trials": len(trials),
                "provider_queries_complete": query_complete,
                "exact_wazuh_events_by_trial": dict(sorted(Counter(exact_per_trial).items())),
                "trials_with_two_exact_wazuh_events": expected_wazuh,
                "windows_7040_total": sum(
                    len(run.get("windows_system_7040", [])) for run in trials
                ),
                "csg_auto_capture_count": captured if condition == "dwell" else None,
                "csg_auto_capture_rate": csg_rate,
                "csg_wilson_95_interval": csg_ci,
                "stable_control_wazuh_false_event_trials": control_false,
            }
        )

    duplicate_ids = {
        event_id: sorted(owners) for event_id, owners in all_exact_ids.items() if len(owners) > 1
    }
    treatment = [run for run in runs if run.get("condition") == "dwell"]
    captured = sum(bool((run.get("validation") or {}).get("primary_capture")) for run in treatment)
    expected_wazuh_trials = sum(
        len(queries.get(run["trial_id"], {}).get("exact_target_events", [])) == 2
        for run in treatment
    )
    reconciliation_overlap = sum(
        len(
            queries.get(run["trial_id"], {}).get(
                "query_evidence_id_overlap_with_reconciliation", []
            )
        )
        for run in runs
    )
    reconciliation_ids = sum(
        len(queries.get(run["trial_id"], {}).get("reconciliation_evidence_ids", [])) for run in runs
    )
    stable = [run for run in runs if run.get("condition") == "stable_no_change"]
    equal_snapshot_attributes = sum(
        next(
            obj["attributes"]
            for obj in run["snapshot_before"].get("objects", [])
            if obj.get("object_key") == run["target"]["object_key"]
        )
        == next(
            obj["attributes"]
            for obj in run["snapshot_after"].get("objects", [])
            if obj.get("object_key") == run["target"]["object_key"]
        )
        for run in treatment
    )
    return {
        "schema_version": "1.0",
        "campaign_id": campaign.get("campaign_id"),
        "analysis_type": "posthoc_wazuh_visibility_and_cross_plane_consistency",
        "frozen_primary_outcome_modified": False,
        "interpretation_boundary": (
            "Benign startup-mode changes on one Windows VM; this does not establish "
            "malicious-activity detection accuracy."
        ),
        "treatment_trials": len(treatment),
        "csg_auto_state_capture": {
            "captured_trials": captured,
            "trials": len(treatment),
            "rate": captured / len(treatment) if treatment else None,
            "wilson_95_interval": wilson_interval(captured, len(treatment)),
            "captured_auto_transition_latency_seconds": {
                "n": len(csg_delays),
                "median": statistics.median(csg_delays) if csg_delays else None,
                "p95_nearest_rank": percentile(csg_delays, 0.95),
                "max": max(csg_delays) if csg_delays else None,
            },
        },
        "wazuh_exact_event_plane": {
            "treatment_trials_with_both_exact_7040_events": expected_wazuh_trials,
            "treatment_trials": len(treatment),
            "exact_normalized_event_count": len(all_exact_ids),
            "query_completeness": sum(
                query.get("query_status") == "COMPLETE" for query in queries.values()
            ),
            "query_count": len(queries),
            "windows_system_7040_event_count": sum(
                len(run.get("windows_system_7040", [])) for run in treatment
            ),
            "event_timestamp_offset_vs_windows_system_seconds": {
                "n": len(event_timestamp_offsets),
                "median": statistics.median(event_timestamp_offsets)
                if event_timestamp_offsets
                else None,
                "p95_nearest_rank": percentile(event_timestamp_offsets, 0.95),
                "max_absolute": max(
                    (abs(value) for value in event_timestamp_offsets), default=None
                ),
                "interpretation": "Source timestamp agreement only; not Wazuh ingestion latency.",
            },
        },
        "reconciliation": {
            "reconciliation_evidence_ids": reconciliation_ids,
            "exact_query_event_id_overlap": reconciliation_overlap,
            "all_observed_transition_evidence_reconciled_exactly": reconciliation_overlap
            == reconciliation_ids,
            "duplicate_exact_wazuh_event_ids_across_services": duplicate_ids,
        },
        "snapshot_and_control_checks": {
            "treatment_snapshots_with_identical_target_attributes": equal_snapshot_attributes,
            "treatment_trials": len(treatment),
            "stable_no_change_controls": len(stable),
            "stable_controls_without_target_wazuh_service_modified_events": sum(
                len(queries.get(run["trial_id"], {}).get("exact_target_events", [])) == 0
                for run in stable
            ),
            "stable_controls_without_csg_mode_transitions": sum(
                not any(
                    record.get("transition_type") == "SERVICE_START_MODE_CHANGED"
                    for record in run.get("transition_records", [])
                )
                for run in stable
            ),
        },
        "by_condition": by_condition,
        "trial_level": trial_audit,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("campaign_dir", type=Path)
    args = parser.parse_args()
    result = summarize(args.campaign_dir)
    output = args.campaign_dir / "analysis" / "wazuh-visibility-posthoc"
    (output / "detailed-analysis.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {key: value for key, value in result.items() if key != "trial_level"},
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
