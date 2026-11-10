"""Independently audit and summarize a frozen Windows service campaign."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from validate_service_drift_result import validate

Json = dict[str, Any]
CONDITIONS = ("complete", "target_selective_drop", "no_change")
SOURCE_FILES = {
    "controller_sha256": Path("scripts/run_frozen_service_campaign_windows.ps1"),
    "drill_sha256": Path("scripts/run_service_drift_drill_windows.ps1"),
    "validator_sha256": Path("scripts/validate_service_drift_result.py"),
}


def read_json(path: Path) -> Json:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def exact_event(event: Json, host_id: str, service_name: str, event_type: str) -> bool:
    target = event.get("target") or {}
    attributes = event.get("attributes") or {}
    key = str(event.get("target_key") or target.get("key") or "").casefold()
    name = str(event.get("service_name") or attributes.get("service_name") or "").casefold()
    return (
        event.get("host_id") == host_id
        and event.get("source") == "wazuh"
        and event.get("normalized_type") == event_type
        and key == f"service:{service_name}".casefold()
        and name == service_name.casefold()
    )


def windows_event_key(event: Json) -> str:
    identity = (event.get("metadata") or {}).get("windows_event_identity") or {}
    fields = ("agent_id", "channel", "event_record_id", "event_code", "provider_name")
    values = [identity.get(field) for field in fields]
    if all(value is not None for value in values):
        return json.dumps(values, separators=(",", ":"))
    return str(event.get("event_id") or "unknown-event")


def group_windows_event_representations(events: list[Json]) -> list[list[Json]]:
    groups: dict[str, list[Json]] = {}
    for event in events:
        groups.setdefault(windows_event_key(event), []).append(event)
    return list(groups.values())


def target_modify_finding(payload: Json, service_name: str, delta_id: str) -> Json | None:
    object_key = f"service:{service_name.casefold()}"
    candidates = [
        finding
        for finding in payload.get("findings", [])
        if finding.get("category") == "service"
        and str(finding.get("object_key", "")).casefold() == object_key
        and str((finding.get("reconciliation") or {}).get("delta_id", "")) == delta_id
    ]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda finding: int((finding.get("reconciliation") or {}).get("version") or 0),
    )


def wilson(successes: int, trials: int) -> list[float] | None:
    if trials == 0:
        return None
    z = 1.959963984540054
    proportion = successes / trials
    denominator = 1 + z * z / trials
    center = (proportion + z * z / (2 * trials)) / denominator
    margin = (
        z
        * math.sqrt(proportion * (1 - proportion) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    return [round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4)]


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(quantile * len(ordered)) - 1)
    return round(ordered[index], 4)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("--output-directory", type=Path)
    args = parser.parse_args()
    run_dir = args.run_directory.resolve()
    campaign_dir = run_dir / "campaign"
    analysis_dir = (args.output_directory or (run_dir / "analysis")).resolve()
    if analysis_dir.exists():
        raise SystemExit(f"Refusing to overwrite existing audit output: {analysis_dir}")

    manifest_path = campaign_dir / "campaign-manifest.json"
    schedule_path = campaign_dir / "frozen-schedule.json"
    protocol_path = run_dir / "PROTOCOL.md"
    manifest = read_json(manifest_path)
    schedule = read_json(schedule_path)
    checks: list[Json] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    check(
        "controller_completed_all_trials",
        manifest.get("status") == "COMPLETED_ALL_30_VALIDATED_TRIALS"
        and manifest.get("completed_trials") == 30,
        f"status={manifest.get('status')}; completed={manifest.get('completed_trials')}",
    )
    check(
        "frozen_schedule_hash",
        sha256(schedule_path) == manifest.get("frozen_schedule_sha256"),
        f"sha256={sha256(schedule_path)}",
    )
    check(
        "protocol_hash",
        sha256(protocol_path) == manifest.get("protocol_sha256"),
        f"sha256={sha256(protocol_path)}",
    )
    source_hashes: dict[str, str] = {}
    root = Path(__file__).resolve().parents[1]
    for field, relative_path in SOURCE_FILES.items():
        actual = sha256(root / relative_path)
        source_hashes[field] = actual
        check(f"source_{field}", actual == manifest.get(field), f"sha256={actual}")

    listed_schedule = {row.get("trial_id"): row for row in manifest.get("schedule", [])}
    frozen_by_id = {row.get("trial_id"): row for row in schedule}
    schedule_matches = set(listed_schedule) == set(frozen_by_id)
    if schedule_matches:
        schedule_matches = all(
            all(
                listed_schedule[key].get(field) == frozen_by_id[key].get(field)
                for field in (
                    "block",
                    "condition",
                    "repetition",
                    "service_name",
                    "distractor_service_name",
                )
            )
            for key in frozen_by_id
        )
    check("mutable_manifest_matches_frozen_schedule", schedule_matches, f"slots={len(schedule)}")

    counts = {condition: 0 for condition in CONDITIONS}
    blocks: dict[int, set[str]] = {}
    mutating_targets: list[str] = []
    distractor_names: list[str] = []
    no_change_names: list[str] = []
    for row in schedule:
        condition = row.get("condition")
        if condition in counts:
            counts[condition] += 1
        blocks.setdefault(int(row.get("block", 0)), set()).add(str(condition))
        if condition == "no_change":
            no_change_names.append(str(row.get("service_name", "")))
        else:
            mutating_targets.append(str(row.get("service_name", "")))
            distractor_names.append(str(row.get("distractor_service_name", "")))
    check(
        "balanced_10x3_schedule",
        counts == {c: 10 for c in CONDITIONS} and len(schedule) == 30,
        f"condition_counts={counts}",
    )
    check(
        "complete_randomized_blocks",
        len(blocks) == 10 and all(set(CONDITIONS) == value for value in blocks.values()),
        f"blocks={len(blocks)}",
    )
    check(
        "unique_mutating_service_names",
        len(mutating_targets) == len(set(mutating_targets)) == 20,
        f"unique={len(set(mutating_targets))}/20",
    )
    check(
        "unique_distractor_names",
        len(distractor_names) == len(set(distractor_names)) == 20,
        f"unique={len(set(distractor_names))}/20",
    )
    check(
        "no_change_uses_unchanged_control_service",
        len(no_change_names) == 10 and set(no_change_names) == {"Winmgmt"},
        f"control_names={sorted(set(no_change_names))}; n={len(no_change_names)}",
    )
    check(
        "target_and_distractor_names_disjoint",
        not (set(mutating_targets) & set(distractor_names)),
        f"name_collisions={len(set(mutating_targets) & set(distractor_names))}",
    )

    remote_validations: dict[str, Json] = {}
    rows: list[Json] = []
    independent_validations: dict[str, Json] = {}
    target_event_ids: list[str] = []
    distractor_event_ids: list[str] = []
    target_event_id_owners: dict[str, set[str]] = {}
    distractor_event_id_owners: dict[str, set[str]] = {}
    target_source_event_owners: dict[str, set[str]] = {}
    distractor_source_event_owners: dict[str, set[str]] = {}
    normalized_target_event_count = 0
    distinct_target_source_event_count = 0
    state_latencies: list[float] = []
    first_query_delays: list[float] = []
    signed_event_offsets: list[float] = []
    primary_counts = {
        condition: {
            "n": 0,
            "state_observed": 0,
            "expected_result_correct": 0,
            "exact_target_event_present": 0,
            "local_target_event_present": 0,
            "wrong_object_event_present_and_rejected": 0,
            "false_positive_findings": 0,
        }
        for condition in CONDITIONS
    }

    for frozen in schedule:
        trial_id = str(frozen["trial_id"])
        condition = str(frozen["condition"])
        raw_path = campaign_dir / trial_id / "run.json"
        remote_validation_path = campaign_dir / trial_id / "validation.json"
        payload = read_json(raw_path)
        remote_validation = read_json(remote_validation_path)
        local_validation = validate(payload)
        remote_validations[trial_id] = remote_validation
        independent_validations[trial_id] = local_validation

        source_name = str(frozen["service_name"])
        trial_identity_ok = (
            payload.get("experiment_id") == manifest.get("experiment_id")
            and payload.get("trial_id") == trial_id
            and payload.get("telemetry_condition") == condition
            and str(payload.get("service_name", "")).casefold() == source_name.casefold()
            and payload.get("run_status") == "COMPLETED"
        )
        check(
            f"{trial_id}_identity", trial_identity_ok, "raw IDs/condition match frozen assignment"
        )
        check(
            f"{trial_id}_independent_validator",
            local_validation.get("passed") is True and remote_validation.get("passed") is True,
            f"local={local_validation.get('passed')}; endpoint={remote_validation.get('passed')}",
        )
        if local_validation.get("passed") != remote_validation.get("passed"):
            check(f"{trial_id}_validator_agreement", False, "endpoint and local validator disagree")
        else:
            check(f"{trial_id}_validator_agreement", True, "endpoint and local validator agree")

        identity = f"service:{source_name.casefold()}"
        target_deltas = [
            delta
            for delta in payload.get("target_state_deltas", [])
            if delta.get("category") == "service"
            and str(delta.get("object_key", "")).casefold() == identity
            and delta.get("delta_type") == "MODIFY"
        ]
        state = payload.get("state_transition") or {}
        before = state.get("before") or {}
        after = state.get("after") or {}
        mutation_observed = (
            (
                len(target_deltas) == 1
                and before.get("service_name", "").casefold() == source_name.casefold()
                and after.get("service_name", "").casefold() == source_name.casefold()
                and before.get("start_mode") == "Manual"
                and after.get("start_mode") == "Auto"
            )
            if condition != "no_change"
            else (
                state.get("delta_type") == "NONE"
                and state.get("attributes_unchanged") is True
                and state.get("independent_os_attributes_unchanged") is True
                and state.get("new_target_delta_count") == 0
                and state.get("new_target_finding_count") == 0
                and payload.get("action_journal", {}).get("mutation_performed") is False
                and not payload.get("target_state_deltas")
                and not payload.get("findings")
            )
        )
        check(
            f"{trial_id}_state_or_no_change",
            mutation_observed,
            f"condition={condition}; target_modify_deltas={len(target_deltas)}",
        )

        modify_delta_id = str(target_deltas[0].get("delta_id")) if len(target_deltas) == 1 else ""
        finding = (
            target_modify_finding(payload, source_name, modify_delta_id)
            if modify_delta_id
            else None
        )
        reconciliation = (finding or {}).get("reconciliation") or {}
        matched_ids = set(reconciliation.get("matched_evidence_ids") or [])
        evidence = payload.get("verified_exact_wazuh_evidence") or {}
        target_modify_events = list(evidence.get("service_modified") or [])
        exact_target_events = [
            event
            for event in target_modify_events
            if exact_event(event, str(payload.get("host_id")), source_name, "service_modified")
        ]
        target_event_groups = group_windows_event_representations(exact_target_events)
        exact_event_ids = {
            str(event.get("event_id")) for event in exact_target_events if event.get("event_id")
        }
        local_7040 = [
            event
            for event in (payload.get("windows_source_evidence") or {}).get("events", [])
            if event.get("event_id") == 7040
            and source_name.casefold() in str(event.get("message", "")).casefold()
        ]
        distractor_details = (payload.get("same_host_distractor_proof") or {}).get("details") or {}
        distractor_name = str(distractor_details.get("distractor_service_name") or "")
        distractor_events = list(
            (distractor_details.get("modify") or {}).get("exact_wazuh_events") or []
        )
        exact_distractors = [
            event
            for event in distractor_events
            if distractor_name
            and exact_event(
                event, str(payload.get("host_id")), distractor_name.casefold(), "service_modified"
            )
        ]
        distractor_event_groups = group_windows_event_representations(exact_distractors)
        correct_event_citation = (
            bool(exact_event_ids & matched_ids) and matched_ids <= exact_event_ids
        )
        status = reconciliation.get("status") if finding else None
        expected = {
            "complete": status == "CONSISTENT"
            and correct_event_citation
            and len(target_event_groups) == 1,
            "target_selective_drop": (
                status == "UNEXPLAINED"
                and not matched_ids
                and not target_modify_events
                and bool(local_7040)
                and bool(exact_distractors)
                and len(distractor_event_groups) == 1
                and distractor_name.casefold() != source_name.casefold()
            ),
            "no_change": mutation_observed,
        }[condition]
        service_health = payload.get("event_plane_status") or {}
        if condition != "no_change":
            expected = expected and (
                service_health.get("event_query_status") == "SUCCEEDED"
                and service_health.get("endpoint_service_status") == "Running"
                and service_health.get("endpoint_collection_status") == "active"
                and service_health.get("manager_status") == "AVAILABLE"
                and service_health.get("indexer_status") == "AVAILABLE"
            )
        check(
            f"{trial_id}_condition_outcome",
            expected,
            (
                f"status={status}; exact_target_event_count={len(exact_target_events)}; "
                f"local_7040={len(local_7040)}; "
                f"exact_distractors={len(exact_distractors)}"
            ),
        )

        counts = primary_counts[condition]
        counts["n"] += 1
        if condition == "no_change":
            counts["expected_result_correct"] += int(expected)
            counts["false_positive_findings"] += int(bool(payload.get("findings")))
        else:
            counts["state_observed"] += int(mutation_observed)
            counts["expected_result_correct"] += int(expected)
            counts["exact_target_event_present"] += int(bool(exact_target_events))
            counts["local_target_event_present"] += int(bool(local_7040))
            counts["wrong_object_event_present_and_rejected"] += int(
                condition == "target_selective_drop"
                and bool(exact_distractors)
                and status == "UNEXPLAINED"
                and not matched_ids
            )
            action_time = timestamp(
                (payload.get("timing_boundaries") or {}).get("action_completed_at")
            )
            received_time = timestamp(
                (payload.get("timing_boundaries") or {}).get("state_received_at")
            )
            if action_time and received_time:
                delay = (received_time - action_time).total_seconds()
                if delay >= 0:
                    state_latencies.append(delay)
            if condition == "complete":
                normalized_target_event_count += len(exact_target_events)
                distinct_target_source_event_count += len(target_event_groups)
                for event in exact_target_events:
                    event_id = str(event.get("event_id", ""))
                    if event_id:
                        target_event_ids.append(event_id)
                        target_event_id_owners.setdefault(event_id, set()).add(trial_id)
                for group in target_event_groups:
                    target_source_event_owners.setdefault(windows_event_key(group[0]), set()).add(
                        trial_id
                    )
                if len(target_event_groups) == 1:
                    group = target_event_groups[0]
                    event = next(
                        (
                            item
                            for item in group
                            if "wazuh-alerts"
                            in str((item.get("source_reference") or {}).get("index", ""))
                        ),
                        group[0],
                    )
                    source_group_ids = {
                        str(item.get("event_id")) for item in group if item.get("event_id")
                    }
                    event_time = timestamp(event.get("event_time"))
                    for timeline_entry in payload.get("timeline", []):
                        response = timeline_entry.get("response") or {}
                        response_ids = set(response.get("exact_target_event_ids") or [])
                        response_ids.update(response.get("newly_ingested_target_event_ids") or [])
                        retrieved_at = timestamp(response.get("response_received_at"))
                        if source_group_ids & response_ids and event_time and retrieved_at:
                            query_delay = (retrieved_at - event_time).total_seconds()
                            if query_delay >= 0:
                                first_query_delays.append(query_delay)
                            break
                    offset = (payload.get("latency_measurements") or {}).get(
                        "event_occurrence_offset_from_action_end_seconds"
                    )
                    if isinstance(offset, (int, float)):
                        signed_event_offsets.append(float(offset))
            else:
                for event in exact_distractors:
                    event_id = str(event.get("event_id", ""))
                    if event_id:
                        distractor_event_ids.append(event_id)
                        distractor_event_id_owners.setdefault(event_id, set()).add(trial_id)
                for group in distractor_event_groups:
                    distractor_source_event_owners.setdefault(
                        windows_event_key(group[0]), set()
                    ).add(trial_id)

        rows.append(
            {
                "block": frozen.get("block"),
                "trial_id": trial_id,
                "condition": condition,
                "service_name": source_name,
                "distractor_service_name": distractor_name or "",
                "state_or_no_change_verified": mutation_observed,
                "target_modify_delta_count": len(target_deltas),
                "exact_target_modify_event_count": len(exact_target_events),
                "distinct_target_windows_event_count": len(target_event_groups),
                "target_windows_event_record_ids": ";".join(
                    sorted(
                        {
                            str(
                                (event.get("metadata") or {})
                                .get("windows_event_identity", {})
                                .get("event_record_id", "")
                            )
                            for group in target_event_groups
                            for event in group
                        }
                        - {""}
                    )
                ),
                "local_target_event_7040_count": len(local_7040),
                "exact_wrong_object_modify_event_count": len(exact_distractors),
                "distinct_wrong_object_windows_event_count": len(distractor_event_groups),
                "reconciliation_status": status or "NO_FINDING",
                "matched_evidence_ids": ";".join(sorted(matched_ids)),
                "target_event_ids": ";".join(sorted(exact_event_ids)),
                "distractor_event_ids": ";".join(
                    sorted(
                        str(event.get("event_id"))
                        for event in exact_distractors
                        if event.get("event_id")
                    )
                ),
                "expected_outcome_correct": expected,
                "validator_passed": local_validation.get("passed") is True,
                "action_to_probe_observation_seconds": (
                    payload.get("latency_measurements") or {}
                ).get("state_detection_seconds"),
            }
        )

    reused_target_ids = [
        event_id for event_id, owners in target_event_id_owners.items() if len(owners) > 1
    ]
    reused_distractor_ids = [
        event_id for event_id, owners in distractor_event_id_owners.items() if len(owners) > 1
    ]
    reused_target_records = [
        key for key, owners in target_source_event_owners.items() if len(owners) > 1
    ]
    reused_distractor_records = [
        key for key, owners in distractor_source_event_owners.items() if len(owners) > 1
    ]
    check(
        "target_event_ids_not_reused_across_trials",
        not reused_target_ids,
        f"reused_ids={len(reused_target_ids)}",
    )
    check(
        "distractor_event_ids_not_reused_across_trials",
        not reused_distractor_ids,
        f"reused_ids={len(reused_distractor_ids)}",
    )
    check(
        "target_windows_event_records_not_reused_across_trials",
        not reused_target_records,
        (
            f"reused_records={len(reused_target_records)}; "
            f"unique_underlying_events={len(target_source_event_owners)}"
        ),
    )
    check(
        "distractor_windows_event_records_not_reused_across_trials",
        not reused_distractor_records,
        (
            f"reused_records={len(reused_distractor_records)}; "
            f"unique_underlying_events={len(distractor_source_event_owners)}"
        ),
    )
    check(
        "target_event_ids_do_not_overlap_distractor_ids",
        not (set(target_event_ids) & set(distractor_event_ids)),
        f"overlap={len(set(target_event_ids) & set(distractor_event_ids))}",
    )
    check(
        "state_latency_available_for_all_mutations",
        len(state_latencies) == 20,
        f"valid_nonnegative_measurements={len(state_latencies)}/20",
    )
    check(
        "first_query_delay_available_for_all_complete_trials",
        len(first_query_delays) == 10,
        f"valid_nonnegative_measurements={len(first_query_delays)}/10",
    )
    check(
        "signed_event_offset_available_for_all_complete_trials",
        len(signed_event_offsets) == 10,
        f"measurements={len(signed_event_offsets)}/10",
    )

    postflight_path = campaign_dir / "postflight.json"
    postflight = read_json(postflight_path)
    check(
        "endpoint_postflight_restored",
        postflight.get("postflight_valid") is True,
        (
            f"wazuh={postflight.get('wazuh_service_status')}; "
            f"pid={postflight.get('wazuh_service_pid')}; "
            f"config_restored={postflight.get('wazuh_config_restored')}; "
            f"leftovers={postflight.get('windows_leftover_test_services')}"
        ),
    )
    check(
        "postflight_wazuh_pid_present",
        int(postflight.get("wazuh_service_pid") or 0) > 0,
        f"pid={postflight.get('wazuh_service_pid')}",
    )
    check(
        "preflight_wazuh_baseline_matches_postflight",
        postflight.get("wazuh_agent_config_sha256")
        == (read_json(campaign_dir / "preflight.json")).get("wazuh_agent_config_sha256"),
        "Wazuh agent configuration SHA-256 is unchanged",
    )

    metrics: dict[str, Json] = {}
    for condition, values in primary_counts.items():
        n = values["n"]
        metrics[condition] = {
            **values,
            "correct_outcome_rate": values["expected_result_correct"] / n if n else None,
            "correct_outcome_wilson_95_ci": wilson(values["expected_result_correct"], n),
        }
    mutation_n = primary_counts["complete"]["n"] + primary_counts["target_selective_drop"]["n"]
    state_n = (
        primary_counts["complete"]["state_observed"]
        + primary_counts["target_selective_drop"]["state_observed"]
    )
    metrics["overall"] = {
        "planned_trials": 30,
        "raw_trials": len(rows),
        "independent_validations_passed": sum(row["validator_passed"] for row in rows),
        "mutation_trials": mutation_n,
        "mutations_observed_by_native_probe": state_n,
        "normalized_complete_arm_target_event_evidence_entries": normalized_target_event_count,
        "distinct_complete_arm_windows_event_records": distinct_target_source_event_count,
        "normalized_duplicate_representations": normalized_target_event_count
        - distinct_target_source_event_count,
        "distinct_suppression_arm_distractor_windows_event_records": len(
            distractor_source_event_owners
        ),
        "retained_state_visibility_under_selective_event_drop": {
            "successes": primary_counts["target_selective_drop"]["state_observed"],
            "trials": primary_counts["target_selective_drop"]["n"],
            "rate": primary_counts["target_selective_drop"]["state_observed"]
            / max(1, primary_counts["target_selective_drop"]["n"]),
            "wilson_95_ci": wilson(
                primary_counts["target_selective_drop"]["state_observed"],
                primary_counts["target_selective_drop"]["n"],
            ),
        },
        "complete_arm_exact_consistent": (
            f"{primary_counts['complete']['expected_result_correct']}/"
            f"{primary_counts['complete']['n']}"
        ),
        "selective_drop_arm_exact_unexplained": (
            f"{primary_counts['target_selective_drop']['expected_result_correct']}/"
            f"{primary_counts['target_selective_drop']['n']}"
        ),
        "no_change_false_findings": (
            f"{primary_counts['no_change']['false_positive_findings']}/"
            f"{primary_counts['no_change']['n']}"
        ),
        "state_action_to_probe_observation_seconds": {
            "n": len(state_latencies),
            "median": round(statistics.median(state_latencies), 4) if state_latencies else None,
            "p95_nearest_rank": percentile(state_latencies, 0.95),
            "min": round(min(state_latencies), 4) if state_latencies else None,
            "max": round(max(state_latencies), 4) if state_latencies else None,
            "interpretation": (
                "Synchronous action-triggered one-shot probe response; "
                "not autonomous scheduled-probe latency."
            ),
        },
        "event_timestamp_to_first_csg_query_response_seconds": {
            "n": len(first_query_delays),
            "median": round(statistics.median(first_query_delays), 4)
            if first_query_delays
            else None,
            "p95_nearest_rank": percentile(first_query_delays, 0.95),
            "interpretation": (
                "Time from Windows event timestamp to first recorded CSG provider-query "
                "response containing the exact Wazuh event; not Wazuh ingestion latency."
            ),
        },
        "event_timestamp_minus_action_completion_signed_seconds": {
            "n": len(signed_event_offsets),
            "median": round(statistics.median(signed_event_offsets), 4)
            if signed_event_offsets
            else None,
            "interpretation": (
                "Signed host event-time offset; not a latency or source-ingestion measurement."
            ),
        },
    }

    audit_valid = all(item["passed"] for item in checks)
    audit = {
        "schema_version": "csg-frozen-service-campaign-audit-v1",
        "experiment_id": manifest.get("experiment_id"),
        "audited_at_utc": datetime.now(UTC).isoformat(),
        "audit_script_sha256": sha256(Path(__file__).resolve()),
        "audit_valid": audit_valid,
        "host_id": manifest.get("host_id"),
        "checks_passed": sum(item["passed"] for item in checks),
        "checks_total": len(checks),
        "checks": checks,
        "condition_metrics": metrics,
        "trial_summary": rows,
        "notes": [
            "Repeated trials are on one Windows VM and are not independent host replications.",
            "The temporary inert service is not malware; results do not establish "
            "malicious-activity detection.",
            "The selective-drop arm filters only the target Event 7040 and exact target "
            "service FIM path; Wazuh remains active and the target Event 7040 remains "
            "in the local Windows System log.",
            "Latency fields are separated by measurement boundary; no metric here "
            "estimates Wazuh event ingestion latency.",
        ],
    }

    analysis_dir.mkdir(parents=True)
    (analysis_dir / "independent-validation.json").write_text(
        json.dumps(independent_validations, indent=2) + "\n", encoding="utf-8"
    )
    (analysis_dir / "campaign-audit.json").write_text(
        json.dumps(audit, indent=2) + "\n", encoding="utf-8"
    )
    (analysis_dir / "trial-summary.json").write_text(
        json.dumps(rows, indent=2) + "\n", encoding="utf-8"
    )
    if rows:
        with (analysis_dir / "trial-summary.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    artifact_paths = [
        protocol_path,
        *(root / path for path in SOURCE_FILES.values()),
        Path(__file__).resolve(),
    ]
    artifact_paths.extend(path for path in campaign_dir.rglob("*") if path.is_file())
    artifact_entries = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256(path),
            "size_bytes": path.stat().st_size,
        }
        for path in sorted(set(artifact_paths))
    ]
    artifact_manifest = {
        "schema_version": "csg-experiment-artifact-manifest-v1",
        "experiment_id": manifest.get("experiment_id"),
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "entries": artifact_entries,
        "manifest_scope_note": (
            "Hashes protocol, frozen source files, schedule, pre/postflight, raw trial "
            "artifacts, endpoint validations, and controller manifests; analysis outputs "
            "are separate derived products."
        ),
    }
    artifact_manifest_path = analysis_dir / "artifact-manifest.json"
    artifact_manifest_path.write_text(
        json.dumps(artifact_manifest, indent=2) + "\n", encoding="utf-8"
    )
    (analysis_dir / "artifact-manifest.sha256").write_text(
        f"{sha256(artifact_manifest_path)}  artifact-manifest.json\n", encoding="ascii"
    )
    print(
        json.dumps(
            {
                "audit_valid": audit_valid,
                "checks_passed": audit["checks_passed"],
                "checks_total": audit["checks_total"],
                "metrics": metrics,
            },
            indent=2,
        )
    )
    if not audit_valid:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
