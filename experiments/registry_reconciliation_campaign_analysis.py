"""Audit and summarize a frozen three-condition Windows reconciliation campaign."""

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

WILSON_Z_95 = 1.959963984540054
CONDITIONS = ("registry_complete", "registry_eventid_drop", "registry_no_change")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_identity(value: Any) -> str:
    text = str(value or "").strip().casefold().replace("\\", "/")
    while "//" in text:
        text = text.replace("//", "/")
    return text.replace(":/", "/")


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def seconds_between(start: Any, end: Any) -> float | None:
    first, second = parse_time(start), parse_time(end)
    if first is None or second is None:
        return None
    return (second - first).total_seconds()


def wilson_interval(successes: int, total: int) -> list[float] | None:
    if total == 0:
        return None
    p = successes / total
    z2 = WILSON_Z_95**2
    denominator = 1 + z2 / total
    center = (p + z2 / (2 * total)) / denominator
    half_width = WILSON_Z_95 * math.sqrt(p * (1 - p) / total + z2 / (4 * total**2)) / denominator
    return [max(0.0, center - half_width), min(1.0, center + half_width)]


def latest_reconciliation(run: dict[str, Any]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for row in run.get("target", {}).get("reconciliation_history", []):
        if row.get("latest"):
            candidates.append(row["latest"])
        candidates.extend(row.get("revisions") or [])
    return max(
        candidates,
        key=lambda item: (int(item.get("version") or 0), str(item.get("created_at") or "")),
        default={},
    )


def event_identity_matches(event: dict[str, Any], key: str, host_id: str) -> bool:
    target = event.get("target") or {}
    attributes = event.get("attributes") or {}
    normalized_key = normalize_identity(target.get("key") or target.get("object_key"))
    if not normalized_key:
        normalized_key = normalize_identity("registry:" + str(attributes.get("target_object") or ""))
    return (
        event.get("host_id") == host_id
        and event.get("normalized_type") == "registry_value_modified"
        and normalized_key == normalize_identity(key)
    )


def query_health(run: dict[str, Any], wazuh_events: list[dict[str, Any]]) -> dict[str, Any]:
    observation = run.get("source_event_ingestion", {}).get("provider_observation") or {}
    if observation:
        return {
            "query_complete": observation.get("query_complete") is True,
            "coverage_status": observation.get("coverage_status"),
            "endpoint_collection_status": observation.get("endpoint_collection_status"),
            "transport_status": observation.get("transport_status"),
            "index_status": observation.get("index_status"),
            "returned_event_count": len(observation.get("events") or []),
        }
    retrievals = [
        (event.get("metadata") or {}).get("retrieval") or {}
        for event in wazuh_events
    ]
    health = [
        (event.get("metadata") or {}).get("source_health") or {}
        for event in wazuh_events
    ]
    retrieval = retrievals[0] if retrievals else {}
    source = health[0] if health else {}
    return {
        "query_complete": bool(retrieval.get("complete")) if retrieval else False,
        "coverage_status": "COMPLETE" if retrieval.get("complete") else "UNKNOWN",
        "endpoint_collection_status": source.get("endpoint_collection_status"),
        "transport_status": source.get("transport_status"),
        "index_status": source.get("index_status"),
        "returned_event_count": retrieval.get("normalized_events"),
    }


def trial_outcome(
    trial_id: str, schedule: dict[str, Any], run: dict[str, Any], postflight: dict[str, Any]
) -> dict[str, Any]:
    condition = str(schedule.get("condition"))
    host_id = str(run.get("host_id") or "")
    target_key = str(run.get("target_object_key") or "")
    target = run.get("target") or {}
    source = run.get("source_event_ingestion") or {}
    local_events = target.get("sysmon_exact_events") or []
    provider_events = [
        event for event in target.get("wazuh_provider_exact_events") or []
        if event_identity_matches(event, target_key, host_id)
    ]
    database_events = [
        event for event in target.get("database_exact_events") or []
        if event_identity_matches(event, target_key, host_id)
    ]
    deltas = [
        delta for delta in target.get("deltas") or []
        if delta.get("delta_type") == "ADD"
        and normalize_identity(delta.get("object_key")) == normalize_identity(target_key)
    ]
    findings = [
        finding for finding in target.get("findings") or []
        if normalize_identity(finding.get("object_key")) == normalize_identity(target_key)
    ]
    reconciliation = latest_reconciliation(run)
    matched_ids = [str(value) for value in reconciliation.get("matched_evidence_ids") or []]
    provider_ids = {str(event.get("event_id")) for event in provider_events if event.get("event_id")}
    state = run.get("target_state") or {}
    query = query_health(run, provider_events)
    source_absence_verified = (
        query["query_complete"] is True
        and query["coverage_status"] == "COMPLETE"
        and query["endpoint_collection_status"] == "AVAILABLE"
        and query["transport_status"] == "AVAILABLE"
        and query["index_status"] == "AVAILABLE"
    )
    local_event_ids = [str(event.get("record_id")) for event in local_events]
    exact_wazuh_identity_valid = all(
        event_identity_matches(event, target_key, host_id) for event in provider_events
    )
    state_seen = state.get("absent_before") is True and state.get("present_after") is True
    delta_seen = len(deltas) == 1
    cleanup = run.get("cleanup") or {}
    cleanup_pass = (
        cleanup.get("target_absent") is True
        and cleanup.get("cleanup_probe_succeeded") is True
        and not (cleanup.get("errors") or [])
        and (condition == "registry_no_change" or cleanup.get("distractor_absent") is True)
    )
    filter_status = (run.get("target_event_filter") or {}).get("status")
    action = (run.get("action_journal") or {}).get("target_create") or {}
    action_start = action.get("started_at")
    action_end = action.get("completed_at")
    first_local_time = min(
        (event.get("event_time_utc") for event in local_events if event.get("event_time_utc")),
        default=None,
    )
    first_wazuh_time = min(
        (event.get("event_time") for event in provider_events if event.get("event_time")),
        default=None,
    )
    observed_at = (
        ((run.get("observations") or {}).get("after") or {})
        .get("categories", {}).get("registry", {}).get("observed_at")
    )
    first_delta_time = min(
        (delta.get("created_at") for delta in deltas if delta.get("created_at")),
        default=None,
    )
    finalized_at = reconciliation.get("finalized_at")
    start_dt, end_dt, local_event_dt = map(parse_time, (action_start, action_end, first_local_time))
    if local_event_dt is None:
        local_event_timing = "NO_LOCAL_EVENT"
    elif start_dt and local_event_dt < start_dt:
        local_event_timing = "BEFORE_ACTION_INVALID"
    elif end_dt and local_event_dt <= end_dt:
        local_event_timing = "DURING_ACTION_BRACKET"
    else:
        local_event_timing = "AFTER_ACTION_COMPLETION"
    latencies = {
        "action_completion_to_local_sysmon_event_seconds": seconds_between(action_end, first_local_time),
        "action_completion_to_wazuh_event_timestamp_seconds": seconds_between(action_end, first_wazuh_time),
        "mutation_start_to_local_sysmon_event_seconds": seconds_between(action_start, first_local_time),
        "mutation_start_to_wazuh_event_timestamp_seconds": seconds_between(action_start, first_wazuh_time),
        "mutation_action_bracket_seconds": seconds_between(action_start, action_end),
        "action_to_probe_observation_seconds": seconds_between(action_end, observed_at),
        "action_to_delta_creation_seconds": seconds_between(action_end, first_delta_time),
        "action_to_final_reconciliation_seconds": seconds_between(action_end, finalized_at),
    }
    negative_latency_fields = [key for key, value in latencies.items() if value is not None and value < 0]
    latency_invalid = any(
        field not in {
            "action_completion_to_local_sysmon_event_seconds",
            "mutation_start_to_local_sysmon_event_seconds",
        }
        for field in negative_latency_fields
    ) or local_event_timing == "BEFORE_ACTION_INVALID"

    if condition == "registry_complete":
        expected_outcome = (
            state_seen and delta_seen and bool(findings) and bool(local_events)
            and bool(provider_events) and bool(database_events)
            and reconciliation.get("finalized") is True
            and reconciliation.get("status") == "CONSISTENT"
            and bool(set(matched_ids) & provider_ids)
        )
    elif condition == "registry_eventid_drop":
        expected_outcome = (
            state_seen and delta_seen and bool(findings) and bool(local_events)
            and source_absence_verified and not provider_events and not database_events
            and reconciliation.get("finalized") is True
            and reconciliation.get("status") == "UNEXPLAINED"
            and not matched_ids and filter_status == "RESTORED_AND_HEALTHY"
        )
    else:
        no_change = run.get("no_change_control") or {}
        expected_outcome = (
            no_change.get("target_absent_before") is True
            and no_change.get("target_absent_after") is True
            and no_change.get("new_delta_count") == 0
            and no_change.get("new_finding_count") == 0
            and not (target.get("deltas") or [])
            and not (target.get("findings") or [])
            and not local_events and not provider_events and not database_events
        )

    return {
        "trial_id": trial_id,
        "condition": condition,
        "schedule_status": schedule.get("status"),
        "trial_pass": run.get("trial_pass") is True and schedule.get("trial_pass") is True,
        "protocol_adherent": run.get("protocol_adherent") is True,
        "expected_outcome_pass": bool(expected_outcome),
        "target_name": run.get("target_name"),
        "target_object_key": target_key,
        "state_seen": bool(state_seen),
        "delta_count_exact_target_add": len(deltas),
        "finding_count_exact_target": len(findings),
        "local_sysmon_exact_target_count": len(local_events),
        "local_sysmon_record_ids": local_event_ids,
        "wazuh_exact_target_count": len(provider_events),
        "wazuh_exact_target_event_ids": sorted(provider_ids),
        "csg_database_exact_target_count": len(database_events),
        "wazuh_event_identity_valid": exact_wazuh_identity_valid,
        "provider_query": query,
        "absence_evidence_query_healthy": source_absence_verified,
        "reconciliation_status": reconciliation.get("status"),
        "reconciliation_finalized": reconciliation.get("finalized") is True,
        "reconciliation_version": reconciliation.get("version"),
        "reconciliation_matched_evidence_ids": matched_ids,
        "exact_event_id_linked": bool(set(matched_ids) & provider_ids),
        "filter_status": filter_status,
        "local_sysmon_event_timing_classification": local_event_timing,
        "mutation_action_bracket_seconds": latencies["mutation_action_bracket_seconds"],
        "cleanup_pass": cleanup_pass,
        "cleanup_errors": cleanup.get("errors") or [],
        "postflight_pass": postflight.get("passed") is True,
        "postflight_config_restored": postflight.get("configuration_restored") is True,
        "postflight_wazuh_config_sha256": postflight.get("wazuh_config_sha256"),
        "latencies_seconds": latencies,
        "latency_invalid": latency_invalid,
        "negative_latency_fields": negative_latency_fields,
    }


def metric(successes: int, total: int) -> dict[str, Any]:
    return {
        "successes": successes,
        "total": total,
        "proportion": successes / total if total else None,
        "wilson_95": wilson_interval(successes, total),
    }


def latency_summary(rows: list[dict[str, Any]], field: str) -> dict[str, Any]:
    values: list[float] = []
    invalid_negative = 0
    for row in rows:
        value = (row.get("latencies_seconds") or {}).get(field)
        if value is None:
            continue
        if value < 0:
            invalid_negative += 1
            continue
        values.append(float(value))
    if not values:
        return {"n_valid": 0, "n_negative_excluded": invalid_negative}
    ordered = sorted(values)
    p95 = ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]
    return {
        "n_valid": len(values),
        "n_negative_excluded": invalid_negative,
        "min": min(values),
        "median": statistics.median(values),
        "mean": statistics.mean(values),
        "p95_nearest_rank": p95,
        "max": max(values),
    }


def analyze(campaign_dir: Path) -> dict[str, Any]:
    manifest_path = campaign_dir / "campaign-manifest.json"
    manifest = load_json(manifest_path)
    outcomes: list[dict[str, Any]] = []
    artifact_hashes: dict[str, str] = {}
    schedule_rows = manifest.get("schedule") or []
    for entry in schedule_rows:
        trial_id = str(entry["trial_id"])
        path = campaign_dir / trial_id / "run.json"
        if not path.is_file():
            raise FileNotFoundError(f"Missing raw trial artifact for {trial_id}: {path}")
        run = load_json(path)
        artifact_hashes[trial_id] = sha256(path)
        outcomes.append(
            trial_outcome(trial_id, entry, run, entry.get("post_trial_health") or {})
        )

    grouped: dict[str, list[dict[str, Any]]] = {
        condition: [row for row in outcomes if row["condition"] == condition]
        for condition in CONDITIONS
    }
    metrics: dict[str, Any] = {}
    for condition, rows in grouped.items():
        total = len(rows)
        metrics[condition] = {
            "n": total,
            "campaign_pass": metric(sum(row["trial_pass"] for row in rows), total),
            "independent_evidence_audit_pass": metric(sum(row["expected_outcome_pass"] for row in rows), total),
            "state_seen": metric(sum(row["state_seen"] for row in rows), total),
            "target_delta_count_one": metric(sum(row["delta_count_exact_target_add"] == 1 for row in rows), total),
            "cleanup_pass": metric(sum(row["cleanup_pass"] for row in rows), total),
            "postflight_pass": metric(sum(row["postflight_pass"] for row in rows), total),
            "provider_query_complete": metric(sum(row["provider_query"].get("query_complete") is True for row in rows), total),
            "latencies": {
                field: latency_summary(rows, field)
                for field in (
                    "action_completion_to_local_sysmon_event_seconds",
                    "action_completion_to_wazuh_event_timestamp_seconds",
                    "mutation_start_to_local_sysmon_event_seconds",
                    "mutation_start_to_wazuh_event_timestamp_seconds",
                    "mutation_action_bracket_seconds",
                    "action_to_probe_observation_seconds",
                    "action_to_delta_creation_seconds",
                    "action_to_final_reconciliation_seconds",
                )
            },
        }
        if condition == "registry_complete":
            metrics[condition].update(
                exact_local_event=metric(sum(row["local_sysmon_exact_target_count"] > 0 for row in rows), total),
                exact_wazuh_event=metric(sum(row["wazuh_exact_target_count"] > 0 for row in rows), total),
                exact_event_linked=metric(sum(row["exact_event_id_linked"] for row in rows), total),
                consistent_reconciliation=metric(sum(row["reconciliation_status"] == "CONSISTENT" and row["reconciliation_finalized"] for row in rows), total),
                local_event_during_action_bracket=metric(sum(row["local_sysmon_event_timing_classification"] == "DURING_ACTION_BRACKET" for row in rows), total),
            )
        elif condition == "registry_eventid_drop":
            metrics[condition].update(
                local_event_retained=metric(sum(row["local_sysmon_exact_target_count"] > 0 for row in rows), total),
                complete_healthy_provider_observation=metric(sum(row["absence_evidence_query_healthy"] for row in rows), total),
                exact_wazuh_event_absent=metric(sum(row["absence_evidence_query_healthy"] and row["wazuh_exact_target_count"] == 0 for row in rows), total),
                unexplained_reconciliation=metric(sum(row["reconciliation_status"] == "UNEXPLAINED" and row["reconciliation_finalized"] and not row["reconciliation_matched_evidence_ids"] for row in rows), total),
                local_event_during_action_bracket=metric(sum(row["local_sysmon_event_timing_classification"] == "DURING_ACTION_BRACKET" for row in rows), total),
            )
        else:
            false_delta = sum(row["delta_count_exact_target_add"] > 0 for row in rows)
            false_findings = sum(row["finding_count_exact_target"] > 0 for row in rows)
            metrics[condition].update(
                no_false_target_delta=metric(total - false_delta, total),
                no_false_target_finding=metric(total - false_findings, total),
                zero_target_events=metric(sum(row["local_sysmon_exact_target_count"] == 0 and row["wazuh_exact_target_count"] == 0 for row in rows), total),
            )

    return {
        "schema_version": "csg-registry-three-condition-campaign-analysis-v1",
        "analysis_created_utc": datetime.now(UTC).isoformat(),
        "campaign_id": manifest.get("experiment_id"),
        "execution_kind": manifest.get("execution_kind"),
        "campaign_status": manifest.get("status"),
        "host_id": manifest.get("host_id"),
        "protocol_sha256": manifest.get("protocol_sha256"),
        "trial_script_sha256": manifest.get("trial_script_sha256"),
        "controller_sha256": manifest.get("controller_sha256"),
        "seed": manifest.get("random_seed"),
        "declared_conditions": manifest.get("declared_conditions"),
        "planned_trials": sum(manifest.get("repetitions_per_condition", 0) for _ in manifest.get("declared_conditions", [])),
        "observed_trials": len(outcomes),
        "schedule_passed": sum(row["trial_pass"] for row in outcomes),
        "schedule_failed": sum(not row["trial_pass"] for row in outcomes),
        "all_protocol_adherent": all(row["protocol_adherent"] for row in outcomes),
        "all_cleanup_passed": all(row["cleanup_pass"] for row in outcomes),
        "all_postflight_passed": all(row["postflight_pass"] and row["postflight_config_restored"] for row in outcomes),
        "invalid_negative_latency_count": sum(row["latency_invalid"] for row in outcomes),
        "negative_completion_to_local_event_offsets": sum(
            (row.get("latencies_seconds") or {}).get("action_completion_to_local_sysmon_event_seconds") is not None
            and (row.get("latencies_seconds") or {}).get("action_completion_to_local_sysmon_event_seconds") < 0
            for row in outcomes
        ),
        "local_event_timing_classifications": {
            value: sum(row["local_sysmon_event_timing_classification"] == value for row in outcomes)
            for value in ("DURING_ACTION_BRACKET", "AFTER_ACTION_COMPLETION", "BEFORE_ACTION_INVALID", "NO_LOCAL_EVENT")
        },
        "metrics_by_condition": metrics,
        "trial_artifact_sha256": artifact_hashes,
        "campaign_manifest_sha256": sha256(manifest_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    campaign_dir = args.campaign_dir.resolve()
    output_dir = (args.output_dir or campaign_dir.parent / "analysis").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = load_json(campaign_dir / "campaign-manifest.json")
    outcome_rows: list[dict[str, Any]] = []
    for entry in manifest.get("schedule") or []:
        trial_id = str(entry["trial_id"])
        raw = load_json(campaign_dir / trial_id / "run.json")
        outcome_rows.append(
            trial_outcome(trial_id, entry, raw, entry.get("post_trial_health") or {})
        )
    aggregate = analyze(campaign_dir)
    with (output_dir / "trial-outcomes.jsonl").open("w", encoding="utf-8") as stream:
        for row in outcome_rows:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    with (output_dir / "trial-outcomes.csv").open("w", newline="", encoding="utf-8") as stream:
        columns = [
            "trial_id", "condition", "trial_pass", "protocol_adherent", "expected_outcome_pass",
            "state_seen", "delta_count_exact_target_add", "finding_count_exact_target",
            "local_sysmon_exact_target_count", "wazuh_exact_target_count",
            "csg_database_exact_target_count", "reconciliation_status", "reconciliation_finalized",
            "reconciliation_matched_evidence_ids", "provider_query", "cleanup_pass", "postflight_pass",
            "local_sysmon_event_timing_classification", "mutation_action_bracket_seconds",
            "latencies_seconds", "latency_invalid",
        ]
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for row in outcome_rows:
            csv_row = {column: row.get(column) for column in columns}
            csv_row.update({
                "provider_query": json.dumps(row["provider_query"], sort_keys=True),
                "reconciliation_matched_evidence_ids": json.dumps(row["reconciliation_matched_evidence_ids"]),
                "latencies_seconds": json.dumps(row["latencies_seconds"], sort_keys=True),
            })
            writer.writerow(csv_row)
    with (output_dir / "aggregate.json").open("w", encoding="utf-8") as stream:
        json.dump(aggregate, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({
        "observed_trials": aggregate["observed_trials"],
        "passed": aggregate["schedule_passed"],
        "failed": aggregate["schedule_failed"],
        "invalid_negative_latency_count": aggregate["invalid_negative_latency_count"],
        "all_cleanup_passed": aggregate["all_cleanup_passed"],
        "all_postflight_passed": aggregate["all_postflight_passed"],
    }, indent=2))


if __name__ == "__main__":
    main()
