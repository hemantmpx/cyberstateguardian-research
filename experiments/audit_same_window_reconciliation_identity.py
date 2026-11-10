"""Independently audit exact-object reconciliation in a frozen Windows run."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except (TypeError, ValueError):
        return None


def _key(value: Any) -> str:
    return str(value or "").strip().replace("/", "\\").casefold()


def _as_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return [value] if isinstance(value, dict) else []


def audit_result(result: dict[str, Any]) -> dict[str, Any]:
    runner = result.get("runner_result") or {}
    scenarios = [
        item for item in runner.get("scenarios", [])
        if item.get("kind") == "scheduled_task"
    ]
    scenario = scenarios[0] if len(scenarios) == 1 else {}
    plane = scenario.get("event_plane") or {}
    retrieval = plane.get("retrieval") or {}
    local_source = scenario.get("local_source_evidence") or {}
    local_target_events = _as_list(local_source.get("exact_events"))
    local_target_event = local_target_events[0] if len(local_target_events) == 1 else {}
    distractor_evidence = scenario.get("distractor_evidence") or {}
    local_distractor = distractor_evidence.get("local_windows_event") or {}
    shared_probe_id = (scenario.get("state_plane") or {}).get("after_action_observation_id")
    target_events = _as_list(plane.get("exact_matches"))
    distractor_events = _as_list(
        plane.get("exact_distractor_events") or retrieval.get("exact_distractor_events")
    )
    reconciliation = result.get("final_target_reconciliation") or {}
    reconciliation_metadata = reconciliation.get("metadata") or {}
    reconciliation_event_plane = reconciliation_metadata.get("event_plane") or {}
    window = reconciliation.get("observation_window") or {}
    start, end = _utc(window.get("start")), _utc(window.get("end"))
    target_key = _key(scenario.get("expected_object_key"))
    target_name = str(result.get("target_task_name") or scenario.get("object_name") or "")
    distractor_name = str(result.get("expected_collected_distractor_task_name") or "")
    expected_distractor_key = _key(f"scheduled_task:\\{distractor_name}")
    matched_ids = sorted(set(reconciliation.get("matched_evidence_ids") or []))
    target_ids = sorted(
        {str(item.get("event_id")) for item in target_events if item.get("event_id")}
    )
    distractor_ids = sorted(
        {str(item.get("event_id")) for item in distractor_events if item.get("event_id")}
    )

    target_event = target_events[0] if len(target_events) == 1 else {}
    distractor_event = distractor_events[0] if len(distractor_events) == 1 else {}

    def within_window(event: dict[str, Any]) -> bool:
        timestamp = _utc(event.get("event_time"))
        return bool(start and end and timestamp and start <= timestamp <= end)

    expected_type = str(scenario.get("expected_event_type") or "")
    local_target_name = str(
        (local_target_event.get("event_data") or {}).get("TaskName")
        or (local_target_event.get("event_data") or {}).get("Task_Name")
        or ""
    ).lstrip("\\")
    local_distractor_name = str(local_distractor.get("task_name") or "").lstrip("\\")
    exact_local_target_event = bool(
        local_target_event
        and local_source.get("query_status") == "COMPLETE"
        and local_target_event.get("event_id") == 4698
        and local_target_event.get("log_name") == "Security"
        and local_target_event.get("exact_identity_match") is True
        and _key(local_target_name) == _key(target_name)
    )
    exact_local_distractor_event = bool(
        local_distractor
        and local_distractor.get("event_id") == 4698
        and _key(local_distractor_name) == _key(distractor_name)
    )
    distinct_local_record_ids = bool(
        exact_local_target_event
        and exact_local_distractor_event
        and local_target_event.get("record_id") is not None
        and local_distractor.get("record_id") is not None
        and local_target_event.get("record_id") != local_distractor.get("record_id")
    )
    local_target_inside_window = bool(
        exact_local_target_event
        and within_window({"event_time": local_target_event.get("event_time_utc")})
    )
    exact_target_event_identity = bool(
        target_event
        and target_event.get("source") == "wazuh"
        and target_event.get("host_id") == result.get("host_id")
        and target_event.get("normalized_type") == expected_type == "scheduled_task_created"
        and str((target_event.get("attributes") or {}).get("event_code")) == "4698"
        and _key((target_event.get("target") or {}).get("key")) == target_key
    )
    same_host = bool(
        distractor_event
        and distractor_event.get("host_id") == result.get("host_id")
        and (not target_event or target_event.get("host_id") == result.get("host_id"))
    )
    same_type = bool(
        distractor_event
        and expected_type == "scheduled_task_created"
        and distractor_event.get("normalized_type") == expected_type
        and str((distractor_event.get("attributes") or {}).get("event_code")) == "4698"
        and (not target_event or target_event.get("normalized_type") == expected_type)
    )
    distinct_object = bool(
        distractor_event and target_key
        and distractor_event.get("source") == "wazuh"
        and _key((distractor_event.get("target") or {}).get("key")) == expected_distractor_key
        and (not target_event or _key((target_event.get("target") or {}).get("key")) == target_key)
        and _key((distractor_event.get("target") or {}).get("key")) != target_key
    )
    query_complete = bool(
        plane.get("query_complete") is True
        and retrieval.get("query_complete") is True
        and retrieval.get("coverage_status") == "COMPLETE"
        and retrieval.get("endpoint_collection_status") == "AVAILABLE"
        and retrieval.get("transport_status") == "AVAILABLE"
        and retrieval.get("index_status") == "AVAILABLE"
    )
    reconciliation_source_healthy = bool(
        reconciliation_metadata.get("event_retrieval_complete") is True
        and reconciliation_metadata.get("source_health_known_degraded") is False
        and reconciliation_metadata.get("reconciliation_semantics") != "INCONCLUSIVE"
        and reconciliation_event_plane.get("query_complete") is True
        and reconciliation_event_plane.get("coverage_status") == "COMPLETE"
        and reconciliation_event_plane.get("endpoint_collection_status") == "AVAILABLE"
        and reconciliation_event_plane.get("transport_status") == "AVAILABLE"
        and reconciliation_event_plane.get("index_status") == "AVAILABLE"
    )
    exact_target_match_only = bool(
        reconciliation.get("finalized") is True
        and reconciliation.get("status") == "CONSISTENT"
        and target_ids
        and exact_target_event_identity
        and matched_ids == target_ids
        and not set(matched_ids).intersection(distractor_ids)
    )
    target_present_during_filter = bool(
        result.get("target_event_present_during_filter") is True
        and result.get("exact_wazuh_target_event_count_during_filter") == len(target_ids)
        and len(target_ids) > 0
    )
    capture_drop_checks = {
        "native_probe_observed_target_state_transition": result.get(
            "direct_probe_state_sequence_passed"
        ) is True,
        "complete_healthy_wazuh_query": query_complete,
        "exact_target_event_absent_from_wazuh": (
            not target_present_during_filter
            and result.get("exact_wazuh_target_event_count_during_filter") == 0
            and not target_ids
        ),
        "exact_local_target_event_present_in_window": (
            exact_local_target_event and local_target_inside_window
        ),
        "exact_target_absent_from_csg_event_store": result.get(
            "target_absent_from_csg_event_store_during_filter"
        ) is True,
        "one_exact_wazuh_distractor_event_present": (
            len(distractor_events) == 1
            and len(distractor_ids) == 1
            and distractor_event.get("source") == "wazuh"
        ),
        "same_host_same_event_type_different_object": same_host and same_type and distinct_object,
        "local_target_and_distractor_are_distinct_physical_records": distinct_local_record_ids,
        "distractor_probe_state_observed_and_cleaned": (
            distractor_evidence.get("state_observed_after_action") is True
            and distractor_evidence.get("target_and_distractor_observed_same_probe") is True
            and shared_probe_id
            and distractor_evidence.get("probe_observation_id") == shared_probe_id
            and len(distractor_evidence.get("probe_target_items") or []) == 1
            and len(distractor_evidence.get("probe_distractor_items") or []) == 1
            and distractor_evidence.get("state_still_present_after_cleanup") is False
            and distractor_evidence.get("event_inside_before_after_probe_interval") is True
        ),
        "distractor_inside_target_reconciliation_window": within_window(distractor_event),
        "healthy_event_plane_at_final_reconciliation": reconciliation_source_healthy,
        "target_finalized_unexplained_without_evidence": (
            reconciliation.get("status") == "UNEXPLAINED"
            and reconciliation.get("finalized") is True
            and not matched_ids
        ),
    }
    capture_drop_passed = all(capture_drop_checks.values())
    checks = {
        "single_scheduled_task_scenario": len(scenarios) == 1,
        "exact_target_event_identity": exact_target_event_identity,
        "complete_healthy_event_query": query_complete,
        "same_host_same_event_type": same_host and same_type,
        "different_exact_object_identity": distinct_object,
        "target_event_inside_reconciliation_window": within_window(target_event),
        "distractor_event_inside_reconciliation_window": within_window(distractor_event),
        "finalized_reconciliation_matches_target_only": exact_target_match_only,
        "target_name_filter_did_not_suppress_target": target_present_during_filter,
    }
    specificity_passed = all(
        checks[name]
        for name in (
            "single_scheduled_task_scenario",
            "complete_healthy_event_query",
            "same_host_same_event_type",
            "different_exact_object_identity",
            "target_event_inside_reconciliation_window",
            "distractor_event_inside_reconciliation_window",
            "finalized_reconciliation_matches_target_only",
            "target_name_filter_did_not_suppress_target",
        )
    )
    return {
        "schema_version": "csg-same-window-identity-audit-v2",
        "classification": (
            "LIVE_COMPLETE_TELEMETRY_IDENTITY_SPECIFICITY_CONTROL_NOT_CAPTURE_DROP"
            if specificity_passed and not capture_drop_passed
            else "CAPTURE_DROP_PASS"
            if capture_drop_passed
            else "INCOMPLETE_OR_INVALID"
        ),
        "identity_specificity_control_passed": specificity_passed,
        "capture_drop_passed": capture_drop_passed,
        "host_id": result.get("host_id"),
        "target_task_name": target_name,
        "target_object_key": target_key,
        "distractor_task_name": distractor_name,
        "target_event_ids": target_ids,
        "distractor_event_ids": distractor_ids,
        "matched_evidence_ids": matched_ids,
        "reconciliation_status": reconciliation.get("status"),
        "reconciliation_window": window,
        "checks": checks,
        "capture_drop_checks": capture_drop_checks,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result_json", type=Path)
    parser.add_argument("output_json", type=Path)
    args = parser.parse_args()
    result_path = args.result_json.resolve()
    auditor_path = Path(__file__).resolve()
    source = json.loads(result_path.read_text(encoding="utf-8-sig"))
    audit = audit_result(source)
    audit.update(
        {
            "audited_at_utc": datetime.now(UTC).isoformat(),
            "input_artifact": str(result_path),
            "input_sha256": _sha256(result_path),
            "auditor_sha256": _sha256(auditor_path),
        }
    )
    output_path = args.output_json.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: audit[key] for key in (
        "classification", "identity_specificity_control_passed", "capture_drop_passed",
        "target_event_ids", "distractor_event_ids", "matched_evidence_ids",
    )}, indent=2))


if __name__ == "__main__":
    main()
