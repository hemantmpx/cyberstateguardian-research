"""Audit a healthy post-run Wazuh query without rewriting CSG's frozen result."""

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


def _task_name(value: Any) -> str:
    normalized = str(value or "").strip().replace("/", "\\")
    if normalized.casefold().startswith("scheduled_task:"):
        normalized = normalized.split(":", maxsplit=1)[1]
    return normalized.lstrip("\\").casefold()


def audit_postrun_window(run: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any]:
    scenarios = [
        item
        for item in (run.get("runner_result") or {}).get("scenarios", [])
        if item.get("kind") == "scheduled_task"
    ]
    scenario = scenarios[0] if len(scenarios) == 1 else {}
    reconciliation = run.get("final_target_reconciliation") or {}
    window = reconciliation.get("observation_window") or {}
    reconciliation_metadata = reconciliation.get("metadata") or {}
    reconciliation_event_plane = reconciliation_metadata.get("event_plane") or {}
    start, end = _utc(window.get("start")), _utc(window.get("end"))
    retrieval = (observation.get("metadata") or {}).get("retrieval") or {}
    retrieved_start, retrieved_end = _utc(retrieval.get("start")), _utc(retrieval.get("end"))
    target_name = str(run.get("target_task_name") or scenario.get("object_name") or "")
    distractor_name = str(run.get("expected_collected_distractor_task_name") or "")
    host_id = run.get("host_id")
    events = [event for event in observation.get("events", []) if isinstance(event, dict)]

    def identity(event: dict[str, Any]) -> str:
        attributes = event.get("attributes") or {}
        target = event.get("target") or {}
        value = target.get("task_name") or target.get("key") or attributes.get("task_name")
        return _task_name(value)

    def in_window(event: dict[str, Any]) -> bool:
        event_time = _utc(event.get("event_time"))
        return bool(start and end and event_time and start <= event_time <= end)

    target_named_events = [event for event in events if identity(event) == _task_name(target_name)]
    distractor_events = [
        event
        for event in events
        if identity(event) == _task_name(distractor_name)
        and event.get("host_id") == host_id
        and event.get("normalized_type") == "scheduled_task_created"
        and str((event.get("attributes") or {}).get("event_code")) == "4698"
    ]
    sources = retrieval.get("sources") or {}
    source_queries_complete = bool(sources) and all(
        source.get("complete") is True and source.get("status") == "AVAILABLE"
        for source in sources.values()
    )
    query_started = _utc(retrieval.get("query_started_at"))
    finalized_at = _utc(reconciliation.get("finalized_at"))
    distractor_evidence = scenario.get("distractor_evidence") or {}
    state_plane = scenario.get("state_plane") or {}
    local_evidence = scenario.get("local_source_evidence") or {}
    local_target_events = local_evidence.get("exact_events") or []
    local_target = local_target_events[0] if len(local_target_events) == 1 else {}
    local_target_name = (local_target.get("event_data") or {}).get("TaskName") or (
        local_target.get("event_data") or {}
    ).get("Task_Name")
    local_target_time = _utc(local_target.get("event_time_utc"))
    original_finalization_not_healthy = bool(
        reconciliation_metadata.get("source_health_known_degraded") is True
        or reconciliation_metadata.get("reconciliation_semantics")
        in {"INCONCLUSIVE", "UNCORROBORATED_DEGRADED"}
        or any(
            reconciliation_event_plane.get(field) not in (None, expected)
            for field, expected in (
                ("query_complete", True),
                ("coverage_status", "COMPLETE"),
                ("endpoint_collection_status", "AVAILABLE"),
                ("transport_status", "AVAILABLE"),
                ("index_status", "AVAILABLE"),
            )
        )
    )

    checks = {
        "one_assigned_scheduled_task_scenario": len(scenarios) == 1,
        "postrun_query_retrieved_exact_reconciliation_window": bool(
            start and end and retrieved_start == start and retrieved_end == end
        ),
        "postrun_query_started_after_original_finalization": bool(
            query_started and finalized_at and query_started > finalized_at
        ),
        "complete_healthy_postrun_query": (
            observation.get("query_complete") is True
            and observation.get("coverage_status") == "COMPLETE"
            and observation.get("endpoint_collection_status") == "AVAILABLE"
            and observation.get("transport_status") == "AVAILABLE"
            and observation.get("index_status") == "AVAILABLE"
            and source_queries_complete
        ),
        "no_exact_target_named_event_in_postrun_query": len(target_named_events) == 0,
        "one_same_host_type_event_for_exact_distractor": len(distractor_events) == 1,
        "distractor_event_inside_original_reconciliation_window": (
            len(distractor_events) == 1 and in_window(distractor_events[0])
        ),
        "target_event_was_locally_recorded_exactly": (
            local_evidence.get("query_status") == "COMPLETE"
            and len(local_target_events) == 1
            and local_target.get("event_id") == 4698
            and local_target.get("log_name") == "Security"
            and local_target.get("exact_identity_match") is True
            and _task_name(local_target_name) == _task_name(target_name)
            and bool(start and end and local_target_time and start <= local_target_time <= end)
        ),
        "native_probe_observed_target_and_cleanup": (
            run.get("direct_probe_state_sequence_passed") is True
            and state_plane.get("direct_windows_verification", {}).get(
                "target_absent_after_cleanup"
            )
            is True
        ),
        "same_probe_observed_target_and_distractor": (
            distractor_evidence.get("state_observed_after_action") is True
            and distractor_evidence.get("target_and_distractor_observed_same_probe") is True
            and distractor_evidence.get("probe_observation_id")
            == state_plane.get("after_action_observation_id")
            and len(distractor_evidence.get("probe_target_items") or []) == 1
            and len(distractor_evidence.get("probe_distractor_items") or []) == 1
            and distractor_evidence.get("state_still_present_after_cleanup") is False
        ),
        "original_csg_finalization_remains_unexplained_without_citations": (
            reconciliation.get("status") == "UNEXPLAINED"
            and reconciliation.get("finalized") is True
            and not reconciliation.get("matched_evidence_ids")
        ),
        "original_csg_finalization_was_not_healthy": (
            original_finalization_not_healthy
        ),
    }
    corroboration_checks = {
        key: value
        for key, value in checks.items()
        if key != "original_csg_finalization_was_not_healthy"
    }
    corroboration_passed = all(corroboration_checks.values())
    return {
        "schema_version": "csg-postrun-wazuh-window-audit-v1",
        "classification": (
            "POSTRUN_CAPTURE_DROP_CORROBORATED_ORIGINAL_FINALIZATION_DEGRADED"
            if corroboration_passed and checks["original_csg_finalization_was_not_healthy"]
            else "POSTRUN_CAPTURE_DROP_CORROBORATED"
            if corroboration_passed
            else "INCOMPLETE_OR_INVALID"
        ),
        "postrun_corroboration_passed": corroboration_passed,
        "original_csg_finalization_promoted": False,
        "host_id": host_id,
        "target_task_name": target_name,
        "distractor_task_name": distractor_name,
        "target_named_event_count": len(target_named_events),
        "distractor_event_ids": [event.get("event_id") for event in distractor_events],
        "distractor_event_times": [event.get("event_time") for event in distractor_events],
        "reconciliation_window": window,
        "postrun_query_window": {
            "start": retrieval.get("start"),
            "end": retrieval.get("end"),
            "query_started_at": retrieval.get("query_started_at"),
            "query_completed_at": retrieval.get("query_completed_at"),
            "retrieved_count": observation.get("retrieved_count"),
            "total_hits": observation.get("total_hits"),
        },
        "original_reconciliation": {
            "status": reconciliation.get("status"),
            "finalized": reconciliation.get("finalized"),
            "source_health_known_degraded": (reconciliation.get("metadata") or {}).get(
                "source_health_known_degraded"
            ),
            "matched_evidence_ids": reconciliation.get("matched_evidence_ids", []),
        },
        "checks": checks,
        "interpretation_limit": (
            "This is an independent healthy post-run retrieval of the original event-time window. "
            "It corroborates exact target absence and same-host wrong-object presence, but it does "
            "not rewrite or upgrade the original CSG reconciliation record, prove source health "
            "at original finalization, estimate reliability, or establish malicious detection gain."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_json", type=Path)
    parser.add_argument("observation_json", type=Path)
    parser.add_argument("output_json", type=Path)
    args = parser.parse_args()
    run = json.loads(args.run_json.read_text(encoding="utf-8-sig"))
    observation = json.loads(args.observation_json.read_text(encoding="utf-8-sig"))
    result = audit_postrun_window(run, observation)
    result["provenance"] = {
        "run_artifact": str(args.run_json),
        "run_sha256": _sha256(args.run_json),
        "postrun_observation_artifact": str(args.observation_json),
        "postrun_observation_sha256": _sha256(args.observation_json),
        "auditor_sha256": _sha256(Path(__file__)),
        "audited_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                key: result[key]
                for key in ("classification", "postrun_corroboration_passed", "checks")
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
