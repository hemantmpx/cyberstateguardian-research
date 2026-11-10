"""Validate the object-specific proof emitted by the Windows service drill."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

Json = dict[str, Any]


def _findings(snapshot: Json | None) -> list[Json]:
    return list((snapshot or {}).get("findings") or [])


def _transition_candidates(
    snapshot: Json | None, delta_type: str, service_name: str | None
) -> list[Json]:
    expected_type = {
        "ADD": "service_created",
        "MODIFY": "service_modified",
    }.get(delta_type)
    if expected_type is None:
        return []
    expected_key = f"service:{service_name.lower()}" if service_name else None
    candidates: list[Json] = []
    for finding in _findings(snapshot):
        if expected_key and (
            finding.get("category") != "service" or finding.get("object_key") != expected_key
        ):
            continue
        reconciliation = finding.get("reconciliation") or {}
        evidence_types = {
            row.get("event_type")
            for row in reconciliation.get("match_reasons", [])
            if row.get("event_type")
        }
        evidence_types.update(reconciliation.get("missing_expected_evidence_types") or [])
        if expected_type in evidence_types:
            candidates.append(finding)
    return candidates


def _finding(
    snapshot: Json | None, delta_type: str, service_name: str | None = None
) -> Json | None:
    candidates = _transition_candidates(snapshot, delta_type, service_name)
    if not candidates:
        return None
    event_type = {"ADD": "service_created", "MODIFY": "service_modified"}[delta_type]
    evidence = (snapshot or {}).get("verified_exact_wazuh_evidence") or {}
    exact_ids = {
        item.get("event_id") for item in evidence.get(event_type, []) if item.get("event_id")
    }
    evidence_linked = [
        finding
        for finding in candidates
        if exact_ids.intersection(
            (finding.get("reconciliation") or {}).get("matched_evidence_ids") or []
        )
    ]
    if evidence_linked:
        candidates = evidence_linked
    return max(
        candidates,
        key=lambda finding: (
            int((finding.get("reconciliation") or {}).get("version") or 0),
            (finding.get("reconciliation") or {}).get("finalized") is True,
            str(
                (finding.get("reconciliation") or {}).get("finalized_at")
                or (finding.get("reconciliation") or {}).get("created_at")
                or ""
            ),
        ),
    )


def _target_transition_delta_ids(
    snapshot: Json | None, service_name: str, delta_type: str
) -> set[str]:
    archived = (snapshot or {}).get("target_state_deltas")
    if isinstance(archived, list):
        expected_key = f"service:{service_name.lower()}"
        return {
            str(delta["delta_id"])
            for delta in archived
            if delta.get("category") == "service"
            and delta.get("object_key") == expected_key
            and delta.get("delta_type") == delta_type
            and delta.get("delta_id")
        }
    return {
        str((finding.get("reconciliation") or {}).get("delta_id") or finding.get("finding_id"))
        for finding in _transition_candidates(snapshot, delta_type, service_name)
    }


def _status(finding: Json | None) -> str | None:
    return ((finding or {}).get("reconciliation") or {}).get("status")


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _same_host_distractor_result(
    payload: Json, service_name: str, host_id: str
) -> tuple[bool, str]:
    proof = payload.get("same_host_distractor_proof") or {}
    bounded = proof.get("bounded_observation") or {}
    target_finding = _finding(bounded, "ADD", service_name)
    target_key = f"service:{service_name.lower()}"
    distractor = bounded.get("verified_distractor_wazuh_evidence") or {}
    distractor_events = distractor.get("service_created") or []
    details = proof.get("details") or {}
    source_states = {
        "before": (details.get("source_before") or {}).get("status"),
        "stopped": (details.get("source_during_target_add") or {}).get("status"),
        "restored": (details.get("source_after_add_restore") or {}).get("status"),
    }
    target_deltas = [
        delta
        for delta in (bounded.get("target_state_deltas") or [])
        if delta.get("category") == "service"
        and delta.get("object_key") == target_key
        and delta.get("delta_type") == "ADD"
    ]
    reconciliation = (target_finding or {}).get("reconciliation") or {}
    metadata = reconciliation.get("metadata") or {}
    tolerance = timedelta(seconds=max(0, int(metadata.get("event_time_tolerance_seconds") or 0)))
    valid_event = False
    for event in distractor_events:
        event_time = _parse_timestamp(event.get("event_time"))
        window = target_deltas[0].get("observation_window") or {} if len(target_deltas) == 1 else {}
        window_start = _parse_timestamp(window.get("start"))
        window_end = _parse_timestamp(window.get("end"))
        event_key = str(
            event.get("target_key") or (event.get("target") or {}).get("key") or ""
        ).lower()
        if (
            event_time
            and window_start
            and window_end
            and event.get("host_id") == host_id
            and event.get("source") == "wazuh"
            and event.get("normalized_type") == "service_created"
            and event_key
            and event_key != target_key
            and window_start - tolerance <= event_time <= window_end + tolerance
        ):
            valid_event = True
            break
    exact_target_create_count = (bounded.get("verified_exact_wazuh_evidence") or {}).get(
        "exact_create_count", 0
    )
    valid = (
        _status(target_finding) == "UNEXPLAINED"
        and not (reconciliation.get("matched_evidence_ids") or [])
        and exact_target_create_count == 0
        and len(target_deltas) == 1
        and distractor.get("host_id") == host_id
        and valid_event
        and source_states
        == {
            "before": "Running",
            "stopped": "Stopped",
            "restored": "Running",
        }
    )
    detail = (
        "a same-host service_created event for a different service was inside the "
        "target ADD observation window; "
        "the target remained UNEXPLAINED with no target event citation"
        if valid
        else f"target status={_status(target_finding) or 'missing'}, target exact create count="
        f"{exact_target_create_count}, target ADD delta count={len(target_deltas)}, "
        f"same-window wrong-object event={valid_event}, source states={source_states}"
    )
    return valid, detail


def _target_selective_suppression_result(
    payload: Json, service_name: str, host_id: str, *, require_distractor: bool = True
) -> tuple[bool, str]:
    proof = payload.get("target_selective_suppression_proof") or {}
    observation = proof.get("observation") or {}
    routes = proof.get("verified_routes") or {}
    restore = proof.get("restoration") or {}
    transition = payload.get("state_transition") or {}
    evidence = payload.get("verified_exact_wazuh_evidence") or {}
    target_finding = _finding(payload, "MODIFY", service_name)
    target_reconciliation = (target_finding or {}).get("reconciliation") or {}
    target_key = f"service:{service_name.lower()}"
    target_events = evidence.get("service_modified") or []
    target_local_events = [
        event
        for event in (payload.get("windows_source_evidence") or {}).get("events", [])
        if event.get("event_id") == 7040
        and service_name.lower() in str(event.get("message") or "").lower()
    ]
    distractor_details = (payload.get("same_host_distractor_proof") or {}).get("details") or {}
    distractor_events = (distractor_details.get("modify") or {}).get("exact_wazuh_events") or []
    expected_distractor = str(distractor_details.get("distractor_service_name") or "")
    target_deltas = [
        delta
        for delta in (payload.get("target_state_deltas") or [])
        if delta.get("host_id") == host_id
        and delta.get("category") == "service"
        and delta.get("object_key") == target_key
        and delta.get("delta_type") == "MODIFY"
    ]
    tolerance_seconds = int(
        (target_reconciliation.get("metadata") or {}).get("event_time_tolerance_seconds") or 0
    )
    tolerance = timedelta(seconds=max(0, tolerance_seconds))
    distractor_matches_target_window = False
    target_window = (
        target_deltas[0].get("observation_window") or {} if len(target_deltas) == 1 else {}
    )
    window_start = _parse_timestamp(target_window.get("start"))
    window_end = _parse_timestamp(target_window.get("end"))
    for event in distractor_events:
        event_time = _parse_timestamp(event.get("event_time"))
        event_key = str(
            event.get("target_key") or (event.get("target") or {}).get("key") or ""
        ).lower()
        if (
            event_time
            and window_start
            and window_end
            and event.get("host_id") == host_id
            and event.get("source") == "wazuh"
            and event.get("normalized_type") == "service_modified"
            and event_key
            and expected_distractor
            and event_key == f"service:{expected_distractor.casefold()}"
            and str(event.get("service_name") or "").casefold() == expected_distractor.casefold()
            and expected_distractor.casefold() != service_name.casefold()
            and window_start - tolerance <= event_time <= window_end + tolerance
        ):
            distractor_matches_target_window = True
            break
    distractor_check = (
        observation.get("wrong_object_wazuh_service_modified_count", 0) > 0
        and distractor_matches_target_window
        if require_distractor
        else observation.get("wrong_object_wazuh_service_modified_count", 0) == 0
        and not distractor_events
    )

    original_hash = proof.get("original_config_sha256")
    effective_hash = proof.get("effective_config_sha256")
    hash_shape_ok = all(
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value.lower())
        for value in (original_hash, effective_hash, restore.get("restored_config_sha256"))
    )
    query = str(proof.get("system_eventchannel_query") or "")
    expected_registry_path = (
        "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\" + service_name
    )
    target_state_ok = (
        (transition.get("independent_os_before") or {}).get("start_mode") == "Manual"
        and (transition.get("independent_os_after") or {}).get("start_mode") == "Auto"
        and (transition.get("before") or {}).get("start_mode") == "Manual"
        and (transition.get("after") or {}).get("start_mode") == "Auto"
    )
    status_ok = (
        str(observation.get("endpoint_service_status", "")).casefold() == "running"
        and str(observation.get("endpoint_collection_status", "")).casefold() == "active"
        and str(observation.get("manager_status", "")).casefold() == "available"
        and str(observation.get("indexer_status", "")).casefold() == "available"
        and observation.get("event_query_status") == "SUCCEEDED"
        and str((routes.get("wazuh_service") or {}).get("status", "")).casefold() == "running"
        and str((routes.get("endpoint_agent") or {}).get("status", "")).casefold() == "active"
        and str((routes.get("indexer") or {}).get("status", "")).casefold() == "available"
        and str((restore.get("service") or {}).get("status", "")).casefold() == "running"
        and str((restore.get("endpoint_agent") or {}).get("status", "")).casefold() == "active"
        and str((restore.get("indexer") or {}).get("status", "")).casefold() == "available"
    )
    valid = (
        proof.get("status") == "APPLIED_AND_HEALTHY"
        and proof.get("ignored_registry_path") == expected_registry_path
        and proof.get("verified_routes", {}).get("system_eventchannel") is True
        and proof.get("verified_routes", {}).get("services_registry_fim") is True
        and "EventID != 7040" in query
        and service_name in query
        and observation.get("local_target_event_7040_count", 0) > 0
        and observation.get("csg_database_target_service_modified_count") == 0
        and not target_events
        and distractor_check
        and observation.get("target_reconciliation_status") == "UNEXPLAINED"
        and _status(target_finding) == "UNEXPLAINED"
        and not (target_reconciliation.get("matched_evidence_ids") or [])
        and len(target_deltas) == 1
        and bool(target_local_events)
        and target_state_ok
        and hash_shape_ok
        and original_hash != effective_hash
        and restore.get("status") == "RESTORED_AND_HEALTHY"
        and restore.get("restored_config_sha256") == original_hash
        and status_ok
    )
    detail = (
        "local Event 7040 and the exact Manual-to-Auto state transition were verified; "
        "the target event was absent, the required wrong-object condition was met, "
        "CSG left the target UNEXPLAINED, Wazuh stayed healthy, and the original "
        "configuration hash was restored"
        if valid
        else "selective suppression proof failed one or more independent checks: "
        f"status={proof.get('status')}, local_target_7040={len(target_local_events)}, "
        f"target_wazuh_modify={len(target_events)}, target_deltas={len(target_deltas)}, "
        f"windowed_distractor={distractor_matches_target_window}, "
        f"target_reconciliation={_status(target_finding)}, state_change={target_state_ok}, "
        f"config_restored={restore.get('restored_config_sha256') == original_hash}, "
        f"healthy={status_ok}"
    )
    return valid, detail


def _has_wrong_service_modify_in_window(
    events: list[Json],
    *,
    service_name: str,
    host_id: str,
    start: datetime | None,
    end: datetime | None,
    tolerance: timedelta,
    expected_service_name: str | None = None,
) -> bool:
    target_key = f"service:{service_name.lower()}"
    for event in events:
        event_time = _parse_timestamp(event.get("event_time"))
        event_key = str(
            event.get("target_key") or (event.get("target") or {}).get("key") or ""
        ).lower()
        event_service = str(event.get("service_name") or "")
        if (
            event_time
            and start
            and end
            and event.get("host_id") == host_id
            and event.get("source") == "wazuh"
            and event.get("normalized_type") == "service_modified"
            and event_key
            and event_key != target_key
            and event_service
            and event_service.casefold() != service_name.casefold()
            and (
                expected_service_name is None
                or (
                    event_service.casefold() == expected_service_name.casefold()
                    and event_key == f"service:{expected_service_name.casefold()}"
                )
            )
            and start - tolerance <= event_time <= end + tolerance
        ):
            return True
    return False


def _complete_distractor_result(payload: Json, service_name: str, host_id: str) -> tuple[bool, str]:
    proof = (payload.get("same_host_distractor_proof") or {}).get("details") or {}
    modify_proof = proof.get("modify") or {}
    distractor_events = modify_proof.get("exact_wazuh_events") or []
    distractor_name = str(proof.get("distractor_service_name") or "")
    modify_deltas = [
        delta
        for delta in (payload.get("target_state_deltas") or [])
        if delta.get("host_id") == host_id
        and delta.get("category") == "service"
        and delta.get("object_key") == f"service:{service_name.lower()}"
        and delta.get("delta_type") == "MODIFY"
    ]
    modify_finding = _finding(payload, "MODIFY", service_name)
    reconciliation = (modify_finding or {}).get("reconciliation") or {}
    window = modify_deltas[0].get("observation_window") or {} if len(modify_deltas) == 1 else {}
    start = _parse_timestamp(window.get("start"))
    end = _parse_timestamp(window.get("end"))
    tolerance = timedelta(
        seconds=max(
            0, int((reconciliation.get("metadata") or {}).get("event_time_tolerance_seconds") or 0)
        )
    )
    wrong_event = _has_wrong_service_modify_in_window(
        distractor_events,
        service_name=service_name,
        host_id=host_id,
        start=start,
        end=end,
        tolerance=tolerance,
        expected_service_name=distractor_name,
    )
    source_healthy = (
        (proof.get("source_during_target_add") or {}).get("status") == "Running"
        and modify_proof.get("wazuh_service_status") == "Running"
        and (payload.get("event_plane_status") or {}).get("endpoint_service_status") == "Running"
    )
    passed = (
        _status(modify_finding) == "CONSISTENT"
        and len(modify_deltas) == 1
        and wrong_event
        and source_healthy
        and distractor_name
        and distractor_name.casefold() != service_name.casefold()
        and bool(
            (modify_proof.get("local_windows_events") or {}).get("query_status") == "SUCCEEDED"
        )
    )
    return passed, (
        "exact target MODIFY remained CONSISTENT while a same-host wrong-service "
        "service_modified event fell inside its observation window and was rejected"
        if passed
        else f"target MODIFY status={_status(modify_finding)}, deltas={len(modify_deltas)}, "
        f"same-window wrong-object event={wrong_event}, Wazuh healthy={source_healthy}"
    )


def _no_change_distractor_result(
    payload: Json, service_name: str, host_id: str
) -> tuple[bool, str]:
    details = (payload.get("same_host_distractor_proof") or {}).get("details") or {}
    modify = details.get("modify") or {}
    events = modify.get("exact_wazuh_events") or []
    transition = payload.get("state_transition") or {}
    start = _parse_timestamp(transition.get("before_observed_at"))
    end = _parse_timestamp(transition.get("after_observed_at"))
    modify_start = _parse_timestamp(modify.get("action_started_at"))
    modify_end = _parse_timestamp(modify.get("action_completed_at"))
    tolerance = timedelta(seconds=10)
    distractor_name = str(details.get("distractor_service_name") or "")
    matching_event = _has_wrong_service_modify_in_window(
        events,
        service_name=service_name,
        host_id=host_id,
        start=start,
        end=end,
        tolerance=tolerance,
        expected_service_name=distractor_name,
    )
    locally_verified = any(
        event.get("event_id") == 7040
        and str(modify.get("service_name") or "").casefold()
        in str(event.get("message") or "").casefold()
        for event in (modify.get("local_windows_events") or {}).get("events", [])
    )
    create_events = details.get("distractor_create_events") or []
    exact_create_seen = any(
        event.get("host_id") == host_id
        and event.get("source") == "wazuh"
        and event.get("normalized_type") == "service_created"
        and str(event.get("service_name") or "").casefold() == distractor_name.casefold()
        and str(event.get("target_key") or "").casefold() == f"service:{distractor_name.casefold()}"
        for event in create_events
    )
    cleanup = details.get("cleanup") or {}
    source_healthy = (
        (details.get("source_before") or {}).get("status") == "Running"
        and (details.get("source_after") or {}).get("status") == "Running"
        and (payload.get("event_plane_status") or {}).get("endpoint_service_status") == "Running"
    )
    modify_inside_measurement = bool(
        start and end and modify_start and modify_end and start <= modify_start <= modify_end <= end
    )
    passed = (
        bool(modify.get("service_name"))
        and str(modify.get("service_name")).casefold() != service_name.casefold()
        and exact_create_seen
        and matching_event
        and locally_verified
        and (modify.get("local_windows_events") or {}).get("query_status") == "SUCCEEDED"
        and distractor_name
        and distractor_name.casefold() == str(modify.get("service_name") or "").casefold()
        and modify_inside_measurement
        and source_healthy
        and cleanup.get("absent_after_cleanup") is True
        and payload.get("protocol_adherence", {}).get("distractor_control_adherent") is True
    )
    return passed, (
        "target remained unchanged while an exact same-host distractor modification was "
        "verified during the target observation interval"
        if passed
        else (
            f"same-window exact distractor event={matching_event}, "
            f"local Event 7040={locally_verified}, "
            f"action inside target observation={modify_inside_measurement}, "
            f"cleanup={cleanup.get('absent_after_cleanup')}"
        )
    )


def _exact_evidence_ids(snapshot: Json | None) -> set[str]:
    evidence = (snapshot or {}).get("verified_exact_wazuh_evidence") or {}
    return {
        item.get("event_id")
        for key in ("service_created", "service_modified")
        for item in evidence.get(key, [])
        if item.get("event_id")
    }


def _exact_evidence_count(snapshot: Json | None) -> int:
    return len(_exact_evidence_types(snapshot))


def _exact_evidence_types(snapshot: Json | None) -> list[str]:
    evidence = (snapshot or {}).get("verified_exact_wazuh_evidence") or {}
    return [key for key in ("service_created", "service_modified") if evidence.get(key)]


def _event_occurrence_key(event: Json) -> tuple[str, str, str, str, str]:
    attributes = event.get("attributes") or {}
    target = event.get("target") or {}
    metadata = event.get("metadata") or {}
    rule = metadata.get("rule") or {}
    return (
        str(event.get("host_id") or ""),
        str(event.get("normalized_type") or ""),
        str(target.get("key") or event.get("target_key") or "").casefold(),
        str(event.get("event_time") or ""),
        str(attributes.get("event_code") or rule.get("id") or ""),
    )


def _exact_occurrences(snapshot: Json | None, event_type: str) -> tuple[set[str], int]:
    evidence = (snapshot or {}).get("verified_exact_wazuh_evidence") or {}
    events = [item for item in evidence.get(event_type, []) if isinstance(item, dict)]
    event_ids = {str(item["event_id"]) for item in events if item.get("event_id")}
    occurrence_keys = {_event_occurrence_key(item) for item in events}
    return event_ids, len(occurrence_keys)


def _check_exact_identity(
    snapshot: Json | None, service_name: str, expected_host: str
) -> list[str]:
    errors: list[str] = []
    expected_key = f"service:{service_name.lower()}"
    exact_ids = _exact_evidence_ids(snapshot)
    evidence = (snapshot or {}).get("verified_exact_wazuh_evidence") or {}
    for key in ("service_created", "service_modified"):
        for item in evidence.get(key, []):
            if item.get("host_id") != expected_host:
                errors.append(f"{key} evidence {item.get('event_id')} has the wrong host")
            if item.get("service_name", "").lower() != service_name.lower() and (
                item.get("target_key", "").lower() != expected_key
            ):
                errors.append(f"{key} evidence {item.get('event_id')} has the wrong service")
            if item.get("normalized_type") != key:
                errors.append(f"{key} evidence {item.get('event_id')} has the wrong event type")

    for finding in _findings(snapshot):
        if finding.get("category") != "service":
            continue
        if finding.get("object_key") != expected_key:
            errors.append(f"finding {finding.get('finding_id')} has the wrong service object key")
        matched = set(((finding.get("reconciliation") or {}).get("matched_evidence_ids")) or [])
        if not matched.issubset(exact_ids):
            errors.append(
                f"finding {finding.get('finding_id')} cites evidence outside the exact service set"
            )
    return errors


def _check_event_archive(snapshot: Json | None) -> list[str]:
    errors: list[str] = []
    evidence = (snapshot or {}).get("verified_exact_wazuh_evidence") or {}
    required_fields = {
        "event_id",
        "event_time",
        "normalized_type",
        "host_id",
        "target",
        "attributes",
        "source_reference",
        "metadata",
    }
    for key in ("service_created", "service_modified"):
        for item in evidence.get(key, []):
            missing = sorted(field for field in required_fields if field not in item)
            if missing:
                errors.append(
                    f"{key} evidence {item.get('event_id')} is missing archived fields: "
                    f"{', '.join(missing)}"
                )
            attributes = item.get("attributes")
            if not isinstance(attributes, dict):
                continue
            if key == "service_modified":
                for field in ("old_start_mode", "new_start_mode"):
                    if field not in attributes:
                        errors.append(f"{key} evidence {item.get('event_id')} is missing {field}")
    return errors


def validate(payload: Json, *, require_capture_recovery: bool = True) -> Json:
    service_name = str(payload.get("service_name") or "")
    host_id = str(payload.get("host_id") or "")
    checks: list[Json] = []

    def add(name: str, passed: bool | None, detail: str) -> None:
        status = "PASS" if passed is True else "FAIL" if passed is False else "NOT_APPLICABLE"
        checks.append({"name": name, "status": status, "passed": passed, "detail": detail})

    if payload.get("schema_version") == "3":
        adherence = payload.get("protocol_adherence") or {}
        add(
            "artifact_valid",
            adherence.get("artifact_valid") is True,
            "required API and native event queries completed without capture errors"
            if adherence.get("artifact_valid") is True
            else "one or more required artifact capture queries failed",
        )
        if payload.get("telemetry_condition") == "target_selective_drop_clean":
            independently_adherent, adherence_detail = _target_selective_suppression_result(
                payload, service_name, host_id, require_distractor=False
            )
            add(
                "protocol_adherent",
                independently_adherent,
                "clean-suppression adherence recomputed from field-level source, state, "
                "collection-health, reconciliation, and restoration evidence; "
                f"runner_summary_flag={adherence.get('protocol_adherent')!r}; {adherence_detail}",
            )
        else:
            add(
                "protocol_adherent",
                adherence.get("protocol_adherent") is True,
                "declared timing and intervention preconditions were met"
                if adherence.get("protocol_adherent") is True
                else "a declared timing or intervention precondition was not met",
            )
        source_evidence = payload.get("windows_source_evidence") or {}
        source_query_ok = source_evidence.get("query_status") == "SUCCEEDED"
        add(
            "windows_source_query",
            source_query_ok,
            "Windows System event query succeeded and archived the exact-name result"
            if source_query_ok
            else "Windows System event query failed or is missing",
        )
        source_rows = source_evidence.get("events") or []
        if payload.get("telemetry_condition") in {
            "complete",
            "complete_distractor",
            "delayed",
            "delayed_reconciliation",
            "target_selective_drop",
            "target_selective_drop_clean",
        }:
            observed_source_ids = {
                int(item.get("event_id"))
                for item in source_rows
                if service_name.lower() in str(item.get("message") or "").lower()
            }
            source_transitions_ok = {7045, 7040}.issubset(observed_source_ids)
            add(
                "windows_source_transition_events",
                source_transitions_ok,
                f"exact-name source event IDs present: {sorted(observed_source_ids)}; "
                "7045 creation and 7040 modification are expected",
            )
        plane = payload.get("event_plane_status") or {}
        add(
            "manager_and_indexer_health",
            plane.get("manager_status") == "AVAILABLE"
            and plane.get("indexer_status") == "AVAILABLE"
            and plane.get("indexer_health_source") == "GET /api/wazuh/status",
            "manager and indexer health were independently queried"
            if plane.get("manager_status") == "AVAILABLE"
            and plane.get("indexer_status") == "AVAILABLE"
            else (
                "manager/indexer were unavailable or their health was not independently established"
            ),
        )

    identity_errors = _check_exact_identity(payload, service_name, host_id)
    exact_evidence_types = _exact_evidence_types(payload)
    exact_evidence_present = bool(exact_evidence_types)
    add(
        "exact_object_identity",
        (
            bool(service_name and host_id and not identity_errors)
            if exact_evidence_present
            else (False if identity_errors else None)
        ),
        "; ".join(identity_errors)
        if identity_errors
        else "host, service identity, and event type agree for: " + ", ".join(exact_evidence_types)
        if exact_evidence_present
        else (
            "NOT_APPLICABLE: no exact Wazuh event was returned; event absence is checked separately"
        ),
    )
    archive_errors = _check_event_archive(payload)
    add(
        "matched_event_archive",
        not archive_errors if exact_evidence_present else None,
        "; ".join(archive_errors)
        if archive_errors
        else "archive fields valid for exact event types: " + ", ".join(exact_evidence_types)
        if exact_evidence_present
        else "NOT_APPLICABLE: there is no matched event to audit",
    )

    service_name = str(payload.get("service_name") or "")
    final_create = _finding(payload, "ADD", service_name)
    final_modify = _finding(payload, "MODIFY", service_name)
    evidence = payload.get("verified_exact_wazuh_evidence") or {}
    create_event_ids, unique_create_occurrences = _exact_occurrences(payload, "service_created")
    modify_event_ids, unique_modify_occurrences = _exact_occurrences(payload, "service_modified")
    create_citation = bool(
        create_event_ids
        & set((final_create.get("reconciliation") or {}).get("matched_evidence_ids") or [])
        if final_create
        else set()
    )
    modify_citation = bool(
        modify_event_ids
        & set((final_modify.get("reconciliation") or {}).get("matched_evidence_ids") or [])
        if final_modify
        else set()
    )
    complete_applicable = payload.get("telemetry_condition") in {
        "complete",
        "complete_distractor",
        "delayed_reconciliation",
    }
    add(
        "complete_final_evidence",
        (
            unique_create_occurrences == 1
            and unique_modify_occurrences == 1
            and _status(final_create) == "CONSISTENT"
            and _status(final_modify) == "CONSISTENT"
            and create_citation
            and modify_citation
        )
        if complete_applicable
        else None,
        (
            "complete/recoverable-delay runs require one unique exact create and modify "
            "occurrence, both CONSISTENT and citing an exact record ID; "
            f"raw_rows={len(evidence.get('service_created') or [])}/"
            f"{len(evidence.get('service_modified') or [])}, "
            f"unique_occurrences={unique_create_occurrences}/{unique_modify_occurrences}, "
            f"cited={create_citation}/{modify_citation}"
        )
        if complete_applicable
        else "NOT_APPLICABLE: this is not a complete-telemetry run",
    )

    no_change = payload.get("telemetry_condition") in {"no_change", "no_change_distractor"}
    if not no_change:
        delta_counts = {
            transition: len(_target_transition_delta_ids(payload, service_name, transition))
            for transition in ("ADD", "MODIFY")
        }
        add(
            "single_delta_per_target_transition",
            all(count == 1 for count in delta_counts.values()),
            f"target service delta counts: ADD={delta_counts['ADD']}, "
            f"MODIFY={delta_counts['MODIFY']}; one delta per performed transition is expected",
        )

    if no_change:
        expected_events = (payload.get("event_plane_status") or {}).get("expected_events") or {}
        transition = payload.get("state_transition") or {}
        no_change_ok = (
            final_create is None
            and final_modify is None
            and not (payload.get("target_state_deltas") or [])
            and expected_events.get("service_created") == "ABSENT"
            and expected_events.get("service_modified") == "ABSENT"
            and (
                payload.get("schema_version") != "3"
                or (
                    transition.get("before") is not None
                    and transition.get("after") is not None
                    and transition.get("attributes_unchanged") is True
                    and transition.get("independent_os_before") is not None
                    and transition.get("independent_os_after") is not None
                    and transition.get("independent_os_attributes_unchanged") is True
                    and transition.get("new_target_delta_count", 0) == 0
                    and transition.get("new_target_finding_count", 0) == 0
                    and not transition.get("new_target_delta_ids")
                    and not transition.get("new_target_finding_ids")
                )
            )
        )
        add(
            "no_change_control",
            no_change_ok,
            "no state delta, no service findings, and no expected service events"
            if no_change_ok
            else "the no-change control contains a state delta, finding, or expected event",
        )
        if payload.get("telemetry_condition") == "no_change_distractor":
            distractor_ok, distractor_detail = _no_change_distractor_result(
                payload, service_name, host_id
            )
            add("no_change_distractor_rejection", distractor_ok, distractor_detail)

    proof = payload.get("capture_drop_proof") or {}
    bounded = proof.get("bounded_observation")
    recovered = proof.get("post_restore_recovery")
    if payload.get("telemetry_condition") == "capture_drop":
        exact_precondition = proof.get("exact_create_precondition") or {}
        bounded_plane = (bounded or {}).get("event_plane_status") or {}
        add(
            "capture_drop_central_query_path_available",
            (
                bounded_plane.get("manager_status") == "AVAILABLE"
                and bounded_plane.get("indexer_status") == "AVAILABLE"
                and bounded_plane.get("event_query_status") == "SUCCEEDED"
            )
            if payload.get("schema_version") == "3"
            else None,
            "manager and indexer remained reachable while the endpoint Wazuh service was stopped"
            if bounded_plane.get("manager_status") == "AVAILABLE"
            and bounded_plane.get("indexer_status") == "AVAILABLE"
            and bounded_plane.get("event_query_status") == "SUCCEEDED"
            else "central manager/indexer health or event-query success was not established",
        )
        precondition_source = exact_precondition.get("windows_system_event_7045") or []
        precondition_wazuh = exact_precondition.get("exact_wazuh_service_created") or []
        exact_precondition_ok = any(
            item.get("event_id") == 7045
            and service_name.lower() in str(item.get("message") or "").lower()
            for item in precondition_source
        ) and any(
            item.get("host_id") == host_id
            and item.get("normalized_type") == "service_created"
            and (
                str(item.get("target_key") or "").lower() == f"service:{service_name.lower()}"
                or str(item.get("service_name") or "").lower() == service_name.lower()
            )
            for item in precondition_wazuh
        )
        add(
            "capture_drop_exact_create_precondition",
            exact_precondition_ok if payload.get("schema_version") == "3" else None,
            "Wazuh was stopped only after the exact local 7045 and indexed "
            "Wazuh create event were captured"
            if exact_precondition_ok
            else "NOT_APPLICABLE: legacy artifact lacks the new create-event gate"
            if payload.get("schema_version") != "3"
            else "the exact local and indexed create-event preconditions are incomplete",
        )
        source_modify_exists = any(
            item.get("event_id") == 7040
            and service_name.lower() in str(item.get("message") or "").lower()
            for item in (payload.get("windows_source_evidence") or {}).get("events") or []
        )
        add(
            "capture_drop_source_generated_modify_event",
            source_modify_exists if payload.get("schema_version") == "3" else None,
            "Windows System log contains the exact-name 7040 event while WazuhSvc was stopped"
            if source_modify_exists
            else "NOT_APPLICABLE: legacy artifact lacks original Windows event records"
            if payload.get("schema_version") != "3"
            else "no exact-name 7040 record was captured from the Windows System log",
        )
        pre_modify = _finding(bounded, "MODIFY", service_name)
        post_modify = _finding(recovered, "MODIFY", service_name)
        pre_ok = _status(pre_modify) == "UNEXPLAINED"
        post_status = _status(post_modify)
        post_exact_modify_count = (
            (recovered or {}).get("verified_exact_wazuh_evidence", {}).get("exact_modify_count", 0)
        )
        post_matched_ids = set(
            ((post_modify or {}).get("reconciliation") or {}).get("matched_evidence_ids", [])
        )
        recovered_ok = (
            post_status == "CONSISTENT" and post_exact_modify_count == 1 and bool(post_matched_ids)
        )
        not_recovered_ok = (
            post_status == "UNEXPLAINED" and post_exact_modify_count == 0 and not post_matched_ids
        )
        if recovered_ok:
            capture_outcome = "recovered"
        elif not_recovered_ok:
            capture_outcome = "not_recovered_after_restore"
        else:
            capture_outcome = "invalid"
        add(
            "capture_drop_before_restore",
            pre_ok,
            f"pre-restore modification status: {_status(pre_modify) or 'missing'}",
        )
        add(
            "capture_drop_after_restore",
            capture_outcome in {"recovered", "not_recovered_after_restore"}
            if require_capture_recovery
            else recovered is not None,
            f"post-restore modification status: {post_status or 'missing'}; "
            f"outcome: {capture_outcome}",
        )
        add(
            "capture_drop_outcome",
            capture_outcome in {"recovered", "not_recovered_after_restore"},
            "Wazuh modification evidence recovered after restore"
            if capture_outcome == "recovered"
            else "Wazuh modification evidence was not recovered after restore"
            if capture_outcome == "not_recovered_after_restore"
            else "post-restore evidence did not satisfy recovery or not-recovered rules",
        )
        recovery_errors = _check_exact_identity(recovered, service_name, host_id)
        post_restore_evidence_types = _exact_evidence_types(recovered)
        post_restore_evidence_present = bool(post_restore_evidence_types)
        add(
            "post_restore_exact_identity",
            not recovery_errors if post_restore_evidence_present else None,
            "; ".join(recovery_errors)
            if recovery_errors
            else "post-restore identity validated for: " + ", ".join(post_restore_evidence_types)
            if post_restore_evidence_present
            else "NOT_APPLICABLE: no post-restore event exists; non-recovery is checked separately",
        )
        recovery_archive_errors = _check_event_archive(recovered)
        add(
            "post_restore_event_archive",
            not recovery_archive_errors if post_restore_evidence_present else None,
            "; ".join(recovery_archive_errors)
            if recovery_archive_errors
            else "post-restore archive fields valid for: " + ", ".join(post_restore_evidence_types)
            if post_restore_evidence_present
            else "NOT_APPLICABLE: there is no post-restore event archive to audit",
        )

        proof_statuses = proof.get("wazuh_service_proof") or {}
        expected_source_states = {
            "before_stop": "Running",
            "during_drop": "Stopped",
            "after_restore": "Running",
        }
        source_proof_ok = bool(proof_statuses) and all(
            (proof_statuses.get(name) or {}).get("status") == expected
            for name, expected in expected_source_states.items()
        )
        if payload.get("schema_version") == "3":
            source_proof_ok = source_proof_ok and all(
                (
                    int((proof_statuses.get(name) or {}).get("process_id") or 0) == 0
                    if name == "during_drop"
                    else int((proof_statuses.get(name) or {}).get("process_id") or 0) > 0
                )
                for name in expected_source_states
            )
        add(
            "capture_drop_service_proof",
            source_proof_ok,
            "WazuhSvc status and PID prove Running before, Stopped/PID 0 during, "
            "and Running with a process after restoration",
        )
        if payload.get("schema_version") == "3":
            wait_proof = proof.get("finalization_wait") or {}
            add(
                "capture_drop_timing_and_heartbeat",
                wait_proof.get("protocol_adherent") is True,
                f"wait elapsed={wait_proof.get('wall_elapsed_seconds')}; max heartbeat gap="
                f"{wait_proof.get('maximum_heartbeat_gap_seconds')}; wall/monotonic divergence="
                f"{wait_proof.get('wall_monotonic_divergence_seconds')}",
            )

    if payload.get("telemetry_condition") == "telemetry_delay":
        delay_proof = payload.get("telemetry_delay_proof") or {}
        proof_statuses = delay_proof.get("wazuh_service_proof") or {}
        source_proof_ok = all(
            (proof_statuses.get(name) or {}).get("status") == expected
            for name, expected in {
                "before_pause": "Running",
                "during_pause": "Stopped",
                "after_pause": "Running",
            }.items()
        )
        add(
            "telemetry_delay_source_proof",
            source_proof_ok,
            "WazuhSvc was recorded Running before the pause, Stopped during it, "
            "and Running after restoration",
        )
        create_count = evidence.get("exact_create_count", 0)
        modify_count = evidence.get("exact_modify_count", 0)
        add_status = _status(final_create)
        modify_status = _status(final_modify)
        recovered = (
            create_count == 1
            and modify_count == 1
            and add_status == "CONSISTENT"
            and modify_status == "CONSISTENT"
        )
        not_recovered = (
            create_count == 0
            and modify_count == 0
            and add_status == "UNEXPLAINED"
            and modify_status == "UNEXPLAINED"
        )
        add(
            "telemetry_delay_outcome",
            recovered or not_recovered,
            "events recovered after source restoration"
            if recovered
            else "events were not recovered after source restoration"
            if not_recovered
            else "event recovery was partial or did not match the expected transition",
        )

    if payload.get("telemetry_condition") == "same_host_distractor":
        distractor_ok, distractor_detail = _same_host_distractor_result(
            payload, service_name, host_id
        )
        add(
            "same_host_distractor_rejection",
            distractor_ok,
            distractor_detail,
        )
    if payload.get("telemetry_condition") == "complete_distractor":
        distractor_ok, distractor_detail = _complete_distractor_result(
            payload, service_name, host_id
        )
        add("complete_distractor_rejection", distractor_ok, distractor_detail)
    if payload.get("telemetry_condition") in {
        "target_selective_drop",
        "target_selective_drop_clean",
    }:
        require_distractor = payload.get("telemetry_condition") == "target_selective_drop"
        suppression_ok, suppression_detail = _target_selective_suppression_result(
            payload, service_name, host_id, require_distractor=require_distractor
        )
        add(
            "target_selective_suppression_and_distractor"
            if require_distractor
            else "target_selective_suppression_clean",
            suppression_ok,
            suppression_detail,
        )

    state_transition = payload.get("state_transition") or {}
    add(
        "raw_before_after_state",
        None
        if no_change
        else bool(
            state_transition.get("before")
            and state_transition.get("after")
            and state_transition.get("before_observation_id")
            and state_transition.get("after_observation_id")
        ),
        "NOT_APPLICABLE: no-change controls intentionally contain no state transition"
        if no_change
        else "the artifact contains raw service attributes and both direct-probe observation IDs",
    )

    passed = all(check["passed"] is not False for check in checks)
    raw_protocol_flag = (payload.get("protocol_adherence") or {}).get("protocol_adherent")
    protocol_check = next((check for check in checks if check["name"] == "protocol_adherent"), None)
    protocol_assessment = {
        "runner_reported": raw_protocol_flag,
        "independently_recomputed": protocol_check.get("passed") if protocol_check else None,
        "summary_mismatch": bool(
            protocol_check
            and raw_protocol_flag is not None
            and raw_protocol_flag != protocol_check.get("passed")
        ),
    }
    interpretation = "The record proves exact service reconciliation."
    if payload.get("telemetry_condition") == "capture_drop":
        outcome_check = next(
            (check for check in checks if check["name"] == "capture_drop_outcome"),
            None,
        )
        outcome = (
            "recovered"
            if outcome_check and "outcome: recovered" in outcome_check["detail"]
            else "not recovered after restore"
        )
        interpretation = (
            "The record proves exact service reconciliation and shows that the "
            f"modified-service Wazuh event was {outcome}."
        )
    elif payload.get("telemetry_condition") == "same_host_distractor":
        interpretation = (
            "The record tests whether same-host, same-type evidence for a different "
            "service is incorrectly used to explain the target service."
        )
    elif payload.get("telemetry_condition") == "target_selective_drop":
        interpretation = (
            "The record tests exact-object reconciliation under target-specific Wazuh "
            "suppression while preserving collection health and a same-host wrong-object event."
        )
    elif payload.get("telemetry_condition") == "telemetry_delay":
        outcome_check = next(
            (check for check in checks if check["name"] == "telemetry_delay_outcome"),
            None,
        )
        interpretation = (
            "The record proves a controlled Wazuh source pause with native state "
            "collection continuing; events were recovered after restoration."
            if outcome_check and outcome_check["detail"].startswith("events recovered")
            else "The record proves a controlled Wazuh source pause with native state "
            "collection continuing; the expected events were not recovered after restoration."
        )
    elif no_change:
        interpretation = (
            "The record is a valid no-change control: no service state delta, "
            "finding, or expected service event was produced."
        )
    if not passed:
        interpretation = (
            "The record must not be used as proof until every failed check is resolved."
        )
    return {
        "schema_version": "csg-service-drift-validation-v3",
        "run_id": payload.get("run_id"),
        "service_name": service_name,
        "host_id": host_id,
        "passed": passed,
        "protocol_adherence_assessment": protocol_assessment,
        "checks": checks,
        "interpretation": interpretation,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--allow-no-recovery",
        action="store_true",
        help="validate the bounded drop phase without requiring post-restore CONSISTENT",
    )
    args = parser.parse_args()
    payload = json.loads(args.result.read_text(encoding="utf-8-sig"))
    validation = validate(payload, require_capture_recovery=not args.allow_no_recovery)
    output = json.dumps(validation, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    print(output, end="")
    if not validation["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
