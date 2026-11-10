from __future__ import annotations

from copy import deepcopy

from scripts.validate_service_drift_result import (
    _complete_distractor_result,
    _same_host_distractor_result,
    _target_selective_suppression_result,
    validate,
)


def _finding(event_type: str, status: str, event_id: str | None = None) -> dict:
    return {
        "finding_id": f"finding-{event_type}",
        "category": "service",
        "object_key": "service:csgresearch-test",
        "reconciliation": {
            "status": status,
            "matched_evidence_ids": [event_id] if event_id else [],
            "match_reasons": [{"event_type": event_type}] if event_id else [],
            "missing_expected_evidence_types": [] if event_id else [event_type],
        },
    }


def _snapshot(create_status: str, modify_status: str) -> dict:
    return {
        "findings": [
            _finding("service_created", create_status, "wazuh-create"),
            _finding("service_modified", modify_status, "wazuh-modify"),
        ],
        "verified_exact_wazuh_evidence": {
            "exact_create_count": 1,
            "exact_modify_count": 1,
            "service_created": [
                {
                    "event_id": "wazuh-create",
                    "host_id": "win11-arm-lab",
                    "normalized_type": "service_created",
                    "service_name": "CSGResearch-Test",
                    "target_key": "service:csgresearch-test",
                    "target": {"key": "service:csgresearch-test"},
                    "attributes": {"new_start_mode": "Manual"},
                    "source_reference": {"index": "wazuh-alerts"},
                    "metadata": {"rule": {"id": "7045"}},
                    "event_time": "2026-09-28T10:00:00Z",
                }
            ],
            "service_modified": [
                {
                    "event_id": "wazuh-modify",
                    "host_id": "win11-arm-lab",
                    "normalized_type": "service_modified",
                    "service_name": "CSGResearch-Test",
                    "target_key": "service:csgresearch-test",
                    "target": {"key": "service:csgresearch-test"},
                    "attributes": {"old_start_mode": "Manual", "new_start_mode": "Auto"},
                    "source_reference": {"index": "wazuh-alerts"},
                    "metadata": {"rule": {"id": "7040"}},
                    "event_time": "2026-09-28T10:00:01Z",
                }
            ],
        },
        "state_transition": {
            "before_observation_id": "obs-before",
            "after_observation_id": "obs-after",
            "before": {"service_name": "CSGResearch-Test", "start_mode": "Manual"},
            "after": {"service_name": "CSGResearch-Test", "start_mode": "Auto"},
        },
    }


def test_complete_service_record_requires_exact_identity() -> None:
    payload = {
        "run_id": "complete-1",
        "host_id": "win11-arm-lab",
        "service_name": "CSGResearch-Test",
        "telemetry_condition": "complete",
        **_snapshot("CONSISTENT", "CONSISTENT"),
    }

    result = validate(payload)

    assert result["passed"] is True


def test_mirrored_alert_and_archive_records_are_one_event_occurrence() -> None:
    payload = {
        "run_id": "complete-mirrored-index-records-1",
        "host_id": "win11-arm-lab",
        "service_name": "CSGResearch-Test",
        "telemetry_condition": "complete",
        **_snapshot("CONSISTENT", "CONSISTENT"),
    }
    evidence = payload["verified_exact_wazuh_evidence"]
    for event_type in ("service_created", "service_modified"):
        archive_copy = dict(evidence[event_type][0])
        archive_copy["event_id"] = f"{event_type}-archive-copy"
        archive_copy["source_reference"] = {"index": "wazuh-archives-4.x"}
        evidence[event_type].append(archive_copy)
    evidence["exact_create_count"] = 2
    evidence["exact_modify_count"] = 2

    result = validate(payload)

    assert result["passed"] is True
    complete = next(
        check for check in result["checks"] if check["name"] == "complete_final_evidence"
    )
    assert complete["passed"] is True
    assert "unique_occurrences=1/1" in complete["detail"]


def test_complete_status_without_exact_event_citation_fails() -> None:
    payload = {
        "run_id": "complete-without-citation-1",
        "host_id": "win11-arm-lab",
        "service_name": "CSGResearch-Test",
        "telemetry_condition": "complete",
        **_snapshot("CONSISTENT", "CONSISTENT"),
    }
    payload["findings"][0]["reconciliation"]["matched_evidence_ids"] = []
    payload["findings"][1]["reconciliation"]["matched_evidence_ids"] = []

    result = validate(payload)

    assert result["passed"] is False
    complete = next(
        check for check in result["checks"] if check["name"] == "complete_final_evidence"
    )
    assert complete["passed"] is False


def test_archived_deltas_drive_one_transition_count_not_duplicate_findings() -> None:
    payload = {
        "run_id": "complete-delta-archive-1",
        "host_id": "win11-arm-lab",
        "service_name": "CSGResearch-Test",
        "telemetry_condition": "complete",
        **_snapshot("CONSISTENT", "CONSISTENT"),
        "target_state_deltas": [
            {
                "delta_id": "delta-add",
                "category": "service",
                "object_key": "service:csgresearch-test",
                "delta_type": "ADD",
                "before": None,
                "after": {"attributes": {"start_mode": "Manual"}},
            },
            {
                "delta_id": "delta-modify",
                "category": "service",
                "object_key": "service:csgresearch-test",
                "delta_type": "MODIFY",
                "before": {"attributes": {"start_mode": "Manual"}},
                "after": {"attributes": {"start_mode": "Auto"}},
            },
        ],
    }
    payload["findings"].append(dict(payload["findings"][1]))

    result = validate(payload)

    assert result["passed"] is True
    transition_count = next(
        check for check in result["checks"] if check["name"] == "single_delta_per_target_transition"
    )
    assert "ADD=1, MODIFY=1" in transition_count["detail"]


def test_duplicate_archived_target_transition_fails_validation() -> None:
    payload = {
        "run_id": "complete-duplicate-delta-1",
        "host_id": "win11-arm-lab",
        "service_name": "CSGResearch-Test",
        "telemetry_condition": "complete",
        **_snapshot("CONSISTENT", "CONSISTENT"),
        "target_state_deltas": [
            {
                "delta_id": delta_id,
                "category": "service",
                "object_key": "service:csgresearch-test",
                "delta_type": "ADD" if delta_id == "delta-add" else "MODIFY",
            }
            for delta_id in ("delta-add", "delta-modify-1", "delta-modify-2")
        ],
    }

    result = validate(payload)

    assert result["passed"] is False
    transition_count = next(
        check for check in result["checks"] if check["name"] == "single_delta_per_target_transition"
    )
    assert "MODIFY=2" in transition_count["detail"]


def _distractor_payload() -> dict:
    target_key = "service:csgresearch-test"
    return {
        "same_host_distractor_proof": {
            "details": {
                "source_before": {"status": "Running"},
                "source_during_target_add": {"status": "Stopped"},
                "source_after_add_restore": {"status": "Running"},
            },
            "bounded_observation": {
                "findings": [
                    {
                        "category": "service",
                        "object_key": target_key,
                        "reconciliation": {
                            "status": "UNEXPLAINED",
                            "delta_id": "target-add",
                            "metadata": {"event_time_tolerance_seconds": 5},
                            "matched_evidence_ids": [],
                            "missing_expected_evidence_types": ["service_created"],
                        },
                    }
                ],
                "target_state_deltas": [
                    {
                        "delta_id": "target-add",
                        "category": "service",
                        "object_key": target_key,
                        "delta_type": "ADD",
                        "observation_window": {
                            "start": "2026-09-28T09:59:58Z",
                            "end": "2026-09-28T10:00:02Z",
                        },
                    }
                ],
                "verified_exact_wazuh_evidence": {"exact_create_count": 0},
                "verified_distractor_wazuh_evidence": {
                    "host_id": "win11-arm-lab",
                    "service_created": [
                        {
                            "event_id": "wazuh-other-service",
                            "source": "wazuh",
                            "host_id": "win11-arm-lab",
                            "event_time": "2026-09-28T10:00:00Z",
                            "normalized_type": "service_created",
                            "service_name": "CSGDistractor",
                            "target_key": "service:csgdistractor",
                        }
                    ],
                },
            },
        }
    }


def test_same_host_same_type_wrong_object_in_window_is_rejected() -> None:
    passed, detail = _same_host_distractor_result(
        _distractor_payload(), "CSGResearch-Test", "win11-arm-lab"
    )

    assert passed is True
    assert "same-host" in detail


def test_same_host_distractor_outside_transition_window_is_not_a_valid_test() -> None:
    payload = _distractor_payload()
    payload["same_host_distractor_proof"]["bounded_observation"][
        "verified_distractor_wazuh_evidence"
    ]["service_created"][0]["event_time"] = "2026-09-28T10:00:30Z"

    passed, detail = _same_host_distractor_result(payload, "CSGResearch-Test", "win11-arm-lab")

    assert passed is False
    assert "same-window wrong-object event=False" in detail


def test_capture_drop_requires_unexplained_then_recovered_consistent() -> None:
    bounded = _snapshot("CONSISTENT", "UNEXPLAINED")
    recovered = _snapshot("CONSISTENT", "CONSISTENT")
    payload = {
        "run_id": "capture-1",
        "host_id": "win11-arm-lab",
        "service_name": "CSGResearch-Test",
        "telemetry_condition": "capture_drop",
        **recovered,
        "capture_drop_proof": {
            "bounded_observation": bounded,
            "post_restore_recovery": recovered,
            "wazuh_service_proof": {
                "before_stop": {"status": "Running"},
                "during_drop": {"status": "Stopped"},
                "after_restore": {"status": "Running"},
            },
        },
    }

    result = validate(payload)

    assert result["passed"] is True


def test_cross_object_evidence_is_rejected() -> None:
    payload = {
        "run_id": "wrong-object-1",
        "host_id": "win11-arm-lab",
        "service_name": "CSGResearch-Test",
        "telemetry_condition": "complete",
        **_snapshot("CONSISTENT", "CONSISTENT"),
    }
    payload["verified_exact_wazuh_evidence"]["service_created"][0].update(
        service_name="OtherService",
        target_key="service:otherservice",
    )

    result = validate(payload)

    assert result["passed"] is False
    identity = next(check for check in result["checks"] if check["name"] == "exact_object_identity")
    assert identity["status"] == "FAIL"
    assert identity["passed"] is False


def test_matched_event_without_archived_attributes_is_rejected() -> None:
    payload = {
        "run_id": "missing-archive-1",
        "host_id": "win11-arm-lab",
        "service_name": "CSGResearch-Test",
        "telemetry_condition": "complete",
        **_snapshot("CONSISTENT", "CONSISTENT"),
    }
    payload["verified_exact_wazuh_evidence"]["service_modified"][0].pop("attributes")

    result = validate(payload)

    assert result["passed"] is False
    assert any(
        check["name"] == "matched_event_archive" and not check["passed"]
        for check in result["checks"]
    )


def test_uses_latest_target_reconciliation_revision() -> None:
    payload = {
        "run_id": "reconciled-later-1",
        "host_id": "win11-arm-lab",
        "service_name": "CSGResearch-Test",
        "telemetry_condition": "complete",
        **_snapshot("CONSISTENT", "CONSISTENT"),
    }
    old = dict(payload["findings"][1])
    old["reconciliation"] = {
        **old["reconciliation"],
        "status": "UNEXPLAINED",
        "version": 1,
        "finalized": True,
        "matched_evidence_ids": [],
        "match_reasons": [],
        "missing_expected_evidence_types": ["service_modified"],
    }
    latest = {
        **payload["findings"][1],
        "reconciliation": {**payload["findings"][1]["reconciliation"], "version": 2},
    }
    payload["findings"].insert(1, old)
    payload["findings"][2] = latest

    result = validate(payload)

    assert result["passed"] is True


def test_wrong_object_revision_cannot_satisfy_target_transition() -> None:
    payload = {
        "run_id": "wrong-object-revision-1",
        "host_id": "win11-arm-lab",
        "service_name": "CSGResearch-Test",
        "telemetry_condition": "complete",
        **_snapshot("CONSISTENT", "CONSISTENT"),
    }
    payload["findings"][1]["object_key"] = "service:other-service"

    result = validate(payload)

    assert result["passed"] is False
    complete = next(
        check for check in result["checks"] if check["name"] == "complete_final_evidence"
    )
    assert complete["passed"] is False


def test_capture_drop_accepts_not_recovered_event() -> None:
    bounded = _snapshot("CONSISTENT", "UNEXPLAINED")
    recovered = _snapshot("CONSISTENT", "UNEXPLAINED")
    recovered["verified_exact_wazuh_evidence"]["service_modified"] = []
    recovered["verified_exact_wazuh_evidence"]["exact_modify_count"] = 0
    recovered["findings"][1]["reconciliation"]["matched_evidence_ids"] = []
    recovered["findings"][1]["reconciliation"]["match_reasons"] = []
    recovered["findings"][1]["reconciliation"]["missing_expected_evidence_types"] = [
        "service_modified"
    ]
    payload = {
        "run_id": "capture-loss-1",
        "host_id": "win11-arm-lab",
        "service_name": "CSGResearch-Test",
        "telemetry_condition": "capture_drop",
        **recovered,
        "capture_drop_proof": {
            "bounded_observation": bounded,
            "post_restore_recovery": recovered,
            "wazuh_service_proof": {
                "before_stop": {"status": "Running"},
                "during_drop": {"status": "Stopped"},
                "after_restore": {"status": "Running"},
            },
        },
    }

    result = validate(payload)

    assert result["passed"] is True
    outcome = next(check for check in result["checks"] if check["name"] == "capture_drop_outcome")
    assert "not recovered" in outcome["detail"]


def test_telemetry_delay_accepts_source_pause_without_event_recovery() -> None:
    payload = _snapshot("UNEXPLAINED", "UNEXPLAINED")
    payload.update(
        run_id="telemetry-delay-loss-1",
        telemetry_condition="telemetry_delay",
        service_name="CSGResearch-Test",
        host_id="win11-arm-lab",
    )
    payload["verified_exact_wazuh_evidence"]["service_created"] = []
    payload["verified_exact_wazuh_evidence"]["service_modified"] = []
    payload["verified_exact_wazuh_evidence"]["exact_create_count"] = 0
    payload["verified_exact_wazuh_evidence"]["exact_modify_count"] = 0
    for finding in payload["findings"]:
        finding["reconciliation"]["matched_evidence_ids"] = []
        finding["reconciliation"]["match_reasons"] = []
        finding["reconciliation"]["missing_expected_evidence_types"] = [
            "service_created"
            if finding["finding_id"] == "finding-service_created"
            else "service_modified"
        ]
    payload["telemetry_delay_proof"] = {
        "wazuh_service_proof": {
            "before_pause": {"status": "Running"},
            "during_pause": {"status": "Stopped"},
            "after_pause": {"status": "Running"},
        }
    }

    result = validate(payload)

    assert result["passed"] is True
    outcome = next(
        check for check in result["checks"] if check["name"] == "telemetry_delay_outcome"
    )
    assert "not recovered" in outcome["detail"]
    checks = {check["name"]: check for check in result["checks"]}
    assert checks["exact_object_identity"]["status"] == "NOT_APPLICABLE"
    assert checks["matched_event_archive"]["status"] == "NOT_APPLICABLE"


def test_target_selective_suppression_requires_exact_drop_distractor_and_restore() -> None:
    service = "CSGResearch-Test"
    host = "win11-arm-lab"
    target_key = f"service:{service.lower()}"
    payload = {
        "host_id": host,
        "service_name": service,
        "telemetry_condition": "target_selective_drop",
        "state_transition": {
            "before_observation_id": "obs-before",
            "after_observation_id": "obs-after",
            "before": {"start_mode": "Manual"},
            "after": {"start_mode": "Auto"},
            "independent_os_before": {"start_mode": "Manual"},
            "independent_os_after": {"start_mode": "Auto"},
        },
        "findings": [_finding("service_modified", "UNEXPLAINED")],
        "target_state_deltas": [
            {
                "host_id": host,
                "category": "service",
                "object_key": target_key,
                "delta_type": "MODIFY",
                "observation_window": {
                    "start": "2026-10-10T10:00:00Z",
                    "end": "2026-10-10T10:00:10Z",
                },
            }
        ],
        "windows_source_evidence": {
            "query_status": "SUCCEEDED",
            "events": [{"event_id": 7040, "message": f"Service {service} startup mode changed"}],
        },
        "verified_exact_wazuh_evidence": {
            "exact_modify_count": 0,
            "service_modified": [],
        },
        "same_host_distractor_proof": {
            "details": {
                "distractor_service_name": "OtherService",
                "modify": {
                    "exact_wazuh_events": [
                        {
                            "event_id": "wazuh-other-service",
                            "event_time": "2026-10-10T10:00:04Z",
                            "normalized_type": "service_modified",
                            "source": "wazuh",
                            "host_id": host,
                            "service_name": "OtherService",
                            "target_key": "service:otherservice",
                        }
                    ]
                },
            }
        },
        "target_selective_suppression_proof": {
            "status": "APPLIED_AND_HEALTHY",
            "original_config_sha256": "a" * 64,
            "effective_config_sha256": "b" * 64,
            "system_eventchannel_query": (
                f"Event[System/EventID != 7040 or EventData/Data[@Name='param1'] != '{service}']"
            ),
            "ignored_registry_path": (
                "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\" + service
            ),
            "verified_routes": {
                "system_eventchannel": True,
                "services_registry_fim": True,
                "wazuh_service": {"status": "Running"},
                "endpoint_agent": {"status": "active"},
                "indexer": {"status": "available"},
            },
            "observation": {
                "local_target_event_7040_count": 1,
                "csg_database_target_service_modified_count": 0,
                "wrong_object_wazuh_service_modified_count": 1,
                "event_query_status": "SUCCEEDED",
                "endpoint_service_status": "Running",
                "endpoint_collection_status": "active",
                "manager_status": "available",
                "indexer_status": "available",
                "target_reconciliation_status": "UNEXPLAINED",
            },
            "manipulation_valid": True,
            "restoration": {
                "status": "RESTORED_AND_HEALTHY",
                "restored_config_sha256": "a" * 64,
                "service": {"status": "Running"},
                "endpoint_agent": {"status": "active"},
                "indexer": {"status": "available"},
            },
        },
    }

    assert _target_selective_suppression_result(payload, service, host)[0] is True
    distractor_event = payload["same_host_distractor_proof"]["details"]["modify"][
        "exact_wazuh_events"
    ][0]
    distractor_event["service_name"] = "UnrelatedService"
    assert _target_selective_suppression_result(payload, service, host)[0] is False
    distractor_event["service_name"] = "OtherService"
    payload.update(
        schema_version="3",
        run_id="target-selective-pilot",
        protocol_adherence={"artifact_valid": True, "protocol_adherent": True},
        event_plane_status={
            "manager_status": "AVAILABLE",
            "indexer_status": "AVAILABLE",
            "indexer_health_source": "GET /api/wazuh/status",
            "expected_events": {"service_created": "PRESENT", "service_modified": "ABSENT"},
        },
        windows_source_evidence={
            "query_status": "SUCCEEDED",
            "events": [
                {"event_id": 7045, "message": f"Service {service} was created"},
                {"event_id": 7040, "message": f"Service {service} startup mode changed"},
            ],
        },
        target_state_deltas=[
            {
                "delta_id": f"delta-{transition.lower()}",
                "host_id": host,
                "category": "service",
                "object_key": target_key,
                "delta_type": transition,
                "observation_window": {
                    "start": "2026-10-10T10:00:00Z",
                    "end": "2026-10-10T10:00:10Z",
                },
            }
            for transition in ("ADD", "MODIFY")
        ],
    )
    validation = validate(payload)
    assert validation["passed"] is True, [
        check for check in validation["checks"] if check["passed"] is False
    ]
    assert (
        next(
            check
            for check in validation["checks"]
            if check["name"] == "target_selective_suppression_and_distractor"
        )["passed"]
        is True
    )

    clean_payload = deepcopy(payload)
    clean_payload["telemetry_condition"] = "target_selective_drop_clean"
    clean_payload["same_host_distractor_proof"]["details"]["modify"]["exact_wazuh_events"] = []
    clean_payload["target_selective_suppression_proof"]["observation"][
        "wrong_object_wazuh_service_modified_count"
    ] = 0
    clean_payload["target_selective_suppression_proof"]["manipulation_valid"] = False
    clean_payload["protocol_adherence"]["protocol_adherent"] = False
    assert (
        _target_selective_suppression_result(
            clean_payload, service, host, require_distractor=False
        )[0]
        is True
    )
    clean_validation = validate(clean_payload)
    assert clean_validation["passed"] is True, [
        check for check in clean_validation["checks"] if check["passed"] is False
    ]
    assert clean_validation["protocol_adherence_assessment"] == {
        "runner_reported": False,
        "independently_recomputed": True,
        "summary_mismatch": True,
    }

    payload["same_host_distractor_proof"]["details"]["modify"]["exact_wazuh_events"][0][
        "target_key"
    ] = target_key
    assert _target_selective_suppression_result(payload, service, host)[0] is False


def _no_change_payload() -> dict:
    return {
        "schema_version": "3",
        "run_id": "no-change-1",
        "host_id": "win11-arm-lab",
        "service_name": "Winmgmt",
        "telemetry_condition": "no_change",
        "findings": [],
        "target_state_deltas": [],
        "verified_exact_wazuh_evidence": {
            "exact_create_count": 0,
            "exact_modify_count": 0,
            "service_created": [],
            "service_modified": [],
        },
        "event_plane_status": {
            "expected_events": {
                "service_created": "ABSENT",
                "service_modified": "ABSENT",
            },
            "manager_status": "AVAILABLE",
            "indexer_status": "AVAILABLE",
            "indexer_health_source": "GET /api/wazuh/status",
        },
        "windows_source_evidence": {
            "query_status": "SUCCEEDED",
            "events": [],
        },
        "protocol_adherence": {
            "artifact_valid": True,
            "protocol_adherent": True,
        },
        "state_transition": {
            "before": {"start_mode": "Auto"},
            "after": {"start_mode": "Auto"},
            "attributes_unchanged": True,
            "independent_os_before": {"start_mode": "Auto"},
            "independent_os_after": {"start_mode": "Auto"},
            "independent_os_attributes_unchanged": True,
            "new_target_delta_count": 0,
            "new_target_finding_count": 0,
            "new_target_delta_ids": [],
            "new_target_finding_ids": [],
        },
    }


def test_schema3_no_change_accepts_empty_observation_sets() -> None:
    result = validate(_no_change_payload())

    check = next(item for item in result["checks"] if item["name"] == "no_change_control")
    assert check["passed"] is True


def test_schema3_no_change_rejects_a_delta_even_when_its_id_is_missing() -> None:
    payload = _no_change_payload()
    payload["state_transition"]["new_target_delta_count"] = 1

    result = validate(payload)

    check = next(item for item in result["checks"] if item["name"] == "no_change_control")
    assert check["passed"] is False


def test_complete_distractor_must_match_same_type_inside_target_delta_window() -> None:
    service = "CSGResearch-Test"
    host = "win11-arm-lab"
    payload = {
        "service_name": service,
        "host_id": host,
        "findings": [_finding("service_modified", "CONSISTENT", "target-event")],
        "target_state_deltas": [
            {
                "host_id": host,
                "category": "service",
                "object_key": f"service:{service.lower()}",
                "delta_type": "MODIFY",
                "observation_window": {
                    "start": "2026-10-10T10:00:00Z",
                    "end": "2026-10-10T10:00:10Z",
                },
            }
        ],
        "same_host_distractor_proof": {
            "details": {
                "distractor_service_name": "CSGDistractor-Test",
                "source_during_target_add": {"status": "Running"},
                "modify": {
                    "wazuh_service_status": "Running",
                    "local_windows_events": {"query_status": "SUCCEEDED"},
                    "exact_wazuh_events": [
                        {
                            "host_id": host,
                            "source": "wazuh",
                            "normalized_type": "service_modified",
                            "service_name": "CSGDistractor-Test",
                            "target_key": "service:csgdistractor-test",
                            "event_time": "2026-10-10T10:00:05Z",
                        }
                    ],
                },
            }
        },
        "event_plane_status": {"endpoint_service_status": "Running"},
    }

    assert _complete_distractor_result(payload, service, host)[0] is True
    payload["same_host_distractor_proof"]["details"]["modify"]["exact_wazuh_events"][0][
        "event_time"
    ] = "2026-10-10T10:00:20Z"
    assert _complete_distractor_result(payload, service, host)[0] is False


def test_no_change_distractor_requires_verified_in_window_event_and_cleanup() -> None:
    payload = _no_change_payload()
    payload["telemetry_condition"] = "no_change_distractor"
    payload["event_plane_status"]["endpoint_service_status"] = "Running"
    payload["protocol_adherence"]["distractor_control_adherent"] = True
    payload["state_transition"].update(
        before_observed_at="2026-10-10T10:00:00Z",
        after_observed_at="2026-10-10T10:00:10Z",
    )
    payload["same_host_distractor_proof"] = {
        "details": {
            "distractor_service_name": "CSGDistractor-Test",
            "source_before": {"status": "Running"},
            "source_after": {"status": "Running"},
            "distractor_create_events": [
                {
                    "event_id": "create-event",
                    "host_id": "win11-arm-lab",
                    "source": "wazuh",
                    "normalized_type": "service_created",
                    "service_name": "CSGDistractor-Test",
                    "target_key": "service:csgdistractor-test",
                }
            ],
            "modify": {
                "service_name": "CSGDistractor-Test",
                "action_started_at": "2026-10-10T10:00:04Z",
                "action_completed_at": "2026-10-10T10:00:05Z",
                "exact_wazuh_events": [
                    {
                        "event_id": "modify-event",
                        "host_id": "win11-arm-lab",
                        "source": "wazuh",
                        "normalized_type": "service_modified",
                        "service_name": "CSGDistractor-Test",
                        "target_key": "service:csgdistractor-test",
                        "event_time": "2026-10-10T10:00:05Z",
                    }
                ],
                "local_windows_events": {
                    "query_status": "SUCCEEDED",
                    "events": [
                        {
                            "event_id": 7040,
                            "message": "CSGDistractor-Test startup mode modified",
                        }
                    ],
                },
            },
            "cleanup": {"absent_after_cleanup": True},
        }
    }

    result = validate(payload)
    distractor_check = next(
        item for item in result["checks"] if item["name"] == "no_change_distractor_rejection"
    )
    assert distractor_check["passed"] is True
    payload["same_host_distractor_proof"]["details"]["distractor_create_events"][0][
        "service_name"
    ] = "DifferentService"
    result = validate(payload)
    distractor_check = next(
        item for item in result["checks"] if item["name"] == "no_change_distractor_rejection"
    )
    assert distractor_check["passed"] is False
