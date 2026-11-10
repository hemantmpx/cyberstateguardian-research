from experiments.audit_same_window_reconciliation_identity import audit_result


def _result(matched_ids=None, target_present=True):
    target_id = "wazuh-target"
    distractor_id = "wazuh-distractor"
    return {
        "host_id": "win11-arm-lab",
        "target_task_name": "CSGAPTTask1234567890",
        "expected_collected_distractor_task_name": "CSGAPTDis1234567890",
        "target_event_present_during_filter": target_present,
        "exact_wazuh_target_event_count_during_filter": 1 if target_present else 0,
        "direct_probe_state_sequence_passed": True,
        "target_absent_from_csg_event_store_during_filter": not target_present,
        "runner_result": {
            "scenarios": [{
                "kind": "scheduled_task",
                "object_name": "CSGAPTTask1234567890",
                "expected_object_key": "scheduled_task:\\csgapttask1234567890",
                "expected_event_type": "scheduled_task_created",
                "state_plane": {"after_action_observation_id": "observation-shared"},
                "local_source_evidence": {
                    "query_status": "COMPLETE",
                    "exact_events": [{
                        "event_id": 4698,
                        "record_id": 101,
                        "log_name": "Security",
                        "event_time_utc": "2026-10-13T18:39:45Z",
                        "exact_identity_match": True,
                        "event_data": {"TaskName": "\\CSGAPTTask1234567890"},
                    }],
                },
                "distractor_evidence": {
                    "local_windows_event": {
                        "event_id": 4698,
                        "record_id": 102,
                        "event_time_utc": "2026-10-13T18:39:42Z",
                        "task_name": "\\CSGAPTDis1234567890",
                    },
                    "probe_observation_id": "observation-shared",
                    "target_and_distractor_observed_same_probe": True,
                    "probe_target_items": [{"task_name": "\\CSGAPTTask1234567890"}],
                    "probe_distractor_items": [{"task_name": "\\CSGAPTDis1234567890"}],
                    "state_observed_after_action": True,
                    "state_still_present_after_cleanup": False,
                    "event_inside_before_after_probe_interval": True,
                },
                "event_plane": {
                    "query_complete": True,
                    "exact_matches": [{
                        "event_id": target_id,
                        "event_time": "2026-10-13T18:39:45Z",
                        "host_id": "win11-arm-lab",
                        "normalized_type": "scheduled_task_created",
                        "source": "wazuh",
                        "target": {"key": "scheduled_task:\\csgapttask1234567890"},
                        "attributes": {"event_code": "4698"},
                    }] if target_present else [],
                    "exact_distractor_events": [{
                        "event_id": distractor_id,
                        "event_time": "2026-10-13T18:39:42Z",
                        "host_id": "win11-arm-lab",
                        "normalized_type": "scheduled_task_created",
                        "source": "wazuh",
                        "target": {"key": "scheduled_task:\\csgaptdis1234567890"},
                        "attributes": {"event_code": "4698"},
                    }],
                    "retrieval": {
                        "query_complete": True,
                        "coverage_status": "COMPLETE",
                        "endpoint_collection_status": "AVAILABLE",
                        "transport_status": "AVAILABLE",
                        "index_status": "AVAILABLE",
                    },
                },
            }]
        },
        "final_target_reconciliation": {
            "finalized": True,
            "status": "CONSISTENT" if target_present else "UNEXPLAINED",
            "matched_evidence_ids": matched_ids or ([target_id] if target_present else []),
            "observation_window": {
                "start": "2026-10-13T18:39:17Z",
                "end": "2026-10-13T18:40:14Z",
            },
            "metadata": {
                "event_retrieval_complete": True,
                "source_health_known_degraded": False,
                "reconciliation_semantics": "UNCORROBORATED_HEALTHY",
                "event_plane": {
                    "query_complete": True,
                    "coverage_status": "COMPLETE",
                    "endpoint_collection_status": "AVAILABLE",
                    "transport_status": "AVAILABLE",
                    "index_status": "AVAILABLE",
                },
            },
        },
    }


def test_same_window_distinct_event_is_not_used_to_match_target():
    audit = audit_result(_result())

    assert audit["identity_specificity_control_passed"] is True
    assert audit["capture_drop_passed"] is False
    assert audit["classification"].endswith("NOT_CAPTURE_DROP")


def test_wrong_object_citation_fails_identity_specificity_control():
    audit = audit_result(_result(matched_ids=["wazuh-distractor"]))

    assert audit["identity_specificity_control_passed"] is False


def test_target_absence_with_complete_query_and_same_window_distractor_is_capture_drop_pass():
    audit = audit_result(_result(target_present=False))

    assert audit["identity_specificity_control_passed"] is False
    assert audit["capture_drop_passed"] is True
    assert all(audit["capture_drop_checks"].values())


def test_capture_drop_rejects_missing_distractor():
    result = _result(target_present=False)
    result["runner_result"]["scenarios"][0]["event_plane"]["exact_distractor_events"] = []

    audit = audit_result(result)

    assert audit["capture_drop_passed"] is False
    assert audit["capture_drop_checks"]["one_exact_wazuh_distractor_event_present"] is False


def test_capture_drop_rejects_incomplete_source_coverage():
    result = _result(target_present=False)
    result["runner_result"]["scenarios"][0]["event_plane"]["retrieval"][
        "coverage_status"
    ] = "INCOMPLETE"

    audit = audit_result(result)

    assert audit["capture_drop_passed"] is False
    assert audit["capture_drop_checks"]["complete_healthy_wazuh_query"] is False


def test_capture_drop_rejects_degraded_reconciliation_source():
    result = _result(target_present=False)
    result["final_target_reconciliation"]["metadata"]["event_plane"][
        "endpoint_collection_status"
    ] = "DEGRADED"
    result["final_target_reconciliation"]["metadata"]["reconciliation_semantics"] = (
        "INCONCLUSIVE"
    )

    audit = audit_result(result)

    assert audit["capture_drop_passed"] is False
    assert audit["capture_drop_checks"]["healthy_event_plane_at_final_reconciliation"] is False
