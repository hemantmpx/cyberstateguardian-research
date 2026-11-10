from experiments.audit_postrun_wazuh_window import audit_postrun_window


def _inputs():
    run = {
        "host_id": "win11-arm-lab",
        "target_task_name": "CSGAPTTask1234567890",
        "expected_collected_distractor_task_name": "CSGAPTDis1234567890",
        "direct_probe_state_sequence_passed": True,
        "final_target_reconciliation": {
            "status": "UNEXPLAINED",
            "finalized": True,
            "finalized_at": "2026-10-13T18:41:30Z",
            "matched_evidence_ids": [],
            "observation_window": {
                "start": "2026-10-13T18:39:17Z",
                "end": "2026-10-13T18:40:14Z",
            },
            "metadata": {"source_health_known_degraded": True},
        },
        "runner_result": {
            "scenarios": [
                {
                    "kind": "scheduled_task",
                    "object_name": "CSGAPTTask1234567890",
                    "state_plane": {
                        "after_action_observation_id": "shared",
                        "direct_windows_verification": {"target_absent_after_cleanup": True},
                    },
                    "local_source_evidence": {
                        "query_status": "COMPLETE",
                        "exact_events": [
                            {
                                "event_id": 4698,
                                "record_id": 1,
                                "log_name": "Security",
                                "event_time_utc": "2026-10-13T18:39:45Z",
                                "exact_identity_match": True,
                                "event_data": {"TaskName": "\\CSGAPTTask1234567890"},
                            }
                        ],
                    },
                    "distractor_evidence": {
                        "state_observed_after_action": True,
                        "target_and_distractor_observed_same_probe": True,
                        "probe_observation_id": "shared",
                        "probe_target_items": [{}],
                        "probe_distractor_items": [{}],
                        "state_still_present_after_cleanup": False,
                    },
                }
            ]
        },
    }
    observation = {
        "query_complete": True,
        "coverage_status": "COMPLETE",
        "endpoint_collection_status": "AVAILABLE",
        "transport_status": "AVAILABLE",
        "index_status": "AVAILABLE",
        "retrieved_count": 1,
        "total_hits": 1,
        "metadata": {
            "retrieval": {
                "start": "2026-10-13T18:39:17+00:00",
                "end": "2026-10-13T18:40:14+00:00",
                "query_started_at": "2026-10-13T18:42:00Z",
                "query_completed_at": "2026-10-13T18:42:01Z",
                "sources": {"alert": {"status": "AVAILABLE", "complete": True}},
            }
        },
        "events": [
            {
                "event_id": "distractor-event",
                "host_id": "win11-arm-lab",
                "event_time": "2026-10-13T18:39:42Z",
                "normalized_type": "scheduled_task_created",
                "target": {},
                "attributes": {"event_code": "4698", "task_name": "\\CSGAPTDis1234567890"},
            }
        ],
    }
    return run, observation


def test_postrun_audit_corroborates_without_promoting_original_finalization():
    run, observation = _inputs()

    audit = audit_postrun_window(run, observation)

    assert audit["postrun_corroboration_passed"] is True
    assert audit["original_csg_finalization_promoted"] is False
    assert audit["classification"] == (
        "POSTRUN_CAPTURE_DROP_CORROBORATED_ORIGINAL_FINALIZATION_DEGRADED"
    )


def test_postrun_audit_rejects_target_event_even_if_distractor_exists():
    run, observation = _inputs()
    target = dict(observation["events"][0])
    target["event_id"] = "target-event"
    target["attributes"] = {"event_code": "4698", "task_name": "\\CSGAPTTask1234567890"}
    observation["events"].append(target)

    audit = audit_postrun_window(run, observation)

    assert audit["postrun_corroboration_passed"] is False
    assert audit["checks"]["no_exact_target_named_event_in_postrun_query"] is False


def test_postrun_audit_rejects_mismatched_or_unhealthy_query_window():
    run, observation = _inputs()
    observation["metadata"]["retrieval"]["end"] = "2026-10-13T18:41:00Z"
    observation["endpoint_collection_status"] = "DEGRADED"

    audit = audit_postrun_window(run, observation)

    assert audit["postrun_corroboration_passed"] is False
    assert audit["checks"]["postrun_query_retrieved_exact_reconciliation_window"] is False
    assert audit["checks"]["complete_healthy_postrun_query"] is False


def test_postrun_audit_accepts_canonical_scheduled_task_object_key():
    run, observation = _inputs()
    event = observation["events"][0]
    event["target"] = {"key": "scheduled_task:\\CSGAPTDis1234567890"}
    event["attributes"].pop("task_name")

    audit = audit_postrun_window(run, observation)

    assert audit["postrun_corroboration_passed"] is True


def test_postrun_audit_labels_inconclusive_degraded_finalization():
    run, observation = _inputs()
    metadata = run["final_target_reconciliation"]["metadata"]
    metadata["source_health_known_degraded"] = False
    metadata["reconciliation_semantics"] = "INCONCLUSIVE"
    metadata["event_plane"] = {
        "query_complete": True,
        "coverage_status": "COMPLETE",
        "endpoint_collection_status": "DEGRADED",
        "transport_status": "AVAILABLE",
        "index_status": "AVAILABLE",
    }

    audit = audit_postrun_window(run, observation)

    assert audit["postrun_corroboration_passed"] is True
    assert audit["checks"]["original_csg_finalization_was_not_healthy"] is True
    assert audit["classification"] == (
        "POSTRUN_CAPTURE_DROP_CORROBORATED_ORIGINAL_FINALIZATION_DEGRADED"
    )
