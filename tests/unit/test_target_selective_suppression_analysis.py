import json

import pytest
from experiments.target_selective_suppression_analysis import (
    CHECK_NAME,
    CONDITION_KEY,
    analyze_campaign,
    analyze_trial,
    exact_mcnemar_two_sided,
)


def _trial():
    target = "CSGTargetService"
    object_key = f"service:{target.lower()}"
    wrong = "CSGDistractorService"
    delta_id = "delta-target-modify"
    local_xml = (
        "<Event xmlns='urn:test'><EventData><Data Name='param1'>"
        f"{target}</Data></EventData></Event>"
    )
    run = {
        "run_id": "run-1",
        "run_status": "COMPLETED",
        "telemetry_condition": "target_selective_drop",
        "host_id": "win11-arm-lab",
        "service_name": target,
        "target_state_deltas": [
            {
                "delta_id": delta_id,
                "category": "service",
                "object_key": object_key,
                "delta_type": "MODIFY",
                "before": {
                    "attributes": {"start_mode": "manual"},
                    "metadata": {"source": "direct_probe", "observation_id": "obs-before"},
                },
                "after": {
                    "attributes": {"start_mode": "auto"},
                    "metadata": {"source": "direct_probe", "observation_id": "obs-after"},
                },
            }
        ],
        "findings": [
            {
                "finding_id": "finding-1",
                "object_key": object_key,
                "reconciliation": {
                    "delta_id": delta_id,
                    "status": "UNEXPLAINED",
                    "matched_evidence_ids": [],
                    "observation_window": {
                        "start": "2026-10-10T12:00:00Z",
                        "end": "2026-10-10T12:01:00Z",
                    },
                },
            }
        ],
        "windows_source_evidence": {
            "query_status": "SUCCEEDED",
            "query": {"log_name": "System", "exact_service_name": target},
            "events": [
                {
                    "event_id": 7040,
                    "record_id": 42,
                    "event_time": "2026-10-10T12:00:06Z",
                    "raw_xml": local_xml,
                }
            ],
        },
        "target_selective_suppression_proof": {
            "status": "APPLIED_AND_HEALTHY",
            "manipulation_valid": True,
            "original_config_sha256": "config-hash",
            "observation": {
                "local_target_event_7040_count": 1,
                "csg_database_target_service_modified_count": 0,
                "wrong_object_wazuh_service_modified_count": 1,
                "target_reconciliation_status": "UNEXPLAINED",
                "endpoint_collection_status": "active",
                "manager_status": "AVAILABLE",
                "indexer_status": "AVAILABLE",
                "distractor_exact_event_ids": ["wazuh-wrong-1"],
            },
            "restoration": {"restored_config_sha256": "config-hash"},
        },
        "event_plane_status": {"expected_events": {"service_modified": "ABSENT"}},
        "verified_exact_wazuh_evidence": {"service_modified": []},
        "same_host_distractor_proof": {
            "details": {
                "modify_sync": {"query_complete": True},
                "modify": {
                    "exact_wazuh_events": [
                        {
                            "event_id": "wazuh-wrong-1",
                            "source": "wazuh",
                            "host_id": "win11-arm-lab",
                            "normalized_type": "service_modified",
                            "service_name": wrong,
                            "target_key": f"service:{wrong.lower()}",
                            "event_time": "2026-10-10T12:00:05Z",
                            "source_reference": {
                                "index": "wazuh-archives-4.x-test",
                                "document_id": "doc-1",
                            },
                        }
                    ]
                },
                "cleanup": {"absent_after_cleanup": True},
                "cleanup_probe_observation": {
                    "categories": {"service": {"items": [{"service_name": "OtherService"}]}}
                },
            }
        },
        "action_journal": {"service_cleanup": {"command_exit_code": 0}},
        "probe_scheduled_task": {"after": "Running"},
    }
    validation = {"passed": True, "checks": [{"name": CHECK_NAME, "status": "PASS"}]}
    return run, validation


def test_paired_analysis_distinguishes_loose_and_exact_identity_matching():
    run, validation = _trial()
    row = analyze_trial("trial-1", run, validation)

    assert row["target_windows_event"]["record_id"] == 42
    assert row["paired_method_outcomes"] == {
        "exact_target_event_only_detected_modify": False,
        "native_probe_only_detected_state_change": True,
        "loose_host_type_time_ablation_would_match_wrong_object": True,
        "exact_host_type_object_match_would_match_wrong_object": False,
        "csg_target_status": "UNEXPLAINED",
        "csg_false_consistent_for_target": False,
        "csg_state_change_observed": True,
    }


def test_analysis_fails_if_only_distractor_event_is_outside_target_window():
    run, validation = _trial()
    event = run["same_host_distractor_proof"]["details"]["modify"]["exact_wazuh_events"][0]
    event["event_time"] = "2026-10-10T12:02:00Z"
    with pytest.raises(ValueError, match="no fully materialized wrong-object event"):
        analyze_trial("trial-1", run, validation)


def test_analysis_fails_if_local_event_names_a_different_service():
    run, validation = _trial()
    event = run["windows_source_evidence"]["events"][0]
    event["raw_xml"] = event["raw_xml"].replace("CSGTargetService", "NotTheTarget")
    with pytest.raises(ValueError, match="target-named local Event 7040"):
        analyze_trial("trial-1", run, validation)


def test_campaign_analysis_hashes_inputs_and_reports_paired_counts(tmp_path):
    campaign = tmp_path / "campaign"
    trial_dir = campaign / "trial-1"
    trial_dir.mkdir(parents=True)
    run, validation = _trial()
    (trial_dir / "run.json").write_text(json.dumps(run), encoding="utf-8")
    (trial_dir / "validation.json").write_text(json.dumps(validation), encoding="utf-8")
    (campaign / "aggregate.json").write_text(
        json.dumps(
            {
                "campaign_id": "test-campaign",
                "conditions": {CONDITION_KEY: {"included_trials": 1, "trial_ids": ["trial-1"]}},
            }
        ),
        encoding="utf-8",
    )

    result = analyze_campaign(campaign)

    assert result["summary"]["native_probe_state_change_detected"]["successes"] == 1
    assert result["summary"]["exact_target_wazuh_modify_detected"]["successes"] == 0
    assert (
        result["paired_comparisons"]["native_probe_state_vs_exact_target_event"][
            "exact_two_sided_mcnemar_p_descriptive_only"
        ]
        == 1.0
    )
    assert result["input_sha256"]["trial-1/run.json"]


def test_exact_mcnemar_small_all_discordant_pair_value():
    assert exact_mcnemar_two_sided(5, 0) == 0.0625
