from datetime import datetime

from experiments.wazuh_fim_comparison import (
    _canonical_registry_path,
    _restore_verification,
    _summarize,
    _trial_analysis,
)


def test_registry_paths_normalize_hku_and_hkey_users() -> None:
    assert (
        _canonical_registry_path("registry:hku/s-1-5-21-100/software/test/run/value")
        == "hkey_users\\s-1-5-21-100\\software\\test\\run\\value"
    )
    assert (
        _canonical_registry_path("HKEY_USERS\\S-1-5-21-100\\Software\\Test\\Run")
        == "hkey_users\\s-1-5-21-100\\software\\test\\run"
    )


def test_fim_match_requires_exact_path_and_value_and_deduplicates_observation() -> None:
    record = {
        "trial_id": "registry_complete-01",
        "condition": "registry_complete",
        "host_id": "win11-arm-lab",
        "trial_pass": True,
        "target_name": "CSGValueA",
        "target_object_key": "registry:hku/s-1-5-21-100/software/test/run/csgvaluea",
        "started_at": "2026-10-07T12:00:00Z",
        "action_journal": {
            "target_create": {"started_at": "2026-10-07T12:00:05Z"},
        },
        "target": {
            "decision_at": "2026-10-07T12:00:20Z",
            "deltas": [{"delta_type": "ADD"}],
            "findings": [{"finding_id": "finding-1"}],
            "reconciliation_history": [
                {
                    "latest": {
                        "status": "CONSISTENT",
                        "matched_evidence_ids": ["wazuh-event-1"],
                    }
                }
            ],
            "wazuh_provider_exact_events": [
                {
                    "event_id": "wazuh-event-1",
                    "host_id": "win11-arm-lab",
                    "event_time": "2026-10-07T12:00:10Z",
                    "normalized_type": "registry_value_modified",
                    "target": {
                        "target_object": ("HKU\\S-1-5-21-100\\Software\\Test\\Run\\CSGValueA")
                    },
                    "source_reference": {
                        "index": "wazuh-archives-4.x-2026.10.07",
                        "document_id": "archive-doc-1",
                    },
                }
            ],
        },
        "bounded_distractor": {"matched_ids": ["distractor-event-1"]},
        "observations": {
            "after": {
                "categories": {
                    "registry": {
                        "items": [
                            {
                                "name": "CSGValueA",
                                "path": "hku:/s-1-5-21-100/software/test/run",
                            }
                        ]
                    }
                }
            }
        },
        "cleanup": {"started_at": "2026-10-07T12:00:30Z", "target_absent": True},
    }
    exact_alert = {
        "agent_name": "win11-arm-lab",
        "syscheck_path": "HKEY_USERS\\S-1-5-21-100\\Software\\Test\\Run",
        "syscheck_value_name": "CSGValueA",
        "syscheck_event": "added",
        "timestamp": "2026-10-07T12:00:10Z",
        "document_id": "doc-a",
        "rule_id": "751",
    }
    duplicate_rule_alert = {**exact_alert, "document_id": "doc-b", "rule_id": "752"}
    wrong_path_alert = {
        **exact_alert,
        "document_id": "doc-c",
        "syscheck_path": "HKEY_USERS\\S-1-5-21-100\\Software\\Other\\Run",
    }

    result = _trial_analysis(
        record,
        [exact_alert, duplicate_rule_alert, wrong_path_alert],
        [
            {
                "document_id": "archive-doc-1",
                "event_code": "13",
                "target_object": "HKU\\S-1-5-21-100\\Software\\Test\\Run\\CSGValueA",
                "timestamp": "2026-10-07T12:00:10Z",
            }
        ],
        query_end=datetime.fromisoformat("2026-10-07T12:10:00+00:00"),
    )

    assert result["csg_state_present_after"] is True
    assert result["exact_target_fim_at_decision"] is True
    assert len(result["exact_target_fim_documents"]) == 2
    assert result["exact_target_fim_unique_observations"] == 1
    assert len(result["same_name_wrong_path_documents"]) == 1
    assert result["csg_matched_evidence_ids"] == ["wazuh-event-1"]
    assert result["csg_exact_target_archive_link_valid"] is True
    assert result["csg_matched_wazuh_events"][0]["source_reference"]["document_id"] == (
        "archive-doc-1"
    )
    assert result["bounded_distractor_matched_evidence_ids"] == ["distractor-event-1"]


def test_sysmon_match_requires_full_target_object_and_event_id_13() -> None:
    record = {
        "trial_id": "registry_complete-02",
        "condition": "registry_complete",
        "target_name": "CSGConfRunA",
        "target_object_key": ("registry:hku/s-1-5-21-100/software/test/run/csgconfruna"),
        "action_journal": {
            "target_create": {
                "started_at": "2026-10-07T12:00:05Z",
                "completed_at": "2026-10-07T12:00:06Z",
            }
        },
        "target": {"decision_at": "2026-10-07T12:00:20Z"},
        "cleanup": {"completed_at": "2026-10-07T12:00:30Z"},
    }
    exact = {
        "document_id": "sysmon-exact",
        "event_code": "13",
        "target_object": ("HKU\\S-1-5-21-100\\Software\\Test\\Run\\CSGConfRunA"),
        "timestamp": "2026-10-07T12:00:10Z",
    }
    wrong_value = {
        **exact,
        "document_id": "sysmon-wrong-value",
        "target_object": "HKU\\S-1-5-21-100\\Software\\Test\\Run\\OtherValue",
    }
    wrong_event = {**exact, "document_id": "sysmon-wrong-event", "event_code": "12"}

    result = _trial_analysis(
        record,
        [],
        [exact, wrong_value, wrong_event],
        query_end=datetime.fromisoformat("2026-10-07T12:10:00+00:00"),
    )

    assert [item["document_id"] for item in result["exact_target_sysmon_index_documents"]] == [
        "sysmon-exact"
    ]
    assert result["exact_target_sysmon_index_at_decision"] is True


def test_summary_keeps_missing_artifacts_in_assigned_denominator() -> None:
    summary = _summarize(
        [
            {
                "condition": "registry_complete",
                "trial_status": "MISSING_ARTIFACT",
                "run_artifact_found": False,
                "cleanup_verified": False,
                "csg_state_present_after": False,
                "exact_target_fim_at_decision": False,
                "exact_target_fim_during_action_to_cleanup": False,
                "exact_distractor_fim_unique_observations": 0,
                "exact_distractor_fim_added_unique_observations": 0,
                "csg_reconciliation_statuses": [],
                "csg_matched_evidence_ids": [],
                "exact_target_fim_documents": [],
                "exact_target_fim_unique_observations": 0,
                "exact_target_fim_added_documents": [],
                "exact_target_fim_added_unique_observations": 0,
                "exact_target_fim_deleted_after_cleanup_documents": [],
            }
        ]
    )

    assert summary["registry_complete"]["assigned_trials"] == 1
    assert summary["registry_complete"]["missing_run_artifacts"] == 1


def test_restore_verification_uses_controller_health_polling_when_no_separate_file() -> None:
    result = _restore_verification(
        {
            "restored_original_config": True,
            "original_agent_config_sha256": "original-hash",
            "initial_restore_agent_status": "disconnected",
            "agent_active_after_restore": True,
            "service_after_restore": {"state": "Running", "pid": 1234},
            "restore_health_checks": [
                {"api_ok": True, "agent_status": "pending"},
                {"api_ok": True, "agent_status": "active"},
            ],
        },
        {},
    )

    assert result["config_hash_matches_original"] is True
    assert result["initial_wazuh_agent_status"] == "disconnected"
    assert result["wazuh_agent_status"] == "active"
    assert result["health_check_count"] == 2


def test_restore_verification_prefers_explicit_verification_artifact() -> None:
    explicit = {"config_hash_matches_original": True, "wazuh_agent_status": "active"}
    assert _restore_verification({"restored_original_config": False}, explicit) is explicit
