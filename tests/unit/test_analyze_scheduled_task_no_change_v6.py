import pytest
from experiments.analyze_scheduled_task_no_change_v6 import (
    evaluate_trial,
    exact_binomial_interval,
)


def _trial() -> dict:
    return {
        "trial_id": "no-change-01",
        "sentinel_task_name": "CSGNoChange01",
        "status": "PASS",
        "condition": "no_change",
        "action_attempted": False,
        "actions": [],
        "before_observation": {
            "observation_id": "before-id",
            "observed_at": "2026-10-12T00:00:00Z",
            "category": {"category": "scheduled_task", "status": "healthy"},
            "task_identity_count": 1,
            "task_names": ["\\Task\\Existing"],
        },
        "after_observation": {
            "observation_id": "after-id",
            "observed_at": "2026-10-12T00:00:10Z",
            "category": {"category": "scheduled_task", "status": "healthy"},
            "task_identity_count": 1,
            "task_names": ["\\task\\existing"],
            "interval_delta_ids": [],
            "interval_finding_ids": [],
        },
        "task_identity_changes": [],
        "sentinel_absent_before": True,
        "sentinel_absent_after": True,
        "new_scheduled_task_deltas": [],
        "new_scheduled_task_findings": [],
        "exact_target_local_security_events": [],
        "exact_target_provider_events": [],
        "expected_target_event_status": "NOT_APPLICABLE",
        "event_query": {
            "query_complete": True,
            "coverage_status": "COMPLETE",
            "endpoint_collection_status": "AVAILABLE",
            "transport_status": "AVAILABLE",
            "central_index_status": "AVAILABLE",
            "retrieved_count": 0,
            "total_hits": 0,
            "error": None,
        },
        "pre_health": {
            "api_ok": True,
            "wazuh_agent_status": "active",
            "wazuh_service_state": "Running",
            "sysmon_services": [{"state": "Running"}],
        },
        "post_health": {
            "api_ok": True,
            "wazuh_agent_status": "active",
            "wazuh_service_state": "Running",
            "sysmon_services": [{"state": "Running"}],
        },
        "gates": {"gate_one": True, "gate_two": True},
    }


def test_no_change_trial_passes_independent_checks():
    result = evaluate_trial(_trial(), "no-change-01", "CSGNoChange01")
    assert result["audited_pass"] is True
    assert result["task_identity_set_stable"] is True
    assert result["target_event_status"] == "NOT_APPLICABLE"


def test_wrong_object_or_mutation_fails_no_change_audit():
    trial = _trial()
    trial["after_observation"]["task_names"].append("\\Task\\New")
    trial["after_observation"]["task_identity_count"] = 2
    trial["task_identity_changes"] = [{"task_name": "\\Task\\New"}]
    result = evaluate_trial(trial, "no-change-01", "CSGNoChange01")
    assert result["audited_pass"] is False
    assert "task_identity_sets_unchanged" in result["failed_checks"]


def test_clopper_pearson_exact_interval_for_all_successes():
    interval = exact_binomial_interval(10, 10)
    assert interval is not None
    assert interval[0] == pytest.approx(0.6915028921812392)
    assert interval[1] == 1.0
