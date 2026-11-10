import json

from experiments.audit_service_dwell_campaign import summarize


def _trial(trial_id, service, evidence_id):
    object_key = f"service:{service.lower()}"
    snapshot = {"objects": [{"object_key": object_key, "attributes": {"start_mode": "Manual"}}]}
    return {
        "trial_id": trial_id,
        "condition": "dwell",
        "planned_dwell_seconds": 2,
        "replicate": int(trial_id[-1]),
        "host_id": "lab",
        "target": {"service_name": service, "object_key": object_key},
        "snapshot_before": snapshot,
        "snapshot_after": snapshot,
        "monitor_health_before": {"status": "HEALTHY"},
        "monitor_health_after": {"status": "HEALTHY"},
        "wazuh_service_before": {"status": "Running"},
        "wazuh_service_after": {"status": "Running"},
        "cleanup": {"completed": True, "service_absent": True},
        "action_timeline": [
            {
                "action": "manual_to_auto",
                "completed_at_utc": "2026-10-11T00:00:01Z",
                "exit_code": 0,
            },
            {"action": "auto_to_manual", "invoked_at_utc": "2026-10-11T00:00:03Z", "exit_code": 0},
        ],
        "actual_dwell_seconds": 2,
        "transition_records": [
            {
                "transition_id": f"delta-{trial_id}",
                "host_id": "lab",
                "object_key": object_key,
                "transition_type": "SERVICE_START_MODE_CHANGED",
                "observed_at": "2026-10-11T00:00:02Z",
                "new_state": {"start_mode": "Auto"},
            }
        ],
        "validation": {"outcome": "CAPTURED"},
        "windows_system_7040": [],
        "reconciliation_attempts": [
            {
                "status": "CORROBORATED",
                "matched_evidence_ids": [evidence_id],
                "match_reasons": [
                    {"reason": "exact service object and transition-compatible event"}
                ],
            }
        ],
    }


def test_audit_recomputes_exact_object_capture(tmp_path):
    _write_campaign(tmp_path, [_trial("trial-001", "CSGOne", "wazuh-1")])
    result = summarize(tmp_path)
    assert result["integrity_status"] == "PASS"
    assert result["outcomes_by_condition"]["dwell"]["CAPTURED"] == 1


def test_audit_flags_wazuh_evidence_reused_for_distinct_services(tmp_path):
    _write_campaign(
        tmp_path,
        [
            _trial("trial-001", "CSGOne", "wazuh-reused"),
            _trial("trial-002", "CSGTwo", "wazuh-reused"),
        ],
    )
    result = summarize(tmp_path)
    assert result["integrity_status"] == "REVIEW_REQUIRED"
    assert result["duplicate_wazuh_evidence_across_objects"] == {
        "wazuh-reused": ["CSGOne", "CSGTwo"]
    }


def _write_campaign(tmp_path, trials):
    plan = [
        {"condition": "dwell", "dwell_seconds": 2, "replicate": index}
        for index, _trial_data in enumerate(trials, start=1)
    ]
    (tmp_path / "campaign-manifest.json").write_text(
        json.dumps(
            {
                "campaign_id": "audit-test",
                "host_id": "lab",
                "scheduled_trials": len(plan),
                "completed_trials": len(plan),
                "planned_trials": plan,
            }
        ),
        encoding="utf-8",
    )
    for trial in trials:
        path = tmp_path / trial["trial_id"]
        path.mkdir()
        (path / "run.json").write_text(json.dumps(trial), encoding="utf-8")
