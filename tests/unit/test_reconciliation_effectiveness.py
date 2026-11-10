import json

import pytest
from experiments.reconciliation_effectiveness import analyze_campaign, wilson_interval


def _event(event_id: str, *, event_type: str, host: str, object_key: str, name: str) -> dict:
    return {
        "event_id": event_id,
        "source": "wazuh",
        "host_id": host,
        "normalized_type": event_type,
        "event_time": "2026-10-02T12:00:05Z",
        "target_key": object_key,
        "service_name": name,
        "source_reference": {"index": "wazuh-alerts-4.x-2026.10.02", "document_id": event_id},
        "attributes": {"rule_id": "61138", "rule_level": 5},
    }


def _run(
    condition: str,
    trial_id: str,
    *,
    wrong_object: bool = False,
    no_change: bool = False,
) -> dict:
    name = f"CSG{trial_id}"
    key = f"service:{name.lower()}"
    host = "win11-arm-lab"
    transitions = [] if no_change else ["ADD", "MODIFY"]
    event_types = {"ADD": "service_created", "MODIFY": "service_modified"}
    evidence = {
        "service_created": []
        if no_change or wrong_object
        else [
            _event("created", event_type="service_created", host=host, object_key=key, name=name)
        ],
        "service_modified": []
        if no_change
        else [
            _event("modified", event_type="service_modified", host=host, object_key=key, name=name)
        ],
    }
    deltas = []
    findings = []
    for transition in transitions:
        delta_id = f"delta-{transition}"
        event = evidence[event_types[transition]]
        matched_ids = [row["event_id"] for row in event]
        status = "CONSISTENT" if matched_ids else "UNEXPLAINED"
        deltas.append(
            {
                "delta_id": delta_id,
                "object_key": key,
                "delta_type": transition,
                "before": {"metadata": {"source": "direct_probe"}},
                "after": {"metadata": {"source": "direct_probe"}},
            }
        )
        findings.append(
            {
                "finding_id": f"finding-{transition}",
                "delta_id": delta_id,
                "object_key": key,
                "category": "service",
                "reconciliation": {"status": status, "matched_evidence_ids": matched_ids},
            }
        )
    wrong_event = _event(
        "wrong-created",
        event_type="service_created",
        host=host,
        object_key="service:other-service",
        name="OtherService",
    )
    return {
        "run_status": "COMPLETED",
        "telemetry_condition": condition,
        "host_id": host,
        "service_name": name,
        "started_at": "2026-10-02T12:00:00Z",
        "ended_at": "2026-10-02T12:01:00Z",
        "event_plane_status": {"event_query_status": "COMPLETE"},
        "target_state_deltas": deltas,
        "findings": findings,
        "verified_exact_wazuh_evidence": evidence,
        "same_host_distractor_proof": (
            {"details": {"distractor_event": [wrong_event]}} if wrong_object else None
        ),
    }


def _write_trial(root, condition: str, trial_id: str, run: dict) -> None:
    trial_dir = root / trial_id
    trial_dir.mkdir()
    (trial_dir / "run.json").write_text(json.dumps(run), encoding="utf-8")
    (trial_dir / "validation.json").write_text('{"passed": true}', encoding="utf-8")


def test_three_way_baselines_and_distractor_are_object_scoped(tmp_path):
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    schedule = []
    records = [
        ("complete", "complete-1", _run("complete", "complete-1")),
        (
            "same_host_distractor",
            "same_host_distractor-1",
            _run("same_host_distractor", "same_host_distractor-1", wrong_object=True),
        ),
        ("no_change", "no_change-1", _run("no_change", "no_change-1", no_change=True)),
    ]
    for condition, trial_id, run in records:
        _write_trial(campaign, condition, trial_id, run)
        schedule.append({"condition": condition, "trial_id": trial_id, "status": "COMPLETED"})
    (campaign / "campaign-manifest.json").write_text(
        json.dumps({"experiment_id": "unit-test", "status": "COMPLETED", "schedule": schedule}),
        encoding="utf-8",
    )

    result = analyze_campaign(campaign)

    assert (
        result["workflow_success_counts"]["event_only_detected_both_transitions"]["successes"] == 1
    )
    assert (
        result["workflow_success_counts"]["state_only_detected_both_transitions"]["successes"] == 2
    )
    assert result["workflow_success_counts"]["csg_emitted_both_target_findings"]["successes"] == 2
    distractor = next(row for row in result["trials"] if row["condition"] == "same_host_distractor")
    assert distractor["wrong_object_control"]["wrong_object_event_rejected"] is True
    assert distractor["transitions"]["ADD"]["reconciliation_status"] == "UNEXPLAINED"
    assert result["no_change_control"]["false_positive_trials"]["csg"]["count"] == 0
    assert result["no_change_control"]["false_positive_trials"]["event_only"]["count"] == 0
    assert result["no_change_control"]["false_positive_trials"]["state_only"]["count"] == 0


def test_exact_event_identity_mismatch_is_not_counted_as_event_detection(tmp_path):
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    run = _run("complete", "complete-1")
    run["verified_exact_wazuh_evidence"]["service_created"][0]["target_key"] = (
        "service:somebody-else"
    )
    _write_trial(campaign, "complete", "complete-1", run)
    (campaign / "campaign-manifest.json").write_text(
        json.dumps(
            {
                "experiment_id": "identity-test",
                "status": "COMPLETED",
                "schedule": [
                    {"condition": "complete", "trial_id": "complete-1", "status": "COMPLETED"}
                ],
            }
        ),
        encoding="utf-8",
    )

    result = analyze_campaign(campaign)
    add = result["trials"][0]["transitions"]["ADD"]
    assert add["event_detected"] is False
    assert add["reconciliation_decision_correct"] is False


def test_archive_event_is_not_counted_as_native_wazuh_alert(tmp_path):
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    run = _run("complete", "complete-archive-1")
    run["verified_exact_wazuh_evidence"]["service_created"][0]["source_reference"]["index"] = (
        "wazuh-archives-4.x-2026.10.02"
    )
    _write_trial(campaign, "complete", "complete-archive-1", run)
    (campaign / "campaign-manifest.json").write_text(
        json.dumps(
            {
                "experiment_id": "archive-source-test",
                "status": "COMPLETED",
                "schedule": [
                    {
                        "condition": "complete",
                        "trial_id": "complete-archive-1",
                        "status": "COMPLETED",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = analyze_campaign(campaign)
    add = result["trials"][0]["transitions"]["ADD"]
    modify = result["trials"][0]["transitions"]["MODIFY"]

    assert add["event_detected"] is True
    assert add["wazuh_alert_detected"] is False
    assert add["exact_wazuh_archive_count"] == 1
    assert modify["wazuh_alert_detected"] is True
    assert (
        result["workflow_success_counts"]["wazuh_alert_only_detected_both_transitions"]["successes"]
        == 0
    )
    assert (
        result["workflow_success_counts"]["event_only_detected_both_transitions"]["successes"] == 1
    )


def test_wilson_interval_handles_empty_and_extreme_samples():
    assert wilson_interval(0, 0) is None
    assert wilson_interval(0, 10)[0] == 0.0
    assert wilson_interval(10, 10)[1] == pytest.approx(1.0)


def test_incomplete_event_query_cannot_be_counted_as_event_absence(tmp_path):
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    run = _run("capture_drop", "capture_drop-1")
    run["event_plane_status"]["event_query_status"] = "INCOMPLETE"
    _write_trial(campaign, "capture_drop", "capture_drop-1", run)
    (campaign / "campaign-manifest.json").write_text(
        json.dumps(
            {
                "experiment_id": "incomplete-query-test",
                "status": "COMPLETED",
                "schedule": [
                    {
                        "condition": "capture_drop",
                        "trial_id": "capture_drop-1",
                        "status": "COMPLETED",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="central event query was not recorded as complete"):
        analyze_campaign(campaign)
