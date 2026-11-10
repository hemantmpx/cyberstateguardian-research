import json

from experiments.analyze_scheduled_task_distractor_campaign import (
    markdown_report,
    summarize,
    wilson_interval,
    write_outputs,
)


def _write_trial(root, trial_id, target_event_id, distractor_event_id):
    trial = root / "trials" / trial_id
    trial.mkdir(parents=True)
    checks = {
        "target_positive_control_passed": True,
        "distractor_event_ingested": True,
        "same_host_and_event_class_different_object": True,
        "distractor_event_inside_target_padded_window": True,
        "both_objects_observed_in_one_probe_snapshot": True,
        "target_consistent_with_only_target_evidence": True,
        "cleanup_verified": True,
        "wazuh_service_running_after_trial": True,
    }
    (trial / "trial.json").write_text(
        json.dumps(
            {
                "status": "PASS",
                "started_at_utc": "2026-10-11T07:00:00Z",
                "ended_at_utc": "2026-10-11T07:01:00Z",
                "target_task_name": f"target-{trial_id}",
                "distractor_task_name": f"distractor-{trial_id}",
                "condition_checks": checks,
                "target_reconciliation": {
                    "status": "CONSISTENT",
                    "finalized": True,
                    "exact_target_event_ids": [target_event_id],
                    "matched_evidence_ids": [target_event_id],
                },
                "distractor": {"exact_wazuh_event": {"event_id": distractor_event_id}},
            }
        ),
        encoding="utf-8",
    )


def test_wilson_interval_and_assigned_denominator_with_missing_trial(tmp_path):
    assert wilson_interval(0, 0) is None
    assert wilson_interval(1, 1)[0] < 1
    (tmp_path / "campaign-manifest.json").write_text(
        json.dumps(
            {
                "campaign_id": "test-campaign",
                "status": "INCOMPLETE",
                "host_id": "win-lab",
                "trials": [
                    {"sequence": 1, "trial_id": "trial-01", "status": "PASS"},
                    {"sequence": 2, "trial_id": "trial-02", "status": "NOT_RUN"},
                ],
            }
        ),
        encoding="utf-8",
    )
    _write_trial(tmp_path, "trial-01", "target-event-1", "distractor-event-1")

    result = summarize(tmp_path)

    assert result["assigned_trials"] == 2
    assert result["artifacts_present"] == 1
    assert result["primary_successes"] == 1
    assert result["posthoc_exact_target_link_among_trials_with_target_event"][
        "successes"
    ] == 1
    assert result["posthoc_exact_target_link_among_trials_with_target_event"][
        "denominator"
    ] == 1
    assert result["wilson_95_percent_interval_assigned_denominator"] == wilson_interval(1, 2)
    assert result["failed_or_incomplete_assigned_trials"] == ["trial-02"]
    report = markdown_report(result)
    assert (
        "restricted to trials where the archived outer controller confirmed distractor ingestion"
        in report
    )
    assert "excludes the failed distractor ingestion assignment" not in report
    write_outputs(result, tmp_path / "analysis")
    assert (tmp_path / "analysis" / "trials.csv").is_file()


def test_reused_event_id_is_reported_and_does_not_hide_passes(tmp_path):
    assignments = [
        {"sequence": 1, "trial_id": "trial-01", "status": "PASS"},
        {"sequence": 2, "trial_id": "trial-02", "status": "PASS"},
    ]
    (tmp_path / "campaign-manifest.json").write_text(
        json.dumps({"campaign_id": "test", "status": "COMPLETE", "trials": assignments}),
        encoding="utf-8",
    )
    _write_trial(tmp_path, "trial-01", "shared-target", "distractor-event-1")
    _write_trial(tmp_path, "trial-02", "shared-target", "distractor-event-2")

    result = summarize(tmp_path)

    assert result["primary_successes"] == 2
    assert result["cross_trial_event_id_reuse_detected"] is True
    assert result["cross_trial_wazuh_event_id_reuse"]["shared-target"] == [
        "trial-01",
        "trial-02",
    ]


def test_incomplete_provider_query_is_distinguished_from_wrong_object_match(tmp_path):
    assignment = {"sequence": 1, "trial_id": "trial-01", "status": "FAIL"}
    (tmp_path / "campaign-manifest.json").write_text(
        json.dumps({"campaign_id": "test", "status": "COMPLETE_WITH_GAPS", "trials": [assignment]}),
        encoding="utf-8",
    )
    _write_trial(tmp_path, "trial-01", "target-event", "distractor-event")
    result_path = tmp_path / "trials" / "trial-01" / "trial.json"
    trial = json.loads(result_path.read_text())
    trial["condition_checks"]["target_positive_control_passed"] = False
    trial["target_runner"] = {
        "scenarios": [
            {
                "event_plane": {"query_complete": False},
                "action": {"error": "provider operation timed out"},
            }
        ]
    }
    result_path.write_text(json.dumps(trial), encoding="utf-8")

    summary = summarize(tmp_path)
    row = summary["trials"][0]

    assert row["primary_success"] is False
    assert row["target_cites_only_its_exact_event"] is True
    assert row["inner_target_event_query_complete"] is False
    assert "inner target Wazuh provider query was incomplete" in row["failure_reasons"]
    assert any("provider operation timed out" in reason for reason in row["failure_reasons"])
    report = markdown_report(summary)
    assert "Incomplete provider queries: 1/1 nested target runs" in report
    assert "The two provider-query-incomplete runs" not in report


def test_nested_target_run_survives_outer_distractor_controller_failure(tmp_path):
    assignment = {"sequence": 1, "trial_id": "trial-01", "status": "FAIL"}
    (tmp_path / "campaign-manifest.json").write_text(
        json.dumps({"campaign_id": "test", "status": "COMPLETE_WITH_GAPS", "trials": [assignment]}),
        encoding="utf-8",
    )
    _write_trial(tmp_path, "trial-01", "target-event", "distractor-event")
    trial_path = tmp_path / "trials" / "trial-01" / "trial.json"
    trial = json.loads(trial_path.read_text())
    trial["status"] = "FAIL_OR_MANIPULATION_NOT_ATTAINED"
    trial["condition_checks"]["distractor_event_ingested"] = False
    trial["condition_checks"]["target_positive_control_passed"] = False
    trial["target_reconciliation"] = {"status": "MISSING", "finalized": False}
    trial["target_runner"] = None
    trial["error"] = "outer API event-ingest timeout"
    trial_path.write_text(json.dumps(trial), encoding="utf-8")
    nested_dir = trial_path.parent / "target-run"
    nested_dir.mkdir()
    (nested_dir / "run.json").write_text(
        json.dumps(
            {
                "scenarios": [
                    {
                        "positive_control": {"passed": True},
                        "event_plane": {
                            "query_complete": True,
                            "exact_matches": [{"event_id": "target-event"}],
                        },
                        "csg_reconciliation": {
                            "status": "CONSISTENT",
                            "finalized": True,
                            "matched_evidence_ids": "target-event",
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    summary = summarize(tmp_path)
    row = summary["trials"][0]

    assert summary["primary_successes"] == 0
    assert summary["posthoc_exact_target_link_among_trials_with_target_event"]["successes"] == 1
    assert summary["posthoc_exact_target_link_when_distractor_ingested"]["denominator"] == 0
    assert summary["nested_target_only_positive_control_passes"] == 1
    assert row["inner_target_positive_control_passed"] is True
    assert row["target_cites_only_its_exact_event"] is True
    assert any(
        "nested target-only positive control passed" in reason for reason in row["failure_reasons"]
    )
    assert any(
        "CSG event-ingest confirmation was missing" in reason
        for reason in row["failure_reasons"]
    )


def test_posthoc_audit_is_reported_separately_without_rewriting_primary(tmp_path):
    assignment = {"sequence": 1, "trial_id": "trial-01", "status": "FAIL"}
    (tmp_path / "campaign-manifest.json").write_text(
        json.dumps({"campaign_id": "test", "status": "COMPLETE_WITH_GAPS", "trials": [assignment]}),
        encoding="utf-8",
    )
    _write_trial(tmp_path, "trial-01", "target-event", "distractor-event")
    trial_path = tmp_path / "trials" / "trial-01" / "trial.json"
    trial = json.loads(trial_path.read_text())
    trial["status"] = "FAIL_OR_MANIPULATION_NOT_ATTAINED"
    trial["condition_checks"]["distractor_event_ingested"] = False
    trial["error"] = "API request timed out"
    trial_path.write_text(json.dumps(trial), encoding="utf-8")
    audit_path = tmp_path / "trial-01-audit.json"
    audit_path.write_text(
        json.dumps(
            {
                "campaign_id": "test",
                "trial_id": "trial-01",
                "adjudication": "not_upgraded_due_to_unproven_ingest_order",
                "api_access_log": {"late_post_200_at_utc": "2026-10-11T07:25:44Z"},
                "probe_observation": {"observed_at": "2026-10-11T07:23:35Z"},
                "original_trial_ended_at_utc": "2026-10-11T07:25:14Z",
            }
        ),
        encoding="utf-8",
    )

    result = summarize(tmp_path, posthoc_audit_path=audit_path)

    assert result["assigned_trials"] == 1
    assert result["primary_successes"] == 0
    assert result["posthoc_ingest_timeout_audit"]["trial_id"] == "trial-01"
    assert result["trials"][0]["primary_success"] is False
    assert "not upgraded" in markdown_report(result)


def test_v5_requires_distractor_store_readback_before_target_evaluation(tmp_path):
    assignment = {"sequence": 1, "trial_id": "trial-01", "status": "PASS"}
    (tmp_path / "campaign-manifest.json").write_text(
        json.dumps({"campaign_id": "test-v5", "status": "COMPLETE", "trials": [assignment]}),
        encoding="utf-8",
    )
    _write_trial(tmp_path, "trial-01", "target-event", "distractor-event")
    trial_path = tmp_path / "trials" / "trial-01" / "trial.json"
    trial = json.loads(trial_path.read_text())
    trial["controller_version"] = "v5-pre-ingest-snapshot-post-ingest-and-order-verification"
    trial["condition_checks"]["distractor_available_before_target_evaluation"] = False
    trial_path.write_text(json.dumps(trial), encoding="utf-8")

    summary = summarize(tmp_path)
    assert summary["primary_successes"] == 0
    assert "distractor_available_before_target_evaluation" in summary["trials"][0][
        "failed_checks"
    ]

    trial["condition_checks"]["distractor_available_before_target_evaluation"] = True
    trial_path.write_text(json.dumps(trial), encoding="utf-8")
    assert summarize(tmp_path)["primary_successes"] == 1


def test_v3_protocol_counts_and_enforces_ninth_chronology_gate(tmp_path):
    assignment = {"sequence": 1, "trial_id": "trial-01", "status": "PASS"}
    (tmp_path / "campaign-manifest.json").write_text(
        json.dumps(
            {
                "campaign_id": "test-v3",
                "status": "FAILED",
                "strict_gate_version": "v3-target-add-exact-event-readback",
                "trials": [assignment],
            }
        ),
        encoding="utf-8",
    )
    _write_trial(tmp_path, "trial-01", "target-event", "distractor-event")
    trial_path = tmp_path / "trials" / "trial-01" / "trial.json"
    trial = json.loads(trial_path.read_text())
    trial["condition_checks"]["distractor_available_before_target_evaluation"] = False
    trial_path.write_text(json.dumps(trial), encoding="utf-8")

    result = summarize(tmp_path)
    assert result["strict_gate_check_count"] == 9
    assert result["primary_successes"] == 0
    assert "distractor_available_before_target_evaluation" in result["trials"][0][
        "failed_checks"
    ]
    assert "all 9 frozen checks" in markdown_report(result)

    trial["condition_checks"]["distractor_available_before_target_evaluation"] = True
    trial_path.write_text(json.dumps(trial), encoding="utf-8")
    assert summarize(tmp_path)["primary_successes"] == 1


def test_v9_controller_enforces_chronology_even_with_legacy_manifest(tmp_path):
    assignment = {"sequence": 1, "trial_id": "trial-01", "status": "PASS"}
    (tmp_path / "campaign-manifest.json").write_text(
        json.dumps({"campaign_id": "test-controller-v9", "trials": [assignment]}),
        encoding="utf-8",
    )
    _write_trial(tmp_path, "trial-01", "target-event", "distractor-event")
    trial_path = tmp_path / "trials" / "trial-01" / "trial.json"
    trial = json.loads(trial_path.read_text())
    trial["controller_version"] = "v9-explicit-pretarget-event-store-gate"
    trial["condition_checks"]["distractor_available_before_target_evaluation"] = False
    trial_path.write_text(json.dumps(trial), encoding="utf-8")

    summary = summarize(tmp_path)
    assert summary["strict_gate_check_count"] == 9
    assert summary["primary_successes"] == 0
    assert "distractor_available_before_target_evaluation" in summary["trials"][0][
        "failed_checks"
    ]
