import json

from experiments.registry_positive_control_analysis import analyze_campaign


def _campaign(tmp_path, *, index="wazuh-alerts-4.x-2026.10.04", exact_key=True):
    campaign = tmp_path / "campaign"
    trial = campaign / "registry-positive-01"
    trial.mkdir(parents=True)
    expected_key = "registry:hku/s-1-5-21-1/software/microsoft/windows/currentversion/run/csgtest"
    event_id = "wazuh-test-event"
    target_key = expected_key if exact_key else "registry:hku/other/run/other"
    run = {
        "environment": {"host_id": "win11-arm-lab"},
        "scenarios": [
            {
                "scenario_id": "registry-autorun-persistence",
                "object_name": "CSGTest",
                "expected_object_key": expected_key,
                "action": {
                    "started_at": "2026-10-04T16:27:00Z",
                    "ended_at": "2026-10-04T16:28:00Z",
                },
                "state_plane": {
                    "after_action_observed": [{"object_key": expected_key, "name": "CSGTest"}],
                    "after_action_observation_id": "observation-1",
                    "cleanup_removed_from_probe": True,
                },
                "local_source_evidence": {
                    "query_status": "COMPLETE",
                    "exact_events": [
                        {
                            "event_id": 13,
                            "record_id": 99,
                            "log_name": "Microsoft-Windows-Sysmon/Operational",
                            "event_time_utc": "2026-10-04T16:27:30Z",
                            "exact_identity_match": True,
                        }
                    ],
                },
                "event_plane": {
                    "query_completed": True,
                    "exact_matches": [
                        {
                            "event_id": event_id,
                            "source": "wazuh",
                            "host_id": "win11-arm-lab",
                            "normalized_type": "registry_value_modified",
                            "event_time": "2026-10-04T16:27:31Z",
                            "target": {"key": target_key},
                            "source_reference": {"index": index},
                        }
                    ],
                },
                "deltas": [
                    {"delta_id": "delta-add", "delta_type": "ADD", "object_key": expected_key}
                ],
                "findings": [
                    {
                        "delta_id": "delta-add",
                        "object_key": expected_key,
                        "reconciliation": {
                            "status": "CONSISTENT",
                            "version": 2,
                            "matched_evidence_ids": [event_id],
                            "observation_window": {
                                "start": "2026-10-04T16:27:25Z",
                                "end": "2026-10-04T16:27:35Z",
                            },
                            "metadata": {"event_time_tolerance_seconds": 5},
                        },
                    }
                ],
            }
        ],
    }
    (trial / "run.json").write_text(json.dumps(run), encoding="utf-8")
    manifest = {
        "schema_version": "csg-windows-registry-positive-campaign-v1",
        "experiment_id": "registry-test",
        "status": "COMPLETED",
        "environment": "pretrial-environment.json",
        "schedule": [
            {
                "trial_id": "registry-positive-01",
                "status": "COMPLETED_PASS",
            }
        ],
    }
    (campaign / "campaign-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return campaign


def test_campaign_requires_exact_state_local_event_wazuh_and_reconciliation(tmp_path):
    result = analyze_campaign(_campaign(tmp_path))

    assert result["completed_trials"] == 1
    assert result["strict_positive_controls_passed"] == 1
    assert result["trials_with_exact_wazuh_source"]["alert_index"] == 1
    assert result["trials"][0]["reconciliation_linked_to_exact_event"] is True
    assert result["trials"][0]["csg_event_time_tolerance_seconds"] == 5


def test_archive_is_reported_separately_from_native_alerts(tmp_path):
    result = analyze_campaign(_campaign(tmp_path, index="wazuh-archives-4.x-2026.10.04"))

    assert result["trials_with_exact_wazuh_source"]["alert_index"] == 0
    assert result["trials_with_exact_wazuh_source"]["archive_index"] == 1
    assert result["strict_positive_controls_passed"] == 1


def test_wrong_object_event_fails_exact_identity_gate(tmp_path):
    result = analyze_campaign(_campaign(tmp_path, exact_key=False))

    assert result["strict_positive_controls_passed"] == 0
    assert result["trials"][0]["exact_wazuh_event_count"] == 0


def test_exact_event_outside_csg_window_is_reported_as_timing_miss(tmp_path):
    campaign = _campaign(tmp_path)
    run_path = campaign / "registry-positive-01" / "run.json"
    run = json.loads(run_path.read_text())
    scenario = run["scenarios"][0]
    scenario["event_plane"]["exact_matches"][0]["event_time"] = "2026-10-04T16:27:24Z"
    reconciliation = scenario["findings"][0]["reconciliation"]
    reconciliation.update(status="UNEXPLAINED", matched_evidence_ids=[])
    run_path.write_text(json.dumps(run))

    result = analyze_campaign(campaign)
    trial = result["trials"][0]

    assert trial["reconciliation_linkage_diagnosis"] == (
        "EXACT_EVENT_OUTSIDE_CSG_RECONCILIATION_WINDOW"
    )
    assert trial["exact_wazuh_event_window_checks"][0][
        "seconds_outside_csg_reconciliation_window"
    ] == 1.0
    assert result["stage_counts"]["exact_wazuh_event_any_index"] == 1
    assert result["stage_counts"]["csg_reconciled_exact_wazuh_event"] == 0


def test_canonical_campaign_label_preserves_raw_manifest_id(tmp_path):
    result = analyze_campaign(_campaign(tmp_path), campaign_label="registry-v2-timing-calibration")

    assert result["campaign_id"] == "registry-v2-timing-calibration"
    assert result["source_campaign_id"] == "registry-test"
