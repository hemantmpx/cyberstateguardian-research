import json

import pytest
from experiments.summarize_service_dwell_cohorts import summarize_cohorts


def _write_campaign(path, campaign_id, seed, protocol_sha):
    path.mkdir(parents=True)
    manifest = {
        "campaign_id": campaign_id,
        "status": "COMPLETED",
        "host_id": "win11-lab",
        "random_seed": seed,
        "scheduled_trials": 50,
        "completed_trials": 50,
        "implementation_sha256": "runner-sha",
        "protocol_sha256": protocol_sha,
        "windows": {"build": "26200", "architecture": "ARM64"},
        "probe": {
            "settings_sha256": "probe-sha",
            "poll_interval_seconds": 5,
            "transition_enabled": True,
            "services_enabled": True,
        },
    }
    (path / "campaign-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (path / "analysis").mkdir()
    rows = []
    for dwell, captured in ((0.25, 0), (2.0, 3), (6.0, 9), (12.0, 10)):
        rows.append(
            {
                "condition": "dwell",
                "planned_dwell_seconds": dwell,
                "scheduled": 10,
                "evaluable": 10,
                "primary_numerator": captured,
                "primary_denominator": 10,
                "primary_rate": captured / 10,
                "wilson_95_percent_interval": [0.0, 1.0],
            }
        )
    rows.append(
        {
            "condition": "stable_no_change",
            "planned_dwell_seconds": 12.0,
            "scheduled": 10,
            "evaluable": 10,
            "primary_numerator": 10,
            "primary_denominator": 10,
            "false_transitions": 0,
            "wilson_95_percent_interval": [0.7, 1.0],
        }
    )
    (path / "analysis" / "aggregate.json").write_text(
        json.dumps({"campaign_status": "COMPLETED", "condition_summaries": rows}),
        encoding="utf-8",
    )
    (path / "analysis" / "raw-evidence-audit.json").write_text(
        json.dumps(
            {
                "integrity_status": "PASS",
                "raw_run_files": 50,
                "unique_service_objects": 50,
                "reconciliation_status_counts": {"CORROBORATED": 50},
                "duplicate_wazuh_evidence_across_objects": {},
                "duplicate_windows_system_record_ids_across_objects": {},
            }
        ),
        encoding="utf-8",
    )
    visibility_dir = path / "analysis" / "wazuh-visibility-posthoc"
    visibility_dir.mkdir()
    (visibility_dir / "summary.json").write_text(
        json.dumps(
            {
                "campaign_id": campaign_id,
                "query_status_counts_by_condition": {
                    "dwell": {"COMPLETE": 40, "exact_events_2": 40},
                    "stable_no_change": {"COMPLETE": 10, "exact_events_0": 10},
                },
                "duplicate_exact_wazuh_event_ids_across_services": {},
                "unique_exact_wazuh_event_ids": 80,
                "windows_system_7040_counts_by_condition": {
                    "dwell": 80,
                    "stable_no_change": 0,
                },
                "reconciliation_event_id_overlap": {"matched": 50, "reconciliation_ids": 50},
            }
        ),
        encoding="utf-8",
    )


def test_pools_only_after_audits_and_exact_event_checks_pass(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    _write_campaign(first, "c1", 10, "p1")
    _write_campaign(second, "c2", 11, "p2")

    result = summarize_cohorts([first, second])

    assert [(row["captured"], row["trials"]) for row in result["pooled_dwell_capture"]] == [
        (0, 20),
        (6, 20),
        (18, 20),
        (20, 20),
    ]
    assert result["pooled_stable_no_change_control"]["no_false_transition"] == 20
    assert result["pooled_wazuh_visibility"]["exact_target_events"] == 160


def test_rejects_different_probe_settings(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    _write_campaign(first, "c1", 10, "p1")
    _write_campaign(second, "c2", 11, "p2")
    manifest_path = second / "campaign-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["probe"]["settings_sha256"] = "different-probe-sha"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="probe setting settings_sha256"):
        summarize_cohorts([first, second])
