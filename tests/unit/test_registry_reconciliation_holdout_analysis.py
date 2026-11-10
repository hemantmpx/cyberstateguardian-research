from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from experiments.analyze_registry_reconciliation_holdout import (
    _condition_outcome,
    _exact_wazuh_event,
    _trial_latencies,
    analyze_campaign,
    normalize_registry_identity,
    sha256_file,
    wilson_interval,
)

HOST = "win11-arm-lab"
TARGET = "registry:hku/sid-1/software/run/csgtarget"
DISTRACTOR = "registry:hku/sid-1/software/run/csgdistractor"


def event(event_id: str, key: str, at: str = "2026-10-05T20:00:05Z") -> dict:
    return {
        "event_id": event_id,
        "host_id": HOST,
        "source": "wazuh",
        "normalized_type": "registry_value_modified",
        "event_time": at,
        "target": {"key": key},
        "attributes": {"target_object": key.removeprefix("registry:").replace("/", "\\")},
    }


def base_trial(condition: str) -> dict:
    return {
        "trial_id": f"{condition}-01",
        "condition": condition,
        "host_id": HOST,
        "target_name": "CSGTarget",
        "target_object_key": TARGET,
        "distractor_name": None,
        "distractor_object_key": None,
        "trial_pass": True,
        "protocol_adherent": True,
        "protocol_parameters": {"event_time_tolerance_seconds": 10},
        "target_state": {"absent_before": True, "present_after": True},
        "target": {
            "deltas": [
                {
                    "object_key": TARGET,
                    "delta_type": "ADD",
                    "observation_window": {
                        "start": "2026-10-05T20:00:00Z",
                        "end": "2026-10-05T20:00:10Z",
                    },
                }
            ],
            "findings": [{"object_key": TARGET}],
            "database_exact_events": [event("e1", TARGET)],
            "wazuh_provider_exact_events": [],
            "sysmon_exact_events": [{"record_id": 12}],
            "reconciliation_history": [
                {
                    "latest": {
                        "status": "CONSISTENT",
                        "finalized": True,
                        "matched_evidence_ids": ["e1"],
                    }
                }
            ],
        },
        "source_event_ingestion": {"database_verified": []},
        "bounded_distractor": {
            "wrong_object_event_inside_target_window": False,
            "finalized_status": None,
        },
        "no_change_control": {},
        "cleanup": {
            "target_absent": True,
            "distractor_absent": True,
            "cleanup_probe_succeeded": True,
        },
    }


def test_normalizes_wazuh_hku_registry_key() -> None:
    assert normalize_registry_identity(r"registry:HKU:\\SID-1\\Software\\Run\\Value") == (
        "hku/sid-1/software/run/value"
    )


def test_complete_requires_exact_event_cited_inside_causal_window() -> None:
    trial = base_trial("registry_complete")
    assert _condition_outcome(trial)[0]

    trial["target"]["reconciliation_history"][0]["latest"]["matched_evidence_ids"] = ["other"]
    assert not _condition_outcome(trial)[0]

    late_event = event("late", TARGET, "2026-10-05T20:00:30Z")
    assert not _exact_wazuh_event(late_event, trial)


def test_wrong_object_condition_requires_distractor_rejection() -> None:
    trial = base_trial("registry_wrong_object")
    trial["distractor_object_key"] = DISTRACTOR
    distractor = event("distractor-event", DISTRACTOR)
    trial["target"]["database_exact_events"] = []
    trial["target"]["reconciliation_history"] = [
        {
            "latest": {
                "status": "UNEXPLAINED",
                "finalized": True,
                "matched_evidence_ids": [],
            }
        }
    ]
    trial["source_event_ingestion"]["database_verified"] = [distractor]
    trial["bounded_distractor"] = {
        "wrong_object_event_inside_target_window": True,
        "finalized_status": "UNEXPLAINED",
    }
    assert _condition_outcome(trial)[0]

    contaminated = deepcopy(trial)
    contaminated["target"]["reconciliation_history"][0]["latest"]["matched_evidence_ids"] = [
        "distractor-event"
    ]
    assert not _condition_outcome(contaminated)[0]

    outside_window = deepcopy(trial)
    outside_window["source_event_ingestion"]["database_verified"][0]["event_time"] = (
        "2026-10-05T20:01:00Z"
    )
    assert not _condition_outcome(outside_window)[0]


def test_no_change_requires_no_delta_finding_or_telemetry() -> None:
    trial = base_trial("registry_no_change")
    trial["target_state"] = {"absent_before": True, "present_after": False}
    trial["target"] = {
        "deltas": [],
        "findings": [],
        "database_exact_events": [],
        "sysmon_exact_events": [],
        "reconciliation_history": [],
    }
    trial["no_change_control"] = {
        "target_absent_before": True,
        "target_absent_after": True,
        "new_delta_count": 0,
        "new_finding_count": 0,
    }
    assert _condition_outcome(trial)[0]

    trial["target"]["deltas"] = [{"object_key": TARGET, "delta_type": "ADD"}]
    assert not _condition_outcome(trial)[0]


def test_wilson_intervals_are_finite_for_all_success_and_failure() -> None:
    all_success = wilson_interval(30, 30)
    all_failure = wilson_interval(0, 30)
    assert all_success is not None and all_failure is not None
    assert all_success[0] < 1.0 and abs(all_success[1] - 1.0) < 1e-12
    assert all_failure[0] == 0.0 and all_failure[1] > 0.0
    assert round(all_success[0], 3) == 0.886
    assert round(all_failure[1], 3) == 0.114


def test_negative_latency_is_excluded_and_counted() -> None:
    trial = base_trial("registry_complete")
    trial["action_journal"] = {"target_create": {"completed_at": "2026-10-05T20:00:06Z"}}
    trial["observations"] = {"after": {"observed_at": "2026-10-05T20:00:05Z"}}
    trial["target"]["reconciliation_history"][0]["latest"]["finalized_at"] = "2026-10-05T20:00:07Z"

    latency = _trial_latencies(trial)
    assert latency["state_observation_seconds_after_action"] is None
    assert latency["state_observation_negative_excluded_count"] == 1
    assert latency["target_wazuh_event_seconds_after_action"] is None
    assert latency["target_wazuh_event_negative_excluded_count"] == 1


def test_campaign_analysis_requires_frozen_hashes_and_preregistered_counts(tmp_path: Path) -> None:
    protocol_path = tmp_path / "PROTOCOL.md"
    analyzer_hash = sha256_file(
        Path(__file__).resolve().parents[2]
        / "experiments/analyze_registry_reconciliation_holdout.py"
    )
    controller_hash = "a" * 64
    runner_hash = "b" * 64
    protocol_path.write_text(
        f"Analyzer SHA-256: `{analyzer_hash}`\n"
        f"Windows controller SHA-256: `{controller_hash}`\n"
        f"Windows trial runner SHA-256: `{runner_hash}`\n",
        encoding="utf-8",
    )

    condition_trials = []
    for condition in ("registry_complete", "registry_wrong_object", "registry_no_change"):
        trial = base_trial(condition)
        trial["trial_id"] = f"{condition}-01"
        trial["target_name"] = f"CSG-{condition}"
        trial["target_object_key"] = f"{TARGET}-{condition}"
        delta = trial["target"]["deltas"][0]
        delta["object_key"] = trial["target_object_key"]
        trial["target"]["findings"][0]["object_key"] = trial["target_object_key"]
        if condition == "registry_complete":
            event_row = event("complete-event", trial["target_object_key"])
            trial["target"]["database_exact_events"] = [event_row]
            trial["target"]["reconciliation_history"][0]["latest"]["matched_evidence_ids"] = [
                "complete-event"
            ]
        elif condition == "registry_wrong_object":
            trial["target"]["database_exact_events"] = []
            trial["target"]["reconciliation_history"] = [
                {"latest": {"status": "UNEXPLAINED", "finalized": True, "matched_evidence_ids": []}}
            ]
            trial["distractor_object_key"] = DISTRACTOR + "-pilot"
            trial["source_event_ingestion"]["database_verified"] = [
                event("distractor-event", trial["distractor_object_key"])
            ]
            trial["bounded_distractor"] = {
                "wrong_object_event_inside_target_window": True,
                "finalized_status": "UNEXPLAINED",
            }
        else:
            trial["target_state"] = {"absent_before": True, "present_after": False}
            trial["target"]["deltas"] = []
            trial["target"]["findings"] = []
            trial["target"]["database_exact_events"] = []
            trial["target"]["sysmon_exact_events"] = []
            trial["target"]["reconciliation_history"] = []
            trial["no_change_control"] = {
                "target_absent_before": True,
                "target_absent_after": True,
                "new_delta_count": 0,
                "new_finding_count": 0,
            }
        condition_trials.append(trial)

    campaign_dir = tmp_path / "campaign"
    campaign_dir.mkdir()
    schedule = []
    for trial in condition_trials:
        trial_id = trial["trial_id"]
        schedule.append(
            {"trial_id": trial_id, "condition": trial["condition"], "status": "COMPLETED_PASS"}
        )
        trial_dir = campaign_dir / trial_id
        trial_dir.mkdir()
        (trial_dir / "run.json").write_text(json.dumps(trial), encoding="utf-8")
    manifest = {
        "protocol_sha256": sha256_file(protocol_path),
        "controller_script_sha256": controller_hash,
        "trial_script_sha256": runner_hash,
        "execution_kind": "prospective_same_host_controlled_holdout",
        "host_id": HOST,
        "random_seed": 20261017,
        "tolerance_seconds": 10,
        "event_lookback_seconds": 300,
        "schedule": schedule,
    }
    (campaign_dir / "campaign-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    analysis = analyze_campaign(campaign_dir, protocol_path, expected_repetitions=1)
    assert analysis["all_outcomes_pass"]
    assert all(
        outcome["outcome"]["successes"] == 1 for outcome in analysis["condition_outcomes"].values()
    )

    manifest["trial_script_sha256"] = "c" * 64
    (campaign_dir / "campaign-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="trial runner"):
        analyze_campaign(campaign_dir, protocol_path, expected_repetitions=1)
