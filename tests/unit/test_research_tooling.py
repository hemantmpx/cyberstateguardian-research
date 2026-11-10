from __future__ import annotations

import copy
import json
import zipfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from experiments.ai_context_evaluation import SCORE_FIELDS
from experiments.baselines import Trial, confusion_metrics, evaluate_trials, fixture_event_detection
from experiments.datasets.windows_apt_2025.loader import iter_dataset, load_scenario_manifest
from experiments.incident_correlation_study import pairwise_correlation_metrics
from experiments.paired_ai_statistics import paired_statistics
from experiments.paired_reconciliation_statistics import _proportion, evaluate_trial
from experiments.windows_apt_evaluation import evaluate_dataset
from scripts.export_research_database import export_host
from scripts.summarize_benign_noise_window import summarize as summarize_benign_noise_window
from scripts.validate_windows_apt_live_reproduction import validate
from tests.unit.test_reconciliation import _events, _snapshot
from tests.unit.test_reconciliation_lifecycle import _pending_finding, _settings

from csg.api.routes import (
    AI_REVIEW_SCORE_FIELDS,
    AIReviewSaveRequest,
    save_ai_review_draft,
)
from csg.config import get_settings
from csg.db.repositories import CyberStateRepository
from csg.domain.models import EventObservationResult, TimeWindow
from csg.services.incident_correlation import _mapping_entity_keys
from csg.services.reconciliation_lifecycle import ReconciliationLifecycleService


def _healthy_event_observation(finding):
    window = finding.reconciliation.observation_window
    return EventObservationResult(
        query_complete=True,
        endpoint_collection_status="AVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        metadata={
            "query_start": window.start.isoformat(),
            "query_end": window.end.isoformat(),
            "source_health_checked_at": window.start.isoformat(),
        },
    )


def test_baseline_requires_correct_host_target_type_and_time():
    event = _events("svc-create-consistent.json")[0]
    window = TimeWindow(start=event.event_time, end=event.event_time)
    expected = [{"category": "service", "delta_type": "ADD", "object_key": event.target["key"]}]
    assert fixture_event_detection([event], expected, host_id=event.host_id, window=window)
    for change in (
        {"host_id": "other"},
        {"target": {"key": "service:other"}},
        {"normalized_type": "process_start"},
        {"event_time": event.event_time + timedelta(seconds=1)},
    ):
        assert not fixture_event_detection(
            [event.model_copy(update=change)], expected, host_id=event.host_id, window=window
        )


def test_wazuh_baseline_requires_real_source_and_preregistered_rule():
    event = _events("svc-create-consistent.json")[0].model_copy(
        update={
            "source": "wazuh",
            "synthetic": False,
            "metadata": {"rule": {"id": "123", "level": 7}},
        }
    )
    trial = Trial(
        trial_id="t1",
        host_id=event.host_id,
        object_key=event.target["key"],
        window=TimeWindow(start=event.event_time, end=event.event_time),
        positive=True,
        condition="complete",
        event_types=["service_created"],
    )
    result = evaluate_trials([trial], [event], [], wazuh_rule_ids={"123"})
    assert result["metrics"]["wazuh"]["tp"] == 1
    assert (
        evaluate_trials([trial], [event], [], wazuh_rule_ids={"456"})["metrics"]["wazuh"]["fn"] == 1
    )
    synthetic = event.model_copy(update={"synthetic": True})
    assert not evaluate_trials([trial], [synthetic], [], wazuh_rule_ids={"123"})["trials"][0][
        "wazuh"
    ]
    with pytest.raises(ValueError, match="overlapping"):
        evaluate_trials(
            [trial, trial.model_copy(update={"trial_id": "t2"})], [], [], wazuh_rule_ids={"123"}
        )


def test_metrics_preserve_undefined_rates_and_missing_labels():
    assert confusion_metrics([], [])["precision"] is None
    assert confusion_metrics([True, False], [False, True])["fp"] == 1
    assert pairwise_correlation_metrics({}, {})["pairwise_precision"] is None
    with pytest.raises(ValueError):
        pairwise_correlation_metrics({"f1": "i1"}, {})


def test_benign_noise_summary_reports_rates_without_claiming_false_positive_accuracy(
    tmp_path: Path,
):
    run = {
        "run_id": "noise-1",
        "trial_id": "noise-trial-1",
        "telemetry_condition": "no_change",
        "started_at": "2026-09-28T10:00:00Z",
        "ended_at": "2026-09-28T12:00:00Z",
        "findings": [
            {
                "finding_id": "f1",
                "category": "service",
                "authorization_status": "APPROVED",
                "risk": {"severity": "MEDIUM"},
                "reconciliation": {
                    "status": "UNEXPLAINED",
                    "metadata": {"reconciliation_semantics": "UNCORROBORATED_HEALTHY"},
                },
            }
        ],
    }
    (tmp_path / "noise-1.json").write_text(json.dumps(run), encoding="utf-8")

    summary = summarize_benign_noise_window(tmp_path, window_hours=2)

    assert summary["counts"]["unique_findings"] == 1
    assert summary["rates_per_hour"]["findings"] == 0.5
    assert summary["counts"]["potentially_false_escalations"] == 1
    assert "not a false-positive rate" in summary["interpretation"]


def test_ai_review_submission_lifecycle_locks_completed_review(tmp_path: Path, monkeypatch):
    from fastapi import HTTPException

    import csg.api.routes as routes

    study_dir = tmp_path / "study"
    study_dir.mkdir()
    packet = {
        "schema_version": "review-v1",
        "study_version": "test-study",
        "items": [
            {"review_id": "item-1", "subject": {}, "analysis": {"summary": "one"}},
            {"review_id": "item-2", "subject": {}, "analysis": {"summary": "two"}},
        ],
    }
    (study_dir / "review_items.blinded.json").write_text(json.dumps(packet), encoding="utf-8")
    monkeypatch.setattr(routes, "_ai_review_study_dir", lambda _runs, _study: study_dir)
    settings = get_settings()

    def items(complete: bool) -> list[dict]:
        scores = {field: 3 if complete else None for field in AI_REVIEW_SCORE_FIELDS}
        scores.update(
            root_cause_identification_correct=True if complete else None,
            unsupported_claim_count=0 if complete else None,
            reviewer_notes="",
        )
        return [{**item, "scores": scores} for item in packet["items"]]

    draft = save_ai_review_draft(
        "test-study",
        AIReviewSaveRequest(reviewer_id="reviewer-1", items=items(False)),
        settings,
    )
    assert draft["status"] == "saved"
    assert draft["review_status"] == "DRAFT"

    with pytest.raises(HTTPException) as incomplete:
        save_ai_review_draft(
            "test-study",
            AIReviewSaveRequest(reviewer_id="reviewer-1", items=items(False), submit=True),
            settings,
        )
    assert incomplete.value.status_code == 422

    submitted = save_ai_review_draft(
        "test-study",
        AIReviewSaveRequest(reviewer_id="reviewer-1", items=items(True), submit=True),
        settings,
    )
    assert submitted["status"] == "submitted"
    assert submitted["review_status"] == "SUBMITTED"

    with pytest.raises(HTTPException) as locked:
        save_ai_review_draft(
            "test-study",
            AIReviewSaveRequest(reviewer_id="reviewer-1", items=items(True)),
            settings,
        )
    assert locked.value.status_code == 409


def _reviews():
    items, key = [], {}
    for subject in ("host1-incident", "host2-incident"):
        for condition in ("A", "B", "C"):
            for trial in range(3):
                review_id = f"{subject}-{condition}-{trial}"
                key[review_id] = condition
                scores = {field: 4 if condition == "C" else 2 for field in SCORE_FIELDS}
                scores.update(root_cause_identification_correct=True, unsupported_claim_count=0)
                items.append(
                    {
                        "review_id": review_id,
                        "subject": {"incident_id": subject},
                        "analysis": {"summary": "test"},
                        "scores": scores,
                    }
                )
    return {"reviewer_id": "analyst-1", "items": items}, key


def test_paired_statistics_uses_subjects_not_trials_and_deduplicates():
    pytest.importorskip("scipy")
    review, key = _reviews()
    result = paired_statistics([review, copy.deepcopy(review)], key, resamples=100)
    metric = result["comparisons"]["C_minus_A"]["metrics"][SCORE_FIELDS[0]]
    assert metric["n_subjects"] == 2
    assert metric["mean_difference"] == 2
    assert metric["sign_test_two_sided_p"] == 0.5
    assert metric["bootstrap_95_percentile_ci"] == [2, 2]
    assert result["unique_rating_records"] == 18


def test_paired_statistics_requires_identity_and_rejects_conflicting_duplicates():
    pytest.importorskip("scipy")
    review, key = _reviews()
    with pytest.raises(ValueError, match="reviewer_id"):
        paired_statistics([{**review, "reviewer_id": ""}], key)
    conflict = copy.deepcopy(review)
    conflict["items"][0]["scores"][SCORE_FIELDS[0]] = 0
    with pytest.raises(ValueError, match="conflicting"):
        paired_statistics([review, conflict], key)


def test_common_system_account_does_not_supply_correlation_entity():
    assert _mapping_entity_keys({"account": "NT AUTHORITY\\SYSTEM"}) == set()
    assert _mapping_entity_keys({"process_id": 123}) == {"pid:123"}


def test_windows_apt_loader_streams_flattened_zip_records(tmp_path: Path):
    archive = tmp_path / "windows-apt.zip"
    csv_data = (
        "_id,_source.@timestamp,_source.agent.name,_source.data.win.system.eventID,"
        "_source.data.win.eventdata.serviceName\n"
        'event-1,"Nov 30, 2024 @ 20:30:08.057",Maryam,7045,TestSvc\n'
    )
    manifest = "Scenrario_ID,Scenario_Name\nS01,Test scenario\n"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("dataset/combined.csv", csv_data)
        handle.writestr("dataset/scenario_manifest.csv", manifest)

    event = next(iter_dataset(archive))
    assert event.normalized_type == "service_created"
    assert event.event_time.isoformat() == "2024-11-30T20:30:08.057000+00:00"
    assert event.target["key"] == "service:testsvc"
    assert len(load_scenario_manifest(archive)) == 1


def test_windows_apt_preserves_host_identity_and_measures_populated_context(tmp_path: Path):
    archive = tmp_path / "windows-apt-identities.zip"
    csv_data = (
        "_id,_index,_source.@timestamp,_source.agent.id,_source.agent.name,"
        "_source.data.win.system.channel,_source.data.win.system.providerName,"
        "_source.data.win.system.eventID,_source.data.win.eventdata.targetObject\n"
        'e1,wazuh-alerts-4.x-2024.12.01,"Dec 1, 2024 @ 06:24:24.979",1,host-one,'
        "Microsoft-Windows-Sysmon/Operational,Microsoft-Windows-Sysmon,13,"
        "HKCU\\Software\\Example\\Run\\one\n"
        'e2,wazuh-alerts-4.x-2024.12.01,"Dec 1, 2024 @ 06:24:24.979",2,host-two,'
        "Microsoft-Windows-Sysmon/Operational,Microsoft-Windows-Sysmon,13,"
        "HKCU\\Software\\Example\\Run\\one\n"
    )
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("dataset/combined.csv", csv_data)

    events = list(iter_dataset(archive))
    report = evaluate_dataset(archive)
    assert events[0].normalized_type == "registry_value_modified"
    assert events[0].target["key"] == "registry:hkcu\\software\\example\\run\\one"
    assert events[0].host_id != events[1].host_id
    assert [event.event_id for event in events] == [
        event.event_id for event in iter_dataset(archive)
    ]
    assert report["dataset"]["distinct_source_agent_count"] == 2
    assert report["dataset"]["distinct_dataset_host_count"] == 2
    assert report["normalization"]["target_identity_by_event_type"]["registry_value_modified"] == {
        "semantic_events": 2,
        "with_target_identity": 2,
        "coverage_rate": 1.0,
    }
    assert report["context_attributes"]["registry_context"]["count"] == 2


def test_windows_apt_directory_reader_uses_combined_csv_once(tmp_path: Path):
    (tmp_path / "combined.csv").write_text(
        "_id,_source.@timestamp,_source.agent.name\ne1,2024-12-01T00:00:00Z,host-one\n",
        encoding="utf-8",
    )
    (tmp_path / "period.csv").write_text(
        "_id,_source.@timestamp,_source.agent.name\ne2,2024-12-01T00:00:00Z,host-one\n",
        encoding="utf-8",
    )
    (tmp_path / "scenario_manifest.csv").write_text(
        "Scenrario_ID,Scenario_Name\nS01,not an event\n",
        encoding="utf-8",
    )
    assert len(list(iter_dataset(tmp_path))) == 1


def test_windows_apt_service_modified_event_carries_exact_transition():
    from experiments.datasets.windows_apt_2025.loader import normalize_record

    event = normalize_record(
        {
            "_id": "service-change-1",
            "_index": "wazuh-alerts-4.x-2024.12.01",
            "_source": {
                "@timestamp": "2024-12-01T06:24:24.979Z",
                "agent": {"id": "2", "name": "wazuh-agent"},
                "data": {
                    "win": {
                        "system": {
                            "channel": "System",
                            "providerName": "Service Control Manager",
                            "eventID": "7040",
                            "eventRecordID": "12345",
                        },
                        "eventdata": {
                            "param1": "Background Intelligent Transfer Service",
                            "param2": "demand start",
                            "param3": "auto start",
                            "param4": "BITS",
                        },
                    }
                },
            },
        }
    )

    assert event.normalized_type == "service_modified"
    assert event.target["key"] == "service:bits"
    assert event.attributes["service_display_name"] == "Background Intelligent Transfer Service"
    assert event.attributes["service_start_mode_before"] == "demand start"
    assert event.attributes["service_start_mode_after"] == "auto start"
    assert event.source_reference["document_id"] == "service-change-1"


def test_paired_campaign_analysis_requires_same_host_type_and_full_target():
    target_key = "registry:hku/user/software/run/csgtrial"
    record = {
        "trial_id": "complete-01",
        "condition": "registry_complete",
        "host_id": "win11-arm-lab",
        "trial_pass": True,
        "target_object_key": target_key,
        "target_state": {"present_after": True},
        "protocol_parameters": {"event_time_tolerance_seconds": 5},
        "action_journal": {
            "target_create": {
                "started_at": "2026-10-08T10:00:05Z",
                "completed_at": "2026-10-08T10:00:06Z",
                "exit_code": 0,
            }
        },
        "wazuh_service": {
            "before": {
                "status": "Running",
                "process_id": 101,
                "captured_at": "2026-10-08T09:59:55Z",
            },
            "during": None,
            "after": {
                "status": "Running",
                "process_id": 101,
                "captured_at": "2026-10-08T10:01:00Z",
            },
        },
        "target": {
            "deltas": [
                {
                    "observation_window": {
                        "start": "2026-10-08T10:00:00Z",
                        "end": "2026-10-08T10:00:10Z",
                    }
                }
            ],
            "wazuh_provider_exact_events": [
                {
                    "event_id": "wazuh-exact",
                    "host_id": "win11-arm-lab",
                    "event_time": "2026-10-08T10:00:05Z",
                    "normalized_type": "registry_value_modified",
                    "target": {"key": target_key},
                }
            ],
            "reconciliation_history": [
                {"latest": {"status": "CONSISTENT", "matched_evidence_ids": ["wazuh-exact"]}}
            ],
        },
        "cleanup": {
            "target_absent": True,
            "distractor_absent": True,
            "cleanup_probe_succeeded": True,
        },
    }
    assigned = {"trial_id": "complete-01", "condition": "registry_complete"}
    outcome = evaluate_trial(record, assigned)
    assert outcome["analysis_pass"] is True
    assert outcome["action_to_state_observation_upper_bound_seconds"] == 4

    record["target"]["wazuh_provider_exact_events"][0]["target"]["key"] = "registry:other"
    assert evaluate_trial(record, assigned)["analysis_pass"] is False


def test_paired_campaign_analysis_rejects_distractor_and_scores_no_change():
    cleanup = {
        "target_absent": True,
        "distractor_absent": True,
        "cleanup_probe_succeeded": True,
    }
    wrong = {
        "trial_id": "wrong-01",
        "condition": "registry_wrong_object",
        "host_id": "win11-arm-lab",
        "target_state": {"present_after": True},
        "target_object_key": "registry:hku/user/software/run/csgtrial",
        "distractor_object_key": "registry:hku/user/software/run/csgother",
        "protocol_parameters": {"event_time_tolerance_seconds": 5},
        "action_journal": {"target_create": {"started_at": "2026-10-08T10:00:05Z", "exit_code": 0}},
        "wazuh_service": {
            "before": {
                "status": "Running",
                "process_id": 101,
                "captured_at": "2026-10-08T09:59:55Z",
            },
            "during": {
                "status": "Stopped",
                "process_id": 0,
                "captured_at": "2026-10-08T10:00:04Z",
            },
            "after": {
                "status": "Running",
                "process_id": 202,
                "captured_at": "2026-10-08T10:01:30Z",
            },
        },
        "target": {
            "wazuh_provider_exact_events": [],
            "deltas": [
                {
                    "observation_window": {
                        "start": "2026-10-08T10:00:00Z",
                        "end": "2026-10-08T10:00:10Z",
                    }
                }
            ],
            "reconciliation_history": [
                {"latest": {"status": "UNEXPLAINED", "matched_evidence_ids": []}}
            ],
        },
        "source_event_ingestion": {
            "database_verified": [
                {
                    "event_id": "wazuh-distractor",
                    "host_id": "win11-arm-lab",
                    "event_time": "2026-10-08T10:00:05Z",
                    "normalized_type": "registry_value_modified",
                    "target": {"key": "registry:hku/user/software/run/csgother"},
                    "source_reference": {"document_id": "sysmon-doc-1"},
                }
            ]
        },
        "bounded_distractor": {
            "wrong_object_event_inside_target_window": True,
            "wrong_object_event_ids": ["wazuh-distractor"],
            "finalized_status": "UNEXPLAINED",
        },
        "cleanup": cleanup,
    }
    assigned_wrong = {"trial_id": "wrong-01", "condition": "registry_wrong_object"}
    assert evaluate_trial(wrong, assigned_wrong)["analysis_pass"] is True
    wrong["wazuh_service"]["during"]["status"] = "Running"
    assert evaluate_trial(wrong, assigned_wrong)["analysis_pass"] is False
    wrong["wazuh_service"]["during"]["status"] = "Stopped"
    wrong["target"]["reconciliation_history"] = [
        {"latest": {"status": "CONSISTENT", "matched_evidence_ids": ["wazuh-distractor"]}}
    ]
    assert evaluate_trial(wrong, assigned_wrong)["analysis_pass"] is False

    no_change = {
        "trial_id": "no-change-01",
        "condition": "registry_no_change",
        "target": {},
        "no_change_control": {
            "target_absent_before": True,
            "target_absent_after": True,
            "new_delta_count": 0,
            "new_finding_count": 0,
        },
        "cleanup": cleanup,
    }
    assert (
        evaluate_trial(no_change, {"trial_id": "no-change-01", "condition": "registry_no_change"})[
            "analysis_pass"
        ]
        is True
    )
    assert _proportion(5, 10)["wilson_95"] == [0.236593, 0.763407]


def test_database_export_preserves_snapshots_and_histories(db_session):
    repo = CyberStateRepository(db_session)
    finding = _pending_finding(repo)
    repo.create_snapshot(_snapshot("baseline.json"))
    event = _events("svc-create-consistent.json")[0]
    repo.create_events(
        [event.model_copy(update={"event_id": f"export-{index}"}) for index in range(501)]
    )
    result = export_host(repo, finding.host_id)
    assert result["retrieval_limit"] is None
    assert result["counts"]["snapshots"] == 1
    assert result["counts"]["reconciliations"] == 1
    assert result["counts"]["events"] == 501
    assert len(result["content_sha256"]) == 64


def test_stale_reconciliation_writer_cannot_overwrite_new_version(db_session):
    repo = CyberStateRepository(db_session)
    old = _pending_finding(repo)
    ReconciliationLifecycleService(_settings()).reevaluate_pending(
        repo,
        now=old.reconciliation.observation_window.end + timedelta(minutes=2),
        event_observation=_healthy_event_observation(old),
    )
    assert not repo.save_reconciliation_revision(old, old.reconciliation.reconciliation_id)
    assert repo.get_finding(old.finding_id).reconciliation.version == 2
    assert len(repo.list_reconciliations(finding_id=old.finding_id)) == 2


def test_transport_counters_measure_encoded_body_and_queue_drops(monkeypatch):
    import requests

    from cyberstateguardian_probe.transport import QueuedTransport

    bodies = []

    def post(*args, **kwargs):
        bodies.append(kwargs["data"])
        return SimpleNamespace(ok=True)

    monkeypatch.setattr(requests, "post", post)
    transport = QueuedTransport("http://lab", "secret", 1, 1, 1)
    assert transport.send_or_queue({"observation_id": "one"})
    assert transport.metrics["successful_uploads"] == 1
    assert transport.metrics["request_body_bytes_attempted"] == len(bodies[0])
    monkeypatch.setattr(transport, "flush", lambda: False)
    transport.send_or_queue({"id": 2})
    transport.send_or_queue({"id": 3})
    assert transport.metrics["dropped_observations"] == 1


def test_resource_monitor_emits_explicit_sampled_measurements():
    from cyberstateguardian_probe.measurements import ResourceMonitor

    with ResourceMonitor() as monitor:
        pass
    result = monitor.result()
    assert result["samples"] >= 2
    assert result["sampled_peak_process_tree_rss_bytes"] > 0
    assert result["sampled_process_tree_cpu_seconds"] >= 0


def test_live_reproduction_validator_rejects_cross_object_wazuh_evidence():
    payload = {
        "schema_version": "csg-windows-apt-live-reproduction-v1",
        "exact_replication": False,
        "environment": {"host_id": "win11-arm-lab"},
        "scenarios": [
            {
                "scenario_id": "service-persistence",
                "kind": "service",
                "object_name": "CSGAPTServiceOne",
                "expected_object_key": "service:csgaptserviceone",
                "expected_event_type": "service_created",
                "state_plane": {
                    "source": "direct_probe",
                    "after_action_observed": [{"service_name": "CSGAPTServiceOne"}],
                    "cleanup_removed_from_probe": True,
                },
                "event_plane": {
                    "source": "wazuh",
                    "exact_matches": [
                        {
                            "event_id": "event-one",
                            "host_id": "win11-arm-lab",
                            "normalized_type": "service_created",
                            "target": {"key": "service:csgaptserviceother"},
                            "attributes": {"service_name": "CSGAPTServiceOther"},
                        }
                    ],
                },
                "findings": [],
                "action": {"cleanup_completed": True},
            }
        ]
        * 4,
    }
    result = validate(payload)
    assert result["passed"] is False
    assert result["scenario_results"][0]["checks"]["exact_object_identity"]["passed"] is False


def test_capture_replay_masks_events_without_changing_state():
    from experiments.captured_telemetry_study import replay_capture

    before = _snapshot("baseline.json").model_copy(update={"source": "direct_probe"})
    after = _snapshot("new_service.json").model_copy(update={"source": "direct_probe"})
    event = _events("svc-create-consistent.json")[0].model_copy(
        update={"source": "wazuh", "synthetic": False}
    )
    bundle = {
        "snapshots": [s.model_dump(mode="json") for s in (before, after)],
        "events": [event.model_dump(mode="json")],
    }
    result = replay_capture(
        bundle,
        before_id=before.snapshot_id,
        after_id=after.snapshot_id,
        object_key=event.target["key"],
        key_event_ids={event.event_id},
    )
    assert len(result["conditions"]) == 6
    assert result["conditions"]["complete"]["reconciliations"][0]["status"] == "CONSISTENT"
    assert (
        result["conditions"]["key_events_removed"]["reconciliations"][0]["status"] == "UNEXPLAINED"
    )
    assert (
        result["conditions"]["complete"]["deltas"]
        == result["conditions"]["source_unavailable"]["deltas"]
    )


def test_latency_keeps_missing_and_clock_errors_visible():
    from experiments.latency_summary import Measurement, summarize

    action = _events("svc-create-consistent.json")[0].event_time
    rows = [
        Measurement(
            trial_id="1",
            condition="complete",
            action_at=action,
            state_received_at=action + timedelta(seconds=2),
        ),
        Measurement(
            trial_id="2",
            condition="complete",
            action_at=action,
            state_received_at=action - timedelta(seconds=1),
            failure_reason="clock",
        ),
    ]
    stage = summarize(rows)["conditions"]["complete"]["stages"]["state_received_at"]
    assert stage["n"] == 1
    assert stage["mean_seconds"] == 2
    assert stage["negative_clock_or_label_errors"] == 1
    with pytest.raises(ValueError, match="timezone"):
        Measurement(trial_id="bad", condition="complete", action_at=action.replace(tzinfo=None))


def test_live_campaign_manifest_requires_checkpointed_trial_outputs(tmp_path: Path):
    import json

    from scripts.validate_live_campaign import validate_manifest

    campaign = tmp_path / "campaign"
    trial = campaign / "complete-1"
    trial.mkdir(parents=True)
    (trial / "run.json").write_text("{}", encoding="utf-8")
    manifest = {
        "schema_version": "csg-live-telemetry-campaign-v3",
        "experiment_id": "exp-1",
        "status": "COMPLETED",
        "conditions": ["complete"],
        "schedule": [
            {
                "trial_id": "complete-1",
                "condition": "complete",
                "status": "COMPLETED",
                "output": str(trial / "run.json"),
            }
        ],
    }
    manifest_path = campaign / "campaign-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = validate_manifest(manifest_path)
    assert result["passed"] is True
    assert result["completed_trials"] == 1

    manifest["schedule"][0]["status"] = "FAILED"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = validate_manifest(manifest_path)
    assert result["passed"] is False
    assert "failure.json" in " ".join(result["errors"])


def test_live_campaign_manifest_resolves_copied_windows_paths(tmp_path: Path):
    import json

    from scripts.validate_live_campaign import validate_manifest

    campaign = tmp_path / "campaign"
    trial = campaign / "complete-1"
    trial.mkdir(parents=True)
    (trial / "run.json").write_text("{}", encoding="utf-8")
    manifest = {
        "schema_version": "csg-live-telemetry-campaign-v3",
        "experiment_id": "exp-foreign",
        "status": "COMPLETED",
        "conditions": ["complete"],
        "schedule": [
            {
                "trial_id": "complete-1",
                "condition": "complete",
                "status": "COMPLETED",
                "output": r"C:\CSG\research-campaign\complete-1\run.json",
            }
        ],
    }
    manifest_path = campaign / "campaign-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = validate_manifest(manifest_path)

    assert result["passed"] is True


def test_paired_bootstrap_is_reproducible_and_missing_condition_is_excluded():
    pytest.importorskip("scipy")
    review, key = _reviews()
    for item in review["items"]:
        if "host2-incident-C" in item["review_id"]:
            item["scores"][SCORE_FIELDS[0]] = 3
    first = paired_statistics([review], key, seed=10, resamples=100)
    second = paired_statistics([review], key, seed=10, resamples=100)
    assert first == second
    metric = first["comparisons"]["C_minus_A"]["metrics"][SCORE_FIELDS[0]]
    assert metric["bootstrap_95_percentile_ci"] == [1.0, 2.0]
    review["items"] = [item for item in review["items"] if key[item["review_id"]] != "C"]
    empty = paired_statistics([review], key, resamples=100)
    assert empty["comparisons"]["C_minus_A"]["metrics"][SCORE_FIELDS[0]]["n_subjects"] == 0


def test_reconciliation_history_failure_rolls_back_current_finding(db_session, monkeypatch):
    repo = CyberStateRepository(db_session)
    original = _pending_finding(repo)

    def fail(*args, **kwargs):
        raise RuntimeError("injected write failure")

    monkeypatch.setattr(repo, "create_reconciliation", fail)
    with pytest.raises(RuntimeError, match="injected"):
        ReconciliationLifecycleService(_settings()).reevaluate_pending(
            repo,
            now=original.reconciliation.observation_window.end + timedelta(minutes=2),
            event_observation=_healthy_event_observation(original),
        )
    assert repo.get_finding(original.finding_id).reconciliation.version == 1
    assert len(repo.list_reconciliations(finding_id=original.finding_id)) == 1
