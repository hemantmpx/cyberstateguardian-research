from __future__ import annotations

from datetime import UTC, datetime

from experiments.ai_context_evaluation import (
    aggregate_completed_reviews,
    create_blinded_review_package,
)
from experiments.ai_context_study import build_study_export
from experiments.incident_correlation_study import run_study
from experiments.runner.run_scenarios import (
    ROOT,
    aggregate_metrics,
    replay_events_at_origin,
    run_all,
    run_scenario,
)
from tests.conftest import ROOT as PROJECT_ROOT

from csg.config import Settings
from csg.db.repositories import CyberStateRepository
from csg.domain.models import Finding, Host, NormalizedEvent, StateDelta
from csg.services.incident_correlation import IncidentCorrelationService


def test_all_scenarios_pass_and_metrics_have_denominators(tmp_path) -> None:
    runs = run_all(output_dir=tmp_path)
    metrics = aggregate_metrics(runs)

    assert all(run.success for run in runs)
    assert metrics["detection_rate"]["denominator"] == 7
    assert metrics["false_positive_rate_for_benign"]["denominator"] == 2
    assert metrics["transient_recovery_rate"]["denominator"] == 1
    assert metrics["telemetry_inconsistency_detection_rate"] == {
        "numerator": 3,
        "denominator": 3,
        "rate": 1.0,
        "definition": "expected state/event inconsistencies identified by reconciliation",
    }
    assert metrics["telemetry_degradation_study"]["conditions"] == 5
    assert metrics["telemetry_degradation_study"]["csg_state_plane_detection_rate"] == 1.0
    assert metrics["telemetry_degradation_study"]["event_only_baseline_detection_rate"] == 0.4
    assert (tmp_path / "summary.csv").exists()
    assert (tmp_path / "metrics.json").exists()


def test_failed_run_is_retained() -> None:
    run = run_scenario(ROOT / "experiments/scenarios/svc-create-consistent.json")
    edited = run.model_copy(update={"success": False, "failure_reason": "forced"})
    metrics = aggregate_metrics([edited])
    assert edited.failure_reason == "forced"
    assert metrics["scenario_success"]["numerator"] == 0


def test_incident_correlation_fixture_has_no_false_merges_or_splits() -> None:
    metrics = run_study()["metrics"]
    assert metrics["pairwise_precision"] == 1.0
    assert metrics["pairwise_recall"] == 1.0
    assert metrics["false_merge_pairs"] == 0
    assert metrics["false_split_pairs"] == 0


def test_replay_events_at_origin_preserves_order() -> None:
    run = run_scenario(ROOT / "experiments/scenarios/svc-create-consistent.json")
    events = run.actual_observations["events"]
    from csg.domain.models import NormalizedEvent

    typed = [NormalizedEvent.model_validate(event) for event in events]
    replayed = replay_events_at_origin(typed, datetime(2026, 9, 14, 1, 0, tzinfo=UTC))
    assert replayed[0].event_time == datetime(2026, 9, 14, 1, 0, tzinfo=UTC)
    assert replayed[0].metadata["replayed"] is True


def test_ai_context_study_exports_token_matched_four_conditions(db_session, monkeypatch) -> None:
    settings = Settings(
        CSG_AUTHORIZED_STATE_PATH=PROJECT_ROOT / "config/authorized-state.example.yaml",
        CSG_RISK_RULES_PATH=PROJECT_ROOT / "config/risk-rules.yaml",
        CSG_AI_CONTEXT_MAX_EVENTS=25,
    )
    run = run_scenario(ROOT / "experiments/scenarios/svc-create-consistent.json")
    repo = CyberStateRepository(db_session)
    repo.upsert_host(
        Host(
            host_id=run.host_id,
            hostname=run.host_id,
            role="research-target",
            os="Windows 11",
            architecture="arm64",
        )
    )
    repo.create_deltas(
        [StateDelta.model_validate(item) for item in run.actual_observations["deltas"]]
    )
    repo.create_events(
        [NormalizedEvent.model_validate(item) for item in run.actual_observations["events"]]
    )
    findings = [
        repo.create_finding(Finding.model_validate(item))
        for item in run.actual_observations["findings"]
    ]
    incident = IncidentCorrelationService(settings).assign_finding(repo, findings[0])

    payload = build_study_export(repo, settings, incident_id=incident.incident_id)

    assert list(payload["conditions"]) == ["A", "B", "C", "D"]
    assert payload["conditions"]["A"]["mode"] == "finding_only"
    assert payload["conditions"]["A"]["input_metrics"]["evidence_items"] == 0
    assert payload["conditions"]["B"]["input_metrics"]["evidence_items"] >= 1
    assert payload["conditions"]["C"]["input_metrics"]["state_deltas"] >= 1
    assert payload["conditions"]["D"]["mode"] == "full_context_token_matched"
    assert (
        payload["conditions"]["D"]["input_metrics"]["characters"]
        <= payload["conditions"]["B"]["input_metrics"]["characters"]
    )
    assert payload["conditions"]["C"]["human_evaluation"]["unsupported_claim_count"] is None
    assert payload["prior_ai_memory_excluded"] is True

    from experiments.ai_context_study import _fit_package_to_character_budget

    from csg.domain.models import EvidencePackage

    oversized = EvidencePackage.model_validate(payload["conditions"]["C"]["package"])
    irreducible = _fit_package_to_character_budget(oversized, 1)
    assert len(irreducible.model_dump_json()) > 1

    from types import SimpleNamespace

    from csg.services.incident_context import IncidentContextBuilder

    built = []
    original = IncidentContextBuilder.build_for_incident

    def build_with_memory(self, *args, **kwargs):
        package = original(self, *args, **kwargs)
        built.append(package.context_mode)
        return package.model_copy(update={"interpretive_memory": {"summary": "previous AI"}})

    def fake_analysis(_repo, _settings, package):
        assert len(built) == 3
        assert package.interpretive_memory is None
        return SimpleNamespace(model_dump=lambda **_: {"response_json": {"summary": "test"}})

    monkeypatch.setattr(IncidentContextBuilder, "build_for_incident", build_with_memory)
    monkeypatch.setattr("experiments.ai_context_study._run_analysis", fake_analysis)
    repeated = build_study_export(
        repo, settings, incident_id=incident.incident_id, run_ai=True, repetitions=2
    )
    assert len(repeated["execution_order"]) == 8
    assert all(len(condition["trials"]) == 2 for condition in repeated["conditions"].values())


def test_ai_context_review_is_blinded_and_aggregates_completed_scores() -> None:
    study = {
        "study_version": "test",
        "subject": {"incident_id": "incident-1"},
        "ground_truth": {"root_cause": "service persistence"},
        "conditions": {
            condition: {
                "package_hash": f"hash-{condition}",
                "analysis": {
                    "context_mode": "full_context",
                    "evidence_package_hash": "secret-condition-metadata",
                    "response_json": {"summary": "Model interpretation"},
                },
                "human_evaluation": {},
            }
            for condition in ("A", "B", "C")
        },
    }
    review, key = create_blinded_review_package(study)
    assert len(review["items"]) == 3
    assert all("condition" not in item for item in review["items"])
    assert all("context_mode" not in item["analysis"] for item in review["items"])
    assert "secret-condition-metadata" not in str(review)
    for item in review["items"]:
        item["scores"] = {
            "attack_chain_reconstruction_accuracy_0_to_5": 4,
            "mitre_attack_mapping_accuracy_0_to_5": 4,
            "evidence_grounding_accuracy_0_to_5": 5,
            "analyst_usefulness_0_to_5": 4,
            "confidence_calibration_0_to_5": 4,
            "unsupported_claim_count": 0,
            "root_cause_identification_correct": True,
        }

    aggregate = aggregate_completed_reviews([review], key)

    assert aggregate["completed_reviews"] == 3
    assert aggregate["conditions"]["A"]["metrics"]["root_cause_identification_correct"]["mean"] == 1
    review["items"][0]["scores"]["unsupported_claim_count"] = False
    assert aggregate_completed_reviews([review], key)["completed_reviews"] == 2
    review["items"][1]["analysis"] = None
    assert aggregate_completed_reviews([review], key)["completed_reviews"] == 1
    assert (
        aggregate["conditions"]["C"]["metrics"]["evidence_grounding_accuracy_0_to_5"]["mean"] == 5.0
    )
