from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tests.conftest import ROOT, load_json

from csg.db.repositories import CyberStateRepository
from csg.domain.enums import (
    AuthorizationStatus,
    DeltaType,
    ObservationKind,
    ReconciliationStatus,
    Severity,
)
from csg.domain.models import (
    ExperimentRun,
    Finding,
    Host,
    NormalizedEvent,
    ReconciliationResult,
    RiskScore,
    StateDelta,
    StateSnapshot,
    StateTransitionRecord,
    TimeWindow,
    TransitionMonitorHealth,
    TransitionReconciliationResult,
)


def test_repository_persists_core_artifacts(db_session) -> None:
    repo = CyberStateRepository(db_session)
    host = repo.upsert_host(
        Host(
            host_id="win-lab-01",
            hostname="win11-arm-lab",
            role="windows-target",
            os="windows-11",
            architecture="arm64",
        ),
    )
    snapshot = StateSnapshot.model_validate(
        load_json(ROOT / "experiments/fixtures/state/baseline.json")
    )
    repo.create_snapshot(snapshot)
    event = NormalizedEvent(
        event_id="evt-test",
        host_id=host.host_id,
        event_time=datetime(2026, 9, 13, 20, 0, tzinfo=UTC),
        normalized_type="service_created",
        actor={},
        target={"key": "service:test"},
        attributes={},
        source="synthetic_fixture",
        synthetic=True,
    )
    repo.create_events([event])
    delta = StateDelta(
        host_id=host.host_id,
        category="service",
        object_key="service:test",
        delta_type=DeltaType.ADD,
        observation_window=TimeWindow(start=snapshot.built_at, end=snapshot.built_at),
    )
    repo.create_deltas([delta])
    reconciliation = ReconciliationResult(
        host_id=host.host_id,
        status=ReconciliationStatus.CONSISTENT,
        matched_evidence_ids=[event.event_id],
        observation_window=TimeWindow(start=snapshot.built_at, end=snapshot.built_at),
    )
    finding = Finding(
        host_id=host.host_id,
        observation_kind=ObservationKind.STATE_DELTA,
        delta_id=delta.delta_id,
        category="service",
        object_key="service:test",
        reconciliation=reconciliation,
        authorization_status=AuthorizationStatus.UNKNOWN,
        authorization_reason="test",
        risk=RiskScore(total=10, severity=Severity.LOW, components=[], rules_version="test"),
    )
    repo.create_finding(finding)
    run = ExperimentRun(
        scenario_id="repo-test",
        host_id=host.host_id,
        ground_truth_classification="suspicious",
    )
    repo.create_experiment_run(run)

    assert repo.get_host(host.host_id) == host
    assert repo.latest_snapshot(host.host_id).snapshot_id == snapshot.snapshot_id
    assert (
        repo.get_events(host.host_id, snapshot.built_at, snapshot.built_at)[0].event_id
        == "evt-test"
    )
    assert repo.list_deltas(host.host_id)[0].object_key == "service:test"
    assert repo.list_findings(host.host_id)[0].finding_id == finding.finding_id
    assert repo.list_experiment_runs()[0].scenario_id == "repo-test"


def test_repository_transition_records_are_idempotent_and_filtered(db_session) -> None:
    repo = CyberStateRepository(db_session)
    observed = datetime(2026, 10, 4, 12, 5, tzinfo=UTC)
    transition = StateTransitionRecord(
        transition_id="transition-repo-1",
        host_id="transition-host",
        category="service",
        object_key="service:sample",
        transition_type="SERVICE_CONFIG_MODIFIED",
        observed_at=observed,
        capture_method="test_adapter",
        collector_health="HEALTHY",
        old_state={"start_mode": "manual"},
        new_state={"start_mode": "auto"},
        changed_fields=["start_mode"],
        sequence_number=1,
    )

    stored, inserted = repo.create_transition_records([transition, transition])
    assert inserted == 1
    assert len(stored) == 1
    assert repo.get_transition_record(transition.transition_id) == transition
    assert (
        len(
            repo.list_transition_records(
                "transition-host",
                start=observed - timedelta(seconds=1),
                end=observed + timedelta(seconds=1),
                category="service",
                object_key="service:sample",
            )
        )
        == 1
    )
    duplicate, duplicate_count = repo.create_transition_records([transition])
    assert duplicate_count == 0
    assert duplicate[0].transition_id == transition.transition_id

    health = TransitionMonitorHealth(
        host_id="transition-host",
        category="service",
        monitor_id="services-1",
        status="HEALTHY",
        capture_method="test_adapter",
        started_at=observed - timedelta(minutes=1),
        observed_at=observed,
        last_heartbeat_at=observed,
        coverage_start=observed - timedelta(minutes=1),
        baseline_established=True,
        metrics={"captured": 1},
    )
    assert repo.create_transition_monitor_health([health]) == [health]
    assert repo.latest_transition_monitor_health("transition-host") == [health]

    result = TransitionReconciliationResult(
        transition_id=transition.transition_id,
        host_id=transition.host_id,
        status="CORROBORATED",
        matched_evidence_ids=["wazuh-test"],
        observation_window=TimeWindow(start=observed, end=observed),
    )
    repo.create_transition_reconciliation(result)
    history = repo.transition_reconciliation_history(transition.transition_id)
    assert len(history) == 1
    assert history[0].status == result.status
    assert history[0].matched_evidence_ids == ["wazuh-test"]
    assert repo.latest_transition_reconciliations([transition.transition_id]) == {
        transition.transition_id: result
    }
