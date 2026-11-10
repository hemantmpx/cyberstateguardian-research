from __future__ import annotations

from datetime import timedelta

from tests.conftest import ROOT, load_json

from csg.config import Settings
from csg.db.repositories import CyberStateRepository
from csg.domain.enums import (
    AuthorizationStatus,
    ObservationKind,
    ReconciliationStatus,
    Severity,
)
from csg.domain.models import (
    EventObservationResult,
    Finding,
    NormalizedEvent,
    RiskScore,
    StateSnapshot,
)
from csg.services.reconciliation import (
    ReconciliationEngine,
    ReconciliationLifecycle,
    source_health_attribution_for_window,
)
from csg.services.reconciliation_lifecycle import ReconciliationLifecycleService
from csg.state.diff import DeltaEngine


def _snapshot(name: str) -> StateSnapshot:
    return StateSnapshot.model_validate(load_json(ROOT / "experiments/fixtures/state" / name))


def _settings() -> Settings:
    return Settings(
        CSG_AUTHORIZED_STATE_PATH=ROOT / "config/authorized-state.example.yaml",
        CSG_RISK_RULES_PATH=ROOT / "config/risk-rules.yaml",
        CSG_RECONCILIATION_GRACE_SECONDS=60,
    )


def _pending_finding(repo: CyberStateRepository) -> Finding:
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("new_service.json"))[0]
    repo.create_deltas([delta])
    engine = ReconciliationEngine()
    pending = ReconciliationLifecycle(engine, grace_seconds=60).evaluate(
        delta,
        [],
        now=delta.observation_window.end + timedelta(minutes=1),
    )
    finding = Finding(
        host_id=delta.host_id,
        observation_kind=ObservationKind.STATE_DELTA,
        delta_id=delta.delta_id,
        category=delta.category,
        object_key=delta.object_key,
        reconciliation=pending,
        authorization_status=AuthorizationStatus.UNKNOWN,
        authorization_reason="test",
        risk=RiskScore(total=35, severity=Severity.MEDIUM, rules_version="test"),
        created_at=delta.created_at,
    )
    pending = pending.model_copy(update={"finding_id": finding.finding_id})
    finding = finding.model_copy(update={"reconciliation": pending})
    repo.create_reconciliation(pending)
    return repo.create_finding(finding)


def test_late_event_creates_new_final_reconciliation_version(db_session) -> None:
    repo = CyberStateRepository(db_session)
    finding = _pending_finding(repo)
    delta = repo.get_delta(finding.delta_id or "")
    assert delta is not None
    assert finding.reconciliation.status == ReconciliationStatus.PENDING_EVIDENCE

    repo.create_events(
        [
            NormalizedEvent(
                event_id="late-service-event",
                host_id=delta.host_id,
                event_time=delta.observation_window.end,
                normalized_type="service_created",
                target={"key": delta.object_key},
                attributes={"service_name": "SystemUpdate"},
                source="wazuh",
            )
        ]
    )
    updated = ReconciliationLifecycleService(_settings()).reevaluate_pending(
        repo,
        now=delta.observation_window.end + timedelta(minutes=2),
    )

    assert len(updated.updated_findings) == 1
    result = updated.updated_findings[0].reconciliation
    assert result.status == ReconciliationStatus.CONSISTENT
    assert result.finalized is True
    assert result.version == 2
    history = repo.list_reconciliations(delta_id=delta.delta_id)
    assert [item.version for item in history] == [1, 2]
    assert history[1].supersedes_reconciliation_id == history[0].reconciliation_id


def test_pending_reconciliation_finalizes_unexplained_after_deadline(db_session) -> None:
    repo = CyberStateRepository(db_session)
    finding = _pending_finding(repo)
    deadline = finding.reconciliation.observation_window.end + timedelta(minutes=2)

    service = ReconciliationLifecycleService(_settings())
    without_observation = service.reevaluate_pending(repo, now=deadline)
    assert without_observation.updated_findings == []
    assert repo.get_finding(finding.finding_id).reconciliation.finalized is False

    observation = EventObservationResult(
        query_complete=True,
        endpoint_collection_status="AVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        metadata={
            "query_start": finding.reconciliation.observation_window.start.isoformat(),
            "query_end": finding.reconciliation.observation_window.end.isoformat(),
            "source_health_checked_at": finding.reconciliation.observation_window.start.isoformat(),
        },
    )
    updated = service.reevaluate_pending(
        repo,
        now=deadline,
        event_observation=observation,
    )

    result = updated.updated_findings[0].reconciliation
    assert result.status == ReconciliationStatus.UNEXPLAINED
    assert result.finalized is True
    assert result.metadata["reconciliation_semantics"] == "UNCORROBORATED_HEALTHY"


def test_final_result_can_be_revised_by_late_evidence_and_is_idempotent(db_session) -> None:
    repo = CyberStateRepository(db_session)
    finding = _pending_finding(repo)
    service = ReconciliationLifecycleService(_settings())
    now = finding.reconciliation.observation_window.end + timedelta(minutes=2)
    assert service.reevaluate_pending(repo, now=now).updated_findings == []
    event = NormalizedEvent(
        event_id="very-late",
        host_id=finding.host_id,
        event_time=finding.reconciliation.observation_window.end - timedelta(minutes=5),
        normalized_type="service_created",
        target={"key": finding.object_key},
        source="wazuh",
        source_reference={"index": "wazuh-archives-test", "document_id": "very-late"},
    )
    repo.create_events(
        [event.model_copy(update={"normalized_type": "wazuh_alert", "target": {}})]
    )
    repo.create_events([event])
    revised = service.reevaluate_pending(repo, now=now, events=[event])
    assert len(revised.updated_findings) == 1
    result = revised.updated_findings[0].reconciliation
    assert result.status == ReconciliationStatus.CONSISTENT
    assert result.version == 2
    assert len(repo.list_findings()) == 1
    assert [r.version for r in repo.list_reconciliations(finding_id=finding.finding_id)] == [
        1,
        2,
    ]
    assert service.reevaluate_pending(repo, now=now, events=[event]).updated_findings == []


def test_pending_query_filters_before_limiting(db_session) -> None:
    repo = CyberStateRepository(db_session)
    for _ in range(6):
        finding = _pending_finding(repo)
        repo.create_finding(
            finding.model_copy(
                update={
                    "reconciliation": finding.reconciliation.model_copy(update={"finalized": True})
                }
            )
        )
    pending = _pending_finding(repo)
    assert [f.finding_id for f in repo.list_pending_reconciliation_findings(limit=1)] == [
        pending.finding_id
    ]


def test_source_health_changes_missing_evidence_semantics() -> None:
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("new_service.json"))[0]
    engine = ReconciliationEngine()
    healthy = EventObservationResult(
        query_complete=True,
        endpoint_collection_status="AVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        metadata={"source_health_checked_at": delta.observation_window.start.isoformat()},
    )
    degraded = healthy.model_copy(update={"endpoint_collection_status": "DEGRADED"})
    deadline = delta.observation_window.end + timedelta(minutes=2)

    healthy_result = ReconciliationLifecycle(engine, grace_seconds=60).evaluate(
        delta,
        [],
        now=deadline,
        event_observation=healthy,
    )
    degraded_result = ReconciliationLifecycle(engine, grace_seconds=60).evaluate(
        delta,
        [],
        now=deadline,
        event_observation=degraded,
    )

    assert healthy_result.finalized is True
    assert healthy_result.metadata["reconciliation_semantics"] == "UNCORROBORATED_HEALTHY"
    assert degraded_result.finalized is True
    assert degraded_result.metadata["reconciliation_semantics"] == "UNCORROBORATED_DEGRADED"


def test_known_source_degradation_survives_worker_finalization() -> None:
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("new_service.json"))[0]
    engine = ReconciliationEngine()
    observation = EventObservationResult(
        query_complete=True,
        endpoint_collection_status="UNAVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        metadata={
            "query_start": delta.observation_window.start.isoformat(),
            "query_end": delta.observation_window.end.isoformat(),
            "source_health_checked_at": delta.observation_window.start.isoformat(),
        },
    )
    lifecycle = ReconciliationLifecycle(engine, grace_seconds=60)
    provisional = lifecycle.evaluate(
        delta,
        [],
        now=delta.observation_window.end + timedelta(seconds=30),
        event_observation=observation,
    )
    recovery_observation = EventObservationResult(
        query_complete=True,
        endpoint_collection_status="AVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
    )
    finalized = lifecycle.evaluate(
        delta,
        [],
        now=delta.observation_window.end + timedelta(seconds=90),
        previous=provisional,
        evidence_complete=True,
        event_observation=recovery_observation,
    )

    assert provisional.status == ReconciliationStatus.PENDING_EVIDENCE
    assert provisional.metadata["reconciliation_semantics"] == "UNCORROBORATED_DEGRADED"
    assert finalized.status == ReconciliationStatus.UNEXPLAINED
    assert finalized.finalized is True
    assert finalized.metadata["reconciliation_semantics"] == "UNCORROBORATED_DEGRADED"
    assert finalized.metadata["source_health_known_degraded"] is True
    assert (
        finalized.metadata["source_health_evidence"]["endpoint_collection_status"] == "UNAVAILABLE"
    )
    assert (
        finalized.metadata["source_health_last_observation"]["endpoint_collection_status"]
        == "AVAILABLE"
    )


def test_health_semantic_change_is_not_discarded_while_pending() -> None:
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("new_service.json"))[0]
    lifecycle = ReconciliationLifecycle(ReconciliationEngine(), grace_seconds=60)
    healthy = lifecycle.evaluate(
        delta,
        [],
        now=delta.observation_window.end - timedelta(seconds=30),
        evidence_complete=True,
    )
    degraded = lifecycle.evaluate(
        delta,
        [],
        now=delta.observation_window.end - timedelta(seconds=20),
        previous=healthy,
        event_observation=EventObservationResult(
            query_complete=True,
            endpoint_collection_status="UNAVAILABLE",
            transport_status="AVAILABLE",
            index_status="AVAILABLE",
            coverage_status="COMPLETE",
            metadata={
                "source_health_checked_at": delta.observation_window.start.isoformat()
            },
        ),
    )

    assert healthy.status == ReconciliationStatus.PENDING_EVIDENCE
    assert degraded.status == ReconciliationStatus.PENDING_EVIDENCE
    assert degraded.metadata["reconciliation_semantics"] == "UNCORROBORATED_DEGRADED"
    assert not ReconciliationLifecycleService._materially_unchanged(healthy, degraded)


def test_bounded_degraded_observation_finalizes_without_false_healthy_state(db_session) -> None:
    repo = CyberStateRepository(db_session)
    finding = _pending_finding(repo)
    service = ReconciliationLifecycleService(_settings())
    finalized_at = finding.reconciliation.observation_window.end + timedelta(minutes=2)

    without_observation = service.reevaluate_pending(repo, now=finalized_at)
    assert without_observation.updated_findings == []
    assert repo.get_finding(finding.finding_id).reconciliation.finalized is False

    observation = EventObservationResult(
        query_complete=True,
        endpoint_collection_status="UNAVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        metadata={
            "query_start": finding.reconciliation.observation_window.start.isoformat(),
            "query_end": finding.reconciliation.observation_window.end.isoformat(),
            "affected_object_keys": [finding.object_key],
            "source_degradation_interval": {
                "start": finding.reconciliation.observation_window.start.isoformat(),
                "end": finding.reconciliation.observation_window.end.isoformat(),
            },
        },
    )
    wrong_scope = observation.model_copy(
        update={"metadata": {**observation.metadata, "affected_object_keys": ["service:other"]}}
    )
    ignored = service.reevaluate_pending(
        repo,
        now=finalized_at + timedelta(seconds=1),
        event_observation=wrong_scope,
    )
    assert ignored.updated_findings == []
    assert repo.get_finding(finding.finding_id).reconciliation.version == 1

    revised = service.reevaluate_pending(
        repo,
        now=finalized_at + timedelta(seconds=2),
        event_observation=observation,
    )

    assert len(revised.updated_findings) == 1
    result = revised.updated_findings[0].reconciliation
    assert result.finalized is True
    assert result.version == 2
    assert result.metadata["reconciliation_semantics"] == "UNCORROBORATED_DEGRADED"
    assert result.metadata["source_health_known_degraded"] is True

    correction_observation = EventObservationResult(
        query_complete=False,
        endpoint_collection_status="AVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="PARTIAL",
        metadata={
            "query_start": finding.reconciliation.observation_window.start.isoformat(),
            "query_end": finding.reconciliation.observation_window.end.isoformat(),
            "affected_object_keys": [finding.object_key],
            "source_health_correction": {
                "reason": "The recorded outage interval does not overlap this finding window.",
                "evidence_reference": "capture-drop-002/outage-timeline.json",
            },
        },
    )
    assert correction_observation.metadata.get("affected_object_keys") == [finding.object_key]
    assert ReconciliationLifecycleService._observation_applies(finding, correction_observation)
    persisted = repo.list_findings(limit=500)
    assert len(persisted) == 1
    assert persisted[0].object_key == finding.object_key
    assert ReconciliationLifecycleService._observation_applies(persisted[0], correction_observation)
    corrected = service.reevaluate_pending(
        repo,
        now=finalized_at + timedelta(seconds=3),
        event_observation=correction_observation,
    )
    assert len(corrected.updated_findings) == 1, corrected.unchanged_count
    corrected_result = corrected.updated_findings[0].reconciliation
    assert corrected_result.version == 3
    assert corrected_result.status == ReconciliationStatus.PENDING_EVIDENCE
    assert corrected_result.finalized is False
    assert corrected_result.metadata["reconciliation_semantics"] == "INCONCLUSIVE"
    assert corrected_result.metadata["source_health_known_degraded"] is False
    assert "source_health_correction" in corrected_result.metadata


def test_finalization_without_new_query_preserves_prior_health_as_stale() -> None:
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("new_service.json"))[0]
    window = delta.observation_window
    lifecycle = ReconciliationLifecycle(ReconciliationEngine(), grace_seconds=60)
    prior_observation = EventObservationResult(
        query_complete=True,
        endpoint_collection_status="DEGRADED",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        metadata={
            "query_start": window.start.isoformat(),
            "query_end": window.end.isoformat(),
            "source_health_checked_at": window.start.isoformat(),
        },
    )
    pending = lifecycle.evaluate(
        delta,
        [],
        now=window.end + timedelta(seconds=30),
        event_observation=prior_observation,
    )
    finalized = lifecycle.evaluate(
        delta,
        [],
        now=window.end + timedelta(seconds=90),
        previous=pending,
        evidence_complete=True,
    )

    last_observation = finalized.metadata["event_plane_last_observation"]
    assert finalized.finalized is True
    assert finalized.metadata["reconciliation_semantics"] == "UNCORROBORATED_DEGRADED"
    assert "event_plane" not in finalized.metadata
    assert last_observation["observation_current_for_revision"] is False
    assert last_observation["observation"]["endpoint_collection_status"] == "DEGRADED"


def test_later_poll_preserves_prior_in_window_healthy_attribution() -> None:
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("new_service.json"))[0]
    window = delta.observation_window
    lifecycle = ReconciliationLifecycle(ReconciliationEngine(), grace_seconds=60)
    in_window = EventObservationResult(
        query_complete=True,
        endpoint_collection_status="AVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        metadata={"source_health_checked_at": window.start.isoformat()},
    )
    pending = lifecycle.evaluate(
        delta,
        [],
        now=window.end + timedelta(seconds=30),
        event_observation=in_window,
    )
    later_poll = EventObservationResult(
        query_complete=True,
        endpoint_collection_status="AVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        metadata={
            "query_start": (window.start - timedelta(minutes=5)).isoformat(),
            "query_end": (window.end + timedelta(minutes=5)).isoformat(),
            "source_health_checked_at": (window.end + timedelta(minutes=3)).isoformat(),
        },
    )

    finalized = lifecycle.evaluate(
        delta,
        [],
        now=window.end + timedelta(seconds=90),
        previous=pending,
        event_observation=later_poll,
    )

    assert finalized.finalized is True
    assert finalized.status == ReconciliationStatus.UNEXPLAINED
    assert finalized.metadata["reconciliation_semantics"] == "UNCORROBORATED_HEALTHY"
    assert finalized.metadata["source_health_attribution"] == "AVAILABLE"
    assert finalized.metadata["source_health_attribution_source"] == "prior_in_window_observation"
    assert finalized.metadata["source_health_attribution_observation"]["metadata"][
        "source_health_checked_at"
    ] == window.start.isoformat()
    assert finalized.metadata["event_plane_last_observation"][
        "observation_current_for_revision"
    ] is True


def test_degraded_observation_requires_target_and_outage_overlap(db_session) -> None:
    finding = _pending_finding(CyberStateRepository(db_session))
    window = finding.reconciliation.observation_window
    broad_query = {
        "query_start": (window.start - timedelta(minutes=5)).isoformat(),
        "query_end": (window.end + timedelta(minutes=5)).isoformat(),
        "affected_object_keys": [finding.object_key],
        "source_health_checked_at": (window.end + timedelta(minutes=4)).isoformat(),
        "source_degradation_interval": {
            "start": (window.end + timedelta(seconds=1)).isoformat(),
            "end": (window.end + timedelta(minutes=3)).isoformat(),
        },
    }
    observation = EventObservationResult(
        query_complete=True,
        endpoint_collection_status="UNAVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        metadata=broad_query,
    )

    assert ReconciliationLifecycleService._observation_applies(finding, observation)
    assert (
        source_health_attribution_for_window(window, finding.object_key, observation)
        == "UNKNOWN"
    )
    overlapping = observation.model_copy(
        update={
            "metadata": {
                **broad_query,
                "source_degradation_interval": {
                    "start": window.start.isoformat(),
                    "end": (window.start + timedelta(seconds=1)).isoformat(),
                },
            }
        }
    )
    assert ReconciliationLifecycleService._observation_applies(finding, overlapping)
    assert (
        source_health_attribution_for_window(window, finding.object_key, overlapping)
        == "DEGRADED"
    )
    wrong_object = finding.model_copy(update={"object_key": "service:unrelated"})
    assert not ReconciliationLifecycleService._observation_applies(wrong_object, overlapping)
    assert (
        source_health_attribution_for_window(window, wrong_object.object_key, overlapping)
        == "UNKNOWN"
    )


def test_unbounded_degraded_health_is_not_attributed_outside_finding_window() -> None:
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("new_service.json"))[0]
    observation = EventObservationResult(
        query_complete=True,
        endpoint_collection_status="DEGRADED",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        metadata={
            "source_health_checked_at": (
                delta.observation_window.end + timedelta(minutes=1)
            ).isoformat()
        },
    )
    result = ReconciliationLifecycle(ReconciliationEngine(), grace_seconds=60).evaluate(
        delta,
        [],
        now=delta.observation_window.end + timedelta(minutes=2),
        event_observation=observation,
    )

    assert result.metadata["source_health_known_degraded"] is False
    assert result.metadata["source_health_attribution"] == "UNKNOWN"
    assert result.metadata["reconciliation_semantics"] == "INCONCLUSIVE"

    query_end_is_not_a_health_check = observation.model_copy(
        update={
            "metadata": {
                "retrieval": {"end": delta.observation_window.start.isoformat()}
            }
        }
    )
    assert (
        source_health_attribution_for_window(
            delta.observation_window,
            delta.object_key,
            query_end_is_not_a_health_check,
        )
        == "UNKNOWN"
    )
