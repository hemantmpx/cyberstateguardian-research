from __future__ import annotations

from datetime import UTC, datetime, timedelta

from csg.config import Settings
from csg.db.repositories import CyberStateRepository
from csg.domain.enums import TransitionReconciliationStatus
from csg.domain.models import (
    EventObservationResult,
    NormalizedEvent,
    StateTransitionRecord,
)
from csg.services.transition_reconciliation import TransitionReconciliationService

NOW = datetime(2026, 10, 4, 18, 0, tzinfo=UTC)
OBJECT_KEY = "service:csg-research-target"


def _transition(**overrides) -> StateTransitionRecord:
    values = {
        "host_id": "win11-lab",
        "category": "service",
        "object_key": OBJECT_KEY,
        "transition_type": "SERVICE_START_MODE_CHANGED",
        "observed_at": NOW,
        "window_start": NOW,
        "window_end": NOW,
        "old_state": {"service_name": "CSGResearchTarget", "start_mode": "Manual"},
        "new_state": {"service_name": "CSGResearchTarget", "start_mode": "Automatic"},
        "changed_fields": ["start_mode"],
        "capture_method": "test_fixture",
        "collector_health": "HEALTHY",
    }
    values.update(overrides)
    return StateTransitionRecord(**values)


def _service_event(**overrides) -> NormalizedEvent:
    values = {
        "event_id": "wazuh-exact-service-event",
        "host_id": "win11-lab",
        "event_time": NOW,
        "normalized_type": "service_modified",
        "attributes": {
            "service_name": "CSGResearchTarget",
            "old_start_mode": "demand start",
            "new_start_mode": "auto",
        },
        "target": {"key": OBJECT_KEY},
        "source": "wazuh",
    }
    values.update(overrides)
    return NormalizedEvent(**values)


class StaticEventProvider:
    def __init__(self, result):
        self.result = result
        self.queries = []

    async def get_events(self, host_id, start, end):
        self.queries.append((host_id, start, end))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _settings() -> Settings:
    return Settings(CSG_EVENT_TIME_TOLERANCE_SECONDS=5)


async def test_exact_object_and_transition_is_corroborated_and_query_is_bounded(
    db_session, monkeypatch
) -> None:
    provider = StaticEventProvider([_service_event()])
    monkeypatch.setattr(
        "csg.services.transition_reconciliation.build_event_provider", lambda _: provider
    )
    repo = CyberStateRepository(db_session)
    transition = _transition()

    result = await TransitionReconciliationService(_settings()).reconcile(repo, transition)

    assert result.status == TransitionReconciliationStatus.CORROBORATED
    assert result.matched_evidence_ids == ["wazuh-exact-service-event"]
    assert provider.queries == [
        ("win11-lab", NOW - timedelta(seconds=5), NOW + timedelta(seconds=5))
    ]
    assert repo.transition_reconciliation_history(transition.transition_id) == [result]


async def test_same_host_and_event_type_for_different_service_is_not_a_match(
    db_session, monkeypatch
) -> None:
    distractor = _service_event(
        event_id="wazuh-other-service",
        attributes={
            "service_name": "DifferentService",
            "old_start_mode": "manual",
            "new_start_mode": "auto",
        },
        target={"key": "service:different-service"},
    )
    monkeypatch.setattr(
        "csg.services.transition_reconciliation.build_event_provider",
        lambda _: StaticEventProvider([distractor]),
    )

    result = await TransitionReconciliationService(_settings()).reconcile(
        CyberStateRepository(db_session), _transition()
    )

    assert result.status == TransitionReconciliationStatus.UNEXPLAINED_BY_EVENT_PLANE
    assert result.matched_evidence_ids == []


async def test_same_object_with_incompatible_state_change_is_contradicted(
    db_session, monkeypatch
) -> None:
    contradictory = _service_event(
        attributes={
            "service_name": "CSGResearchTarget",
            "old_start_mode": "auto",
            "new_start_mode": "disabled",
        }
    )
    monkeypatch.setattr(
        "csg.services.transition_reconciliation.build_event_provider",
        lambda _: StaticEventProvider([contradictory]),
    )

    result = await TransitionReconciliationService(_settings()).reconcile(
        CyberStateRepository(db_session), _transition()
    )

    assert result.status == TransitionReconciliationStatus.CONTRADICTED
    assert result.metadata["transition_mismatches"][0]["reason"] == (
        "same object and operation type but incompatible transition"
    )


async def test_event_for_wrong_host_or_outside_time_window_cannot_corroborate(
    db_session, monkeypatch
) -> None:
    wrong_host = _service_event(event_id="wrong-host", host_id="other-host")
    late = _service_event(event_id="late", event_time=NOW + timedelta(minutes=1))
    monkeypatch.setattr(
        "csg.services.transition_reconciliation.build_event_provider",
        lambda _: StaticEventProvider([wrong_host, late]),
    )

    result = await TransitionReconciliationService(_settings()).reconcile(
        CyberStateRepository(db_session), _transition()
    )

    assert result.status == TransitionReconciliationStatus.UNEXPLAINED_BY_EVENT_PLANE
    assert result.matched_evidence_ids == []


async def test_privileged_group_transition_matches_wazuh_member_sid_exactly(
    db_session, monkeypatch
) -> None:
    member = "win11-lab/csgresearchuser"
    sid = "S-1-5-21-1-2-3-1002"
    object_key = f"privileged_group:administrators:{member}"
    transition = _transition(
        category="privileged_group",
        object_key=object_key,
        transition_type="PRIVILEGED_MEMBER_ADDED",
        old_state=None,
        new_state={"group": "Administrators", "member": member, "sid": sid},
    )
    event = NormalizedEvent(
        event_id="wazuh-member-sid-exact",
        host_id=transition.host_id,
        event_time=NOW,
        normalized_type="privileged_group_member_added",
        target={"group": "Administrators", "member_sid": sid},
        attributes={"event_code": "4732", "group": "Administrators", "member_sid": sid},
        source="wazuh",
    )
    monkeypatch.setattr(
        "csg.services.transition_reconciliation.build_event_provider",
        lambda _: StaticEventProvider([event]),
    )

    result = await TransitionReconciliationService(_settings()).reconcile(
        CyberStateRepository(db_session), transition
    )

    assert result.status == TransitionReconciliationStatus.CORROBORATED
    assert result.matched_evidence_ids == [event.event_id]
    assert result.match_reasons[0]["reason"] == (
        "exact privileged-group name and member SID matched"
    )


async def test_privileged_group_transition_rejects_wrong_member_sid(
    db_session, monkeypatch
) -> None:
    member = "win11-lab/csgresearchuser"
    transition = _transition(
        category="privileged_group",
        object_key=f"privileged_group:administrators:{member}",
        transition_type="PRIVILEGED_MEMBER_ADDED",
        old_state=None,
        new_state={"group": "Administrators", "member": member, "sid": "S-1-5-21-1-2-3-1002"},
    )
    event = NormalizedEvent(
        event_id="wazuh-member-sid-distractor",
        host_id=transition.host_id,
        event_time=NOW,
        normalized_type="privileged_group_member_added",
        target={"group": "Administrators", "member_sid": "S-1-5-21-1-2-3-9999"},
        attributes={
            "event_code": "4732",
            "group": "Administrators",
            "member_sid": "S-1-5-21-1-2-3-9999",
        },
        source="wazuh",
    )
    monkeypatch.setattr(
        "csg.services.transition_reconciliation.build_event_provider",
        lambda _: StaticEventProvider([event]),
    )

    result = await TransitionReconciliationService(_settings()).reconcile(
        CyberStateRepository(db_session), transition
    )

    assert result.status == TransitionReconciliationStatus.UNEXPLAINED_BY_EVENT_PLANE
    assert result.matched_evidence_ids == []


async def test_unavailable_event_query_is_pending_then_late_event_creates_revision(
    db_session, monkeypatch
) -> None:
    provider = StaticEventProvider(RuntimeError("index temporarily unavailable"))
    monkeypatch.setattr(
        "csg.services.transition_reconciliation.build_event_provider", lambda _: provider
    )
    repo = CyberStateRepository(db_session)
    transition = _transition()
    service = TransitionReconciliationService(_settings())

    pending = await service.reconcile(repo, transition)
    provider.result = EventObservationResult(
        events=[_service_event()],
        query_complete=True,
        endpoint_collection_status="AVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        retrieved_count=1,
    )
    corroborated = await service.reconcile(repo, transition)

    assert pending.status == TransitionReconciliationStatus.PENDING_EVIDENCE
    assert pending.finalized is False
    assert corroborated.status == TransitionReconciliationStatus.CORROBORATED
    assert corroborated.version == 2
    assert corroborated.supersedes_reconciliation_id == pending.reconciliation_id
    assert [
        row.version for row in repo.transition_reconciliation_history(transition.transition_id)
    ] == [
        1,
        2,
    ]


async def test_unsupported_transition_is_not_applicable(db_session) -> None:
    result = await TransitionReconciliationService(_settings()).reconcile(
        CyberStateRepository(db_session),
        _transition(category="process", transition_type="PROCESS_EXIT"),
    )

    assert result.status == TransitionReconciliationStatus.NOT_APPLICABLE
    assert result.metadata["reason"]
