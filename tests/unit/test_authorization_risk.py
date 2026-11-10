from __future__ import annotations

from tests.conftest import ROOT, load_json

from csg.domain.enums import AuthorizationStatus, ReconciliationStatus
from csg.domain.models import EventObservationResult, NormalizedEvent, StateSnapshot
from csg.services.authorization import AuthorizationService
from csg.services.reconciliation import ReconciliationEngine
from csg.services.risk import RiskEngine
from csg.state.diff import DeltaEngine


def _snapshot(name: str) -> StateSnapshot:
    return StateSnapshot.model_validate(load_json(ROOT / "experiments/fixtures/state" / name))


def _events(name: str) -> list[NormalizedEvent]:
    payload = load_json(ROOT / "experiments/fixtures/events" / name)
    return [NormalizedEvent.model_validate(row) for row in payload["events"]]


def test_approved_change_lowers_risk_but_keeps_delta_visible() -> None:
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("approved_service.json"))[0]
    reconciliation = ReconciliationEngine().reconcile_delta(
        delta, _events("approved-service-install.json")
    )
    decision = AuthorizationService(ROOT / "config/authorized-state.example.yaml").evaluate_delta(
        delta
    )
    score = RiskEngine(ROOT / "config/risk-rules.yaml").score_delta(
        delta,
        reconciliation,
        decision.status,
    )

    assert decision.status == AuthorizationStatus.APPROVED_CHANGE
    assert reconciliation.status == ReconciliationStatus.CONSISTENT
    assert delta.object_key == "service:approvedagent"
    assert score.total == 10


def test_privileged_group_violation_scores_high() -> None:
    delta = DeltaEngine().diff(
        _snapshot("baseline.json"), _snapshot("privileged_group_change.json")
    )[0]
    reconciliation = ReconciliationEngine().reconcile_delta(
        delta, _events("privileged-group-change.json")
    )
    decision = AuthorizationService(ROOT / "config/authorized-state.example.yaml").evaluate_delta(
        delta
    )
    score = RiskEngine(ROOT / "config/risk-rules.yaml").score_delta(
        delta,
        reconciliation,
        decision.status,
    )

    assert decision.status == AuthorizationStatus.VIOLATION
    assert score.severity.value == "HIGH"
    assert score.total == 75


def test_expected_service_requires_configured_attributes(tmp_path) -> None:
    policy = tmp_path / "authorized.yaml"
    policy.write_text(
        "\n".join(
            [
                "version: test",
                "hosts:",
                "  win-lab-01:",
                "    expected_services:",
                "      - object_key: service:eventlog",
                "        attributes:",
                "          binary_path: c:/windows/system32/svchost.exe -k localservice",
                "          start_mode: auto",
                "          account: nt authority/localservice",
            ]
        ),
        encoding="utf-8",
    )
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("modified_service.json"))[0]

    decision = AuthorizationService(policy).evaluate_delta(delta)

    assert decision.status == AuthorizationStatus.VIOLATION
    assert "attributes" in decision.reason


def test_known_event_source_outage_has_distinct_risk_from_healthy_missing_event() -> None:
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("modified_service.json"))[0]
    engine = ReconciliationEngine()
    healthy = engine.reconcile_delta(
        delta,
        [],
        event_observation=EventObservationResult(
            query_complete=True,
            endpoint_collection_status="AVAILABLE",
            transport_status="AVAILABLE",
            index_status="AVAILABLE",
            coverage_status="COMPLETE",
        ),
    )
    degraded = engine.reconcile_delta(
        delta,
        [],
        event_observation=EventObservationResult(
            query_complete=True,
            endpoint_collection_status="DEGRADED",
            transport_status="AVAILABLE",
            index_status="AVAILABLE",
            coverage_status="COMPLETE",
        ),
    )
    status = AuthorizationStatus.UNKNOWN
    healthy_score = RiskEngine(ROOT / "config/risk-rules.yaml").score_delta(
        delta,
        healthy.model_copy(
            update={"metadata": {"reconciliation_semantics": "UNCORROBORATED_HEALTHY"}}
        ),
        status,
    )
    degraded_score = RiskEngine(ROOT / "config/risk-rules.yaml").score_delta(
        delta,
        degraded.model_copy(
            update={"metadata": {"reconciliation_semantics": "UNCORROBORATED_DEGRADED"}}
        ),
        status,
    )
    assert healthy_score.total > degraded_score.total
