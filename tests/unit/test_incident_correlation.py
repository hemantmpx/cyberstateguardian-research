from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tests.conftest import ROOT

from csg.config import Settings
from csg.db.repositories import CyberStateRepository
from csg.domain.enums import (
    AIContextMode,
    AuthorizationStatus,
    ObservationKind,
    ReconciliationStatus,
    Severity,
)
from csg.domain.models import (
    AIAnalysisRecord,
    Finding,
    Host,
    ReconciliationResult,
    RiskScore,
    TimeWindow,
)
from csg.services.incident_context import IncidentContextBuilder
from csg.services.incident_correlation import IncidentCorrelationService


def _settings() -> Settings:
    return Settings(
        CSG_AUTHORIZED_STATE_PATH=ROOT / "config/authorized-state.example.yaml",
        CSG_RISK_RULES_PATH=ROOT / "config/risk-rules.yaml",
        CSG_INCIDENT_CORRELATION_WINDOW_SECONDS=3600,
        CSG_INCIDENT_TEMPORAL_ONLY_WINDOW_SECONDS=900,
        CSG_INCIDENT_CORRELATION_MIN_SCORE=25,
    )


def _finding(created_at: datetime, category: str, object_key: str) -> Finding:
    return Finding(
        host_id="win11-arm-lab",
        observation_kind=ObservationKind.STATE_DELTA,
        category=category,
        object_key=object_key,
        reconciliation=ReconciliationResult(
            host_id="win11-arm-lab",
            status=ReconciliationStatus.UNEXPLAINED,
            observation_window=TimeWindow(
                start=created_at - timedelta(minutes=15),
                end=created_at + timedelta(minutes=15),
            ),
        ),
        authorization_status=AuthorizationStatus.UNKNOWN,
        authorization_reason="No approved change matched.",
        risk=RiskScore(
            total=55,
            severity=Severity.HIGH,
            components=[],
            rules_version="test",
        ),
        created_at=created_at,
    )


def test_temporal_findings_are_grouped_and_late_finding_starts_new_incident(db_session) -> None:
    repo = CyberStateRepository(db_session)
    repo.upsert_host(
        Host(
            host_id="win11-arm-lab",
            hostname="win11-arm-lab",
            role="windows-target",
            os="Windows 11",
            architecture="arm64",
        )
    )
    service = IncidentCorrelationService(_settings())
    started = datetime(2026, 9, 17, 14, 0, tzinfo=UTC)
    first = repo.create_finding(_finding(started, "service", "service:helper"))
    second = repo.create_finding(
        _finding(started + timedelta(minutes=7), "listener", "listener:tcp:8443")
    )
    late = repo.create_finding(
        _finding(started + timedelta(hours=2), "registry", "registry:defender-exclusion")
    )

    first_incident = service.assign_finding(repo, first)
    repo.create_ai_analysis(
        AIAnalysisRecord(
            finding_id=first.finding_id,
            incident_id=first_incident.incident_id,
            context_version=1,
            context_mode=AIContextMode.FULL_CONTEXT,
            prompt_version="test",
            model="test",
            enabled=True,
            response_json={
                "summary": "First finding summary",
                "what_changed": "A service appeared",
                "likely_cause": "Unknown",
                "evidence_ids": [],
                "delta_ids": [],
                "finding_ids": [first.finding_id],
            },
        )
    )
    second_incident = service.assign_finding(repo, second)
    late_incident = service.assign_finding(repo, late)

    assert first_incident.incident_id == second_incident.incident_id
    assert second_incident.context_version == 2
    assert second_incident.finding_ids == [first.finding_id, second.finding_id]
    assert late_incident.incident_id != first_incident.incident_id
    assert len(repo.list_incidents(host_id="win11-arm-lab")) == 2
    assignment = next(
        item
        for item in repo.list_incident_assignments(second_incident.incident_id)
        if item.finding_id == second.finding_id
    )
    assert assignment.assignment_score >= 25
    assert "same host" in assignment.assignment_reasons[0]

    builder = IncidentContextBuilder(_settings())
    condition_a = builder.build_for_incident(repo, second_incident, mode=AIContextMode.FINDING_ONLY)
    condition_c = builder.build_for_incident(repo, second_incident, mode=AIContextMode.FULL_CONTEXT)
    assert condition_a.incident is None
    assert condition_a.evidence == []
    assert condition_a.state_delta is None
    assert condition_c.incident_id == second_incident.incident_id
    assert condition_c.related_findings[0].finding_id == first.finding_id
    assert condition_c.interpretive_memory is not None
    assert condition_c.interpretive_memory["analysis_id"]


def test_assignment_is_idempotent(db_session) -> None:
    repo = CyberStateRepository(db_session)
    finding = repo.create_finding(
        _finding(datetime(2026, 9, 17, 15, 0, tzinfo=UTC), "service", "service:helper")
    )
    service = IncidentCorrelationService(_settings())

    first = service.assign_finding(repo, finding)
    second = service.assign_finding(repo, finding)

    assert first.incident_id == second.incident_id
    assert second.context_version == 1
    assert len(second.finding_ids) == 1
