from __future__ import annotations

from datetime import UTC, datetime

from tests.conftest import ROOT

from csg.config import Settings
from csg.db.repositories import CyberStateRepository
from csg.domain.enums import (
    AuthorizationStatus,
    DeltaType,
    ObservationKind,
    ReconciliationStatus,
    Severity,
)
from csg.domain.models import (
    Finding,
    Host,
    NormalizedEvent,
    ReconciliationResult,
    RiskScore,
    StateDelta,
    StateObject,
    TimeWindow,
)
from csg.services.incident_context import IncidentContextBuilder


def _settings() -> Settings:
    return Settings(
        CSG_AUTHORIZED_STATE_PATH=ROOT / "config/authorized-state.example.yaml",
        CSG_RISK_RULES_PATH=ROOT / "config/risk-rules.yaml",
        CSG_AI_CONTEXT_MAX_EVENTS=10,
        CSG_AI_CONTEXT_RELATED_LIMIT=10,
    )


def _risk() -> RiskScore:
    return RiskScore(total=60, severity=Severity.HIGH, components=[], rules_version="test")


def test_incident_context_includes_delta_timeline_and_related_findings(db_session) -> None:
    repo = CyberStateRepository(db_session)
    repo.upsert_host(
        Host(
            host_id="win11-arm-lab",
            hostname="win11-arm-lab",
            role="windows-target",
            os="Windows 11",
            architecture="arm64",
        ),
    )
    window = TimeWindow(
        start=datetime(2026, 9, 16, 14, 0, tzinfo=UTC),
        end=datetime(2026, 9, 16, 14, 30, tzinfo=UTC),
    )
    service_delta = StateDelta(
        host_id="win11-arm-lab",
        category="service",
        object_key="service:winupdatehelper",
        delta_type=DeltaType.ADD,
        after=StateObject(
            category="service",
            object_key="service:winupdatehelper",
            attributes={
                "service_name": "WinUpdateHelper",
                "binary_path": "C:\\Users\\bob\\update.exe",
                "account": "LocalSystem",
            },
        ),
        observation_window=window,
        created_at=window.end,
    )
    related_delta = StateDelta(
        host_id="win11-arm-lab",
        category="listener",
        object_key="listener:0.0.0.0:tcp:8443",
        delta_type=DeltaType.ADD,
        after=StateObject(
            category="listener",
            object_key="listener:0.0.0.0:tcp:8443",
            attributes={"process_name": "update.exe", "local_port": "8443"},
        ),
        observation_window=window,
        created_at=datetime(2026, 9, 16, 14, 26, tzinfo=UTC),
    )
    repo.create_deltas([service_delta, related_delta])
    service_event = NormalizedEvent(
        event_id="evt-service-created",
        host_id="win11-arm-lab",
        event_time=datetime(2026, 9, 16, 14, 21, tzinfo=UTC),
        normalized_type="service_created",
        actor={"username": "bob"},
        target={"key": "service:winupdatehelper"},
        attributes={"service_name": "WinUpdateHelper", "binary_path": "C:\\Users\\bob\\update.exe"},
        source="wazuh",
    )
    process_event = NormalizedEvent(
        event_id="evt-process-start",
        host_id="win11-arm-lab",
        event_time=datetime(2026, 9, 16, 14, 20, tzinfo=UTC),
        normalized_type="process_start",
        actor={"username": "bob"},
        target={"process_name": "powershell.exe"},
        attributes={"command_line": "powershell -enc ..."},
        source="wazuh",
    )
    repo.create_events([service_event, process_event])
    reconciliation = ReconciliationResult(
        host_id="win11-arm-lab",
        status=ReconciliationStatus.CONSISTENT,
        matched_evidence_ids=["evt-service-created"],
        observation_window=window,
    )
    finding = Finding(
        host_id="win11-arm-lab",
        observation_kind=ObservationKind.STATE_DELTA,
        delta_id=service_delta.delta_id,
        category="service",
        object_key="service:winupdatehelper",
        reconciliation=reconciliation,
        authorization_status=AuthorizationStatus.UNKNOWN,
        authorization_reason="No approved service entry matched WinUpdateHelper.",
        risk=_risk(),
        created_at=window.end,
    )
    related_finding = Finding(
        host_id="win11-arm-lab",
        observation_kind=ObservationKind.STATE_DELTA,
        delta_id=related_delta.delta_id,
        category="listener",
        object_key="listener:0.0.0.0:tcp:8443",
        reconciliation=reconciliation,
        authorization_status=AuthorizationStatus.UNKNOWN,
        authorization_reason="No approved listener matched port 8443.",
        risk=_risk(),
        created_at=datetime(2026, 9, 16, 14, 27, tzinfo=UTC),
    )
    repo.create_finding(finding)
    repo.create_finding(related_finding)

    package = IncidentContextBuilder(_settings()).build_for_finding(repo, finding)

    assert package.finding_id == finding.finding_id
    assert package.state_delta is not None
    assert package.state_delta.delta_id == service_delta.delta_id
    assert [item.evidence_id for item in package.evidence] == [
        "evt-process-start",
        "evt-service-created",
    ]
    assert package.related_deltas[0].delta_id == related_delta.delta_id
    assert package.related_findings[0].finding_id == related_finding.finding_id
    assert package.incident_context["deterministic_results"]["authorization_status"] == "UNKNOWN"
    assert package.incident_context["state_transition"]["after"]["attributes"]["service_name"] == (
        "WinUpdateHelper"
    )
    assert package.incident_context["retrieval_strategy"]["selected_event_count"] == 2
