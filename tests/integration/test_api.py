from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from tests.conftest import ROOT, load_json

from csg.api.deps import db_dependency, settings_dependency
from csg.config import get_settings
from csg.db.repositories import CyberStateRepository
from csg.domain.enums import (
    AuthorizationStatus,
    DeltaType,
    ObservationKind,
    ReconciliationStatus,
    Severity,
)
from csg.domain.models import (
    CategoryStatus,
    EventObservationResult,
    Finding,
    Host,
    ReconciliationResult,
    RiskScore,
    StateDelta,
    StateObject,
    StateSnapshot,
    TimeWindow,
)
from csg.main import app
from csg.services.incident_correlation import IncidentCorrelationService
from csg.services.reconciliation import ReconciliationEngine, ReconciliationLifecycle
from csg.state.diff import DeltaEngine


def test_health() -> None:
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_delta_and_finding_lists_filter_by_exact_object_key(db_session) -> None:
    repo = CyberStateRepository(db_session)
    host_id = "object-filter-test-host"
    repo.upsert_host(
        Host(
            host_id=host_id,
            hostname="object-filter-test-host",
            role="test",
            os="Windows",
            architecture="ARM64",
        )
    )
    observed_at = datetime(2026, 10, 11, 2, 0, tzinfo=UTC)
    for suffix in ("wanted", "other"):
        object_key = f"service:{suffix}"
        created_at = observed_at + (timedelta(minutes=1) if suffix == "other" else timedelta())
        delta = StateDelta(
            host_id=host_id,
            category="service",
            object_key=object_key,
            delta_type=DeltaType.ADD,
            observation_window=TimeWindow(start=observed_at, end=observed_at),
            created_at=created_at,
        )
        repo.create_deltas([delta])
        repo.create_finding(
            Finding(
                host_id=host_id,
                observation_kind=ObservationKind.STATE_DELTA,
                delta_id=delta.delta_id,
                category="service",
                object_key=object_key,
                reconciliation=ReconciliationResult(
                    host_id=host_id,
                    delta_id=delta.delta_id,
                    status=ReconciliationStatus.UNEXPLAINED,
                    observation_window=delta.observation_window,
                ),
                authorization_status=AuthorizationStatus.UNKNOWN,
                authorization_reason="test fixture",
                risk=RiskScore(total=1, severity=Severity.LOW, components=[], rules_version="test"),
                created_at=created_at,
            )
        )

    app.dependency_overrides[db_dependency] = lambda: (yield db_session)
    try:
        client = TestClient(app)
        delta_response = client.get(
            f"/api/hosts/{host_id}/deltas",
            params={"limit": 500, "object_key": "service:wanted"},
        )
        finding_response = client.get(
            "/api/findings",
            params={"host_id": host_id, "limit": 500, "object_key": "service:wanted"},
        )
        filter_time = (observed_at + timedelta(seconds=30)).isoformat()
        newer_delta_response = client.get(
            f"/api/hosts/{host_id}/deltas",
            params={"limit": 500, "created_after": filter_time, "category": "service"},
        )
        newer_finding_response = client.get(
            "/api/findings",
            params={
                "host_id": host_id,
                "limit": 500,
                "created_after": filter_time,
                "category": "service",
            },
        )
        wrong_category_response = client.get(
            f"/api/hosts/{host_id}/deltas",
            params={"limit": 500, "category": "scheduled_task"},
        )
    finally:
        app.dependency_overrides.clear()

    assert delta_response.status_code == 200
    assert [item["object_key"] for item in delta_response.json()] == ["service:wanted"]
    assert finding_response.status_code == 200
    assert [item["object_key"] for item in finding_response.json()] == ["service:wanted"]
    assert newer_delta_response.status_code == 200
    assert [item["object_key"] for item in newer_delta_response.json()] == ["service:other"]
    assert newer_finding_response.status_code == 200
    assert [item["object_key"] for item in newer_finding_response.json()] == ["service:other"]
    assert wrong_category_response.status_code == 200
    assert wrong_category_response.json() == []


def test_empty_degraded_event_observation_is_ingested(db_session) -> None:
    app.dependency_overrides[db_dependency] = lambda: (yield db_session)
    now = datetime.now(UTC)
    observation = EventObservationResult(
        query_complete=True,
        endpoint_collection_status="UNAVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        metadata={
            "query_start": (now - timedelta(minutes=1)).isoformat(),
            "query_end": now.isoformat(),
        },
    )

    try:
        response = TestClient(app).post(
            "/api/hosts/observation-test-host/event-observations",
            json=observation.model_dump(mode="json"),
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["received_event_count"] == 0
    assert response.json()["endpoint_collection_status"] == "UNAVAILABLE"
    assert response.json()["coverage_status"] == "COMPLETE"


def test_event_observation_finalizes_pending_finding_as_degraded(db_session) -> None:
    app.dependency_overrides[db_dependency] = lambda: (yield db_session)
    repo = CyberStateRepository(db_session)
    baseline = StateSnapshot.model_validate(
        load_json(ROOT / "experiments/fixtures/state/baseline.json")
    )
    changed = StateSnapshot.model_validate(
        load_json(ROOT / "experiments/fixtures/state/new_service.json")
    )
    delta = DeltaEngine().diff(baseline, changed)[0]
    repo.create_deltas([delta])
    pending = ReconciliationLifecycle(ReconciliationEngine(), grace_seconds=60).evaluate(
        delta,
        [],
        now=delta.observation_window.end - timedelta(seconds=30),
        evidence_complete=False,
    )
    finding = Finding(
        host_id=delta.host_id,
        observation_kind=ObservationKind.STATE_DELTA,
        delta_id=delta.delta_id,
        category=delta.category,
        object_key=delta.object_key,
        reconciliation=pending,
        authorization_status=AuthorizationStatus.UNKNOWN,
        authorization_reason="test fixture",
        risk=RiskScore(total=35, severity=Severity.MEDIUM, rules_version="test"),
        created_at=delta.created_at,
    )
    pending = pending.model_copy(update={"finding_id": finding.finding_id})
    finding = finding.model_copy(update={"reconciliation": pending})
    repo.create_reconciliation(pending)
    repo.create_finding(finding)
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
            "affected_object_keys": [delta.object_key],
            "source_degradation_interval": {
                "start": delta.observation_window.start.isoformat(),
                "end": delta.observation_window.end.isoformat(),
            },
        },
    )

    try:
        response = TestClient(app).post(
            f"/api/hosts/{delta.host_id}/event-observations",
            json=observation.model_dump(mode="json"),
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    result = response.json()["updated_findings"][0]
    assert result["status"] == "UNEXPLAINED"
    assert result["finalized"] is True
    assert result["reconciliation_semantics"] == "UNCORROBORATED_DEGRADED"
    updated = repo.get_finding(finding.finding_id)
    assert updated is not None
    assert updated.reconciliation.metadata["source_health_known_degraded"] is True


def test_host_and_probe_ingestion_api(db_session) -> None:
    def override_db():
        yield db_session

    app.dependency_overrides[db_dependency] = override_db
    client = TestClient(app)
    settings = get_settings()
    payload = {
        "host_id": "win-lab-01",
        "observed_at": "2026-09-13T20:00:00Z",
        "source": "direct_probe",
        "categories": {
            "service": {
                "category": "service",
                "status": "healthy",
                "observed_at": "2026-09-13T20:00:00Z",
                "items": [
                    {
                        "service_name": "EventLog",
                        "status": "running",
                        "start_mode": "auto",
                        "binary_path": "c:/windows/system32/svchost.exe",
                        "account": "localsystem",
                    },
                ],
            },
        },
        "metadata": {
            "test": True,
            "host": {
                "hostname": "win11-arm-lab",
                "role": "windows-target",
                "os": "Windows 11",
                "architecture": "arm64",
            },
        },
    }
    response = client.post(
        "/api/probe/observations",
        json=payload,
        headers={"Authorization": f"Bearer {settings.lab_shared_token}"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    host_response = client.get("/api/hosts/win-lab-01")
    assert host_response.status_code == 200
    assert host_response.json()["hostname"] == "win11-arm-lab"
    latest = client.get("/api/hosts/win-lab-01/state/latest")
    assert latest.status_code == 200
    assert latest.json()["objects"][0]["object_key"] == "service:eventlog"
    app.dependency_overrides.clear()


def test_transition_api_is_disabled_by_default_and_persists_reverted_history(db_session) -> None:
    app.dependency_overrides[db_dependency] = lambda: (yield db_session)
    settings = get_settings()
    app.dependency_overrides[settings_dependency] = lambda: settings.model_copy(
        update={
            "transition_capture_enabled": True,
            "transition_services_enabled": True,
        }
    )
    repo = CyberStateRepository(db_session)
    start = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
    baseline = {"service_name": "Sample", "start_mode": "manual", "binary_path": "c:/sample.exe"}
    automatic = {"service_name": "Sample", "start_mode": "auto", "binary_path": "c:/sample.exe"}
    for snapshot_id, built_at in (
        ("trajectory-before", start),
        ("trajectory-after", start + timedelta(minutes=30)),
    ):
        repo.create_snapshot(
            StateSnapshot(
                snapshot_id=snapshot_id,
                host_id="transition-api-host",
                built_at=built_at,
                source="direct_probe",
                category_statuses=[
                    CategoryStatus(category="service", status="healthy", source="direct_probe")
                ],
                objects=[
                    StateObject(
                        category="service",
                        object_key="service:sample",
                        attributes=baseline,
                        source_timestamp=built_at,
                    )
                ],
            )
        )

    client = TestClient(app)
    headers = {"Authorization": f"Bearer {settings.lab_shared_token}"}
    batch = {
        "host_id": "transition-api-host",
        "records": [
            {
                "transition_id": "transition-api-1",
                "host_id": "transition-api-host",
                "category": "service",
                "object_key": "service:sample",
                "transition_type": "SERVICE_CONFIG_MODIFIED",
                "observed_at": (start + timedelta(minutes=6)).isoformat(),
                "window_start": (start + timedelta(minutes=6)).isoformat(),
                "window_end": (start + timedelta(minutes=6, seconds=1)).isoformat(),
                "old_state": baseline,
                "new_state": automatic,
                "changed_fields": ["start_mode"],
                "capture_method": "test_adapter",
                "collector_health": "HEALTHY",
                "sequence_number": 1,
            },
            {
                "transition_id": "transition-api-2",
                "host_id": "transition-api-host",
                "category": "service",
                "object_key": "service:sample",
                "transition_type": "SERVICE_CONFIG_MODIFIED",
                "observed_at": (start + timedelta(minutes=11)).isoformat(),
                "window_start": (start + timedelta(minutes=11)).isoformat(),
                "window_end": (start + timedelta(minutes=11, seconds=1)).isoformat(),
                "old_state": automatic,
                "new_state": baseline,
                "changed_fields": ["start_mode"],
                "capture_method": "test_adapter",
                "collector_health": "HEALTHY",
                "sequence_number": 2,
            },
        ],
        "monitor_health": [
            {
                "host_id": "transition-api-host",
                "category": "service",
                "monitor_id": "service-monitor-1",
                "status": "HEALTHY",
                "capture_method": "test_adapter",
                "started_at": start.isoformat(),
                "observed_at": (start + timedelta(minutes=20)).isoformat(),
                "last_heartbeat_at": (start + timedelta(minutes=20)).isoformat(),
                "coverage_start": start.isoformat(),
                "baseline_established": True,
            }
        ],
    }
    accepted = client.post("/api/probe/transitions", json=batch, headers=headers)
    assert accepted.status_code == 200
    assert accepted.json()["created_count"] == 2
    duplicate = client.post("/api/probe/transitions", json=batch, headers=headers)
    assert duplicate.status_code == 200
    assert duplicate.json()["created_count"] == 0
    assert duplicate.json()["duplicate_count"] == 2

    response = client.get(
        "/api/hosts/transition-api-host/trajectories",
        params={"start": start.isoformat(), "end": (start + timedelta(minutes=30)).isoformat()},
    )
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["trajectory_type"] == "REVERTED"
    assert response.json()[0]["snapshot_delta"] is None
    assert len(response.json()[0]["transitions"]) == 2

    timeline = client.get(
        "/api/hosts/transition-api-host/transition-timeline",
        params={"category": "service", "limit": 10},
    )
    assert timeline.status_code == 200
    assert len(timeline.json()) == 2
    assert timeline.json()[0]["transition"]["object_key"] == "service:sample"
    assert timeline.json()[0]["latest_reconciliation"] is None

    listed = client.get(
        "/api/hosts/transition-api-host/transitions",
        params={"category": "service", "object_key": "service:sample"},
    )
    assert listed.status_code == 200
    assert len(listed.json()) == 2
    health = client.get("/api/transition-capture/status", params={"host_id": "transition-api-host"})
    assert health.json()["categories"]["service"]["monitor_health"]["status"] == "HEALTHY"
    app.dependency_overrides.clear()


def test_transition_ingestion_rejects_when_feature_flag_is_off(db_session) -> None:
    app.dependency_overrides[db_dependency] = lambda: (yield db_session)
    settings = get_settings()
    app.dependency_overrides[settings_dependency] = lambda: settings.model_copy(
        update={"transition_capture_enabled": False, "transition_services_enabled": True}
    )
    client = TestClient(app)
    response = client.post(
        "/api/probe/transitions",
        json={"host_id": "disabled-host", "records": []},
        headers={"Authorization": f"Bearer {settings.lab_shared_token}"},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "transition capture is disabled"
    app.dependency_overrides.clear()


def test_incident_context_and_disabled_ai_analysis_api(db_session) -> None:
    def override_db():
        yield db_session

    app.dependency_overrides[db_dependency] = override_db
    settings = get_settings()
    test_settings = settings.model_copy(update={"ai_enabled": False, "openai_api_key": None})
    app.dependency_overrides[settings_dependency] = lambda: test_settings
    repo = CyberStateRepository(db_session)
    observed_at = datetime(2026, 9, 17, 18, 0, tzinfo=UTC)
    finding = repo.create_finding(
        Finding(
            host_id="api-incident-host",
            observation_kind=ObservationKind.STATE_DELTA,
            category="service",
            object_key="service:test",
            reconciliation=ReconciliationResult(
                host_id="api-incident-host",
                status=ReconciliationStatus.UNEXPLAINED,
                observation_window=TimeWindow(
                    start=observed_at - timedelta(minutes=15),
                    end=observed_at + timedelta(minutes=15),
                ),
            ),
            authorization_status=AuthorizationStatus.UNKNOWN,
            authorization_reason="No approved change matched.",
            risk=RiskScore(
                total=45,
                severity=Severity.MEDIUM,
                components=[],
                rules_version="test",
            ),
            created_at=observed_at,
        )
    )
    incident = IncidentCorrelationService(settings).assign_finding(repo, finding)
    client = TestClient(app)

    listed = client.get("/api/incidents")
    context = client.get(f"/api/incidents/{incident.incident_id}/ai-context?mode=finding_only")
    analysis = client.post(f"/api/incidents/{incident.incident_id}/ai-analysis?mode=finding_only")

    assert listed.status_code == 200
    assert listed.json()[0]["incident_id"] == incident.incident_id
    assert context.status_code == 200
    assert context.json()["context_mode"] == "finding_only"
    assert analysis.status_code == 200
    assert analysis.json()["enabled"] is False
    assert client.get(f"/api/ai-analyses?incident_id={incident.incident_id}").json()
    app.dependency_overrides.clear()
