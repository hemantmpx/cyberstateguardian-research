from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from tests.conftest import ROOT

from csg.config import Settings
from csg.db import models as orm
from csg.db.repositories import CyberStateRepository
from csg.domain.enums import ReconciliationStatus
from csg.domain.models import CollectorObservation, ProbeObservation
from csg.services.live_pipeline import LivePipelineService
from csg.state.diff import DeltaEngine


def _settings() -> Settings:
    return Settings(
        CSG_AUTHORIZED_STATE_PATH=ROOT / "config/authorized-state.example.yaml",
        CSG_RISK_RULES_PATH=ROOT / "config/risk-rules.yaml",
        CSG_PIPELINE_ON_INGEST=True,
    )


def _service_items(extra: list[dict] | None = None) -> list[dict]:
    items = [
        {
            "service_name": "EventLog",
            "display_name": "Windows Event Log",
            "status": "running",
            "start_mode": "auto",
            "binary_path": "C:\\Windows\\System32\\svchost.exe",
            "account": "LocalSystem",
        },
    ]
    return items + (extra or [])


def _observation(
    observed_at: datetime,
    services: list[dict],
    *,
    service_observed_at: datetime | None = None,
) -> ProbeObservation:
    return ProbeObservation(
        host_id="win-lab-01",
        observed_at=observed_at,
        source="direct_probe",
        categories={
            "service": CollectorObservation(
                category="service",
                status="healthy",
                observed_at=service_observed_at or observed_at,
                items=services,
            ),
        },
        metadata={
            "host": {
                "hostname": "win11-arm-lab",
                "role": "windows-target",
                "os": "Windows 11",
                "architecture": "arm64",
            },
        },
    )


def _process_observation(observed_at: datetime, processes: list[dict]) -> ProbeObservation:
    return ProbeObservation(
        host_id="win-lab-01",
        observed_at=observed_at,
        source="direct_probe",
        categories={
            "process": CollectorObservation(
                category="process",
                status="healthy",
                observed_at=observed_at,
                items=processes,
            ),
        },
        metadata={
            "host": {
                "hostname": "win11-arm-lab",
                "role": "windows-target",
                "os": "Windows 11",
                "architecture": "arm64",
            },
        },
    )


def test_live_probe_ingestion_creates_reconciled_finding(db_session) -> None:
    repo = CyberStateRepository(db_session)
    pipeline = LivePipelineService(_settings())

    first = pipeline.ingest_probe_observation(
        repo,
        _observation(datetime(2026, 9, 13, 20, 0, tzinfo=UTC), _service_items()),
    )
    second = pipeline.ingest_probe_observation(
        repo,
        _observation(
            datetime(2026, 9, 13, 20, 5, tzinfo=UTC),
            _service_items(
                [
                    {
                        "service_name": "SystemUpdate",
                        "display_name": "System Update Helper",
                        "status": "running",
                        "start_mode": "auto",
                        "binary_path": "C:\\ProgramData\\SystemUpdate\\systemupdate.exe",
                        "account": "LocalSystem",
                    },
                ],
            ),
        ),
    )

    assert first.deltas == []
    host = repo.get_host("win-lab-01")
    assert host is not None
    assert host.hostname == "win11-arm-lab"
    assert host.os == "Windows 11"
    assert len(second.deltas) == 1
    assert len(second.findings) == 1
    assert len(second.incidents) == 1
    assert second.incidents[0].finding_ids == [second.findings[0].finding_id]
    assert second.findings[0].reconciliation.status == ReconciliationStatus.PENDING_EVIDENCE
    assert (
        second.findings[0].reconciliation.metadata["reconciliation_semantics"]
        == "INCONCLUSIVE"
    )
    assert repo.list_deltas_without_findings() == []


def test_late_probe_category_sample_cannot_resurrect_removed_service(db_session) -> None:
    repo = CyberStateRepository(db_session)
    pipeline = LivePipelineService(_settings())
    start = datetime(2026, 9, 13, 20, 0, tzinfo=UTC)
    service = {
        "service_name": "CSGResearchStaleSample",
        "start_mode": "auto",
        "binary_path": "C:\\Windows\\System32\\cmd.exe /c exit 0",
    }

    pipeline.ingest_probe_observation(repo, _observation(start, _service_items([service])))
    removed_at = start.replace(minute=5)
    removed = pipeline.ingest_probe_observation(
        repo,
        _observation(removed_at, _service_items(), service_observed_at=removed_at),
    )
    late = pipeline.ingest_probe_observation(
        repo,
        _observation(
            start.replace(minute=6),
            _service_items([service]),
            service_observed_at=start.replace(minute=4),
        ),
    )

    assert [delta.delta_type.value for delta in removed.deltas] == ["REMOVE"]
    assert late.deltas == []
    latest = repo.latest_snapshot_by_source("win-lab-01", "direct_probe")
    assert latest is not None
    assert "service:csgresearchstalesample" not in {
        item.object_key for item in latest.objects
    }
    assert latest.metadata["stale_category_observations_retained"] == ["service"]


def test_newer_category_sample_emits_delta_when_probe_envelopes_arrive_out_of_order(
    db_session,
) -> None:
    repo = CyberStateRepository(db_session)
    pipeline = LivePipelineService(_settings())
    start = datetime(2026, 9, 13, 20, 0, tzinfo=UTC)
    service = {
        "service_name": "CSGResearchOutOfOrderSample",
        "start_mode": "auto",
        "binary_path": "C:\\Windows\\System32\\cmd.exe /c exit 0",
    }

    def observation(
        envelope_at: datetime,
        service_items: list[dict],
        service_at: datetime,
        process_at: datetime,
    ) -> ProbeObservation:
        return ProbeObservation(
            host_id="win-lab-01",
            observed_at=envelope_at,
            source="direct_probe",
            categories={
                "service": CollectorObservation(
                    category="service",
                    status="healthy",
                    observed_at=service_at,
                    items=service_items,
                ),
                "process": CollectorObservation(
                    category="process",
                    status="healthy",
                    observed_at=process_at,
                    items=[],
                ),
            },
            metadata={
                "host": {
                    "hostname": "win11-arm-lab",
                    "role": "windows-target",
                    "os": "Windows 11",
                    "architecture": "arm64",
                },
            },
        )

    pipeline.ingest_probe_observation(
        repo,
        observation(start, _service_items(), start, start),
    )
    pipeline.ingest_probe_observation(
        repo,
        observation(
            start.replace(minute=4),
            _service_items(),
            start.replace(minute=5),
            start.replace(minute=7),
        ),
    )
    result = pipeline.ingest_probe_observation(
        repo,
        observation(
            start.replace(minute=4),
            _service_items([service]),
            start.replace(minute=6),
            start.replace(minute=6),
        ),
    )

    assert [delta.delta_type.value for delta in result.deltas] == ["ADD"]
    assert result.deltas[0].object_key == "service:csgresearchoutofordersample"
    latest = repo.latest_snapshot_by_source("win-lab-01", "direct_probe")
    assert latest is not None
    assert "service:csgresearchoutofordersample" in {
        item.object_key for item in latest.objects
    }

    removed = pipeline.ingest_probe_observation(
        repo,
        observation(
            start.replace(minute=8),
            _service_items(),
            start.replace(minute=8),
            start.replace(minute=8),
        ),
    )
    assert [delta.delta_type.value for delta in removed.deltas] == ["REMOVE"]
    latest = repo.latest_snapshot_by_source("win-lab-01", "direct_probe")
    assert latest is not None
    assert "service:csgresearchoutofordersample" not in {
        item.object_key for item in latest.objects
    }


def test_live_pipeline_backlog_is_idempotent(db_session) -> None:
    repo = CyberStateRepository(db_session)
    pipeline = LivePipelineService(_settings())
    pipeline.ingest_probe_observation(
        repo,
        _observation(datetime(2026, 9, 13, 20, 0, tzinfo=UTC), _service_items()),
    )
    created = pipeline.ingest_probe_observation(
        repo,
        _observation(
            datetime(2026, 9, 13, 20, 5, tzinfo=UTC),
            _service_items([{"service_name": "SystemUpdate", "status": "running"}]),
        ),
    )
    rerun = pipeline.process_deltas(repo, created.deltas)

    assert len(repo.list_findings(host_id="win-lab-01")) == 1
    assert rerun.skipped_existing_findings == 1


def test_same_transition_replayed_from_same_prior_snapshot_has_one_delta(db_session) -> None:
    repo = CyberStateRepository(db_session)
    pipeline = LivePipelineService(_settings())
    before = _observation(datetime(2026, 9, 13, 20, 0, tzinfo=UTC), _service_items())
    after = _observation(
        datetime(2026, 9, 13, 20, 5, tzinfo=UTC),
        _service_items([{"service_name": "SystemUpdate", "start_mode": "manual"}]),
    )
    before_snapshot = pipeline.builder.build_from_probe_observation(before)
    after_snapshot = pipeline.builder.build_from_probe_observation(after)
    original = DeltaEngine().diff(before_snapshot, after_snapshot)[0]
    replayed_snapshot = after_snapshot.model_copy(update={"snapshot_id": "new-poll-snapshot"})
    replayed_delta = DeltaEngine().diff(before_snapshot, replayed_snapshot)[0]
    next_transition = DeltaEngine().diff(
        before_snapshot.model_copy(update={"snapshot_id": "later-baseline-snapshot"}),
        replayed_snapshot,
    )[0]
    assert replayed_delta.delta_id == original.delta_id
    assert next_transition.delta_id != original.delta_id
    replay = original.model_copy(
        update={
            "created_at": datetime(2026, 9, 13, 20, 5, 1, tzinfo=UTC),
            "metadata": {**original.metadata, "current_snapshot_id": "replayed-snapshot"},
        }
    )

    stored = repo.create_deltas([original, replay])
    records = db_session.query(orm.StateDeltaRecord).filter_by(object_key=original.object_key).all()

    assert len(stored) == 1
    assert len(records) == 1
    assert stored[0].delta_id == original.delta_id
    assert stored[0].created_at == original.created_at


def test_host_source_ingestion_lock_serializes_local_threads() -> None:
    url = SimpleNamespace(render_as_string=lambda hide_password=True: "sqlite://")
    bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"), url=url)
    repos = [CyberStateRepository(SimpleNamespace(get_bind=lambda: bind)) for _ in range(2)]
    rendezvous = threading.Barrier(2)
    guard = threading.Lock()
    active = 0
    maximum_active = 0

    def ingest(repo: CyberStateRepository) -> None:
        nonlocal active, maximum_active
        rendezvous.wait()
        with repo.host_source_ingestion_lock("win-lab-01", "direct_probe"):
            with guard:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.02)
            with guard:
                active -= 1

    threads = [threading.Thread(target=ingest, args=(repo,)) for repo in repos]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert all(not thread.is_alive() for thread in threads)
    assert maximum_active == 1


def test_postgres_host_source_lock_is_released_after_failure() -> None:
    calls: list[tuple[str, dict]] = []

    class Result:
        def scalar_one(self) -> bool:
            return True

    class Connection:
        def execute(self, statement, parameters):
            calls.append((str(statement), parameters))
            return Result()

        def commit(self) -> None:
            pass

        def close(self) -> None:
            pass

        def invalidate(self) -> None:
            pytest.fail("lock connection should remain healthy")

    connection = Connection()
    url = SimpleNamespace(render_as_string=lambda hide_password=True: "postgresql://db/csg")
    bind = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        url=url,
        connect=lambda: connection,
    )
    repo = CyberStateRepository(SimpleNamespace(get_bind=lambda: bind))

    with (
        pytest.raises(RuntimeError, match="expected test error"),
        repo.host_source_ingestion_lock("win-lab-01", "direct_probe"),
    ):
        raise RuntimeError("expected test error")

    assert [sql for sql, _ in calls] == [
        "SELECT pg_advisory_lock(:lock_id)",
        "SELECT pg_advisory_unlock(:lock_id)",
    ]
    assert calls[0][1] == calls[1][1]


def test_repeated_finding_for_delta_returns_existing_finding(db_session) -> None:
    repo = CyberStateRepository(db_session)
    pipeline = LivePipelineService(_settings())
    pipeline.ingest_probe_observation(
        repo,
        _observation(datetime(2026, 9, 13, 20, 0, tzinfo=UTC), _service_items()),
    )
    result = pipeline.ingest_probe_observation(
        repo,
        _observation(
            datetime(2026, 9, 13, 20, 5, tzinfo=UTC),
            _service_items([{"service_name": "SystemUpdate", "start_mode": "manual"}]),
        ),
    )
    finding = result.findings[0]

    replay = repo.create_finding(finding.model_copy(update={"finding_id": "duplicate-id"}))

    assert replay.finding_id == finding.finding_id
    assert len(repo.list_findings(host_id="win-lab-01")) == 1


def test_live_pipeline_keeps_process_deltas_out_of_findings_by_default(db_session) -> None:
    repo = CyberStateRepository(db_session)
    pipeline = LivePipelineService(_settings())
    pipeline.ingest_probe_observation(
        repo,
        _process_observation(
            datetime(2026, 9, 13, 20, 0, tzinfo=UTC),
            [
                {
                    "name": "explorer.exe",
                    "executable_path": "C:\\Windows\\explorer.exe",
                    "username": "lab\\user",
                    "create_time": "2026-09-13T19:59:00Z",
                },
            ],
        ),
    )
    changed = pipeline.ingest_probe_observation(
        repo,
        _process_observation(
            datetime(2026, 9, 13, 20, 5, tzinfo=UTC),
            [
                {
                    "name": "explorer.exe",
                    "executable_path": "C:\\Windows\\explorer.exe",
                    "username": "lab\\user",
                    "create_time": "2026-09-13T19:59:00Z",
                },
                {
                    "name": "probe.exe",
                    "executable_path": "C:\\Tools\\probe.exe",
                    "username": "lab\\user",
                    "create_time": "2026-09-13T20:04:59Z",
                },
            ],
        ),
    )

    assert len(changed.deltas) == 1
    assert changed.findings == []
    assert changed.skipped_ignored_categories == 1
    assert repo.list_deltas_without_findings(categories={"service"}) == []
    assert pipeline.process_backlog(repo).deltas == []
