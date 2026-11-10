from __future__ import annotations

from datetime import UTC, datetime

from tests.conftest import ROOT, load_json

from csg.config import Settings
from csg.db.repositories import CyberStateRepository
from csg.domain.models import NormalizedEvent, StateSnapshot
from csg.services.provider_sync import ProviderSyncResult, ProviderSyncService


class EmptyEventProvider:
    async def get_events(self, host_id, start, end):
        del host_id, start, end
        return []


async def test_probe_wazuh_mode_keeps_direct_probe_snapshot_authoritative(
    db_session,
    monkeypatch,
) -> None:
    repo = CyberStateRepository(db_session)
    snapshot = StateSnapshot.model_validate(
        load_json(ROOT / "experiments/fixtures/state/baseline.json")
    ).model_copy(update={"source": "direct_probe"})
    repo.create_snapshot(snapshot)
    settings = Settings(
        CSG_STATE_PROVIDER="probe",
        CSG_EVENT_PROVIDER="wazuh",
        CSG_STATE_CROSS_VALIDATION_ENABLED=False,
        CSG_AUTHORIZED_STATE_PATH=ROOT / "config/authorized-state.example.yaml",
        CSG_RISK_RULES_PATH=ROOT / "config/risk-rules.yaml",
    )
    monkeypatch.setattr(
        "csg.services.provider_sync.build_event_provider",
        lambda _settings: EmptyEventProvider(),
    )

    result = await ProviderSyncService(settings).sync_host(repo, snapshot.host_id)

    assert result.snapshot.snapshot_id == snapshot.snapshot_id
    assert result.state_plane_source == "direct_probe"
    assert result.event_plane_source == "wazuh"
    assert result.cross_validation == {"enabled": False, "authoritative": False}
    assert result.snapshot_created is False
    assert ProviderSyncResult(hosts=[result]).snapshot_count == 0


async def test_provider_sync_does_not_assign_trial_scope_to_host_history(
    db_session,
    monkeypatch,
) -> None:
    repo = CyberStateRepository(db_session)
    snapshot = StateSnapshot.model_validate(
        load_json(ROOT / "experiments/fixtures/state/baseline.json")
    ).model_copy(
        update={
            "source": "direct_probe",
            "metadata": {"experiment_id": "EXP-7", "trial_id": "TRIAL-9"},
        }
    )
    repo.create_snapshot(snapshot)
    settings = Settings(
        CSG_STATE_PROVIDER="probe",
        CSG_EVENT_PROVIDER="wazuh",
        CSG_STATE_CROSS_VALIDATION_ENABLED=False,
    )
    historical_event = NormalizedEvent(
        host_id=snapshot.host_id,
        event_time=datetime(2026, 10, 3, 22, 13, tzinfo=UTC),
        normalized_type="process_start",
        source="wazuh",
        metadata={"source_kind": "wazuh_archive"},
    )

    class HistoricalEventProvider:
        async def get_events(self, host_id, start, end):
            del host_id, start, end
            return [historical_event]

    monkeypatch.setattr(
        "csg.services.provider_sync.build_event_provider",
        lambda _settings: HistoricalEventProvider(),
    )

    result = await ProviderSyncService(settings).sync_host(repo, snapshot.host_id)

    assert "experiment_id" not in result.events[0].metadata
    assert "trial_id" not in result.events[0].metadata
    assert result.event_observation.metadata["experiment_id"] == "EXP-7"
    assert result.event_observation.metadata["trial_id"] == "TRIAL-9"
    assert (
        result.event_observation.metadata["scope_semantics"]
        == "sync_context_only_not_event_attribution"
    )


async def test_provider_sync_revises_finalized_finding(db_session, monkeypatch) -> None:
    from datetime import timedelta

    from tests.unit.test_reconciliation_lifecycle import _pending_finding, _settings

    from csg.domain.enums import ReconciliationStatus
    from csg.domain.models import NormalizedEvent
    from csg.services.reconciliation_lifecycle import ReconciliationLifecycleService

    repo = CyberStateRepository(db_session)
    finding = _pending_finding(repo)
    settings = _settings().model_copy(
        update={
            "state_provider": "probe",
            "event_provider": "wazuh",
            "state_cross_validation_enabled": False,
        }
    )
    ReconciliationLifecycleService(settings).reevaluate_pending(
        repo, now=finding.reconciliation.observation_window.end + timedelta(minutes=2)
    )
    snapshot = StateSnapshot.model_validate(
        load_json(ROOT / "experiments/fixtures/state/baseline.json")
    ).model_copy(update={"source": "direct_probe"})
    repo.create_snapshot(snapshot)
    event = NormalizedEvent(
        host_id=finding.host_id,
        event_time=finding.created_at,
        normalized_type="service_created",
        target={"key": finding.object_key},
        source="wazuh",
    )

    class LateEventProvider:
        async def get_events(self, host_id, start, end):
            return [event]

    monkeypatch.setattr(
        "csg.services.provider_sync.build_event_provider", lambda _: LateEventProvider()
    )
    monkeypatch.setattr(
        "csg.services.provider_sync.utc_now",
        lambda: finding.created_at + timedelta(minutes=1),
    )
    result = await ProviderSyncService(settings).sync_host(repo, finding.host_id)
    assert result.pipeline.reconciliation_updates == 1
    assert result.event_observation.metadata["query_start"]
    assert result.event_observation.metadata["source_health_checked_at"]
    assert (
        repo.get_finding(finding.finding_id).reconciliation.status
        == ReconciliationStatus.CONSISTENT
    )


async def test_cross_validation_marks_missing_categories_noncomparable(monkeypatch) -> None:
    snapshot = StateSnapshot.model_validate(
        load_json(ROOT / "experiments/fixtures/state/baseline.json")
    )
    comparison = snapshot.model_copy(update={"objects": [], "category_statuses": []})

    class Inventory:
        async def get_snapshot(self, host_id):
            return comparison

    monkeypatch.setattr(
        "csg.services.provider_sync.WazuhStateProvider.from_settings", lambda _: Inventory()
    )
    settings = Settings(
        CSG_STATE_PROVIDER="probe",
        CSG_EVENT_PROVIDER="wazuh",
        CSG_STATE_CROSS_VALIDATION_ENABLED=True,
    )
    result = await ProviderSyncService(settings)._cross_validate(snapshot, snapshot.host_id)
    assert result["categories"]["service"]["comparable"] is False
    assert result["categories"]["service"]["jaccard_similarity"] is None


async def test_cross_validation_does_not_report_zero_similarity_for_incompatible_identity_schema(
    monkeypatch,
) -> None:
    snapshot = StateSnapshot.model_validate(
        load_json(ROOT / "experiments/fixtures/state/baseline.json")
    )
    comparison = snapshot.model_copy(update={"objects": snapshot.objects[:1]})

    class Inventory:
        async def get_snapshot(self, host_id):
            return comparison

    monkeypatch.setattr(
        "csg.services.provider_sync.WazuhStateProvider.from_settings", lambda _: Inventory()
    )
    settings = Settings(
        CSG_STATE_PROVIDER="probe",
        CSG_EVENT_PROVIDER="wazuh",
        CSG_STATE_CROSS_VALIDATION_ENABLED=True,
    )
    result = await ProviderSyncService(settings)._cross_validate(snapshot, snapshot.host_id)
    process_row = result["categories"].get("process")
    if process_row:
        assert process_row["comparison_status"] == "identity_schema_incompatible"
        assert process_row["jaccard_similarity"] is None
