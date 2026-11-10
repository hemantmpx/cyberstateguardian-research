from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from csg.config import Settings
from csg.db.repositories import CyberStateRepository
from csg.domain.models import EventObservationResult, NormalizedEvent, StateSnapshot, utc_now
from csg.providers.factory import build_event_provider, build_state_provider
from csg.providers.wazuh import WazuhStateProvider
from csg.services.live_pipeline import LivePipelineResult, LivePipelineService
from csg.services.reconciliation_lifecycle import ReconciliationLifecycleService


@dataclass(frozen=True)
class ProviderHostSyncResult:
    host_id: str
    snapshot: StateSnapshot
    events: list[NormalizedEvent]
    pipeline: LivePipelineResult
    state_plane_source: str
    event_plane_source: str
    event_observation: EventObservationResult
    snapshot_created: bool = True
    cross_validation: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderSyncResult:
    hosts: list[ProviderHostSyncResult] = field(default_factory=list)

    @property
    def snapshot_count(self) -> int:
        return sum(host.snapshot_created for host in self.hosts)

    @property
    def event_count(self) -> int:
        return sum(len(host.events) for host in self.hosts)

    @property
    def delta_count(self) -> int:
        return sum(len(host.pipeline.deltas) for host in self.hosts)

    @property
    def finding_count(self) -> int:
        return sum(len(host.pipeline.findings) for host in self.hosts)

    def summary(self) -> dict[str, object]:
        return {
            "snapshot_count": self.snapshot_count,
            "event_count": self.event_count,
            "delta_count": self.delta_count,
            "finding_count": self.finding_count,
            "hosts": [
                {
                    "host_id": host.host_id,
                    "snapshot_id": host.snapshot.snapshot_id,
                    "snapshot_created": host.snapshot_created,
                    "event_count": len(host.events),
                    "event_observation": host.event_observation.model_dump(
                        mode="json", exclude={"events"}
                    ),
                    "delta_count": len(host.pipeline.deltas),
                    "finding_count": len(host.pipeline.findings),
                    "reconciliation_updates": host.pipeline.reconciliation_updates,
                    "state_plane_source": host.state_plane_source,
                    "event_plane_source": host.event_plane_source,
                    "cross_validation": host.cross_validation,
                    "category_statuses": [
                        status.model_dump(mode="json") for status in host.snapshot.category_statuses
                    ],
                }
                for host in self.hosts
            ],
        }


class ProviderSyncService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def sync_hosts(
        self,
        repo: CyberStateRepository,
        host_ids: list[str],
    ) -> ProviderSyncResult:
        results: list[ProviderHostSyncResult] = []
        for host_id in host_ids:
            results.append(await self.sync_host(repo, host_id))
        return ProviderSyncResult(hosts=results)

    async def sync_host(
        self,
        repo: CyberStateRepository,
        host_id: str,
    ) -> ProviderHostSyncResult:
        event_provider = build_event_provider(self.settings)
        pipeline_service = LivePipelineService(self.settings)

        if self.settings.state_provider == "probe":
            snapshot = repo.latest_snapshot_by_source(host_id, "direct_probe")
            if snapshot is None:
                raise ValueError(
                    f"no direct_probe snapshot exists for {host_id}; run the Windows probe first"
                )
        else:
            snapshot = await build_state_provider(self.settings).get_snapshot(host_id)
        now = utc_now()
        event_end = now + timedelta(minutes=5)
        event_start = now - timedelta(seconds=self.settings.wazuh_event_lookback_seconds)
        raw_events = await event_provider.get_events(host_id, event_start, event_end)
        event_observation = (
            raw_events
            if isinstance(raw_events, EventObservationResult)
            else EventObservationResult(
                events=raw_events,
                query_complete=True,
                endpoint_collection_status="AVAILABLE",
                transport_status="AVAILABLE",
                index_status="AVAILABLE",
                coverage_status="COMPLETE",
                retrieved_count=len(raw_events),
            )
        )
        event_observation.metadata.setdefault("query_start", event_start.isoformat())
        event_observation.metadata.setdefault("query_end", event_end.isoformat())
        event_observation.metadata.setdefault("source_health_checked_at", utc_now().isoformat())
        events = event_observation.events
        scope = {
            key: snapshot.metadata[key]
            for key in ("experiment_id", "trial_id")
            if snapshot.metadata.get(key)
        }
        event_observation.metadata.update(scope)
        if scope:
            event_observation.metadata["scope_semantics"] = (
                "sync_context_only_not_event_attribution"
            )
        repo.create_events(events)
        if self.settings.state_provider == "probe":
            pipeline = pipeline_service.process_backlog(
                repo,
                event_observation=event_observation,
            ).model_copy(update={"snapshot_id": snapshot.snapshot_id})
        else:
            pipeline = pipeline_service.ingest_state_snapshot(
                repo,
                snapshot,
                event_observation=event_observation,
            )
        revisions = ReconciliationLifecycleService(self.settings).reevaluate_pending(
            repo,
            host_id=host_id,
            events=events,
            event_observation=event_observation,
        )
        pipeline = pipeline.model_copy(
            update={
                "reconciliation_updates": pipeline.reconciliation_updates
                + len(revisions.updated_findings)
            }
        )
        cross_validation = await self._cross_validate(snapshot, host_id)
        return ProviderHostSyncResult(
            host_id=host_id,
            snapshot=snapshot,
            events=events,
            pipeline=pipeline,
            state_plane_source=(
                "direct_probe" if self.settings.state_provider == "probe" else snapshot.source
            ),
            event_plane_source=self.settings.event_provider,
            event_observation=event_observation,
            snapshot_created=self.settings.state_provider != "probe",
            cross_validation=cross_validation,
        )

    async def _cross_validate(
        self,
        authoritative: StateSnapshot,
        host_id: str,
    ) -> dict[str, object]:
        if (
            not self.settings.state_cross_validation_enabled
            or self.settings.state_provider != "probe"
            or self.settings.event_provider != "wazuh"
        ):
            return {"enabled": False, "authoritative": False}
        try:
            comparison = await WazuhStateProvider.from_settings(self.settings).get_snapshot(host_id)
        except Exception as exc:
            return {
                "enabled": True,
                "authoritative": False,
                "status": "unavailable",
                "source": "wazuh_inventory",
                "error": f"{type(exc).__name__}: {exc}",
            }

        categories = sorted(
            {item.category for item in authoritative.objects}
            | {item.category for item in comparison.objects}
        )
        rows: dict[str, object] = {}
        for category in categories:
            direct = {
                item.object_key for item in authoritative.objects if item.category == category
            }
            wazuh = {item.object_key for item in comparison.objects if item.category == category}
            union = direct | wazuh
            direct_status = authoritative.status_for(category)
            wazuh_status = comparison.status_for(category)
            direct_health = direct_status.status if direct_status else "unavailable"
            wazuh_health = wazuh_status.status if wazuh_status else "unavailable"
            identity_comparison = (
                "identity_schema_incompatible"
                if category in {"process", "listener"}
                else "canonical_object_key"
            )
            comparable = (
                direct_health == wazuh_health == "healthy"
                and identity_comparison == "canonical_object_key"
            )
            rows[category] = {
                "direct_probe_health": direct_health,
                "wazuh_inventory_health": wazuh_health,
                "comparable": comparable,
                "comparison_status": (identity_comparison if not comparable else "comparable"),
                "direct_probe_count": len(direct),
                "wazuh_inventory_count": len(wazuh),
                "intersection_count": len(direct & wazuh),
                "jaccard_similarity": (
                    (round(len(direct & wazuh) / len(union), 4) if union else 1.0)
                    if comparable
                    else None
                ),
                "direct_only": sorted(direct - wazuh)[:25],
                "wazuh_only": sorted(wazuh - direct)[:25],
            }
        return {
            "enabled": True,
            "authoritative": False,
            "status": "complete",
            "source": comparison.source,
            "snapshot_id": comparison.snapshot_id,
            "authoritative_snapshot_id": authoritative.snapshot_id,
            "snapshot_skew_seconds": abs(
                (comparison.built_at - authoritative.built_at).total_seconds()
            ),
            "categories": rows,
        }
