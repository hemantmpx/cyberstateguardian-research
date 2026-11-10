from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from csg.config import Settings
from csg.db.repositories import CyberStateRepository
from csg.domain.enums import ObservationKind
from csg.domain.models import (
    EventObservationResult,
    Finding,
    Host,
    Incident,
    ProbeObservation,
    StateDelta,
    StateSnapshot,
    utc_now,
)
from csg.services.authorization import AuthorizationService
from csg.services.evidence import evidence_from_events
from csg.services.incident_correlation import IncidentCorrelationService
from csg.services.reconciliation import ReconciliationEngine, ReconciliationLifecycle
from csg.services.reconciliation_lifecycle import ReconciliationLifecycleService
from csg.services.risk import RiskEngine
from csg.state.builder import StateBuilder
from csg.state.diff import DeltaEngine


def _events_complete(
    events: list[Any],
    observation: EventObservationResult | None = None,
) -> bool:
    if observation is not None:
        return observation.query_complete and observation.coverage_status == "COMPLETE"
    completion = [
        event.metadata.get("retrieval", {}).get("complete")
        for event in events
        if isinstance(event.metadata, dict)
        and isinstance(event.metadata.get("retrieval"), dict)
    ]
    return bool(completion) and all(value is True for value in completion)


class LivePipelineResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observation_id: str | None = None
    snapshot_id: str | None = None
    deltas: list[StateDelta] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    incidents: list[Incident] = Field(default_factory=list)
    skipped_existing_findings: int = 0
    skipped_ignored_categories: int = 0
    reconciliation_updates: int = 0


class LivePipelineService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.builder = StateBuilder()
        self.delta_engine = DeltaEngine()
        self.reconciliation = ReconciliationEngine(
            settings.observation_window_seconds,
            settings.event_time_tolerance_seconds,
        )
        self.reconciliation_lifecycle = ReconciliationLifecycle(
            self.reconciliation,
            grace_seconds=settings.reconciliation_grace_seconds,
        )
        self.reconciliation_updates = ReconciliationLifecycleService(settings)
        self.authorization = AuthorizationService(
            settings.resolve_path(settings.authorized_state_path),
        )
        self.risk = RiskEngine(settings.resolve_path(settings.risk_rules_path))
        self.incident_correlation = IncidentCorrelationService(settings)

    def ingest_probe_observation(
        self,
        repo: CyberStateRepository,
        observation: ProbeObservation,
    ) -> LivePipelineResult:
        deltas: list[StateDelta] = []
        with repo.host_source_ingestion_lock(observation.host_id, observation.source):
            self._upsert_observed_host(repo, observation)
            previous = repo.latest_snapshot_by_source(
                observation.host_id, observation.source
            )
            repo.create_source_observation(observation)
            snapshot = self.builder.build_from_probe_observation(observation)
            if previous is not None:
                snapshot = self.builder.retain_newer_category_observations(previous, snapshot)
            repo.create_snapshot(snapshot)
            if previous is not None:
                deltas = repo.create_deltas(self.delta_engine.diff(previous, snapshot))

        findings: list[Finding] = []
        skipped_existing = 0
        skipped_ignored = 0
        incidents: list[Incident] = []
        if self.settings.pipeline_on_ingest and deltas:
            processed = self.process_deltas(repo, deltas)
            findings = processed.findings
            incidents = processed.incidents
            skipped_existing = processed.skipped_existing_findings
            skipped_ignored = processed.skipped_ignored_categories

        return LivePipelineResult(
            observation_id=observation.observation_id,
            snapshot_id=snapshot.snapshot_id,
            deltas=deltas,
            findings=findings,
            incidents=incidents,
            skipped_existing_findings=skipped_existing,
            skipped_ignored_categories=skipped_ignored,
        )

    def ingest_state_snapshot(
        self,
        repo: CyberStateRepository,
        snapshot: StateSnapshot,
        event_observation: EventObservationResult | None = None,
    ) -> LivePipelineResult:
        deltas: list[StateDelta] = []
        with repo.host_source_ingestion_lock(snapshot.host_id, snapshot.source):
            self._upsert_snapshot_host(repo, snapshot)
            previous = repo.latest_snapshot_by_source(snapshot.host_id, snapshot.source)
            repo.create_snapshot(snapshot)
            if previous is not None and snapshot.built_at > previous.built_at:
                deltas = repo.create_deltas(self.delta_engine.diff(previous, snapshot))

        findings: list[Finding] = []
        skipped_existing = 0
        skipped_ignored = 0
        incidents: list[Incident] = []
        if self.settings.pipeline_on_ingest and deltas:
            processed = self.process_deltas(
                repo,
                deltas,
                event_observation=event_observation,
            )
            findings = processed.findings
            incidents = processed.incidents
            skipped_existing = processed.skipped_existing_findings
            skipped_ignored = processed.skipped_ignored_categories

        return LivePipelineResult(
            snapshot_id=snapshot.snapshot_id,
            deltas=deltas,
            findings=findings,
            incidents=incidents,
            skipped_existing_findings=skipped_existing,
            skipped_ignored_categories=skipped_ignored,
        )

    def process_backlog(
        self,
        repo: CyberStateRepository,
        limit: int | None = None,
        event_observation: EventObservationResult | None = None,
    ) -> LivePipelineResult:
        deltas = repo.list_deltas_without_findings(
            limit or self.settings.worker_batch_size,
            categories=self.settings.live_finding_category_set,
        )
        processed = self.process_deltas(
            repo,
            deltas,
            event_observation=event_observation,
        )
        backfilled = self.incident_correlation.correlate_backlog(
            repo,
            limit=limit or self.settings.worker_batch_size,
        )
        known = {incident.incident_id: incident for incident in processed.incidents}
        known.update({incident.incident_id: incident for incident in backfilled})
        updates = self.reconciliation_updates.reevaluate_pending(
            repo,
            event_observation=event_observation,
        )
        return processed.model_copy(
            update={
                "incidents": list(known.values()),
                "reconciliation_updates": len(updates.updated_findings),
            }
        )

    def process_deltas(
        self,
        repo: CyberStateRepository,
        deltas: list[StateDelta],
        event_observation: EventObservationResult | None = None,
    ) -> LivePipelineResult:
        findings: list[Finding] = []
        skipped = 0
        ignored = 0
        incidents_by_id: dict[str, Incident] = {}
        for delta in deltas:
            if delta.category not in self.settings.live_finding_category_set:
                ignored += 1
                continue
            if repo.get_finding_by_delta_id(delta.delta_id) is not None:
                skipped += 1
                continue

            window = self.reconciliation.observation_window_for_delta(delta)
            events = repo.get_events(delta.host_id, window.start, window.end)
            evidence = evidence_from_events(events)
            if evidence:
                repo.create_evidence(evidence)

            reconciliation = self.reconciliation_lifecycle.evaluate(
                delta,
                events,
                now=utc_now(),
                evidence_complete=_events_complete(events, event_observation),
                event_observation=event_observation,
            )
            authorization = self.authorization.evaluate_delta(delta)
            risk = self.risk.score_delta(delta, reconciliation, authorization.status)

            finding = Finding(
                host_id=delta.host_id,
                observation_kind=ObservationKind.STATE_DELTA,
                delta_id=delta.delta_id,
                category=delta.category,
                object_key=delta.object_key,
                reconciliation=reconciliation,
                authorization_status=authorization.status,
                authorization_reason=authorization.reason,
                risk=risk,
                created_at=delta.created_at,
                metadata={
                    "pipeline": "live",
                    "matched_authorization_rule": authorization.matched_rule,
                    **{
                        key: delta.metadata[key]
                        for key in ("experiment_id", "trial_id")
                        if delta.metadata.get(key)
                    },
                },
            )
            reconciliation = reconciliation.model_copy(update={"finding_id": finding.finding_id})
            finding = finding.model_copy(update={"reconciliation": reconciliation})
            repo.create_reconciliation(reconciliation)
            saved_finding = repo.create_finding(finding)
            if saved_finding.finding_id != finding.finding_id:
                skipped += 1
                continue
            findings.append(saved_finding)
            incident = self.incident_correlation.assign_finding(repo, saved_finding)
            incidents_by_id[incident.incident_id] = incident

        return LivePipelineResult(
            deltas=deltas,
            findings=findings,
            incidents=list(incidents_by_id.values()),
            skipped_existing_findings=skipped,
            skipped_ignored_categories=ignored,
        )
    def _upsert_observed_host(
        self,
        repo: CyberStateRepository,
        observation: ProbeObservation,
    ) -> None:
        existing = repo.get_host(observation.host_id)
        host_metadata = observation.metadata.get("host")
        host_metadata = host_metadata if isinstance(host_metadata, dict) else {}

        if existing is None or host_metadata:
            repo.upsert_host(
                Host(
                    host_id=observation.host_id,
                    hostname=self._metadata_text(
                        host_metadata,
                        "hostname",
                        fallback=existing.hostname if existing else observation.host_id,
                    ),
                    role=self._metadata_text(
                        host_metadata,
                        "role",
                        fallback=existing.role if existing else "observed-endpoint",
                    ),
                    os=self._metadata_text(
                        host_metadata,
                        "os",
                        "platform",
                        "system",
                        fallback=existing.os if existing else "unknown",
                    ),
                    architecture=self._metadata_text(
                        host_metadata,
                        "architecture",
                        "machine",
                        fallback=existing.architecture if existing else "unknown",
                    ),
                    enabled=existing.enabled if existing else True,
                    created_at=existing.created_at if existing else observation.observed_at,
                    updated_at=observation.observed_at,
                ),
            )

    def _upsert_snapshot_host(
        self,
        repo: CyberStateRepository,
        snapshot: StateSnapshot,
    ) -> None:
        existing = repo.get_host(snapshot.host_id)
        host_metadata = snapshot.metadata.get("host")
        host_metadata = host_metadata if isinstance(host_metadata, dict) else {}

        if existing is None or host_metadata:
            repo.upsert_host(
                Host(
                    host_id=snapshot.host_id,
                    hostname=self._metadata_text(
                        host_metadata,
                        "hostname",
                        "name",
                        fallback=existing.hostname if existing else snapshot.host_id,
                    ),
                    role=self._metadata_text(
                        host_metadata,
                        "role",
                        fallback=existing.role if existing else "observed-endpoint",
                    ),
                    os=self._metadata_text(
                        host_metadata,
                        "os",
                        "platform",
                        "system",
                        fallback=existing.os if existing else "unknown",
                    ),
                    architecture=self._metadata_text(
                        host_metadata,
                        "architecture",
                        "machine",
                        fallback=existing.architecture if existing else "unknown",
                    ),
                    enabled=existing.enabled if existing else True,
                    created_at=existing.created_at if existing else snapshot.built_at,
                    updated_at=snapshot.built_at,
                ),
            )

    @staticmethod
    def _metadata_text(
        metadata: dict[str, Any],
        *keys: str,
        fallback: str,
    ) -> str:
        for key in keys:
            value = metadata.get(key)
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return fallback
