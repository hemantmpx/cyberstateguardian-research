from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from csg.config import Settings
from csg.db.repositories import CyberStateRepository
from csg.domain.models import (
    EventObservationResult,
    Finding,
    NormalizedEvent,
    ReconciliationResult,
    ensure_utc,
    utc_now,
)
from csg.services.evidence import evidence_from_events
from csg.services.incident_correlation import finding_entity_keys
from csg.services.reconciliation import (
    ReconciliationEngine,
    ReconciliationLifecycle,
    source_health_attribution_for_window,
)
from csg.services.risk import RiskEngine


def _events_complete(
    events: list[NormalizedEvent],
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


@dataclass(frozen=True)
class ReconciliationUpdateResult:
    updated_findings: list[Finding] = field(default_factory=list)
    reconciliations: list[ReconciliationResult] = field(default_factory=list)
    unchanged_count: int = 0


class ReconciliationLifecycleService:
    """Re-runs provisional reconciliation as events arrive or windows expire."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        engine = ReconciliationEngine(
            settings.observation_window_seconds,
            settings.event_time_tolerance_seconds,
        )
        self.lifecycle = ReconciliationLifecycle(
            engine,
            grace_seconds=settings.reconciliation_grace_seconds,
        )
        self.risk = RiskEngine(settings.resolve_path(settings.risk_rules_path))

    def reevaluate_pending(
        self,
        repo: CyberStateRepository,
        *,
        host_id: str | None = None,
        now: datetime | None = None,
        limit: int | None = None,
        events: list[NormalizedEvent] | None = None,
        event_observation: EventObservationResult | None = None,
    ) -> ReconciliationUpdateResult:
        checked_at = ensure_utc(now or utc_now())
        updated: list[Finding] = []
        reconciliations: list[ReconciliationResult] = []
        unchanged = 0
        candidates = repo.list_pending_reconciliation_findings(host_id=host_id, limit=limit)
        by_id = {
            finding.finding_id: finding
            for finding in candidates
            if self._observation_applies(finding, event_observation)
        }
        by_id.update(
            {
                finding.finding_id: finding
                for finding in repo.findings_overlapping_events(events or [])
                if self._observation_applies(finding, event_observation)
            }
        )
        affected_objects = (
            event_observation.metadata.get("affected_object_keys")
            if event_observation is not None
            else None
        )
        if isinstance(affected_objects, list) and affected_objects:
            object_keys = {str(key).casefold() for key in affected_objects}
            by_id.update(
                {
                    finding.finding_id: finding
                    for finding in repo.list_findings(host_id=host_id, limit=limit or 500)
                    if finding.object_key.casefold() in object_keys
                    and self._observation_applies(finding, event_observation)
                }
            )
        elif self._source_is_degraded(event_observation):
            by_id.update(
                {
                    finding.finding_id: finding
                    for finding in repo.list_findings(host_id=host_id, limit=limit or 500)
                    if finding.delta_id and self._observation_applies(finding, event_observation)
                }
            )
        for finding in by_id.values():
            if not finding.delta_id:
                unchanged += 1
                continue
            delta = repo.get_delta(finding.delta_id)
            if delta is None:
                unchanged += 1
                continue
            window = finding.reconciliation.observation_window
            events = repo.get_events(finding.host_id, window.start, window.end)
            evidence = evidence_from_events(events)
            if evidence:
                repo.create_evidence(evidence)
            result = self.lifecycle.evaluate(
                delta,
                events,
                now=checked_at,
                previous=finding.reconciliation,
                finding_id=finding.finding_id,
                evidence_complete=_events_complete(events, event_observation),
                event_observation=event_observation,
            )
            if self._materially_unchanged(finding.reconciliation, result):
                unchanged += 1
                continue

            risk = self.risk.score_delta(delta, result, finding.authorization_status)
            metadata = dict(finding.metadata)
            history = list(metadata.get("reconciliation_history", []))
            history.append(
                {
                    "version": result.version,
                    "reconciliation_id": result.reconciliation_id,
                    "status": result.status.value,
                    "finalized": result.finalized,
                    "evaluated_at": result.created_at.isoformat(),
                }
            )
            metadata["reconciliation_history"] = history[-50:]
            saved = finding.model_copy(
                update={
                    "reconciliation": result,
                    "risk": risk,
                    "metadata": metadata,
                }
            )
            if not repo.save_reconciliation_revision(
                saved, finding.reconciliation.reconciliation_id
            ):
                unchanged += 1
                continue
            self._bump_incident_context(repo, saved)
            updated.append(saved)
            reconciliations.append(result)
        return ReconciliationUpdateResult(
            updated_findings=updated,
            reconciliations=reconciliations,
            unchanged_count=unchanged,
        )

    @staticmethod
    def _observation_applies(finding: Finding, observation: EventObservationResult | None) -> bool:
        if observation is None:
            return True
        affected_objects = observation.metadata.get("affected_object_keys")
        if (
            isinstance(affected_objects, list)
            and affected_objects
            and finding.object_key.casefold()
            not in {str(key).casefold() for key in affected_objects}
        ):
            return False
        start_value = observation.metadata.get("query_start")
        end_value = observation.metadata.get("query_end")
        if not start_value or not end_value:
            window = finding.reconciliation.observation_window
            event_in_window = any(
                event.host_id == finding.host_id
                and window.start <= event.event_time <= window.end
                for event in observation.events
            )
            health_in_window = source_health_attribution_for_window(
                window,
                finding.object_key,
                observation,
            ) != "UNKNOWN"
            return event_in_window or health_in_window
        try:
            start = ensure_utc(datetime.fromisoformat(str(start_value).replace("Z", "+00:00")))
            end = ensure_utc(datetime.fromisoformat(str(end_value).replace("Z", "+00:00")))
        except ValueError:
            return False
        window = finding.reconciliation.observation_window
        return not (start > window.end or end < window.start)

    @staticmethod
    def _source_is_degraded(observation: EventObservationResult | None) -> bool:
        return observation is not None and (
            observation.endpoint_collection_status in {"DEGRADED", "UNAVAILABLE"}
            or observation.transport_status in {"DEGRADED", "UNAVAILABLE"}
            or observation.index_status in {"DEGRADED", "UNAVAILABLE"}
        )

    @staticmethod
    def _materially_unchanged(
        previous: ReconciliationResult,
        current: ReconciliationResult,
    ) -> bool:
        return (
            previous.status == current.status
            and previous.finalized == current.finalized
            and previous.matched_evidence_ids == current.matched_evidence_ids
            and previous.missing_expected_evidence_types == current.missing_expected_evidence_types
            and previous.metadata.get("reconciliation_semantics")
            == current.metadata.get("reconciliation_semantics")
            and previous.metadata.get("source_health_known_degraded")
            == current.metadata.get("source_health_known_degraded")
        )

    @staticmethod
    def _bump_incident_context(repo: CyberStateRepository, finding: Finding) -> None:
        incident = repo.get_incident_for_finding(finding.finding_id)
        if incident is None:
            return
        metadata = dict(incident.metadata)
        metadata["last_reconciliation_update"] = {
            "finding_id": finding.finding_id,
            "version": finding.reconciliation.version,
            "status": finding.reconciliation.status.value,
        }
        members = repo.list_incident_findings(incident.incident_id)
        highest = max(members, key=lambda member: member.risk.total)
        evidence_ids = {
            eid for member in members for eid in member.reconciliation.matched_evidence_ids
        }
        entities = {entity for member in members for entity in finding_entity_keys(repo, member)}
        metadata["evidence_ids"] = sorted(evidence_ids)[:500]
        repo.save_incident(
            incident.model_copy(
                update={
                    "context_version": incident.context_version + 1,
                    "updated_at": utc_now(),
                    "risk_score": highest.risk.total,
                    "severity": highest.risk.severity,
                    "entity_keys": sorted(entities)[:200],
                    "metadata": metadata,
                }
            )
        )
