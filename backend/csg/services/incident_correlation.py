from __future__ import annotations

from datetime import timedelta
from typing import Any

from csg.config import Settings
from csg.db.repositories import CyberStateRepository
from csg.domain.enums import IncidentStatus, Severity
from csg.domain.models import Finding, Incident, IncidentFindingAssignment, utc_now

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class IncidentCorrelationService:
    """Deterministically groups findings without allowing AI to influence assignment."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def assign_finding(
        self,
        repo: CyberStateRepository,
        finding: Finding,
    ) -> Incident:
        existing = repo.get_incident_for_finding(finding.finding_id)
        if existing is not None:
            return existing

        entity_keys = finding_entity_keys(repo, finding)
        evidence_ids = set(finding.reconciliation.matched_evidence_ids)
        active_after = finding.created_at - timedelta(
            seconds=self.settings.incident_correlation_window_seconds
        )
        candidates = [
            incident
            for incident in repo.list_incidents(
                host_id=finding.host_id,
                active_after=active_after,
                limit=100,
            )
            if incident.status in {IncidentStatus.OPEN, IncidentStatus.INVESTIGATING}
        ]

        scored = [
            (
                *self._score_candidate(incident, finding, entity_keys, evidence_ids),
                incident,
            )
            for incident in candidates
        ]
        eligible = [
            item for item in scored if item[0] >= self.settings.incident_correlation_min_score
        ]
        if not eligible:
            return self._create_incident(repo, finding, entity_keys, evidence_ids)

        score, reasons, incident = max(
            eligible,
            key=lambda item: (item[0], item[2].last_activity_at, item[2].incident_id),
        )
        return self._extend_incident(
            repo,
            incident,
            finding,
            entity_keys,
            evidence_ids,
            score,
            reasons,
        )

    def correlate_backlog(
        self,
        repo: CyberStateRepository,
        limit: int = 100,
    ) -> list[Incident]:
        return [
            self.assign_finding(repo, finding)
            for finding in repo.list_unassigned_findings(limit=limit)
        ]

    def _score_candidate(
        self,
        incident: Incident,
        finding: Finding,
        entity_keys: set[str],
        evidence_ids: set[str],
    ) -> tuple[int, list[str]]:
        gap_seconds = abs((finding.created_at - incident.last_activity_at).total_seconds())
        if gap_seconds > self.settings.incident_correlation_window_seconds:
            return 0, ["outside correlation window"]

        score = 0
        reasons: list[str] = []
        if gap_seconds <= self.settings.incident_temporal_only_window_seconds:
            score += 25
            reasons.append(f"same host within {int(gap_seconds)} seconds")
        else:
            score += 10
            reasons.append(f"same host within correlation window ({int(gap_seconds)} seconds)")

        if finding.object_key and finding.object_key in incident.object_keys:
            score += 50
            reasons.append(f"same object {finding.object_key}")

        if finding.category in incident.categories:
            score += 10
            reasons.append(f"same category {finding.category}")

        shared_entities = sorted(entity_keys.intersection(incident.entity_keys))
        if shared_entities:
            points = min(45, len(shared_entities) * 15)
            score += points
            reasons.append(f"shared entities: {', '.join(shared_entities[:5])}")

        incident_evidence = set(incident.metadata.get("evidence_ids", []))
        shared_evidence = sorted(evidence_ids.intersection(incident_evidence))
        if shared_evidence:
            score += 40
            reasons.append(f"shared evidence: {', '.join(shared_evidence[:5])}")

        return score, reasons

    def _create_incident(
        self,
        repo: CyberStateRepository,
        finding: Finding,
        entity_keys: set[str],
        evidence_ids: set[str],
    ) -> Incident:
        now = utc_now()
        incident = Incident(
            host_id=finding.host_id,
            title=f"{finding.category.replace('_', ' ').title()} change on {finding.host_id}",
            severity=finding.risk.severity,
            risk_score=finding.risk.total,
            started_at=finding.created_at,
            last_activity_at=finding.created_at,
            categories=[finding.category],
            object_keys=[finding.object_key] if finding.object_key else [],
            entity_keys=sorted(entity_keys)[:200],
            created_at=now,
            updated_at=now,
            metadata={
                "correlation_version": "csg-incident-correlation-v2",
                "evidence_ids": sorted(evidence_ids),
                **{
                    key: finding.metadata[key]
                    for key in ("experiment_id", "trial_id")
                    if finding.metadata.get(key)
                },
            },
        )
        saved = repo.save_incident(incident)
        repo.attach_finding_to_incident(
            IncidentFindingAssignment(
                incident_id=saved.incident_id,
                finding_id=finding.finding_id,
                assignment_score=100,
                assignment_reasons=["root finding created incident"],
            )
        )
        refreshed = repo.get_incident(saved.incident_id)
        if refreshed is None:  # pragma: no cover - persistence invariant
            raise RuntimeError("incident disappeared after creation")
        return refreshed

    def _extend_incident(
        self,
        repo: CyberStateRepository,
        incident: Incident,
        finding: Finding,
        entity_keys: set[str],
        evidence_ids: set[str],
        score: int,
        reasons: list[str],
    ) -> Incident:
        categories = sorted(set(incident.categories) | {finding.category})
        object_keys = set(incident.object_keys)
        if finding.object_key:
            object_keys.add(finding.object_key)
        severity = max(
            (incident.severity, finding.risk.severity),
            key=lambda value: _SEVERITY_RANK[value],
        )
        metadata = dict(incident.metadata)
        for key in ("experiment_id", "trial_id"):
            if finding.metadata.get(key):
                metadata[key] = finding.metadata[key]
        metadata["evidence_ids"] = sorted(set(metadata.get("evidence_ids", [])) | evidence_ids)[
            :500
        ]
        history = list(metadata.get("assignment_history", []))
        history.append(
            {
                "finding_id": finding.finding_id,
                "score": score,
                "reasons": reasons,
                "assigned_at": utc_now().isoformat(),
            }
        )
        metadata["assignment_history"] = history[-100:]

        updated = incident.model_copy(
            update={
                "title": self._updated_title(incident.host_id, categories),
                "severity": severity,
                "risk_score": max(incident.risk_score, finding.risk.total),
                "started_at": min(incident.started_at, finding.created_at),
                "last_activity_at": max(incident.last_activity_at, finding.created_at),
                "context_version": incident.context_version + 1,
                "categories": categories,
                "object_keys": sorted(object_keys),
                "entity_keys": sorted(set(incident.entity_keys) | entity_keys)[:200],
                "updated_at": utc_now(),
                "metadata": metadata,
            }
        )
        repo.save_incident(updated)
        repo.attach_finding_to_incident(
            IncidentFindingAssignment(
                incident_id=incident.incident_id,
                finding_id=finding.finding_id,
                assignment_score=score,
                assignment_reasons=reasons,
            )
        )
        refreshed = repo.get_incident(incident.incident_id)
        if refreshed is None:  # pragma: no cover - persistence invariant
            raise RuntimeError("incident disappeared after update")
        return refreshed

    @staticmethod
    def _updated_title(host_id: str, categories: list[str]) -> str:
        labels = ", ".join(category.replace("_", " ") for category in categories[:3])
        return f"Correlated {labels} changes on {host_id}"


def finding_entity_keys(repo: CyberStateRepository, finding: Finding) -> set[str]:
    entities: set[str] = set()
    if finding.object_key:
        entities.add(f"object:{finding.object_key.lower()}")

    delta = repo.get_delta(finding.delta_id) if finding.delta_id else None
    if delta:
        entities.add(f"object:{delta.object_key.lower()}")
        for state_object in (delta.before, delta.after):
            if state_object:
                entities.update(_mapping_entity_keys(state_object.attributes))

    window = finding.reconciliation.observation_window
    events = repo.get_events(finding.host_id, window.start, window.end)
    matched_ids = set(finding.reconciliation.matched_evidence_ids)
    for event in events:
        if event.event_id in matched_ids or event.target.get("key") == finding.object_key:
            entities.update(_mapping_entity_keys(event.actor))
            entities.update(_mapping_entity_keys(event.target))
            entities.update(_mapping_entity_keys(event.attributes))
    return entities


def _mapping_entity_keys(mapping: dict[str, Any]) -> set[str]:
    entities: set[str] = set()
    for key, value in mapping.items():
        if value is None or isinstance(value, (dict, list)):
            continue
        normalized = str(value).strip().lower()
        if not normalized:
            continue
        field = key.lower()
        prefix = None
        if "user" in field or "account" in field:
            if normalized.replace("\\", "/") in {
                "system",
                "localsystem",
                "nt authority/system",
                "s-1-5-18",
                "localservice",
                "networkservice",
                "nt authority/local service",
                "nt authority/network service",
                "s-1-5-19",
                "s-1-5-20",
            }:
                continue
            prefix = "account"
        elif "pid" in field or "process_id" in field:
            prefix = "pid"
        elif any(token in field for token in ("process", "image", "executable", "binary")):
            prefix = "process"
        elif "ip" in field or "address" in field or "destination" in field:
            prefix = "network"
        elif "port" in field:
            prefix = "port"
        elif any(token in field for token in ("service", "task", "registry", "object", "key")):
            prefix = "object"
        if prefix:
            entities.add(f"{prefix}:{normalized[:256]}")
    return entities
