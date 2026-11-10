from __future__ import annotations

from csg.domain.enums import AIContextMode
from csg.domain.models import (
    EvidenceItem,
    EvidencePackage,
    Finding,
    Host,
    Incident,
    NormalizedEvent,
    StateDelta,
    TransientObservation,
)
from csg.services.attack_mapping import attack_context_for


def evidence_from_events(events: list[NormalizedEvent]) -> list[EvidenceItem]:
    return [
        EvidenceItem(
            evidence_id=event.event_id,
            host_id=event.host_id,
            evidence_type=event.normalized_type,
            timestamp=event.event_time,
            content={
                "actor": event.actor,
                "target": event.target,
                "attributes": event.attributes,
                "synthetic": event.synthetic,
            },
            source_reference=event.source_reference,
            metadata={
                "source": event.source,
                "scenario_id": event.scenario_id,
                **{
                    key: event.metadata[key]
                    for key in ("experiment_id", "trial_id")
                    if event.metadata.get(key)
                },
            },
        )
        for event in events
    ]


def build_evidence_package(
    host: Host,
    finding: Finding,
    state_delta: StateDelta | None,
    transient_observation: TransientObservation | None,
    evidence: list[EvidenceItem],
    related_deltas: list[StateDelta] | None = None,
    related_findings: list[Finding] | None = None,
    incident_context: dict | None = None,
    incident: Incident | None = None,
    context_mode: AIContextMode = AIContextMode.FULL_CONTEXT,
    interpretive_memory: dict | None = None,
) -> EvidencePackage:
    attack_context = attack_context_for(finding, state_delta)

    return EvidencePackage(
        finding_id=finding.finding_id,
        incident_id=incident.incident_id if incident else None,
        context_mode=context_mode,
        context_version=incident.context_version if incident else 1,
        host=host,
        finding=finding,
        incident=incident,
        state_delta=state_delta,
        transient_observation=transient_observation,
        evidence=evidence,
        related_deltas=related_deltas or [],
        related_findings=related_findings or [],
        source_quality=state_delta.source_quality if state_delta else {},
        attack_context=attack_context,
        incident_context=incident_context or {},
        interpretive_memory=interpretive_memory,
        experiment_id=(state_delta.metadata.get("experiment_id") if state_delta else None)
        or finding.metadata.get("experiment_id"),
        trial_id=(state_delta.metadata.get("trial_id") if state_delta else None)
        or finding.metadata.get("trial_id"),
    )
