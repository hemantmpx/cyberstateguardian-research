from __future__ import annotations

from datetime import timedelta
from typing import Any

from csg.config import Settings
from csg.db.repositories import CyberStateRepository
from csg.domain.enums import AIContextMode
from csg.domain.models import (
    EvidencePackage,
    Finding,
    Incident,
    NormalizedEvent,
    StateDelta,
    TimeWindow,
)
from csg.services.evidence import build_evidence_package, evidence_from_events


class IncidentContextBuilder:
    """Build bounded, reproducible context packages for AI-assisted interpretation."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def build_for_finding(
        self,
        repo: CyberStateRepository,
        finding: Finding,
        mode: AIContextMode = AIContextMode.FULL_CONTEXT,
    ) -> EvidencePackage:
        assigned_incident = repo.get_incident_for_finding(finding.finding_id)
        if mode == AIContextMode.FULL_CONTEXT and assigned_incident is not None:
            findings = repo.list_incident_findings(assigned_incident.incident_id)
            incident = assigned_incident
        else:
            findings = [finding]
            incident = None
        package = self._build(repo, finding, findings, incident, mode)
        if assigned_incident is not None and incident is None:
            package = package.model_copy(
                update={
                    "incident_id": assigned_incident.incident_id,
                    "context_version": assigned_incident.context_version,
                }
            )
        return package

    def build_for_incident(
        self,
        repo: CyberStateRepository,
        incident: Incident,
        mode: AIContextMode = AIContextMode.FULL_CONTEXT,
    ) -> EvidencePackage:
        findings = repo.list_incident_findings(incident.incident_id)
        if not findings:
            raise ValueError(f"incident {incident.incident_id} has no findings")
        trigger = max(findings, key=lambda item: (item.created_at, item.finding_id))
        scoped_findings = findings if mode == AIContextMode.FULL_CONTEXT else [trigger]
        scoped_incident = incident if mode == AIContextMode.FULL_CONTEXT else None
        package = self._build(repo, trigger, scoped_findings, scoped_incident, mode)
        if scoped_incident is None:
            package = package.model_copy(
                update={
                    "incident_id": incident.incident_id,
                    "context_version": incident.context_version,
                }
            )
        return package

    def _build(
        self,
        repo: CyberStateRepository,
        trigger: Finding,
        findings: list[Finding],
        incident: Incident | None,
        mode: AIContextMode,
    ) -> EvidencePackage:
        host = repo.get_host(trigger.host_id)
        if host is None:
            raise ValueError(f"host {trigger.host_id} was not found")

        trigger_delta = repo.get_delta(trigger.delta_id) if trigger.delta_id else None
        deltas = self._finding_deltas(repo, findings)
        retrieval_attempts: list[dict[str, Any]] = []
        selected_events: list[NormalizedEvent] = []
        selected_window: TimeWindow | None = None

        if mode == AIContextMode.EVENT_HISTORY:
            selected_window = trigger.reconciliation.observation_window
            candidates = repo.get_events(
                trigger.host_id,
                selected_window.start,
                selected_window.end,
            )
            if incident is None:
                candidates = self._scope_events_to_trigger(candidates, [trigger], [trigger_delta])
            selected_events = self._rank_events(
                candidates,
                [trigger],
                [trigger_delta] if trigger_delta else [],
                relevant_only=False,
            )
            retrieval_attempts.append(
                self._attempt_record(selected_window, candidates, selected_events, expanded=False)
            )
        elif mode == AIContextMode.FULL_CONTEXT:
            selected_events, selected_window, retrieval_attempts = self._adaptive_timeline(
                repo,
                trigger.host_id,
                findings,
                deltas,
                incident,
            )

        related_deltas: list[StateDelta] = []
        related_findings: list[Finding] = []
        included_delta: StateDelta | None = None
        interpretive_memory: dict[str, Any] | None = None
        if mode == AIContextMode.FULL_CONTEXT:
            included_delta = trigger_delta
            related_deltas = self._related_deltas(
                repo,
                trigger,
                deltas,
                selected_window,
            )
            related_findings = self._related_findings(
                repo,
                trigger,
                findings,
                selected_window,
            )
            interpretive_memory = self._interpretive_memory(repo, incident)

        context = self._context_metadata(
            repo=repo,
            trigger=trigger,
            findings=findings,
            deltas=deltas,
            events=selected_events,
            incident=incident,
            mode=mode,
            window=selected_window,
            retrieval_attempts=retrieval_attempts,
        )
        return build_evidence_package(
            host=host,
            finding=trigger,
            state_delta=included_delta,
            transient_observation=None,
            evidence=evidence_from_events(selected_events),
            related_deltas=related_deltas,
            related_findings=related_findings,
            incident_context=context,
            incident=incident,
            context_mode=mode,
            interpretive_memory=interpretive_memory,
        )

    def _adaptive_timeline(
        self,
        repo: CyberStateRepository,
        host_id: str,
        findings: list[Finding],
        deltas: list[StateDelta],
        incident: Incident | None,
    ) -> tuple[list[NormalizedEvent], TimeWindow, list[dict[str, Any]]]:
        anchor_start = (
            incident.started_at if incident else min(item.created_at for item in findings)
        )
        anchor_end = (
            incident.last_activity_at if incident else max(item.created_at for item in findings)
        )
        attempts: list[dict[str, Any]] = []
        selected: list[NormalizedEvent] = []
        selected_window: TimeWindow | None = None

        for index, seconds in enumerate(self.settings.ai_context_expansion_window_list):
            window = TimeWindow(
                start=anchor_start - timedelta(seconds=seconds),
                end=anchor_end + timedelta(seconds=seconds),
            )
            candidates = repo.get_events(host_id, window.start, window.end)
            if incident is None:
                candidates = self._scope_events_to_trigger(candidates, findings, deltas)
            ranked = self._rank_events(candidates, findings, deltas, relevant_only=True)
            attempts.append(
                self._attempt_record(
                    window,
                    candidates,
                    ranked,
                    expanded=index > 0,
                    tier_seconds=seconds,
                )
            )
            selected = ranked
            selected_window = window
            if len(selected) >= self.settings.ai_context_min_relevant_events:
                break

        if selected_window is None:  # pragma: no cover - settings always supplies one window
            seconds = self.settings.ai_context_window_seconds
            selected_window = TimeWindow(
                start=anchor_start - timedelta(seconds=seconds),
                end=anchor_end + timedelta(seconds=seconds),
            )
        return selected, selected_window, attempts

    def _rank_events(
        self,
        events: list[NormalizedEvent],
        findings: list[Finding],
        deltas: list[StateDelta],
        *,
        relevant_only: bool,
    ) -> list[NormalizedEvent]:
        scored = [(self._event_score(event, findings, deltas), event) for event in events]
        if relevant_only:
            scored = [item for item in scored if item[0] > 0]
        ranked = sorted(
            scored,
            key=lambda item: (-item[0], item[1].event_time, item[1].event_id),
        )[: self.settings.ai_context_max_events]
        return sorted(
            (item[1] for item in ranked),
            key=lambda event: (event.event_time, event.event_id),
        )

    def _event_score(
        self,
        event: NormalizedEvent,
        findings: list[Finding],
        deltas: list[StateDelta],
    ) -> int:
        score = 0
        matched_ids = {
            evidence_id
            for finding in findings
            for evidence_id in finding.reconciliation.matched_evidence_ids
        }
        object_keys = {finding.object_key for finding in findings if finding.object_key}
        categories = {finding.category for finding in findings}
        if event.event_id in matched_ids:
            score += 100
        if event.target.get("key") in object_keys:
            score += 50
        if event.normalized_type in self._expected_event_types(categories):
            score += 25
        if self._shares_object_term(event, object_keys, deltas):
            score += 20
        return score

    def _related_deltas(
        self,
        repo: CyberStateRepository,
        trigger: Finding,
        incident_deltas: list[StateDelta],
        window: TimeWindow | None,
    ) -> list[StateDelta]:
        current_id = trigger.delta_id
        related = {
            delta.delta_id: delta for delta in incident_deltas if delta.delta_id != current_id
        }
        if window:
            for delta in repo.list_deltas(trigger.host_id, limit=500):
                if delta.delta_id != current_id and window.start <= delta.created_at <= window.end:
                    related.setdefault(delta.delta_id, delta)
        return sorted(
            related.values(),
            key=lambda delta: (delta.created_at, delta.delta_id),
        )[: self.settings.ai_context_related_limit]

    def _related_findings(
        self,
        repo: CyberStateRepository,
        trigger: Finding,
        incident_findings: list[Finding],
        window: TimeWindow | None,
    ) -> list[Finding]:
        related = {
            finding.finding_id: finding
            for finding in incident_findings
            if finding.finding_id != trigger.finding_id
        }
        if window:
            for finding in repo.list_findings(host_id=trigger.host_id, limit=500):
                if (
                    finding.finding_id != trigger.finding_id
                    and window.start <= finding.created_at <= window.end
                ):
                    related.setdefault(finding.finding_id, finding)
        return sorted(
            related.values(),
            key=lambda finding: (finding.created_at, finding.finding_id),
        )[: self.settings.ai_context_related_limit]

    @classmethod
    def _scope_events_to_trigger(
        cls,
        events: list[NormalizedEvent],
        findings: list[Finding],
        deltas: list[StateDelta | None],
    ) -> list[NormalizedEvent]:
        """Keep a finding-only study from importing another trial on the same host."""
        object_keys = {finding.object_key for finding in findings if finding.object_key}
        object_keys.update(delta.object_key for delta in deltas if delta is not None)
        matched_ids = {
            evidence_id
            for finding in findings
            for evidence_id in finding.reconciliation.matched_evidence_ids
        }
        scoped = []
        for event in events:
            if event.event_id in matched_ids or event.target.get("key") in object_keys:
                scoped.append(event)
                continue
            if event.normalized_type in {"process_start", "network_activity"}:
                scoped.append(event)
                continue
            if cls._shares_object_term(event, object_keys, [d for d in deltas if d is not None]):
                scoped.append(event)
        return scoped

    @staticmethod
    def _finding_deltas(
        repo: CyberStateRepository,
        findings: list[Finding],
    ) -> list[StateDelta]:
        deltas: list[StateDelta] = []
        seen: set[str] = set()
        for finding in findings:
            if not finding.delta_id or finding.delta_id in seen:
                continue
            delta = repo.get_delta(finding.delta_id)
            if delta:
                deltas.append(delta)
                seen.add(delta.delta_id)
        return sorted(deltas, key=lambda delta: (delta.created_at, delta.delta_id))

    def _context_metadata(
        self,
        *,
        repo: CyberStateRepository,
        trigger: Finding,
        findings: list[Finding],
        deltas: list[StateDelta],
        events: list[NormalizedEvent],
        incident: Incident | None,
        mode: AIContextMode,
        window: TimeWindow | None,
        retrieval_attempts: list[dict[str, Any]],
    ) -> dict[str, Any]:
        assignments = (
            [
                assignment.model_dump(mode="json")
                for assignment in repo.list_incident_assignments(incident.incident_id)
            ]
            if incident
            else []
        )
        retrieval = {
            "strategy": "bounded_timeline",
            "selected_window": window.model_dump(mode="json") if window else None,
            "attempts": retrieval_attempts,
            "selected_event_count": len(events),
            "maximum_events": self.settings.ai_context_max_events,
        }
        finding_results = [
            {
                "finding_id": finding.finding_id,
                "risk": finding.risk.model_dump(mode="json"),
                "authorization": {
                    "status": finding.authorization_status.value,
                    "reason": finding.authorization_reason,
                },
                "reconciliation": finding.reconciliation.model_dump(mode="json"),
            }
            for finding in findings
        ]
        transitions = [self._state_transition(delta) for delta in deltas]
        trigger_transition = next(
            (item for item in transitions if item["delta_id"] == trigger.delta_id),
            None,
        )
        context: dict[str, Any] = {
            "context_version": "csg-incident-context-v2",
            "trigger": {
                "finding_id": trigger.finding_id,
                "delta_id": trigger.delta_id,
                "category": trigger.category,
                "object_key": trigger.object_key,
                "created_at": trigger.created_at.isoformat(),
            },
            "retrieval": retrieval,
            "retrieval_strategy": retrieval,
            "safety_boundary": {
                "ai_role": "interpretation_only",
                "authoritative_sources": [
                    "normalized_events",
                    "state_deltas",
                    "authorization_results",
                    "reconciliation_results",
                    "risk_results",
                ],
                "not_authoritative": [
                    "previous_ai_analysis",
                    "current_ai_hypothesis",
                    "confidence_language",
                ],
                "prohibited_actions": [
                    "change_detector_results",
                    "authorize_changes",
                    "modify_risk_evidence",
                    "delete_findings",
                    "execute_remediation",
                    "declare_ground_truth",
                ],
            },
        }
        if mode == AIContextMode.FULL_CONTEXT:
            context.update(
                {
                    "incident_assignment": {
                        "incident_id": incident.incident_id if incident else None,
                        "deterministic": True,
                        "assignments": assignments,
                    },
                    "deterministic_results": {
                        "risk": trigger.risk.model_dump(mode="json"),
                        "authorization_status": trigger.authorization_status.value,
                        "authorization_reason": trigger.authorization_reason,
                        "reconciliation": trigger.reconciliation.model_dump(mode="json"),
                        "findings": finding_results,
                    },
                    "state_transition": trigger_transition,
                    "state_transitions": transitions,
                    "related_entities": self._related_entity_hints(findings, deltas, events),
                }
            )
        return context

    @staticmethod
    def _interpretive_memory(
        repo: CyberStateRepository,
        incident: Incident | None,
    ) -> dict[str, Any] | None:
        if incident is None or incident.context_version <= 1:
            return None
        analyses = repo.list_ai_analyses(incident_id=incident.incident_id, limit=25)
        previous = next(
            (
                analysis
                for analysis in analyses
                if analysis.response_json and analysis.context_version < incident.context_version
            ),
            None,
        )
        if previous is None:
            return None
        response = previous.response_json or {}
        return {
            "classification": "prior_ai_interpretation_not_evidence",
            "analysis_id": previous.analysis_id,
            "context_version": previous.context_version,
            "summary": response.get("summary"),
            "what_changed": response.get("what_changed"),
            "likely_cause": response.get("likely_cause"),
            "cited_evidence_ids": response.get("evidence_ids", []),
            "cited_delta_ids": response.get("delta_ids", []),
            "cited_finding_ids": response.get("finding_ids", []),
            "instruction": (
                "Use only as continuity context. Re-evaluate against current primary evidence and "
                "do not inherit its confidence or conclusions."
            ),
        }

    @staticmethod
    def _state_transition(delta: StateDelta) -> dict[str, Any]:
        return {
            "delta_id": delta.delta_id,
            "delta_type": delta.delta_type.value,
            "category": delta.category,
            "object_key": delta.object_key,
            "observation_window": delta.observation_window.model_dump(mode="json"),
            "before": delta.before.model_dump(mode="json") if delta.before else None,
            "after": delta.after.model_dump(mode="json") if delta.after else None,
        }

    @staticmethod
    def _attempt_record(
        window: TimeWindow,
        candidates: list[NormalizedEvent],
        selected: list[NormalizedEvent],
        *,
        expanded: bool,
        tier_seconds: int | None = None,
    ) -> dict[str, Any]:
        return {
            "window": window.model_dump(mode="json"),
            "tier_seconds": tier_seconds,
            "expanded": expanded,
            "candidate_event_count": len(candidates),
            "relevant_event_count": len(selected),
        }

    @staticmethod
    def _expected_event_types(categories: set[str]) -> set[str]:
        mapping = {
            "service": {"service_created", "process_start"},
            "listener": {"network_activity", "process_start"},
            "scheduled_task": {
                "scheduled_task_created",
                "scheduled_task_modified",
                "process_start",
            },
            "privileged_group": {"privileged_group_member_added", "process_start"},
            "registry": {"registry_modified", "process_start"},
            "process": {"process_start"},
        }
        return {
            event_type for category in categories for event_type in mapping.get(category, set())
        }

    @staticmethod
    def _shares_object_term(
        event: NormalizedEvent,
        object_keys: set[str],
        deltas: list[StateDelta],
    ) -> bool:
        terms = {value.lower() for value in object_keys if value}
        for delta in deltas:
            terms.add(delta.object_key.lower())
            for state_object in (delta.before, delta.after):
                if not state_object:
                    continue
                for value in state_object.attributes.values():
                    if isinstance(value, str) and len(value) >= 3:
                        terms.add(value.lower())
        haystack = " ".join([str(event.actor), str(event.target), str(event.attributes)]).lower()
        return any(term in haystack for term in terms)

    @staticmethod
    def _related_entity_hints(
        findings: list[Finding],
        deltas: list[StateDelta],
        events: list[NormalizedEvent],
    ) -> dict[str, list[str]]:
        hints: dict[str, set[str]] = {
            "accounts": set(),
            "processes": set(),
            "objects": {finding.object_key for finding in findings if finding.object_key},
            "destinations": set(),
        }
        for delta in deltas:
            hints["objects"].add(delta.object_key)
            for state_object in (delta.before, delta.after):
                if not state_object:
                    continue
                for key, value in state_object.attributes.items():
                    IncidentContextBuilder._classify_hint(hints, key, value)
        for event in events:
            for mapping in (event.actor, event.target, event.attributes):
                for key, value in mapping.items():
                    IncidentContextBuilder._classify_hint(hints, key, value)
        return {key: sorted(values)[:20] for key, values in hints.items()}

    @staticmethod
    def _classify_hint(hints: dict[str, set[str]], key: str, value: Any) -> None:
        if value is None or isinstance(value, (dict, list)):
            return
        text = str(value)
        lowered = key.lower()
        if "user" in lowered or "account" in lowered:
            hints["accounts"].add(text)
        elif any(token in lowered for token in ("process", "image", "executable", "binary")):
            hints["processes"].add(text)
        elif "ip" in lowered or "port" in lowered or "address" in lowered:
            hints["destinations"].add(text)
        elif any(token in lowered for token in ("service", "task", "registry", "object")):
            hints["objects"].add(text)
