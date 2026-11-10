from __future__ import annotations

from datetime import timedelta

from csg.config import Settings
from csg.db.repositories import CyberStateRepository
from csg.domain.enums import (
    DeltaType,
    TransitionReconciliationStatus,
)
from csg.domain.models import (
    EventObservationResult,
    NormalizedEvent,
    StateDelta,
    StateObject,
    StateTransitionRecord,
    TimeWindow,
    TransitionReconciliationResult,
    utc_now,
)
from csg.providers.factory import build_event_provider
from csg.services.reconciliation import ReconciliationEngine


class TransitionReconciliationService:
    """Corroborate an independently captured CSG transition using bounded event evidence."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.engine = ReconciliationEngine(
            observation_window_seconds=0,
            event_time_tolerance_seconds=settings.event_time_tolerance_seconds,
        )

    async def reconcile(
        self,
        repo: CyberStateRepository,
        transition: StateTransitionRecord,
    ) -> TransitionReconciliationResult:
        expected_types = self.expected_event_types(transition)
        start = transition.window_start or transition.observed_at
        end = transition.window_end or transition.observed_at
        tolerance = timedelta(seconds=self.settings.event_time_tolerance_seconds)
        query_window = TimeWindow(start=start - tolerance, end=end + tolerance)
        prior = repo.transition_reconciliation_history(transition.transition_id)
        previous = prior[-1] if prior else None

        if not expected_types:
            result = TransitionReconciliationResult(
                transition_id=transition.transition_id,
                host_id=transition.host_id,
                status=TransitionReconciliationStatus.NOT_APPLICABLE,
                observation_window=query_window,
                version=(previous.version + 1) if previous else 1,
                finalized_at=utc_now(),
                supersedes_reconciliation_id=previous.reconciliation_id if previous else None,
                metadata={
                    "reason": "no compatible event mapping is implemented for this transition"
                },
            )
            return self._persist_if_changed(repo, result, previous)

        try:
            provided = await build_event_provider(self.settings).get_events(
                transition.host_id,
                query_window.start,
                query_window.end,
            )
            observation = (
                provided
                if isinstance(provided, EventObservationResult)
                else EventObservationResult(
                    events=provided,
                    query_complete=True,
                    endpoint_collection_status="AVAILABLE",
                    transport_status="AVAILABLE",
                    index_status="AVAILABLE",
                    coverage_status="COMPLETE",
                    retrieved_count=len(provided),
                )
            )
        except Exception as exc:
            observation = EventObservationResult(
                query_complete=False,
                coverage_status="UNAVAILABLE",
                endpoint_collection_status="UNKNOWN",
                transport_status="UNAVAILABLE",
                index_status="UNKNOWN",
                metadata={"query_error": f"{type(exc).__name__}: {exc}"},
            )

        delta = self._as_delta(transition)
        mismatches: list[dict[str, str]] = []
        matches = [
            event
            for event in observation.events
            if event.normalized_type in expected_types
            and self._operation_matches(transition, event)
            and self.engine.event_matches_delta(event, delta, mismatches)
        ]
        matches.sort(key=lambda event: (event.event_time, event.event_id))
        matched_ids = [event.event_id for event in matches]
        if matched_ids:
            status = TransitionReconciliationStatus.CORROBORATED
            missing: list[str] = []
        elif not observation.query_complete or observation.coverage_status in {
            "PARTIAL",
            "UNAVAILABLE",
            "UNKNOWN",
        }:
            status = TransitionReconciliationStatus.PENDING_EVIDENCE
            missing = expected_types
        elif mismatches:
            status = TransitionReconciliationStatus.CONTRADICTED
            missing = expected_types
        else:
            status = TransitionReconciliationStatus.UNEXPLAINED_BY_EVENT_PLANE
            missing = expected_types

        result = TransitionReconciliationResult(
            transition_id=transition.transition_id,
            host_id=transition.host_id,
            status=status,
            matched_evidence_ids=matched_ids,
            match_reasons=[
                {
                    "event_id": event.event_id,
                    "event_type": event.normalized_type,
                    "reason": self._match_reason(transition, event),
                }
                for event in matches
            ],
            missing_expected_evidence_types=missing,
            observation_window=query_window,
            version=(previous.version + 1) if previous else 1,
            finalized=status != TransitionReconciliationStatus.PENDING_EVIDENCE,
            finalized_at=utc_now()
            if status != TransitionReconciliationStatus.PENDING_EVIDENCE
            else None,
            supersedes_reconciliation_id=previous.reconciliation_id if previous else None,
            metadata={
                "query_complete": observation.query_complete,
                "endpoint_collection_status": observation.endpoint_collection_status,
                "transport_status": observation.transport_status,
                "index_status": observation.index_status,
                "coverage_status": observation.coverage_status,
                "candidate_count": len(observation.events),
                "transition_mismatches": mismatches,
                "event_time_tolerance_seconds": self.settings.event_time_tolerance_seconds,
                "transition_capture_is_independent_evidence": True,
            },
        )
        return self._persist_if_changed(repo, result, previous)

    @staticmethod
    def _match_reason(transition: StateTransitionRecord, event: NormalizedEvent) -> str:
        if transition.category == "privileged_group":
            if event.attributes.get("member_sid") or event.target.get("member_sid"):
                return "exact privileged-group name and member SID matched"
            return "exact privileged-group name and member name matched"
        return f"exact {transition.category} object and transition-compatible event"

    @staticmethod
    def expected_event_types(transition: StateTransitionRecord) -> list[str]:
        name = transition.transition_type
        if transition.category == "service":
            if name in {"CREATE", "SERVICE_CREATED"}:
                return ["service_created"]
            if name in {"REMOVE", "SERVICE_DELETED"}:
                return ["service_deleted"]
            if name in {
                "MODIFY",
                "SERVICE_CONFIG_MODIFIED",
                "SERVICE_START_MODE_CHANGED",
                "SERVICE_BINARY_PATH_CHANGED",
                "SERVICE_ACCOUNT_CHANGED",
            }:
                return ["service_modified"]
        if transition.category == "registry" and name.startswith("REGISTRY_VALUE_"):
            return ["registry_value_modified"]
        if transition.category == "scheduled_task":
            return {
                "CREATE": ["scheduled_task_created"],
                "TASK_CREATED": ["scheduled_task_created"],
                "MODIFY": ["scheduled_task_modified"],
                "TASK_MODIFIED": ["scheduled_task_modified"],
            }.get(name, [])
        if transition.category == "privileged_group":
            return {
                "ADD_MEMBER": ["privileged_group_member_added"],
                "PRIVILEGED_MEMBER_ADDED": ["privileged_group_member_added"],
            }.get(name, [])
        if transition.category == "process" and name in {"START", "PROCESS_START"}:
            return ["process_start"]
        if transition.category == "listener" and name in {"OPEN", "LISTENER_OPENED"}:
            return ["listener_created"]
        return []

    def _as_delta(self, transition: StateTransitionRecord) -> StateDelta:
        delta_type = self._delta_type(transition.transition_type)
        if delta_type is None:
            delta_type = DeltaType.MODIFY
        before = (
            StateObject(
                category=transition.category,
                object_key=transition.object_key,
                attributes=transition.old_state,
                source_timestamp=transition.observed_at,
            )
            if transition.old_state is not None
            else None
        )
        after = (
            StateObject(
                category=transition.category,
                object_key=transition.object_key,
                attributes=transition.new_state,
                source_timestamp=transition.observed_at,
            )
            if transition.new_state is not None
            else None
        )
        return StateDelta(
            delta_id=transition.transition_id,
            host_id=transition.host_id,
            category=transition.category,
            object_key=transition.object_key,
            delta_type=delta_type,
            before=before,
            after=after,
            source_quality={"transition_capture": transition.collector_health},
            observation_window=TimeWindow(
                start=transition.window_start or transition.observed_at,
                end=transition.window_end or transition.observed_at,
            ),
            created_at=transition.observed_at,
            metadata={"source": "transition_record", "transition_id": transition.transition_id},
        )

    @staticmethod
    def _delta_type(transition_type: str) -> DeltaType | None:
        if any(word in transition_type for word in ("MODIFY", "CHANGED", "ENABLED", "DISABLED")):
            return DeltaType.MODIFY
        if any(
            word in transition_type for word in ("REMOVE", "DELETE", "EXIT", "CLOSE", "STOPPED")
        ):
            return DeltaType.REMOVE
        if any(
            word in transition_type for word in ("CREATE", "START", "OPEN", "ADD_MEMBER", "ADDED")
        ):
            return DeltaType.ADD
        return None

    @staticmethod
    def _operation_matches(transition: StateTransitionRecord, event: NormalizedEvent) -> bool:
        if transition.category == "registry":
            event_operation = str(event.attributes.get("event_type", "")).lower()
            if transition.transition_type.endswith(("REMOVED", "DELETED")):
                return event_operation in {"deletevalue", "deletekey"}
            return not event_operation or event_operation in {"setvalue", "createkey"}
        return True

    @staticmethod
    def _persist_if_changed(
        repo: CyberStateRepository,
        result: TransitionReconciliationResult,
        previous: TransitionReconciliationResult | None,
    ) -> TransitionReconciliationResult:
        if previous and (
            previous.status == result.status
            and previous.matched_evidence_ids == result.matched_evidence_ids
            and previous.missing_expected_evidence_types == result.missing_expected_evidence_types
        ):
            return previous
        return repo.create_transition_reconciliation(result)
