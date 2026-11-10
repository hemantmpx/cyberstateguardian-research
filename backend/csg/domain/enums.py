from __future__ import annotations

from enum import StrEnum


class DeltaType(StrEnum):
    ADD = "ADD"
    REMOVE = "REMOVE"
    MODIFY = "MODIFY"


class TrajectoryType(StrEnum):
    STABLE = "STABLE"
    DURABLE = "DURABLE"
    MULTI_STEP_DURABLE = "MULTI_STEP_DURABLE"
    REVERTED = "REVERTED"
    NON_PERSISTENT_TRANSITION = "NON_PERSISTENT_TRANSITION"
    TRANSIENT_OBJECT = "TRANSIENT_OBJECT"
    TRANSITION_CAPTURE_GAP = "TRANSITION_CAPTURE_GAP"
    UNOBSERVED_INTERVAL = "UNOBSERVED_INTERVAL"
    INCONSISTENT = "INCONSISTENT"


class TransitionRelation(StrEnum):
    REPRESENTED_BY_DELTA = "represented_by_delta"
    REVERTED_BEFORE_SNAPSHOT = "reverted_before_snapshot"
    TRANSIENT_BETWEEN_SNAPSHOTS = "transient_between_snapshots"
    PART_OF_MULTISTEP_DELTA = "part_of_multistep_delta"
    NON_PERSISTENT_TRANSITION = "non_persistent_transition"
    NOT_OBSERVED_BY_TRANSITION_MONITOR = "not_observed_by_transition_monitor"


class TransitionReconciliationStatus(StrEnum):
    PENDING_EVIDENCE = "PENDING_EVIDENCE"
    CORROBORATED = "CORROBORATED"
    PARTIALLY_CORROBORATED = "PARTIALLY_CORROBORATED"
    UNEXPLAINED_BY_EVENT_PLANE = "UNEXPLAINED_BY_EVENT_PLANE"
    CONTRADICTED = "CONTRADICTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ReconciliationStatus(StrEnum):
    PENDING_EVIDENCE = "PENDING_EVIDENCE"
    CONSISTENT = "CONSISTENT"
    PARTIALLY_EXPLAINED = "PARTIALLY_EXPLAINED"
    UNEXPLAINED = "UNEXPLAINED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class AuthorizationStatus(StrEnum):
    EXPECTED = "EXPECTED"
    APPROVED_CHANGE = "APPROVED_CHANGE"
    UNKNOWN = "UNKNOWN"
    VIOLATION = "VIOLATION"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ObservationKind(StrEnum):
    STATE_DELTA = "STATE_DELTA"
    EVENT_ONLY = "EVENT_ONLY"


class IncidentStatus(StrEnum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class AIContextMode(StrEnum):
    FINDING_ONLY = "finding_only"
    EVENT_HISTORY = "event_history"
    FULL_CONTEXT = "full_context"
