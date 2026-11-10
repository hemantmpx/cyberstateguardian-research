from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from csg.domain.enums import (
    AIContextMode,
    AuthorizationStatus,
    DeltaType,
    IncidentStatus,
    ObservationKind,
    ReconciliationStatus,
    Severity,
    TrajectoryType,
    TransitionReconciliationStatus,
    TransitionRelation,
)

JsonDict = dict[str, Any]
CategoryName = Literal[
    "process",
    "listener",
    "service",
    "scheduled_task",
    "privileged_group",
    "registry",
    "other",
]
CollectorStatus = Literal["healthy", "partial", "error", "unavailable"]
ScenarioClassification = Literal[
    "benign",
    "suspicious",
    "malicious-simulation",
    "telemetry-failure",
]
MonitorHealthStatus = Literal["HEALTHY", "PARTIAL", "DEGRADED", "OFFLINE", "UNKNOWN"]


def new_uuid() -> str:
    return str(uuid4())


def utc_now() -> datetime:
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class CSGModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Host(CSGModel):
    host_id: str
    hostname: str
    role: str
    os: str
    architecture: str
    enabled: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at", "updated_at")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class CategoryStatus(CSGModel):
    category: str
    status: CollectorStatus
    source: str
    observed_at: datetime = Field(default_factory=utc_now)
    message: str | None = None

    @field_validator("observed_at")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @property
    def usable(self) -> bool:
        return self.status in {"healthy", "partial"}


class StateObject(CSGModel):
    category: str
    object_key: str
    attributes: JsonDict = Field(default_factory=dict)
    source_timestamp: datetime = Field(default_factory=utc_now)
    metadata: JsonDict = Field(default_factory=dict)

    @field_validator("source_timestamp")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class StateSnapshot(CSGModel):
    snapshot_id: str = Field(default_factory=new_uuid)
    host_id: str
    built_at: datetime = Field(default_factory=utc_now)
    source: str
    category_statuses: list[CategoryStatus] = Field(default_factory=list)
    objects: list[StateObject] = Field(default_factory=list)
    metadata: JsonDict = Field(default_factory=dict)

    @field_validator("built_at")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    def status_for(self, category: str) -> CategoryStatus | None:
        return next(
            (status for status in self.category_statuses if status.category == category), None
        )


class TimeWindow(CSGModel):
    start: datetime
    end: datetime

    @field_validator("start", "end")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @model_validator(mode="after")
    def _ordered(self) -> TimeWindow:
        if self.end < self.start:
            raise ValueError("time window end must be greater than or equal to start")
        return self


class StateDelta(CSGModel):
    delta_id: str = Field(default_factory=new_uuid)
    host_id: str
    category: str
    object_key: str
    delta_type: DeltaType
    before: StateObject | None = None
    after: StateObject | None = None
    source_quality: JsonDict = Field(default_factory=dict)
    observation_window: TimeWindow
    created_at: datetime = Field(default_factory=utc_now)
    metadata: JsonDict = Field(default_factory=dict)

    @field_validator("created_at")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class NormalizedEvent(CSGModel):
    event_id: str = Field(default_factory=new_uuid)
    host_id: str
    event_time: datetime
    normalized_type: str
    actor: JsonDict = Field(default_factory=dict)
    target: JsonDict = Field(default_factory=dict)
    attributes: JsonDict = Field(default_factory=dict)
    source: str
    source_reference: JsonDict = Field(default_factory=dict)
    synthetic: bool = False
    scenario_id: str | None = None
    metadata: JsonDict = Field(default_factory=dict)

    @field_validator("event_time")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class EventObservationResult(CSGModel):
    """Events plus the collection facts required to interpret missing evidence."""

    events: list[NormalizedEvent] = Field(default_factory=list)
    query_complete: bool = False
    endpoint_collection_status: Literal["AVAILABLE", "DEGRADED", "UNAVAILABLE", "UNKNOWN"] = (
        "UNKNOWN"
    )
    transport_status: Literal["AVAILABLE", "DEGRADED", "UNAVAILABLE", "UNKNOWN"] = "UNKNOWN"
    index_status: Literal["AVAILABLE", "DEGRADED", "UNAVAILABLE", "UNKNOWN"] = "UNKNOWN"
    coverage_status: Literal["COMPLETE", "PARTIAL", "UNAVAILABLE", "UNKNOWN"] = "UNKNOWN"
    retrieval_pages: int = Field(default=0, ge=0)
    retrieved_count: int = Field(default=0, ge=0)
    total_hits: int | None = Field(default=None, ge=0)
    metadata: JsonDict = Field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self):
        return iter(self.events)

    def __getitem__(self, index: int) -> NormalizedEvent:
        return self.events[index]


class CollectorObservation(CSGModel):
    category: str
    status: CollectorStatus
    observed_at: datetime = Field(default_factory=utc_now)
    items: list[JsonDict] = Field(default_factory=list)
    message: str | None = None

    @field_validator("observed_at")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class ProbeObservation(CSGModel):
    observation_id: str = Field(default_factory=new_uuid)
    host_id: str
    observed_at: datetime = Field(default_factory=utc_now)
    source: str = "direct_probe"
    categories: dict[str, CollectorObservation] = Field(default_factory=dict)
    metadata: JsonDict = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class StateTransitionRecord(CSGModel):
    """A CSG-native observation between authoritative snapshots, never a StateDelta."""

    transition_id: str = Field(default_factory=new_uuid)
    host_id: str
    category: CategoryName
    object_key: str = Field(min_length=1, max_length=512)
    transition_type: str = Field(min_length=2, max_length=64, pattern=r"^[A-Z][A-Z0-9_]+$")
    observed_at: datetime
    received_at: datetime = Field(default_factory=utc_now)
    window_start: datetime | None = None
    window_end: datetime | None = None
    old_state: JsonDict | None = None
    new_state: JsonDict | None = None
    changed_fields: list[str] = Field(default_factory=list)
    source: str = "direct_probe"
    capture_method: str
    collector_health: MonitorHealthStatus = "UNKNOWN"
    snapshot_before_id: str | None = None
    snapshot_after_id: str | None = None
    delta_id: str | None = None
    sequence_number: int | None = Field(default=None, ge=0)
    raw_metadata: JsonDict = Field(default_factory=dict)

    @field_validator("observed_at", "received_at", "window_start", "window_end")
    @classmethod
    def _utc_datetimes(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value else value

    @model_validator(mode="after")
    def _ordered_window(self) -> StateTransitionRecord:
        if self.window_start and self.window_end and self.window_end < self.window_start:
            raise ValueError("transition window end must not precede start")
        return self


class TransitionMonitorHealth(CSGModel):
    health_id: str = Field(default_factory=new_uuid)
    host_id: str
    category: CategoryName
    monitor_id: str = Field(min_length=1, max_length=128)
    status: MonitorHealthStatus
    capture_method: str
    started_at: datetime
    observed_at: datetime = Field(default_factory=utc_now)
    last_heartbeat_at: datetime = Field(default_factory=utc_now)
    coverage_start: datetime | None = None
    coverage_end: datetime | None = None
    baseline_established: bool = False
    restart_count: int = Field(default=0, ge=0)
    metrics: JsonDict = Field(default_factory=dict)
    message: str | None = None

    @field_validator(
        "started_at", "observed_at", "last_heartbeat_at", "coverage_start", "coverage_end"
    )
    @classmethod
    def _utc_datetimes(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value else value


class ProbeTransitionBatch(CSGModel):
    host_id: str
    records: list[StateTransitionRecord] = Field(max_length=1000)
    monitor_health: list[TransitionMonitorHealth] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def _same_host(self) -> ProbeTransitionBatch:
        if any(record.host_id != self.host_id for record in self.records):
            raise ValueError("all transitions must belong to the batch host")
        if any(item.host_id != self.host_id for item in self.monitor_health):
            raise ValueError("all monitor health records must belong to the batch host")
        return self


class TransitionReconciliationResult(CSGModel):
    reconciliation_id: str = Field(default_factory=new_uuid)
    transition_id: str
    host_id: str
    status: TransitionReconciliationStatus
    matched_evidence_ids: list[str] = Field(default_factory=list)
    match_reasons: list[JsonDict] = Field(default_factory=list)
    missing_expected_evidence_types: list[str] = Field(default_factory=list)
    observation_window: TimeWindow
    version: int = Field(default=1, ge=1)
    finalized: bool = True
    finalized_at: datetime | None = None
    supersedes_reconciliation_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    metadata: JsonDict = Field(default_factory=dict)

    @field_validator("created_at", "finalized_at")
    @classmethod
    def _utc_datetimes(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value else value


class TransitionTimelineItem(CSGModel):
    transition: StateTransitionRecord
    latest_reconciliation: TransitionReconciliationResult | None = None


class TrajectoryTransitionLink(CSGModel):
    transition_id: str
    relation: TransitionRelation


class StateTrajectory(CSGModel):
    trajectory_id: str
    host_id: str
    category: CategoryName
    object_key: str
    snapshot_before_id: str
    snapshot_after_id: str
    interval: TimeWindow
    state_before: StateObject | None = None
    state_after: StateObject | None = None
    snapshot_delta: StateDelta | None = None
    transitions: list[StateTransitionRecord] = Field(default_factory=list)
    transition_links: list[TrajectoryTransitionLink] = Field(default_factory=list)
    trajectory_type: TrajectoryType
    coverage_status: MonitorHealthStatus
    coverage_gaps: list[str] = Field(default_factory=list)


class TransientObservation(CSGModel):
    transient_id: str = Field(default_factory=new_uuid)
    host_id: str
    event_id: str
    event_time: datetime
    normalized_type: str
    actor: JsonDict = Field(default_factory=dict)
    target: JsonDict = Field(default_factory=dict)
    attributes: JsonDict = Field(default_factory=dict)
    reason: str
    created_at: datetime = Field(default_factory=utc_now)
    metadata: JsonDict = Field(default_factory=dict)

    @field_validator("event_time", "created_at")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class EvidenceItem(CSGModel):
    evidence_id: str = Field(default_factory=new_uuid)
    host_id: str
    evidence_type: str
    timestamp: datetime
    content: JsonDict = Field(default_factory=dict)
    source_reference: JsonDict = Field(default_factory=dict)
    metadata: JsonDict = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class ReconciliationResult(CSGModel):
    reconciliation_id: str = Field(default_factory=new_uuid)
    host_id: str
    status: ReconciliationStatus
    matched_evidence_ids: list[str] = Field(default_factory=list)
    match_reasons: list[JsonDict] = Field(default_factory=list)
    missing_expected_evidence_types: list[str] = Field(default_factory=list)
    observation_window: TimeWindow
    confidence: float | None = None
    delta_id: str | None = None
    finding_id: str | None = None
    version: int = Field(default=1, ge=1)
    finalized: bool = True
    finalized_at: datetime | None = None
    supersedes_reconciliation_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    metadata: JsonDict = Field(default_factory=dict)

    @field_validator("created_at", "finalized_at")
    @classmethod
    def _utc_datetimes(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value else value


class AuthorizedObject(CSGModel):
    authorization_id: str = Field(default_factory=new_uuid)
    host_id: str
    category: str
    object_key: str
    status: AuthorizationStatus = AuthorizationStatus.EXPECTED
    reason: str
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    metadata: JsonDict = Field(default_factory=dict)

    @field_validator("valid_from", "valid_until")
    @classmethod
    def _optional_utc_datetimes(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value else value


class MaintenanceWindow(CSGModel):
    window_id: str
    host_id: str
    valid_from: datetime
    valid_until: datetime
    categories: list[str] = Field(default_factory=list)
    object_keys: list[str] = Field(default_factory=list)
    reason: str

    @field_validator("valid_from", "valid_until")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    def contains(self, when: datetime, category: str, object_key: str) -> bool:
        checked = ensure_utc(when)
        category_match = not self.categories or category in self.categories
        object_match = not self.object_keys or object_key in self.object_keys
        return self.valid_from <= checked <= self.valid_until and category_match and object_match


class RiskComponent(CSGModel):
    rule_name: str
    points: int
    explanation: str


class RiskScore(CSGModel):
    total: int
    severity: Severity
    components: list[RiskComponent] = Field(default_factory=list)
    rules_version: str


class Finding(CSGModel):
    finding_id: str = Field(default_factory=new_uuid)
    host_id: str
    observation_kind: ObservationKind
    delta_id: str | None = None
    transient_id: str | None = None
    category: str
    object_key: str | None = None
    reconciliation: ReconciliationResult
    authorization_status: AuthorizationStatus
    authorization_reason: str
    risk: RiskScore
    created_at: datetime = Field(default_factory=utc_now)
    metadata: JsonDict = Field(default_factory=dict)

    @field_validator("created_at")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class Incident(CSGModel):
    incident_id: str = Field(default_factory=new_uuid)
    host_id: str
    status: IncidentStatus = IncidentStatus.OPEN
    title: str
    severity: Severity
    risk_score: int = 0
    started_at: datetime
    last_activity_at: datetime
    context_version: int = 1
    finding_ids: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    object_keys: list[str] = Field(default_factory=list)
    entity_keys: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: JsonDict = Field(default_factory=dict)

    @field_validator("started_at", "last_activity_at", "created_at", "updated_at")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class IncidentFindingAssignment(CSGModel):
    incident_id: str
    finding_id: str
    assignment_score: int
    assignment_reasons: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class EvidencePackage(CSGModel):
    package_id: str = Field(default_factory=new_uuid)
    finding_id: str
    incident_id: str | None = None
    context_mode: AIContextMode = AIContextMode.FULL_CONTEXT
    context_version: int = 1
    host: Host
    finding: Finding
    incident: Incident | None = None
    state_delta: StateDelta | None = None
    transient_observation: TransientObservation | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    related_deltas: list[StateDelta] = Field(default_factory=list)
    related_findings: list[Finding] = Field(default_factory=list)
    source_quality: JsonDict = Field(default_factory=dict)
    attack_context: JsonDict | None = None
    incident_context: JsonDict = Field(default_factory=dict)
    interpretive_memory: JsonDict | None = None
    experiment_id: str | None = None
    trial_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class ExperimentScenario(CSGModel):
    scenario_id: str
    description: str
    classification: ScenarioClassification
    initial_state_fixture: str
    resulting_state_fixture: str | None = None
    event_fixture_set: str
    telemetry_condition: str = "complete"
    event_source_status: Literal["available", "degraded", "unavailable"] = "available"
    expected_deltas: list[JsonDict] = Field(default_factory=list)
    expected_reconciliation: ReconciliationStatus
    ground_truth_notes: str
    metadata: JsonDict = Field(default_factory=dict)


class ExperimentRun(CSGModel):
    run_id: str = Field(default_factory=new_uuid)
    scenario_id: str
    host_id: str
    ground_truth_classification: ScenarioClassification
    started_at: datetime = Field(default_factory=utc_now)
    ended_at: datetime | None = None
    provider_configuration: JsonDict = Field(default_factory=dict)
    expected_observations: JsonDict = Field(default_factory=dict)
    actual_observations: JsonDict = Field(default_factory=dict)
    reconciliation_result: JsonDict = Field(default_factory=dict)
    risk_score: JsonDict = Field(default_factory=dict)
    detection_timestamps: JsonDict = Field(default_factory=dict)
    success: bool = True
    failure_reason: str | None = None
    metrics: JsonDict = Field(default_factory=dict)

    @field_validator("started_at", "ended_at")
    @classmethod
    def _optional_utc_datetimes(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value else value


class AIAnalystExplanation(CSGModel):
    summary: str
    what_changed: str
    likely_cause: str
    why_it_matters: str
    authorization_context: str
    telemetry_consistency: str
    attack_relevance: str
    recommended_next_steps: list[str]
    confidence: Literal["low", "medium", "high"]
    uncertainty: str
    evidence_ids: list[str]
    delta_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class AIResponseCitations(CSGModel):
    evidence_ids: list[str] = Field(default_factory=list)
    delta_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)


class AIResponseFact(CSGModel):
    statement: str = Field(min_length=1, max_length=1000)
    citations: AIResponseCitations


class AIResponseHypothesis(CSGModel):
    hypothesis_id: str = Field(min_length=1, max_length=40)
    hypothesis: str = Field(min_length=1, max_length=500)
    rationale: str = Field(min_length=1, max_length=1200)
    supporting: AIResponseCitations
    contradicting: AIResponseCitations = Field(default_factory=AIResponseCitations)
    evidence_needed_to_test: list[str] = Field(min_length=1, max_length=8)
    confidence: Literal["low", "medium", "high"]


class AIResponseAction(CSGModel):
    priority: int = Field(ge=1, le=8)
    action: str = Field(min_length=1, max_length=500)
    objective: str = Field(min_length=1, max_length=500)
    exact_target: str = Field(min_length=1, max_length=500)
    why_this_action: str = Field(min_length=1, max_length=1000)
    expected_information_gain: str = Field(min_length=1, max_length=1000)
    interpretation_if_positive: str = Field(min_length=1, max_length=800)
    interpretation_if_negative: str = Field(min_length=1, max_length=800)
    evidence_basis: AIResponseCitations
    action_type: Literal["investigation", "validation", "containment", "recovery", "escalation"]
    disruptiveness: Literal["none", "low", "medium", "high"]
    prerequisites: list[str] = Field(default_factory=list, max_length=8)
    safety_notes: str = Field(min_length=1, max_length=800)
    trigger_condition: str = ""
    evidence_required_before_action: list[str] = Field(default_factory=list, max_length=8)


class AIResponseEvidenceGap(CSGModel):
    missing_information: str = Field(min_length=1, max_length=500)
    why_it_matters: str = Field(min_length=1, max_length=800)
    how_to_collect_it: str = Field(min_length=1, max_length=800)
    hypotheses_discriminated: list[str] = Field(min_length=1, max_length=5)


class AIResponseOption(CSGModel):
    trigger_condition: str = Field(min_length=1, max_length=800)
    recommended_response: str = Field(min_length=1, max_length=800)
    rationale: str = Field(min_length=1, max_length=800)
    impact: str = Field(min_length=1, max_length=800)
    reversibility: Literal["high", "medium", "low", "not_applicable"]
    evidence_required_before_action: list[str] = Field(min_length=1, max_length=8)
    evidence_basis: AIResponseCitations
    disruptiveness: Literal["none", "low", "medium", "high"]


class AIResponseConsequence(CSGModel):
    condition_if: str = Field(min_length=1, max_length=600)
    consequence: str = Field(min_length=1, max_length=800)


class AIResponseTechniqueCandidate(CSGModel):
    technique_id: str = Field(min_length=1, max_length=20)
    interpretation: str = Field(min_length=1, max_length=800)
    confidence: Literal["low", "medium", "high"]
    citations: AIResponseCitations = Field(default_factory=AIResponseCitations)


class AIAnalystResponseDraft(CSGModel):
    """Model-authored guidance only; deterministic CSG facts are added by the service."""

    assessment_boundary_unknown: list[str] = Field(min_length=1, max_length=12)
    investigative_hypotheses: list[AIResponseHypothesis] = Field(min_length=2, max_length=5)
    general_security_knowledge: list[str] = Field(default_factory=list, max_length=8)
    priority_actions: list[AIResponseAction] = Field(min_length=1, max_length=8)
    evidence_gaps: list[AIResponseEvidenceGap] = Field(default_factory=list, max_length=12)
    response_options: list[AIResponseOption] = Field(default_factory=list, max_length=6)
    possible_consequences: list[AIResponseConsequence] = Field(default_factory=list, max_length=6)
    attack_technique_candidates: list[AIResponseTechniqueCandidate] = Field(
        default_factory=list, max_length=6
    )
    analyst_decision_summary: str = Field(min_length=1, max_length=1200)
    confidence: Literal["low", "medium", "high"]
    uncertainty: str = Field(min_length=1, max_length=800)
    citations: AIResponseCitations = Field(default_factory=AIResponseCitations)


class AIAnalystResponsePlan(CSGModel):
    """Optional post-reconciliation guidance; it cannot represent CSG decisions."""

    incident_anchor: str = Field(min_length=1, max_length=500)
    assessment_boundary_known: list[str] = Field(min_length=1, max_length=8)
    assessment_boundary_unknown: list[str] = Field(min_length=1, max_length=12)
    csg_determined_facts: list[AIResponseFact] = Field(min_length=1, max_length=12)
    investigative_hypotheses: list[AIResponseHypothesis] = Field(min_length=2, max_length=5)
    general_security_knowledge: list[str] = Field(default_factory=list, max_length=8)
    priority_actions: list[AIResponseAction] = Field(min_length=1, max_length=8)
    evidence_gaps: list[AIResponseEvidenceGap] = Field(default_factory=list, max_length=12)
    response_options: list[AIResponseOption] = Field(default_factory=list, max_length=6)
    possible_consequences: list[AIResponseConsequence] = Field(default_factory=list, max_length=6)
    attack_technique_candidates: list[AIResponseTechniqueCandidate] = Field(
        default_factory=list, max_length=6
    )
    analyst_decision_summary: str = Field(min_length=1, max_length=1200)
    confidence: Literal["low", "medium", "high"]
    uncertainty: str = Field(min_length=1, max_length=800)
    citations: AIResponseCitations = Field(default_factory=AIResponseCitations)

    @model_validator(mode="after")
    def _ordered_action_priorities(self) -> AIAnalystResponsePlan:
        priorities = [action.priority for action in self.priority_actions]
        if priorities != list(range(1, len(priorities) + 1)):
            raise ValueError("priority_actions must be ordered contiguously starting at 1")
        return self


class AIAnalysisRecord(CSGModel):
    analysis_id: str = Field(default_factory=new_uuid)
    finding_id: str
    incident_id: str | None = None
    context_version: int = 1
    context_mode: AIContextMode = AIContextMode.FULL_CONTEXT
    evidence_package_hash: str | None = None
    parent_analysis_id: str | None = None
    prompt_version: str
    model: str
    enabled: bool
    response_json: JsonDict | None = None
    validation_errors: list[str] = Field(default_factory=list)
    metadata: JsonDict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at")
    @classmethod
    def _utc_datetimes(cls, value: datetime) -> datetime:
        return ensure_utc(value)
