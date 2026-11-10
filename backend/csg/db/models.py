from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from csg.db.base import Base
from csg.domain.models import utc_now


def uuid_pk() -> str:
    return str(uuid4())


class HostRecord(Base):
    __tablename__ = "hosts"

    host_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(128), nullable=False)
    os: Mapped[str] = mapped_column(String(128), nullable=False)
    architecture: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    snapshots: Mapped[list[StateSnapshotRecord]] = relationship(back_populates="host")
    incidents: Mapped[list[IncidentRecord]] = relationship(back_populates="host")


class SourceObservationRecord(Base):
    __tablename__ = "source_observations"

    observation_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_pk)
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    categories: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class StateSnapshotRecord(Base):
    __tablename__ = "state_snapshots"
    __table_args__ = (
        Index("ix_state_snapshots_host_source_ingested", "host_id", "source", "ingested_at"),
    )

    snapshot_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_pk)
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    built_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, server_default=func.now()
    )
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    category_statuses: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    host: Mapped[HostRecord] = relationship(back_populates="snapshots")
    objects: Mapped[list[StateObjectRecord]] = relationship(
        back_populates="snapshot",
        cascade="all, delete-orphan",
    )


class StateObjectRecord(Base):
    __tablename__ = "state_objects"

    object_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_pk)
    snapshot_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("state_snapshots.snapshot_id"),
        index=True,
    )
    host_id: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    object_key: Mapped[str] = mapped_column(String(512), index=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    source_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    snapshot: Mapped[StateSnapshotRecord] = relationship(back_populates="objects")


class StateDeltaRecord(Base):
    __tablename__ = "state_deltas"

    delta_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_pk)
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    object_key: Mapped[str] = mapped_column(String(512), index=True)
    delta_type: Mapped[str] = mapped_column(String(16), index=True)
    before: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    after: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    source_quality: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    observation_window: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class StateTransitionRecordModel(Base):
    __tablename__ = "state_transition_records"
    __table_args__ = (
        Index("ix_transitions_host_observed", "host_id", "observed_at"),
        Index(
            "ix_transitions_host_object_time", "host_id", "category", "object_key", "observed_at"
        ),
    )

    transition_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    object_key: Mapped[str] = mapped_column(String(512), index=True)
    transition_type: Mapped[str] = mapped_column(String(64), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    old_state: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    new_state: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    changed_fields: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    capture_method: Mapped[str] = mapped_column(String(128), nullable=False)
    collector_health: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    snapshot_before_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("state_snapshots.snapshot_id")
    )
    snapshot_after_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("state_snapshots.snapshot_id")
    )
    delta_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("state_deltas.delta_id"), index=True
    )
    sequence_number: Mapped[int | None] = mapped_column(Integer)
    raw_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class TransitionMonitorHealthRecord(Base):
    __tablename__ = "transition_monitor_health"
    __table_args__ = (
        Index("ix_transition_health_host_category_time", "host_id", "category", "observed_at"),
    )

    health_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    monitor_id: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    capture_method: Mapped[str] = mapped_column(String(128), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    coverage_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    coverage_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    baseline_established: Mapped[bool] = mapped_column(Boolean, nullable=False)
    restart_count: Mapped[int] = mapped_column(Integer, nullable=False)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    message: Mapped[str | None] = mapped_column(Text)


class TransitionReconciliationRecord(Base):
    __tablename__ = "transition_reconciliations"

    reconciliation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    transition_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("state_transition_records.transition_id"), index=True
    )
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    status: Mapped[str] = mapped_column(String(40), index=True)
    matched_evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    match_reasons: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    missing_expected_evidence_types: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    observation_window: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    finalized: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    supersedes_reconciliation_id: Mapped[str | None] = mapped_column(String(36), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class NormalizedEventRecord(Base):
    __tablename__ = "normalized_events"

    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    normalized_type: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    target: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    source: Mapped[str] = mapped_column(String(128), index=True)
    source_reference: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    scenario_id: Mapped[str | None] = mapped_column(String(128), index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class TransientObservationRecord(Base):
    __tablename__ = "transient_observations"

    transient_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_pk)
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    event_id: Mapped[str] = mapped_column(String(128), index=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    normalized_type: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    target: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class EvidenceItemRecord(Base):
    __tablename__ = "evidence_items"

    evidence_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    evidence_type: Mapped[str] = mapped_column(String(128), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    content: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    source_reference: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class ReconciliationResultRecord(Base):
    __tablename__ = "reconciliation_results"

    reconciliation_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_pk)
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    delta_id: Mapped[str | None] = mapped_column(String(36), index=True)
    finding_id: Mapped[str | None] = mapped_column(String(36), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    matched_evidence_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    match_reasons: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    missing_expected_evidence_types: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    observation_window: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    finalized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    supersedes_reconciliation_id: Mapped[str | None] = mapped_column(String(36), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class FindingRecord(Base):
    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_pk)
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    observation_kind: Mapped[str] = mapped_column(String(32), index=True)
    delta_id: Mapped[str | None] = mapped_column(String(36), index=True)
    delta_idempotency_key: Mapped[str | None] = mapped_column(String(36))
    transient_id: Mapped[str | None] = mapped_column(String(36), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    object_key: Mapped[str | None] = mapped_column(String(512), index=True)
    reconciliation: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    authorization_status: Mapped[str] = mapped_column(String(32), index=True)
    authorization_reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class IncidentRecord(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_pk)
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_activity_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    context_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    categories: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    object_keys: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    entity_keys: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    host: Mapped[HostRecord] = relationship(back_populates="incidents")
    finding_assignments: Mapped[list[IncidentFindingRecord]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
    )


class IncidentFindingRecord(Base):
    __tablename__ = "incident_findings"

    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        primary_key=True,
    )
    finding_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("findings.finding_id", ondelete="CASCADE"),
        primary_key=True,
        unique=True,
        index=True,
    )
    assignment_score: Mapped[int] = mapped_column(Integer, nullable=False)
    assignment_reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    incident: Mapped[IncidentRecord] = relationship(back_populates="finding_assignments")


class AuthorizedObjectRecord(Base):
    __tablename__ = "authorized_objects"

    authorization_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_pk)
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    object_key: Mapped[str] = mapped_column(String(512), index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class MaintenanceWindowRecord(Base):
    __tablename__ = "maintenance_windows"

    window_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    categories: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    object_keys: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)


class ExperimentScenarioRecord(Base):
    __tablename__ = "experiment_scenarios"

    scenario_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    classification: Mapped[str] = mapped_column(String(64), nullable=False)
    initial_state_fixture: Mapped[str] = mapped_column(String(255), nullable=False)
    resulting_state_fixture: Mapped[str | None] = mapped_column(String(255))
    event_fixture_set: Mapped[str] = mapped_column(String(255), nullable=False)
    expected_deltas: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    expected_reconciliation: Mapped[str] = mapped_column(String(32), nullable=False)
    ground_truth_notes: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class ExperimentRunRecord(Base):
    __tablename__ = "experiment_runs"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_pk)
    scenario_id: Mapped[str] = mapped_column(String(128), index=True)
    host_id: Mapped[str] = mapped_column(String(128), ForeignKey("hosts.host_id"), index=True)
    ground_truth_classification: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    provider_configuration: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    expected_observations: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    actual_observations: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    reconciliation_result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    risk_score: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    detection_timestamps: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failure_reason: Mapped[str | None] = mapped_column(Text)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class AIAnalysisRecordModel(Base):
    __tablename__ = "ai_analyses"

    analysis_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_pk)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.finding_id"), index=True
    )
    incident_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("incidents.incident_id"), index=True
    )
    context_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    context_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="full_context")
    evidence_package_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    parent_analysis_id: Mapped[str | None] = mapped_column(String(36), index=True)
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    response_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    validation_errors: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


Index(
    "ix_state_objects_host_category_key",
    StateObjectRecord.host_id,
    StateObjectRecord.category,
    StateObjectRecord.object_key,
)
Index("ix_deltas_host_created", StateDeltaRecord.host_id, StateDeltaRecord.created_at)
Index("ix_events_host_time", NormalizedEventRecord.host_id, NormalizedEventRecord.event_time)
Index("ix_findings_host_created", FindingRecord.host_id, FindingRecord.created_at)
Index("uq_findings_delta_idempotency_key", FindingRecord.delta_idempotency_key, unique=True)
Index("ix_incidents_host_activity", IncidentRecord.host_id, IncidentRecord.last_activity_at)
