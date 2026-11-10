from __future__ import annotations

import hashlib
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from csg.db import models as orm
from csg.domain.models import (
    AIAnalysisRecord,
    CategoryStatus,
    EvidenceItem,
    ExperimentRun,
    ExperimentScenario,
    Finding,
    Host,
    Incident,
    IncidentFindingAssignment,
    NormalizedEvent,
    ProbeObservation,
    ReconciliationResult,
    StateDelta,
    StateObject,
    StateSnapshot,
    StateTransitionRecord,
    TimeWindow,
    TransientObservation,
    TransitionMonitorHealth,
    TransitionReconciliationResult,
    ensure_utc,
)

_EVENT_INSERT_BATCH_SIZE = 500

_INGESTION_LOCKS: dict[str, threading.RLock] = {}
_INGESTION_LOCKS_GUARD = threading.Lock()


def _dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


class CyberStateRepository:
    def __init__(self, session: Session):
        self.session = session

    @contextmanager
    def host_source_ingestion_lock(self, host_id: str, source: str) -> Iterator[None]:
        bind = self.session.get_bind()
        url = bind.url.render_as_string(hide_password=True)
        scope = f"csg-ingest:{url}:{host_id}:{source}"
        if bind.dialect.name == "postgresql":
            lock_id = int.from_bytes(
                hashlib.blake2b(scope.encode("utf-8"), digest_size=8).digest(),
                byteorder="big",
                signed=True,
            )
            connection = bind.connect()
            acquired = False
            try:
                connection.execute(text("SELECT pg_advisory_lock(:lock_id)"), {"lock_id": lock_id})
                acquired = True
                yield
            finally:
                if acquired:
                    try:
                        released = connection.execute(
                            text("SELECT pg_advisory_unlock(:lock_id)"),
                            {"lock_id": lock_id},
                        ).scalar_one()
                        connection.commit()
                        if not released:
                            raise RuntimeError("PostgreSQL ingestion lock was not held")
                    except Exception:
                        connection.invalidate()
                        raise
                connection.close()
            return

        lock_key = f"{url}:{host_id}:{source}"
        with _INGESTION_LOCKS_GUARD:
            lock = _INGESTION_LOCKS.setdefault(lock_key, threading.RLock())
        with lock:
            yield

    def upsert_host(self, host: Host) -> Host:
        record = self.session.get(orm.HostRecord, host.host_id)
        data = host.model_dump()
        if record is None:
            record = orm.HostRecord(**data)
            self.session.add(record)
        else:
            for key, value in data.items():
                setattr(record, key, value)
        self.session.commit()
        return self.host_from_record(record)

    def list_hosts(self) -> list[Host]:
        records = self.session.scalars(
            select(orm.HostRecord).order_by(orm.HostRecord.host_id)
        ).all()
        return [self.host_from_record(record) for record in records]

    def get_host(self, host_id: str) -> Host | None:
        record = self.session.get(orm.HostRecord, host_id)
        return self.host_from_record(record) if record else None

    def create_source_observation(self, observation: ProbeObservation) -> ProbeObservation:
        self.ensure_host(observation.host_id)
        record = orm.SourceObservationRecord(
            observation_id=observation.observation_id,
            host_id=observation.host_id,
            observed_at=observation.observed_at,
            source=observation.source,
            categories={
                key: value.model_dump(mode="json") for key, value in observation.categories.items()
            },
            metadata_json=observation.metadata,
        )
        self.session.merge(record)
        self.session.commit()
        return observation

    def latest_source_observation(self, host_id: str) -> ProbeObservation | None:
        record = self.session.scalars(
            select(orm.SourceObservationRecord)
            .where(orm.SourceObservationRecord.host_id == host_id)
            .order_by(orm.SourceObservationRecord.observed_at.desc())
            .limit(1),
        ).first()
        if record is None:
            return None
        return ProbeObservation(
            observation_id=record.observation_id,
            host_id=record.host_id,
            observed_at=record.observed_at,
            source=record.source,
            categories=record.categories,
            metadata=record.metadata_json,
        )

    def create_snapshot(self, snapshot: StateSnapshot) -> StateSnapshot:
        self.ensure_host(snapshot.host_id)
        record = orm.StateSnapshotRecord(
            snapshot_id=snapshot.snapshot_id,
            host_id=snapshot.host_id,
            built_at=snapshot.built_at,
            ingested_at=datetime.now(UTC),
            source=snapshot.source,
            category_statuses=[
                status.model_dump(mode="json") for status in snapshot.category_statuses
            ],
            metadata_json=snapshot.metadata,
        )
        for obj in snapshot.objects:
            record.objects.append(
                orm.StateObjectRecord(
                    host_id=snapshot.host_id,
                    category=obj.category,
                    object_key=obj.object_key,
                    attributes=obj.attributes,
                    source_timestamp=obj.source_timestamp,
                    metadata_json=obj.metadata,
                ),
            )
        self.session.add(record)
        self.session.commit()
        return snapshot

    def latest_snapshot(self, host_id: str) -> StateSnapshot | None:
        record = self.session.scalars(
            select(orm.StateSnapshotRecord)
            .where(orm.StateSnapshotRecord.host_id == host_id)
            .order_by(orm.StateSnapshotRecord.built_at.desc())
            .limit(1),
        ).first()
        return self.snapshot_from_record(record) if record else None

    def latest_snapshot_by_source(
        self,
        host_id: str,
        source: str,
    ) -> StateSnapshot | None:
        ordering = (
            orm.StateSnapshotRecord.ingested_at.desc()
            if source == "direct_probe"
            else orm.StateSnapshotRecord.built_at.desc()
        )
        record = self.session.scalars(
            select(orm.StateSnapshotRecord)
            .where(
                orm.StateSnapshotRecord.host_id == host_id,
                orm.StateSnapshotRecord.source == source,
            )
            .order_by(ordering)
            .limit(1),
        ).first()
        return self.snapshot_from_record(record) if record else None

    def snapshots_for_trajectory_interval(
        self,
        host_id: str,
        start: datetime,
        end: datetime,
        *,
        source: str = "direct_probe",
        limit: int = 500,
    ) -> list[StateSnapshot]:
        if end < start:
            raise ValueError("trajectory interval end must not precede start")
        prior = self.session.scalars(
            select(orm.StateSnapshotRecord)
            .where(
                orm.StateSnapshotRecord.host_id == host_id,
                orm.StateSnapshotRecord.source == source,
                orm.StateSnapshotRecord.built_at < start,
            )
            .order_by(orm.StateSnapshotRecord.built_at.desc())
            .limit(1),
        ).first()
        within = self.session.scalars(
            select(orm.StateSnapshotRecord)
            .where(
                orm.StateSnapshotRecord.host_id == host_id,
                orm.StateSnapshotRecord.source == source,
                orm.StateSnapshotRecord.built_at >= start,
                orm.StateSnapshotRecord.built_at <= end,
            )
            .order_by(orm.StateSnapshotRecord.built_at)
            .limit(limit + 1),
        ).all()
        records = ([prior] if prior else []) + within
        unique = {record.snapshot_id: record for record in records}
        ordered = sorted(
            unique.values(),
            key=lambda record: (ensure_utc(record.built_at), record.snapshot_id),
        )
        return [self.snapshot_from_record(record) for record in ordered]

    def create_transition_records(
        self,
        transitions: Iterable[StateTransitionRecord],
        *,
        commit: bool = True,
    ) -> tuple[list[StateTransitionRecord], int]:
        unique = {item.transition_id: item for item in transitions}
        if not unique:
            return [], 0
        ids = list(unique)
        existing = set(
            self.session.scalars(
                select(orm.StateTransitionRecordModel.transition_id).where(
                    orm.StateTransitionRecordModel.transition_id.in_(ids)
                )
            ).all()
        )
        rows = []
        for item in unique.values():
            self.ensure_host(item.host_id)
            rows.append(
                {
                    "transition_id": item.transition_id,
                    "host_id": item.host_id,
                    "category": item.category,
                    "object_key": item.object_key,
                    "transition_type": item.transition_type,
                    "observed_at": item.observed_at,
                    "received_at": item.received_at,
                    "window_start": item.window_start,
                    "window_end": item.window_end,
                    "old_state": item.old_state,
                    "new_state": item.new_state,
                    "changed_fields": item.changed_fields,
                    "source": item.source,
                    "capture_method": item.capture_method,
                    "collector_health": item.collector_health,
                    "snapshot_before_id": item.snapshot_before_id,
                    "snapshot_after_id": item.snapshot_after_id,
                    "delta_id": item.delta_id,
                    "sequence_number": item.sequence_number,
                    "raw_metadata": item.raw_metadata,
                }
            )
        dialect = self.session.get_bind().dialect.name
        if dialect == "postgresql":
            statement = postgresql_insert(orm.StateTransitionRecordModel).values(rows)
            self.session.execute(statement.on_conflict_do_nothing(index_elements=["transition_id"]))
        elif dialect == "sqlite":
            statement = sqlite_insert(orm.StateTransitionRecordModel).values(rows)
            self.session.execute(statement.on_conflict_do_nothing(index_elements=["transition_id"]))
        else:
            for row in rows:
                self.session.merge(orm.StateTransitionRecordModel(**row))
        if commit:
            self.session.commit()
        stored = self.session.scalars(
            select(orm.StateTransitionRecordModel).where(
                orm.StateTransitionRecordModel.transition_id.in_(ids)
            )
        ).all()
        by_id = {item.transition_id: self.transition_from_record(item) for item in stored}
        result = [by_id[key] for key in ids if key in by_id]
        return result, sum(1 for key in ids if key not in existing)

    def get_transition_record(self, transition_id: str) -> StateTransitionRecord | None:
        record = self.session.get(orm.StateTransitionRecordModel, transition_id)
        return self.transition_from_record(record) if record else None

    def list_transition_records(
        self,
        host_id: str,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        category: str | None = None,
        object_key: str | None = None,
        reconciliation_status: str | None = None,
        limit: int = 200,
    ) -> list[StateTransitionRecord]:
        statement = select(orm.StateTransitionRecordModel).where(
            orm.StateTransitionRecordModel.host_id == host_id
        )
        if start is not None:
            statement = statement.where(orm.StateTransitionRecordModel.observed_at >= start)
        if end is not None:
            statement = statement.where(orm.StateTransitionRecordModel.observed_at <= end)
        if category:
            statement = statement.where(orm.StateTransitionRecordModel.category == category)
        if object_key:
            statement = statement.where(orm.StateTransitionRecordModel.object_key == object_key)
        if reconciliation_status:
            latest_versions = (
                select(
                    orm.TransitionReconciliationRecord.transition_id,
                    func.max(orm.TransitionReconciliationRecord.version).label("latest_version"),
                )
                .group_by(orm.TransitionReconciliationRecord.transition_id)
                .subquery()
            )
            statement = (
                statement.join(
                    latest_versions,
                    latest_versions.c.transition_id == orm.StateTransitionRecordModel.transition_id,
                )
                .join(
                    orm.TransitionReconciliationRecord,
                    and_(
                        orm.TransitionReconciliationRecord.transition_id
                        == latest_versions.c.transition_id,
                        orm.TransitionReconciliationRecord.version
                        == latest_versions.c.latest_version,
                    ),
                )
                .where(orm.TransitionReconciliationRecord.status == reconciliation_status)
            )
        records = self.session.scalars(
            statement.order_by(
                orm.StateTransitionRecordModel.observed_at,
                orm.StateTransitionRecordModel.transition_id,
            ).limit(limit)
        ).all()
        return [self.transition_from_record(record) for record in records]

    def create_transition_monitor_health(
        self,
        records: Iterable[TransitionMonitorHealth],
        *,
        commit: bool = True,
    ) -> list[TransitionMonitorHealth]:
        items = list(records)
        for item in items:
            self.ensure_host(item.host_id)
            self.session.merge(
                orm.TransitionMonitorHealthRecord(
                    health_id=item.health_id,
                    host_id=item.host_id,
                    category=item.category,
                    monitor_id=item.monitor_id,
                    status=item.status,
                    capture_method=item.capture_method,
                    started_at=item.started_at,
                    observed_at=item.observed_at,
                    last_heartbeat_at=item.last_heartbeat_at,
                    coverage_start=item.coverage_start,
                    coverage_end=item.coverage_end,
                    baseline_established=item.baseline_established,
                    restart_count=item.restart_count,
                    metrics=item.metrics,
                    message=item.message,
                )
            )
        if items and commit:
            self.session.commit()
        return items

    def latest_transition_monitor_health(
        self,
        host_id: str,
    ) -> list[TransitionMonitorHealth]:
        records = self.session.scalars(
            select(orm.TransitionMonitorHealthRecord)
            .where(orm.TransitionMonitorHealthRecord.host_id == host_id)
            .order_by(
                orm.TransitionMonitorHealthRecord.observed_at.desc(),
                orm.TransitionMonitorHealthRecord.health_id,
            )
            .limit(500),
        ).all()
        latest: dict[tuple[str, str], orm.TransitionMonitorHealthRecord] = {}
        for record in records:
            latest.setdefault((record.category, record.monitor_id), record)
        return [self.monitor_health_from_record(item) for item in latest.values()]

    def transition_monitor_health_at(
        self,
        host_id: str,
        at: datetime,
    ) -> list[TransitionMonitorHealth]:
        records = self.session.scalars(
            select(orm.TransitionMonitorHealthRecord)
            .where(
                orm.TransitionMonitorHealthRecord.host_id == host_id,
                orm.TransitionMonitorHealthRecord.observed_at <= at,
            )
            .order_by(
                orm.TransitionMonitorHealthRecord.observed_at.desc(),
                orm.TransitionMonitorHealthRecord.health_id,
            )
            .limit(500),
        ).all()
        latest: dict[tuple[str, str], orm.TransitionMonitorHealthRecord] = {}
        for record in records:
            latest.setdefault((record.category, record.monitor_id), record)
        return [self.monitor_health_from_record(item) for item in latest.values()]

    def create_transition_reconciliation(
        self,
        result: TransitionReconciliationResult,
    ) -> TransitionReconciliationResult:
        self.session.add(
            orm.TransitionReconciliationRecord(
                reconciliation_id=result.reconciliation_id,
                transition_id=result.transition_id,
                host_id=result.host_id,
                status=result.status.value,
                matched_evidence_ids=result.matched_evidence_ids,
                match_reasons=result.match_reasons,
                missing_expected_evidence_types=result.missing_expected_evidence_types,
                observation_window=result.observation_window.model_dump(mode="json"),
                version=result.version,
                finalized=result.finalized,
                finalized_at=result.finalized_at,
                supersedes_reconciliation_id=result.supersedes_reconciliation_id,
                created_at=result.created_at,
                metadata_json=result.metadata,
            )
        )
        self.session.commit()
        return result

    def transition_reconciliation_history(
        self,
        transition_id: str,
    ) -> list[TransitionReconciliationResult]:
        records = self.session.scalars(
            select(orm.TransitionReconciliationRecord)
            .where(orm.TransitionReconciliationRecord.transition_id == transition_id)
            .order_by(
                orm.TransitionReconciliationRecord.version,
                orm.TransitionReconciliationRecord.created_at,
            )
        ).all()
        return [self.transition_reconciliation_from_record(record) for record in records]

    def latest_transition_reconciliations(
        self,
        transition_ids: Iterable[str],
    ) -> dict[str, TransitionReconciliationResult]:
        ids = list(set(transition_ids))
        if not ids:
            return {}
        latest_versions = (
            select(
                orm.TransitionReconciliationRecord.transition_id,
                func.max(orm.TransitionReconciliationRecord.version).label("latest_version"),
            )
            .where(orm.TransitionReconciliationRecord.transition_id.in_(ids))
            .group_by(orm.TransitionReconciliationRecord.transition_id)
            .subquery()
        )
        records = self.session.scalars(
            select(orm.TransitionReconciliationRecord).join(
                latest_versions,
                and_(
                    latest_versions.c.transition_id
                    == orm.TransitionReconciliationRecord.transition_id,
                    latest_versions.c.latest_version == orm.TransitionReconciliationRecord.version,
                ),
            )
        ).all()
        return {
            record.transition_id: self.transition_reconciliation_from_record(record)
            for record in records
        }

    def create_deltas(self, deltas: Iterable[StateDelta]) -> list[StateDelta]:
        delta_list = list(deltas)
        by_id: dict[str, StateDelta] = {}
        for delta in delta_list:
            by_id.setdefault(delta.delta_id, delta)
        if not by_id:
            return []
        records = []
        for delta in by_id.values():
            self.ensure_host(delta.host_id)
            records.append(
                {
                    "delta_id": delta.delta_id,
                    "host_id": delta.host_id,
                    "category": delta.category,
                    "object_key": delta.object_key,
                    "delta_type": delta.delta_type.value,
                    "before": _dump(delta.before),
                    "after": _dump(delta.after),
                    "source_quality": delta.source_quality,
                    "observation_window": delta.observation_window.model_dump(mode="json"),
                    "created_at": delta.created_at,
                    "metadata_json": delta.metadata,
                }
            )
        dialect = self.session.get_bind().dialect.name
        if dialect == "postgresql":
            statement = postgresql_insert(orm.StateDeltaRecord).values(records)
            self.session.execute(statement.on_conflict_do_nothing(index_elements=["delta_id"]))
        elif dialect == "sqlite":
            statement = sqlite_insert(orm.StateDeltaRecord).values(records)
            self.session.execute(statement.on_conflict_do_nothing(index_elements=["delta_id"]))
        else:
            for record in records:
                self.session.merge(orm.StateDeltaRecord(**record))
        self.session.commit()
        stored = self.session.scalars(
            select(orm.StateDeltaRecord).where(orm.StateDeltaRecord.delta_id.in_(by_id))
        ).all()
        stored_by_id = {record.delta_id: self.delta_from_record(record) for record in stored}
        return [stored_by_id[delta_id] for delta_id in by_id if delta_id in stored_by_id]

    def list_deltas(
        self,
        host_id: str,
        limit: int = 100,
        object_key: str | None = None,
        created_after: datetime | None = None,
        category: str | None = None,
    ) -> list[StateDelta]:
        statement = select(orm.StateDeltaRecord).where(orm.StateDeltaRecord.host_id == host_id)
        if object_key:
            statement = statement.where(orm.StateDeltaRecord.object_key == object_key)
        if created_after:
            statement = statement.where(orm.StateDeltaRecord.created_at >= created_after)
        if category:
            statement = statement.where(orm.StateDeltaRecord.category == category)
        records = self.session.scalars(
            statement.order_by(orm.StateDeltaRecord.created_at.desc()).limit(limit),
        ).all()
        return [self.delta_from_record(record) for record in records]

    def get_delta(self, delta_id: str) -> StateDelta | None:
        record = self.session.get(orm.StateDeltaRecord, delta_id)
        return self.delta_from_record(record) if record else None

    def list_deltas_without_findings(
        self,
        limit: int = 100,
        categories: Iterable[str] | None = None,
    ) -> list[StateDelta]:
        statement = (
            select(orm.StateDeltaRecord)
            .outerjoin(
                orm.FindingRecord,
                orm.FindingRecord.delta_id == orm.StateDeltaRecord.delta_id,
            )
            .where(orm.FindingRecord.finding_id.is_(None))
        )
        if categories is not None:
            category_list = list(categories)
            if not category_list:
                return []
            statement = statement.where(orm.StateDeltaRecord.category.in_(category_list))
        records = self.session.scalars(
            statement.order_by(orm.StateDeltaRecord.created_at).limit(limit),
        ).all()
        return [self.delta_from_record(record) for record in records]

    def create_events(self, events: Iterable[NormalizedEvent]) -> list[NormalizedEvent]:
        saved: list[NormalizedEvent] = []
        records: list[dict[str, Any]] = []
        ensured_hosts: set[str] = set()
        for event in events:
            if event.host_id not in ensured_hosts:
                self.ensure_host(event.host_id)
                ensured_hosts.add(event.host_id)
            records.append(
                {
                    "event_id": event.event_id,
                    "host_id": event.host_id,
                    "event_time": event.event_time,
                    "normalized_type": event.normalized_type,
                    "actor": event.actor,
                    "target": event.target,
                    "attributes": event.attributes,
                    "source": event.source,
                    "source_reference": event.source_reference,
                    "synthetic": event.synthetic,
                    "scenario_id": event.scenario_id,
                    "metadata_json": event.metadata,
                },
            )
            saved.append(event)
        if records:
            dialect = self.session.get_bind().dialect.name
            if dialect not in {"postgresql", "sqlite"}:
                for record in records:
                    self.session.merge(orm.NormalizedEventRecord(**record))
            else:
                insert = postgresql_insert if dialect == "postgresql" else sqlite_insert
                # Wazuh lookback queries intentionally redeliver stable event IDs.
                for offset in range(0, len(records), _EVENT_INSERT_BATCH_SIZE):
                    statement = insert(orm.NormalizedEventRecord).values(
                        records[offset : offset + _EVENT_INSERT_BATCH_SIZE]
                    )
                    excluded = statement.excluded
                    # Enrich a matching generic Wazuh row; never downgrade or replace a conflict.
                    statement = statement.on_conflict_do_update(
                        index_elements=[orm.NormalizedEventRecord.event_id],
                        set_={
                            "normalized_type": excluded.normalized_type,
                            "actor": excluded.actor,
                            "target": excluded.target,
                            "attributes": excluded.attributes,
                            "metadata_json": excluded.metadata_json,
                        },
                        where=and_(
                            orm.NormalizedEventRecord.source == "wazuh",
                            orm.NormalizedEventRecord.normalized_type == "wazuh_alert",
                            excluded.source == "wazuh",
                            excluded.normalized_type != "wazuh_alert",
                            orm.NormalizedEventRecord.host_id == excluded.host_id,
                            orm.NormalizedEventRecord.event_time == excluded.event_time,
                            orm.NormalizedEventRecord.source_reference["index"].as_string()
                            == excluded.source_reference["index"].as_string(),
                            orm.NormalizedEventRecord.source_reference[
                                "document_id"
                            ].as_string()
                            == excluded.source_reference["document_id"].as_string(),
                        ),
                    )
                    self.session.execute(statement)
        self.session.commit()
        return saved

    def get_events(
        self,
        host_id: str,
        start: datetime,
        end: datetime,
        *,
        normalized_type: str | None = None,
        source: str | None = None,
        object_key: str | None = None,
        object_name: str | None = None,
        limit: int | None = None,
    ) -> list[NormalizedEvent]:
        start = ensure_utc(start)
        end = ensure_utc(end)
        statement = select(orm.NormalizedEventRecord).where(
            orm.NormalizedEventRecord.host_id == host_id,
            orm.NormalizedEventRecord.event_time >= start,
            orm.NormalizedEventRecord.event_time <= end,
        )
        if normalized_type:
            statement = statement.where(
                orm.NormalizedEventRecord.normalized_type == normalized_type
            )
        if source:
            statement = statement.where(orm.NormalizedEventRecord.source == source)
        identity_filters = []
        if object_key:
            identity_filters.append(
                orm.NormalizedEventRecord.target["key"].as_string() == object_key
            )
        if object_name:
            pattern = f"%{object_name}%"
            identity_filters.extend(
                field.ilike(pattern)
                for field in (
                    orm.NormalizedEventRecord.target["key"].as_string(),
                    orm.NormalizedEventRecord.target["name"].as_string(),
                    orm.NormalizedEventRecord.attributes["service_name"].as_string(),
                    orm.NormalizedEventRecord.attributes["task_name"].as_string(),
                    orm.NormalizedEventRecord.attributes["target_object"].as_string(),
                )
            )
        if identity_filters:
            statement = statement.where(or_(*identity_filters))
        statement = statement.order_by(orm.NormalizedEventRecord.event_time)
        if limit is not None:
            statement = statement.limit(limit)
        records = self.session.scalars(statement).all()
        return [self.event_from_record(record) for record in records]

    def create_transients(
        self, transients: Iterable[TransientObservation]
    ) -> list[TransientObservation]:
        saved: list[TransientObservation] = []
        for transient in transients:
            self.session.merge(
                orm.TransientObservationRecord(
                    transient_id=transient.transient_id,
                    host_id=transient.host_id,
                    event_id=transient.event_id,
                    event_time=transient.event_time,
                    normalized_type=transient.normalized_type,
                    actor=transient.actor,
                    target=transient.target,
                    attributes=transient.attributes,
                    reason=transient.reason,
                    created_at=transient.created_at,
                    metadata_json=transient.metadata,
                ),
            )
            saved.append(transient)
        self.session.commit()
        return saved

    def create_evidence(self, evidence: Iterable[EvidenceItem]) -> list[EvidenceItem]:
        saved: list[EvidenceItem] = []
        records: list[dict[str, Any]] = []
        for item in evidence:
            records.append(
                {
                    "evidence_id": item.evidence_id,
                    "host_id": item.host_id,
                    "evidence_type": item.evidence_type,
                    "timestamp": item.timestamp,
                    "content": item.content,
                    "source_reference": item.source_reference,
                    "metadata_json": item.metadata,
                }
            )
            saved.append(item)
        if records:
            dialect = self.session.get_bind().dialect.name
            if dialect == "postgresql":
                insert = postgresql_insert
                parameter_limit = 60_000
            elif dialect == "sqlite":
                insert = sqlite_insert
                parameter_limit = 900
            else:
                for record in records:
                    self.session.merge(orm.EvidenceItemRecord(**record))
                insert = None
                parameter_limit = 0
            if insert is not None:
                batch_size = max(1, parameter_limit // len(records[0]))
                for offset in range(0, len(records), batch_size):
                    statement = insert(orm.EvidenceItemRecord).values(
                        records[offset : offset + batch_size]
                    )
                    statement = statement.on_conflict_do_nothing(
                        index_elements=[orm.EvidenceItemRecord.evidence_id],
                    )
                    self.session.execute(statement)
        self.session.commit()
        return saved

    def create_reconciliation(
        self, result: ReconciliationResult, *, commit: bool = True
    ) -> ReconciliationResult:
        self.session.merge(
            orm.ReconciliationResultRecord(
                reconciliation_id=result.reconciliation_id,
                host_id=result.host_id,
                delta_id=result.delta_id,
                finding_id=result.finding_id,
                status=result.status.value,
                matched_evidence_ids=result.matched_evidence_ids,
                match_reasons=result.match_reasons,
                missing_expected_evidence_types=result.missing_expected_evidence_types,
                observation_window=result.observation_window.model_dump(mode="json"),
                confidence=result.confidence,
                version=result.version,
                finalized=result.finalized,
                finalized_at=result.finalized_at,
                supersedes_reconciliation_id=result.supersedes_reconciliation_id,
                created_at=result.created_at,
                metadata_json=result.metadata,
            ),
        )
        if commit:
            self.session.commit()
        return result

    def save_reconciliation_revision(self, finding: Finding, previous_id: str) -> bool:
        """Compare-and-swap the finding and append history in the same transaction."""
        try:
            changed = self.session.execute(
                update(orm.FindingRecord)
                .where(
                    orm.FindingRecord.finding_id == finding.finding_id,
                    orm.FindingRecord.reconciliation["reconciliation_id"].as_string()
                    == previous_id,
                )
                .values(
                    reconciliation=finding.reconciliation.model_dump(mode="json"),
                    risk=finding.risk.model_dump(mode="json"),
                    metadata_json=finding.metadata,
                )
                .execution_options(synchronize_session=False)
            )
            if changed.rowcount != 1:
                self.session.rollback()
                return False
            self.create_reconciliation(finding.reconciliation, commit=False)
            self.session.commit()
            self.session.expire_all()
            return True
        except Exception:
            self.session.rollback()
            raise

    def list_reconciliations(
        self,
        *,
        delta_id: str | None = None,
        finding_id: str | None = None,
        limit: int = 100,
    ) -> list[ReconciliationResult]:
        statement = select(orm.ReconciliationResultRecord)
        if delta_id:
            statement = statement.where(orm.ReconciliationResultRecord.delta_id == delta_id)
        if finding_id:
            statement = statement.where(orm.ReconciliationResultRecord.finding_id == finding_id)
        records = self.session.scalars(
            statement.order_by(
                orm.ReconciliationResultRecord.version,
                orm.ReconciliationResultRecord.created_at,
            ).limit(limit)
        ).all()
        return [self.reconciliation_from_record(record) for record in records]

    def create_finding(self, finding: Finding) -> Finding:
        self.ensure_host(finding.host_id)
        if finding.delta_id:
            existing = self.get_finding_by_delta_id(finding.delta_id)
            if existing is not None:
                return existing
        record = orm.FindingRecord(
            finding_id=finding.finding_id,
            host_id=finding.host_id,
            observation_kind=finding.observation_kind.value,
            delta_id=finding.delta_id,
            delta_idempotency_key=finding.delta_id,
            transient_id=finding.transient_id,
            category=finding.category,
            object_key=finding.object_key,
            reconciliation=finding.reconciliation.model_dump(mode="json"),
            authorization_status=finding.authorization_status.value,
            authorization_reason=finding.authorization_reason,
            risk=finding.risk.model_dump(mode="json"),
            created_at=finding.created_at,
            metadata_json=finding.metadata,
        )
        try:
            self.session.add(record)
            self.session.commit()
            return finding
        except IntegrityError:
            self.session.rollback()
            if finding.delta_id:
                existing = self.get_finding_by_delta_id(finding.delta_id)
                if existing is not None:
                    return existing
            raise

    def get_finding_by_delta_id(self, delta_id: str) -> Finding | None:
        record = self.session.scalars(
            select(orm.FindingRecord)
            .where(orm.FindingRecord.delta_id == delta_id)
            .order_by(orm.FindingRecord.created_at.desc())
            .limit(1),
        ).first()
        return self.finding_from_record(record) if record else None

    def get_finding_by_transient_id(self, transient_id: str) -> Finding | None:
        record = self.session.scalars(
            select(orm.FindingRecord)
            .where(orm.FindingRecord.transient_id == transient_id)
            .order_by(orm.FindingRecord.created_at.desc())
            .limit(1),
        ).first()
        return self.finding_from_record(record) if record else None

    def list_findings(
        self,
        host_id: str | None = None,
        limit: int = 100,
        object_key: str | None = None,
        created_after: datetime | None = None,
        category: str | None = None,
    ) -> list[Finding]:
        statement = select(orm.FindingRecord).order_by(orm.FindingRecord.created_at.desc())
        if host_id:
            statement = statement.where(orm.FindingRecord.host_id == host_id)
        if object_key:
            statement = statement.where(orm.FindingRecord.object_key == object_key)
        if created_after:
            statement = statement.where(orm.FindingRecord.created_at >= created_after)
        if category:
            statement = statement.where(orm.FindingRecord.category == category)
        statement = statement.limit(limit)
        records = self.session.scalars(statement).all()
        return [self.finding_from_record(record) for record in records]

    def get_finding(self, finding_id: str) -> Finding | None:
        record = self.session.get(orm.FindingRecord, finding_id)
        return self.finding_from_record(record) if record else None

    def list_pending_reconciliation_findings(
        self,
        host_id: str | None = None,
        limit: int | None = None,
    ) -> list[Finding]:
        statement = select(orm.FindingRecord).where(
            orm.FindingRecord.reconciliation["finalized"].as_boolean().is_(False)
        )
        if host_id:
            statement = statement.where(orm.FindingRecord.host_id == host_id)
        statement = statement.order_by(orm.FindingRecord.created_at)
        if limit is not None:
            statement = statement.limit(limit)
        return [self.finding_from_record(row) for row in self.session.scalars(statement)]

    def findings_overlapping_events(self, events: list[NormalizedEvent]) -> list[Finding]:
        times: dict[str, list[datetime]] = {}
        for event in events:
            times.setdefault(event.host_id, []).append(event.event_time)
        if not times:
            return []
        statement = (
            select(orm.FindingRecord)
            .where(orm.FindingRecord.host_id.in_(times), orm.FindingRecord.delta_id.is_not(None))
            .order_by(orm.FindingRecord.finding_id)
        )
        findings = []
        for row in self.session.scalars(statement):
            finding = self.finding_from_record(row)
            window = finding.reconciliation.observation_window
            if any(window.start <= when <= window.end for when in times[finding.host_id]):
                findings.append(finding)
        return findings

    def list_unassigned_findings(self, limit: int = 100) -> list[Finding]:
        records = self.session.scalars(
            select(orm.FindingRecord)
            .outerjoin(
                orm.IncidentFindingRecord,
                orm.IncidentFindingRecord.finding_id == orm.FindingRecord.finding_id,
            )
            .where(orm.IncidentFindingRecord.finding_id.is_(None))
            .order_by(orm.FindingRecord.created_at)
            .limit(limit),
        ).all()
        return [self.finding_from_record(record) for record in records]

    def save_incident(self, incident: Incident) -> Incident:
        self.ensure_host(incident.host_id)
        record = self.session.get(orm.IncidentRecord, incident.incident_id)
        values = {
            "host_id": incident.host_id,
            "status": incident.status.value,
            "title": incident.title,
            "severity": incident.severity.value,
            "risk_score": incident.risk_score,
            "started_at": incident.started_at,
            "last_activity_at": incident.last_activity_at,
            "context_version": incident.context_version,
            "categories": incident.categories,
            "object_keys": incident.object_keys,
            "entity_keys": incident.entity_keys,
            "created_at": incident.created_at,
            "updated_at": incident.updated_at,
            "metadata_json": incident.metadata,
        }
        if record is None:
            record = orm.IncidentRecord(incident_id=incident.incident_id, **values)
            self.session.add(record)
        else:
            for key, value in values.items():
                setattr(record, key, value)
        self.session.commit()
        return self.incident_from_record(record)

    def get_incident(self, incident_id: str) -> Incident | None:
        record = self.session.get(orm.IncidentRecord, incident_id)
        return self.incident_from_record(record) if record else None

    def get_incident_for_finding(self, finding_id: str) -> Incident | None:
        record = self.session.scalars(
            select(orm.IncidentRecord)
            .join(
                orm.IncidentFindingRecord,
                orm.IncidentFindingRecord.incident_id == orm.IncidentRecord.incident_id,
            )
            .where(orm.IncidentFindingRecord.finding_id == finding_id)
            .limit(1),
        ).first()
        return self.incident_from_record(record) if record else None

    def list_incidents(
        self,
        host_id: str | None = None,
        status: str | None = None,
        active_after: datetime | None = None,
        limit: int = 100,
    ) -> list[Incident]:
        statement = select(orm.IncidentRecord)
        if host_id:
            statement = statement.where(orm.IncidentRecord.host_id == host_id)
        if status:
            statement = statement.where(orm.IncidentRecord.status == status)
        if active_after:
            statement = statement.where(
                orm.IncidentRecord.last_activity_at >= ensure_utc(active_after)
            )
        records = self.session.scalars(
            statement.order_by(orm.IncidentRecord.last_activity_at.desc()).limit(limit),
        ).all()
        return [self.incident_from_record(record) for record in records]

    def attach_finding_to_incident(
        self,
        assignment: IncidentFindingAssignment,
    ) -> IncidentFindingAssignment:
        existing = self.session.scalars(
            select(orm.IncidentFindingRecord).where(
                orm.IncidentFindingRecord.finding_id == assignment.finding_id
            )
        ).first()
        if existing is not None and existing.incident_id != assignment.incident_id:
            raise ValueError(
                f"finding {assignment.finding_id} is already assigned to {existing.incident_id}"
            )
        self.session.merge(
            orm.IncidentFindingRecord(
                incident_id=assignment.incident_id,
                finding_id=assignment.finding_id,
                assignment_score=assignment.assignment_score,
                assignment_reasons=assignment.assignment_reasons,
                created_at=assignment.created_at,
            )
        )
        self.session.commit()
        return assignment

    def list_incident_findings(self, incident_id: str) -> list[Finding]:
        records = self.session.scalars(
            select(orm.FindingRecord)
            .join(
                orm.IncidentFindingRecord,
                orm.IncidentFindingRecord.finding_id == orm.FindingRecord.finding_id,
            )
            .where(orm.IncidentFindingRecord.incident_id == incident_id)
            .order_by(orm.FindingRecord.created_at),
        ).all()
        return [self.finding_from_record(record) for record in records]

    def list_incident_assignments(self, incident_id: str) -> list[IncidentFindingAssignment]:
        records = self.session.scalars(
            select(orm.IncidentFindingRecord)
            .where(orm.IncidentFindingRecord.incident_id == incident_id)
            .order_by(orm.IncidentFindingRecord.created_at),
        ).all()
        return [
            IncidentFindingAssignment(
                incident_id=record.incident_id,
                finding_id=record.finding_id,
                assignment_score=record.assignment_score,
                assignment_reasons=record.assignment_reasons,
                created_at=record.created_at,
            )
            for record in records
        ]

    def create_scenario(self, scenario: ExperimentScenario) -> ExperimentScenario:
        self.session.merge(
            orm.ExperimentScenarioRecord(
                scenario_id=scenario.scenario_id,
                description=scenario.description,
                classification=scenario.classification,
                initial_state_fixture=scenario.initial_state_fixture,
                resulting_state_fixture=scenario.resulting_state_fixture,
                event_fixture_set=scenario.event_fixture_set,
                expected_deltas=scenario.expected_deltas,
                expected_reconciliation=scenario.expected_reconciliation.value,
                ground_truth_notes=scenario.ground_truth_notes,
                metadata_json=scenario.metadata,
            ),
        )
        self.session.commit()
        return scenario

    def create_experiment_run(self, run: ExperimentRun) -> ExperimentRun:
        self.ensure_host(run.host_id)
        self.session.merge(
            orm.ExperimentRunRecord(
                run_id=run.run_id,
                scenario_id=run.scenario_id,
                host_id=run.host_id,
                ground_truth_classification=run.ground_truth_classification,
                started_at=run.started_at,
                ended_at=run.ended_at,
                provider_configuration=run.provider_configuration,
                expected_observations=run.expected_observations,
                actual_observations=run.actual_observations,
                reconciliation_result=run.reconciliation_result,
                risk_score=run.risk_score,
                detection_timestamps=run.detection_timestamps,
                success=run.success,
                failure_reason=run.failure_reason,
                metrics=run.metrics,
            ),
        )
        self.session.commit()
        return run

    def list_experiment_runs(self, limit: int = 100) -> list[ExperimentRun]:
        records = self.session.scalars(
            select(orm.ExperimentRunRecord)
            .order_by(orm.ExperimentRunRecord.started_at.desc())
            .limit(limit),
        ).all()
        return [self.experiment_run_from_record(record) for record in records]

    def create_ai_analysis(self, analysis: AIAnalysisRecord) -> AIAnalysisRecord:
        self.session.merge(
            orm.AIAnalysisRecordModel(
                analysis_id=analysis.analysis_id,
                finding_id=analysis.finding_id,
                incident_id=analysis.incident_id,
                context_version=analysis.context_version,
                context_mode=analysis.context_mode.value,
                evidence_package_hash=analysis.evidence_package_hash,
                parent_analysis_id=analysis.parent_analysis_id,
                prompt_version=analysis.prompt_version,
                model=analysis.model,
                enabled=analysis.enabled,
                response_json=analysis.response_json,
                validation_errors=analysis.validation_errors,
                metadata_json=analysis.metadata,
                created_at=analysis.created_at,
            ),
        )
        self.session.commit()
        return analysis

    def list_ai_analyses(
        self,
        finding_id: str | None = None,
        incident_id: str | None = None,
        limit: int = 100,
    ) -> list[AIAnalysisRecord]:
        statement = select(orm.AIAnalysisRecordModel)
        if finding_id:
            statement = statement.where(orm.AIAnalysisRecordModel.finding_id == finding_id)
        if incident_id:
            statement = statement.where(orm.AIAnalysisRecordModel.incident_id == incident_id)
        records = self.session.scalars(
            statement.order_by(orm.AIAnalysisRecordModel.created_at.desc()).limit(limit),
        ).all()
        return [self.ai_analysis_from_record(record) for record in records]

    def ensure_host(self, host_id: str) -> None:
        if self.session.get(orm.HostRecord, host_id) is None:
            now = ensure_utc(datetime.now(UTC))
            self.session.add(
                orm.HostRecord(
                    host_id=host_id,
                    hostname=host_id,
                    role="unknown",
                    os="unknown",
                    architecture="unknown",
                    enabled=True,
                    created_at=now,
                    updated_at=now,
                ),
            )
            self.session.flush()

    @staticmethod
    def host_from_record(record: orm.HostRecord) -> Host:
        return Host.model_validate(
            {
                "host_id": record.host_id,
                "hostname": record.hostname,
                "role": record.role,
                "os": record.os,
                "architecture": record.architecture,
                "enabled": record.enabled,
                "created_at": record.created_at,
                "updated_at": record.updated_at,
            },
        )

    @staticmethod
    def snapshot_from_record(record: orm.StateSnapshotRecord) -> StateSnapshot:
        return StateSnapshot(
            snapshot_id=record.snapshot_id,
            host_id=record.host_id,
            built_at=record.built_at,
            source=record.source,
            category_statuses=[
                CategoryStatus.model_validate(item) for item in record.category_statuses
            ],
            objects=[
                StateObject(
                    category=obj.category,
                    object_key=obj.object_key,
                    attributes=obj.attributes,
                    source_timestamp=obj.source_timestamp,
                    metadata=obj.metadata_json,
                )
                for obj in record.objects
            ],
            metadata=record.metadata_json,
        )

    @staticmethod
    def delta_from_record(record: orm.StateDeltaRecord) -> StateDelta:
        return StateDelta(
            delta_id=record.delta_id,
            host_id=record.host_id,
            category=record.category,
            object_key=record.object_key,
            delta_type=record.delta_type,
            before=StateObject.model_validate(record.before) if record.before else None,
            after=StateObject.model_validate(record.after) if record.after else None,
            source_quality=record.source_quality,
            observation_window=TimeWindow.model_validate(record.observation_window),
            created_at=record.created_at,
            metadata=record.metadata_json,
        )

    @staticmethod
    def transition_from_record(record: orm.StateTransitionRecordModel) -> StateTransitionRecord:
        return StateTransitionRecord(
            transition_id=record.transition_id,
            host_id=record.host_id,
            category=record.category,
            object_key=record.object_key,
            transition_type=record.transition_type,
            observed_at=record.observed_at,
            received_at=record.received_at,
            window_start=record.window_start,
            window_end=record.window_end,
            old_state=record.old_state,
            new_state=record.new_state,
            changed_fields=record.changed_fields,
            source=record.source,
            capture_method=record.capture_method,
            collector_health=record.collector_health,
            snapshot_before_id=record.snapshot_before_id,
            snapshot_after_id=record.snapshot_after_id,
            delta_id=record.delta_id,
            sequence_number=record.sequence_number,
            raw_metadata=record.raw_metadata,
        )

    @staticmethod
    def monitor_health_from_record(
        record: orm.TransitionMonitorHealthRecord,
    ) -> TransitionMonitorHealth:
        return TransitionMonitorHealth(
            health_id=record.health_id,
            host_id=record.host_id,
            category=record.category,
            monitor_id=record.monitor_id,
            status=record.status,
            capture_method=record.capture_method,
            started_at=record.started_at,
            observed_at=record.observed_at,
            last_heartbeat_at=record.last_heartbeat_at,
            coverage_start=record.coverage_start,
            coverage_end=record.coverage_end,
            baseline_established=record.baseline_established,
            restart_count=record.restart_count,
            metrics=record.metrics,
            message=record.message,
        )

    @staticmethod
    def transition_reconciliation_from_record(
        record: orm.TransitionReconciliationRecord,
    ) -> TransitionReconciliationResult:
        return TransitionReconciliationResult(
            reconciliation_id=record.reconciliation_id,
            transition_id=record.transition_id,
            host_id=record.host_id,
            status=record.status,
            matched_evidence_ids=record.matched_evidence_ids,
            match_reasons=record.match_reasons,
            missing_expected_evidence_types=record.missing_expected_evidence_types,
            observation_window=TimeWindow.model_validate(record.observation_window),
            version=record.version,
            finalized=record.finalized,
            finalized_at=record.finalized_at,
            supersedes_reconciliation_id=record.supersedes_reconciliation_id,
            created_at=record.created_at,
            metadata=record.metadata_json,
        )

    @staticmethod
    def event_from_record(record: orm.NormalizedEventRecord) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=record.event_id,
            host_id=record.host_id,
            event_time=record.event_time,
            normalized_type=record.normalized_type,
            actor=record.actor,
            target=record.target,
            attributes=record.attributes,
            source=record.source,
            source_reference=record.source_reference,
            synthetic=record.synthetic,
            scenario_id=record.scenario_id,
            metadata=record.metadata_json,
        )

    @staticmethod
    def reconciliation_from_record(
        record: orm.ReconciliationResultRecord,
    ) -> ReconciliationResult:
        return ReconciliationResult(
            reconciliation_id=record.reconciliation_id,
            host_id=record.host_id,
            delta_id=record.delta_id,
            finding_id=record.finding_id,
            status=record.status,
            matched_evidence_ids=record.matched_evidence_ids,
            match_reasons=record.match_reasons,
            missing_expected_evidence_types=record.missing_expected_evidence_types,
            observation_window=record.observation_window,
            confidence=record.confidence,
            version=record.version,
            finalized=record.finalized,
            finalized_at=record.finalized_at,
            supersedes_reconciliation_id=record.supersedes_reconciliation_id,
            created_at=record.created_at,
            metadata=record.metadata_json,
        )

    @staticmethod
    def finding_from_record(record: orm.FindingRecord) -> Finding:
        return Finding(
            finding_id=record.finding_id,
            host_id=record.host_id,
            observation_kind=record.observation_kind,
            delta_id=record.delta_id,
            transient_id=record.transient_id,
            category=record.category,
            object_key=record.object_key,
            reconciliation=record.reconciliation,
            authorization_status=record.authorization_status,
            authorization_reason=record.authorization_reason,
            risk=record.risk,
            created_at=record.created_at,
            metadata=record.metadata_json,
        )

    @staticmethod
    def incident_from_record(record: orm.IncidentRecord) -> Incident:
        assignments = sorted(record.finding_assignments, key=lambda item: item.created_at)
        return Incident(
            incident_id=record.incident_id,
            host_id=record.host_id,
            status=record.status,
            title=record.title,
            severity=record.severity,
            risk_score=record.risk_score,
            started_at=record.started_at,
            last_activity_at=record.last_activity_at,
            context_version=record.context_version,
            finding_ids=[assignment.finding_id for assignment in assignments],
            categories=record.categories,
            object_keys=record.object_keys,
            entity_keys=record.entity_keys,
            created_at=record.created_at,
            updated_at=record.updated_at,
            metadata=record.metadata_json,
        )

    @staticmethod
    def ai_analysis_from_record(record: orm.AIAnalysisRecordModel) -> AIAnalysisRecord:
        return AIAnalysisRecord(
            analysis_id=record.analysis_id,
            finding_id=record.finding_id,
            incident_id=record.incident_id,
            context_version=record.context_version,
            context_mode=record.context_mode,
            evidence_package_hash=record.evidence_package_hash,
            parent_analysis_id=record.parent_analysis_id,
            prompt_version=record.prompt_version,
            model=record.model,
            enabled=record.enabled,
            response_json=record.response_json,
            validation_errors=record.validation_errors,
            metadata=record.metadata_json,
            created_at=record.created_at,
        )

    @staticmethod
    def experiment_run_from_record(record: orm.ExperimentRunRecord) -> ExperimentRun:
        return ExperimentRun(
            run_id=record.run_id,
            scenario_id=record.scenario_id,
            host_id=record.host_id,
            ground_truth_classification=record.ground_truth_classification,
            started_at=record.started_at,
            ended_at=record.ended_at,
            provider_configuration=record.provider_configuration,
            expected_observations=record.expected_observations,
            actual_observations=record.actual_observations,
            reconciliation_result=record.reconciliation_result,
            risk_score=record.risk_score,
            detection_timestamps=record.detection_timestamps,
            success=record.success,
            failure_reason=record.failure_reason,
            metrics=record.metrics,
        )
