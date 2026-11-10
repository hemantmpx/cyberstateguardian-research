from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import func, select

from csg.db import models as orm
from csg.db.repositories import CyberStateRepository
from csg.domain.models import EvidenceItem, NormalizedEvent


def test_repeated_event_ids_are_idempotent(db_session) -> None:
    repo = CyberStateRepository(db_session)
    event = NormalizedEvent(
        event_id="wazuh-stable-document-id",
        host_id="win11-arm-lab",
        event_time=datetime.now(UTC),
        normalized_type="service_modified",
        source="wazuh",
        target={"key": "service:csgresearchabc123"},
        attributes={"service_name": "CSGResearchABC123"},
    )

    repo.create_events([event, event])
    repo.create_events([event])

    stored = db_session.scalars(
        select(orm.NormalizedEventRecord).where(
            orm.NormalizedEventRecord.event_id == event.event_id
        )
    ).all()
    assert len(stored) == 1


def test_generic_wazuh_event_is_upgraded_by_matching_specific_normalization(db_session) -> None:
    repo = CyberStateRepository(db_session)
    event_time = datetime.now(UTC)
    source_reference = {"index": "wazuh-archives-test", "document_id": "record-5154"}
    generic = NormalizedEvent(
        event_id="wazuh-record-5154",
        host_id="win11-arm-lab",
        event_time=event_time,
        normalized_type="wazuh_alert",
        source="wazuh",
        source_reference=source_reference,
        attributes={"event_code": "5154"},
    )
    specific = generic.model_copy(
        update={
            "normalized_type": "listener_created",
            "target": {"key": "listener:tcp:127.0.0.1:49391"},
            "attributes": {
                "event_code": "5154",
                "protocol": "tcp",
                "local_address": "127.0.0.1",
                "local_port": 49391,
            },
        }
    )

    repo.create_events([generic])
    repo.create_events([specific])
    repo.create_events([generic])

    stored = db_session.get(orm.NormalizedEventRecord, generic.event_id)
    assert stored is not None
    assert stored.normalized_type == "listener_created"
    assert stored.target["key"] == "listener:tcp:127.0.0.1:49391"
    assert stored.attributes["local_port"] == 49391


def test_wazuh_event_enrichment_rejects_identity_conflicts(db_session) -> None:
    repo = CyberStateRepository(db_session)
    generic = NormalizedEvent(
        event_id="wazuh-conflicting-record",
        host_id="win11-arm-lab",
        event_time=datetime.now(UTC),
        normalized_type="wazuh_alert",
        source="wazuh",
        source_reference={"index": "wazuh-archives-test", "document_id": "raw-1"},
    )
    conflicting = generic.model_copy(
        update={
            "event_time": datetime.now(UTC),
            "normalized_type": "listener_created",
            "target": {"key": "listener:tcp:127.0.0.1:49391"},
        }
    )

    repo.create_events([generic])
    repo.create_events([conflicting])

    stored = db_session.get(orm.NormalizedEventRecord, generic.event_id)
    assert stored is not None
    assert stored.normalized_type == "wazuh_alert"
    assert stored.target == {}


def test_large_event_sync_is_inserted_in_postgres_safe_batches(db_session) -> None:
    repo = CyberStateRepository(db_session)
    event_parameter_counts: list[int] = []
    table_name = orm.NormalizedEventRecord.__tablename__

    def record_insert_size(_conn, _cursor, statement, parameters, _context, _many) -> None:
        if statement.lstrip().upper().startswith(f"INSERT INTO {table_name.upper()}"):
            event_parameter_counts.append(len(parameters))

    engine = db_session.get_bind()
    sqlalchemy_event.listen(engine, "before_cursor_execute", record_insert_size)
    try:
        observed_at = datetime.now(UTC)
        events = [
            NormalizedEvent(
                event_id=f"wazuh-large-sync-{index}",
                host_id="win11-arm-lab",
                event_time=observed_at,
                normalized_type="registry_value_modified",
                source="wazuh",
                target={"key": f"registry:test-{index}"},
            )
            for index in range(6_000)
        ]
        repo.create_events(events)
    finally:
        sqlalchemy_event.remove(engine, "before_cursor_execute", record_insert_size)

    stored_count = db_session.scalar(
        select(func.count())
        .select_from(orm.NormalizedEventRecord)
        .where(orm.NormalizedEventRecord.event_id.like("wazuh-large-sync-%"))
    )
    assert stored_count == 6_000
    assert len(event_parameter_counts) > 1
    assert max(event_parameter_counts) < 65_535


def test_repeated_evidence_ids_are_idempotent(db_session) -> None:
    repo = CyberStateRepository(db_session)
    evidence = EvidenceItem(
        evidence_id="wazuh-stable-evidence-id",
        host_id="win11-arm-lab",
        evidence_type="service_modified",
        timestamp=datetime.now(UTC),
        content={"target": {"key": "service:csgresearchabc123"}},
        source_reference={"index": "wazuh-alerts-4.x"},
        metadata={"source": "wazuh"},
    )

    repo.create_evidence([evidence, evidence])
    repo.create_evidence([evidence])

    stored = db_session.scalars(
        select(orm.EvidenceItemRecord).where(
            orm.EvidenceItemRecord.evidence_id == evidence.evidence_id
        )
    ).all()
    assert len(stored) == 1


def test_large_evidence_sync_is_inserted_in_backend_safe_batches(db_session) -> None:
    repo = CyberStateRepository(db_session)
    evidence_parameter_counts: list[int] = []
    table_name = orm.EvidenceItemRecord.__tablename__

    def record_insert_size(_conn, _cursor, statement, parameters, _context, _many) -> None:
        if statement.lstrip().upper().startswith(f"INSERT INTO {table_name.upper()}"):
            evidence_parameter_counts.append(len(parameters))

    engine = db_session.get_bind()
    sqlalchemy_event.listen(engine, "before_cursor_execute", record_insert_size)
    try:
        observed_at = datetime.now(UTC)
        evidence = [
            EvidenceItem(
                evidence_id=f"wazuh-large-evidence-{index}",
                host_id="win11-arm-lab",
                evidence_type="wazuh_alert",
                timestamp=observed_at,
                content={"event_index": index},
                source_reference={"index": "wazuh-archives-test", "document_id": str(index)},
                metadata={"source": "wazuh"},
            )
            for index in range(10_000)
        ]
        repo.create_evidence(evidence)
    finally:
        sqlalchemy_event.remove(engine, "before_cursor_execute", record_insert_size)

    stored_count = db_session.scalar(
        select(func.count())
        .select_from(orm.EvidenceItemRecord)
        .where(orm.EvidenceItemRecord.evidence_id.like("wazuh-large-evidence-%"))
    )
    assert stored_count == 10_000
    assert len(evidence_parameter_counts) > 1
    assert max(evidence_parameter_counts) < 65_535
