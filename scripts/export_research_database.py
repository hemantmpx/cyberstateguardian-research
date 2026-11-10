"""Read-only, uncapped host export from one database transaction."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from sqlalchemy import select

from csg.db import models as orm
from csg.db.repositories import CyberStateRepository
from csg.db.session import SessionLocal
from csg.domain.models import ProbeObservation, utc_now


def export_host(repo: CyberStateRepository, host_id: str) -> dict:
    host = repo.get_host(host_id)
    if host is None:
        raise ValueError(f"unknown host: {host_id}")
    result = {
        "schema_version": "csg-database-research-export-v1",
        "exported_at": utc_now().isoformat(),
        "host": host.model_dump(mode="json"),
        "host_id": host_id,
        "retrieval_limit": None,
    }
    tables = {
        "observations": (
            orm.SourceObservationRecord,
            lambda row: ProbeObservation(
                observation_id=row.observation_id,
                host_id=row.host_id,
                source=row.source,
                observed_at=row.observed_at,
                categories=row.categories,
                metadata=row.metadata_json,
            ),
        ),
        "snapshots": (orm.StateSnapshotRecord, repo.snapshot_from_record),
        "events": (orm.NormalizedEventRecord, repo.event_from_record),
        "deltas": (orm.StateDeltaRecord, repo.delta_from_record),
        "findings": (orm.FindingRecord, repo.finding_from_record),
        "reconciliations": (orm.ReconciliationResultRecord, repo.reconciliation_from_record),
        "incidents": (orm.IncidentRecord, repo.incident_from_record),
    }
    for name, (model, convert) in tables.items():
        statement = (
            select(model)
            .where(model.host_id == host_id)
            .order_by(*model.__table__.primary_key.columns)
        )
        result[name] = [
            convert(row).model_dump(mode="json") for row in repo.session.scalars(statement)
        ]
    result["assignments"] = {
        incident["incident_id"]: [
            a.model_dump(mode="json")
            for a in repo.list_incident_assignments(incident["incident_id"])
        ]
        for incident in result["incidents"]
    }
    result["counts"] = {name: len(result[name]) for name in tables}
    result["content_sha256"] = hashlib.sha256(
        json.dumps(result, sort_keys=True).encode()
    ).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description="Uncapped consistent database evidence export")
    parser.add_argument("host_id")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    with SessionLocal() as session:
        dialect = session.get_bind().dialect.name
        connection = session.connection(
            execution_options={
                "isolation_level": "REPEATABLE READ" if dialect == "postgresql" else "SERIALIZABLE"
            }
        )
        if dialect == "postgresql":
            connection.exec_driver_sql("SET TRANSACTION READ ONLY")
        elif dialect == "sqlite":
            connection.exec_driver_sql("BEGIN")
        result = export_host(CyberStateRepository(session), args.host_id)
        session.rollback()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
