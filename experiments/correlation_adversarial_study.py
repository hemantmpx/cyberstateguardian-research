"""Run deliberately difficult incident-correlation cases and report each assignment."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from csg.config import Settings
from csg.db.base import Base
from csg.db.repositories import CyberStateRepository
from csg.domain.enums import AuthorizationStatus, ObservationKind, ReconciliationStatus, Severity
from csg.domain.models import (
    Finding,
    Host,
    ReconciliationResult,
    RiskScore,
    StateDelta,
    StateObject,
    TimeWindow,
)
from csg.services.incident_correlation import IncidentCorrelationService
from experiments.incident_correlation_study import pairwise_correlation_metrics


def run_adversarial_study() -> dict[str, object]:
    with TemporaryDirectory(prefix="csg-correlation-adversarial-") as directory:
        engine = create_engine(f"sqlite:///{directory}/study.db")
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            repo = CyberStateRepository(session)
            repo.upsert_host(
                Host(
                    host_id="adversarial-lab",
                    hostname="adversarial-lab",
                    role="research-fixture",
                    os="Windows 11",
                    architecture="arm64",
                )
            )
            settings = Settings(
                CSG_AUTHORIZED_STATE_PATH=Path("config/authorized-state.example.yaml"),
                CSG_RISK_RULES_PATH=Path("config/risk-rules.yaml"),
                CSG_INCIDENT_CORRELATION_MIN_SCORE=40,
            )
            service = IncidentCorrelationService(settings)
            anchor = datetime(2026, 9, 22, 14, 0, tzinfo=UTC)
            cases = [
                (
                    "same-host-simultaneous-1",
                    "benign-admin",
                    "service",
                    "service:admin",
                    "c:/windows/system32/sc.exe",
                    0,
                ),
                (
                    "same-host-simultaneous-2",
                    "separate-attack",
                    "listener",
                    "listener:tcp:0.0.0.0:8443",
                    "c:/lab/payload.exe",
                    30,
                ),
                (
                    "same-attack-long-gap-1",
                    "long-attack",
                    "service",
                    "service:long-persistence",
                    "c:/lab/payload.exe",
                    1800,
                ),
                (
                    "same-attack-long-gap-2",
                    "long-attack",
                    "listener",
                    "listener:tcp:0.0.0.0:9001",
                    "c:/lab/payload.exe",
                    3000,
                ),
                (
                    "same-name-unrelated-1",
                    "name-one",
                    "service",
                    "service:name-one",
                    "c:/tools/update.exe",
                    4200,
                ),
                (
                    "same-name-unrelated-2",
                    "name-two",
                    "scheduled_task",
                    "scheduled_task:name-two",
                    "c:/tools/update.exe",
                    4230,
                ),
            ]
            truth, predicted, rows = {}, {}, []
            for label, group, category, object_key, executable, offset in cases:
                created = anchor + timedelta(seconds=offset)
                delta = StateDelta(
                    host_id="adversarial-lab",
                    category=category,
                    object_key=object_key,
                    delta_type="ADD",
                    after=StateObject(
                        category=category,
                        object_key=object_key,
                        attributes={"executable_path": executable, "process_name": executable},
                        source_timestamp=created,
                    ),
                    observation_window=TimeWindow(start=created, end=created),
                    created_at=created,
                )
                repo.create_deltas([delta])
                finding = repo.create_finding(
                    Finding(
                        host_id=delta.host_id,
                        observation_kind=ObservationKind.STATE_DELTA,
                        delta_id=delta.delta_id,
                        category=category,
                        object_key=object_key,
                        reconciliation=ReconciliationResult(
                            host_id=delta.host_id,
                            delta_id=delta.delta_id,
                            status=ReconciliationStatus.UNEXPLAINED,
                            observation_window=delta.observation_window,
                        ),
                        authorization_status=AuthorizationStatus.UNKNOWN,
                        authorization_reason="adversarial correlation fixture",
                        risk=RiskScore(total=40, severity=Severity.MEDIUM, rules_version="study"),
                        created_at=created,
                    )
                )
                incident = service.assign_finding(repo, finding)
                truth[finding.finding_id] = group
                predicted[finding.finding_id] = incident.incident_id
                rows.append(
                    {"label": label, "truth_group": group, "incident_id": incident.incident_id}
                )
            metrics = pairwise_correlation_metrics(truth, predicted)
            return {
                "schema_version": "csg-correlation-adversarial-v1",
                "study": "adversarial_incident_correlation",
                "cases": rows,
                "metrics": metrics,
                "case_design": [
                    "same host and time with unrelated processes",
                    "same attack with a longer gap",
                    "same executable name used by unrelated sequences",
                ],
                "limitation": "Synthetic adversarial labels; not a population estimate.",
            }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run adversarial incident-correlation study")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = run_adversarial_study()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
