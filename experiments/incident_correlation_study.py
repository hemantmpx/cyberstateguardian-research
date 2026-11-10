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
from csg.domain.enums import (
    AuthorizationStatus,
    DeltaType,
    ObservationKind,
    ReconciliationStatus,
    Severity,
)
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

ROOT = Path(__file__).resolve().parents[1]


def pairwise_correlation_metrics(
    truth: dict[str, str],
    predicted: dict[str, str],
) -> dict[str, float | int | None]:
    if set(truth) != set(predicted):
        raise ValueError("truth and predictions must contain identical finding IDs")
    ids = sorted(truth)
    true_positive = false_positive = false_negative = true_negative = 0
    for index, left in enumerate(ids):
        for right in ids[index + 1 :]:
            same_truth = truth[left] == truth[right]
            same_prediction = predicted[left] == predicted[right]
            if same_truth and same_prediction:
                true_positive += 1
            elif not same_truth and same_prediction:
                false_positive += 1
            elif same_truth and not same_prediction:
                false_negative += 1
            else:
                true_negative += 1
    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    return {
        "pairwise_precision": round(true_positive / precision_denominator, 4)
        if precision_denominator
        else None,
        "pairwise_recall": round(true_positive / recall_denominator, 4)
        if recall_denominator
        else None,
        "false_merge_pairs": false_positive,
        "false_split_pairs": false_negative,
        "true_positive_pairs": true_positive,
        "true_negative_pairs": true_negative,
        "finding_count": len(ids),
    }


def run_study() -> dict[str, object]:
    with TemporaryDirectory(prefix="csg-correlation-") as directory:
        engine = create_engine(f"sqlite:///{directory}/study.db")
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            repo = CyberStateRepository(session)
            repo.upsert_host(
                Host(
                    host_id="correlation-lab",
                    hostname="correlation-lab",
                    role="research-fixture",
                    os="Windows 11",
                    architecture="arm64",
                )
            )
            settings = Settings(
                CSG_AUTHORIZED_STATE_PATH=ROOT / "config/authorized-state.example.yaml",
                CSG_RISK_RULES_PATH=ROOT / "config/risk-rules.yaml",
                CSG_INCIDENT_CORRELATION_MIN_SCORE=40,
            )
            service = IncidentCorrelationService(settings)
            anchor = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
            cases = [
                ("attack-a-service", "attack-a", "service", "service:evil", "c:/lab/evil.exe", 0),
                (
                    "attack-a-listener",
                    "attack-a",
                    "listener",
                    "listener:tcp:0.0.0.0:8443",
                    "c:/lab/evil.exe",
                    120,
                ),
                (
                    "attack-a-task",
                    "attack-a",
                    "scheduled_task",
                    "scheduled_task:updater",
                    "c:/lab/evil.exe",
                    180,
                ),
                (
                    "attack-a-registry",
                    "attack-a",
                    "registry",
                    "registry:evil-run",
                    "c:/lab/evil.exe",
                    240,
                ),
                (
                    "benign-b-service",
                    "benign-b",
                    "service",
                    "service:legit",
                    "c:/lab/legit.exe",
                    1200,
                ),
                (
                    "benign-b-listener",
                    "benign-b",
                    "listener",
                    "listener:tcp:127.0.0.1:8080",
                    "c:/lab/legit.exe",
                    1320,
                ),
                (
                    "benign-b-task",
                    "benign-b",
                    "scheduled_task",
                    "scheduled_task:backup",
                    "c:/lab/legit.exe",
                    1440,
                ),
                (
                    "benign-b-registry",
                    "benign-b",
                    "registry",
                    "registry:legit-run",
                    "c:/lab/legit.exe",
                    1560,
                ),
                (
                    "attack-c-service",
                    "attack-c",
                    "service",
                    "service:second-stage",
                    "c:/lab/second.exe",
                    2400,
                ),
                (
                    "attack-c-listener",
                    "attack-c",
                    "listener",
                    "listener:tcp:0.0.0.0:9001",
                    "c:/lab/second.exe",
                    2520,
                ),
                (
                    "attack-c-task",
                    "attack-c",
                    "scheduled_task",
                    "scheduled_task:second-stage",
                    "c:/lab/second.exe",
                    2640,
                ),
                (
                    "attack-c-registry",
                    "attack-c",
                    "registry",
                    "registry:second-run",
                    "c:/lab/second.exe",
                    2760,
                ),
                (
                    "benign-d-service",
                    "benign-d",
                    "service",
                    "service:maintenance",
                    "c:/lab/maintenance.exe",
                    3600,
                ),
                (
                    "benign-d-listener",
                    "benign-d",
                    "listener",
                    "listener:tcp:127.0.0.1:9090",
                    "c:/lab/maintenance.exe",
                    3720,
                ),
                (
                    "benign-d-task",
                    "benign-d",
                    "scheduled_task",
                    "scheduled_task:maintenance",
                    "c:/lab/maintenance.exe",
                    3840,
                ),
                (
                    "benign-d-registry",
                    "benign-d",
                    "registry",
                    "registry:maintenance-run",
                    "c:/lab/maintenance.exe",
                    3960,
                ),
            ]
            truth: dict[str, str] = {}
            predicted: dict[str, str] = {}
            assignments: list[dict[str, object]] = []
            for label, truth_group, category, object_key, executable, offset in cases:
                finding = _persist_finding(
                    repo,
                    label=label,
                    category=category,
                    object_key=object_key,
                    executable=executable,
                    created_at=anchor + timedelta(seconds=offset),
                )
                incident = service.assign_finding(repo, finding)
                truth[finding.finding_id] = truth_group
                predicted[finding.finding_id] = incident.incident_id
                assignment = repo.list_incident_assignments(incident.incident_id)[-1]
                assignments.append(
                    {
                        "label": label,
                        "truth_group": truth_group,
                        "incident_id": incident.incident_id,
                        "score": assignment.assignment_score,
                        "reasons": assignment.assignment_reasons,
                    }
                )
            return {
                "study": "deterministic_incident_correlation",
                "configuration": {
                    "minimum_score": settings.incident_correlation_min_score,
                    "temporal_points": 25,
                    "same_category_points": 10,
                    "shared_entity_points": 15,
                },
                "metrics": pairwise_correlation_metrics(truth, predicted),
                "assignments": assignments,
                "limitations": [
                    "Controlled labeled fixture, not a real-world correlation accuracy estimate.",
                    "Publication results require repeated live attack sequences and "
                    "human-labeled incidents.",
                ],
            }


def _persist_finding(
    repo: CyberStateRepository,
    *,
    label: str,
    category: str,
    object_key: str,
    executable: str,
    created_at: datetime,
) -> Finding:
    window = TimeWindow(start=created_at, end=created_at)
    delta = StateDelta(
        host_id="correlation-lab",
        category=category,
        object_key=object_key,
        delta_type=DeltaType.ADD,
        after=StateObject(
            category=category,
            object_key=object_key,
            attributes={"executable_path": executable, "label": label},
            source_timestamp=created_at,
        ),
        observation_window=window,
        created_at=created_at,
    )
    repo.create_deltas([delta])
    finding = Finding(
        host_id=delta.host_id,
        observation_kind=ObservationKind.STATE_DELTA,
        delta_id=delta.delta_id,
        category=category,
        object_key=object_key,
        reconciliation=ReconciliationResult(
            host_id=delta.host_id,
            delta_id=delta.delta_id,
            status=ReconciliationStatus.UNEXPLAINED,
            observation_window=window,
        ),
        authorization_status=AuthorizationStatus.UNKNOWN,
        authorization_reason="correlation study fixture",
        risk=RiskScore(total=40, severity=Severity.MEDIUM, rules_version="study"),
        created_at=created_at,
        metadata={"label": label},
    )
    return repo.create_finding(finding)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate deterministic incident correlation")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--labels", type=Path, help="JSON with truth and predicted finding-to-incident maps"
    )
    args = parser.parse_args()
    if args.labels:
        labels = json.loads(args.labels.read_text())
        payload = {"metrics": pairwise_correlation_metrics(labels["truth"], labels["predicted"])}
    else:
        payload = run_study()
    rendered = json.dumps(payload, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{rendered}\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
