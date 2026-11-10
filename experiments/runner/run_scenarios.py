from __future__ import annotations

import argparse
import csv
import json
import statistics
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from csg.domain.enums import AuthorizationStatus, ObservationKind, ReconciliationStatus
from csg.domain.models import (
    ExperimentRun,
    ExperimentScenario,
    Finding,
    NormalizedEvent,
    ReconciliationResult,
    StateSnapshot,
    TimeWindow,
    ensure_utc,
)
from csg.services.authorization import AuthorizationService
from csg.services.reconciliation import ReconciliationEngine
from csg.services.risk import RiskEngine
from csg.state.diff import DeltaEngine
from experiments.baselines import fixture_event_detection

ROOT = Path(__file__).resolve().parents[2]


def run_all(
    root: Path = ROOT,
    output_dir: Path | None = None,
    repetitions: int = 1,
) -> list[ExperimentRun]:
    output_dir = output_dir or root / "experiments" / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    runs = [
        run_scenario(path, root=root)
        for _ in range(max(1, repetitions))
        for path in sorted((root / "experiments" / "scenarios").glob("*.json"))
    ]
    for run in runs:
        write_run_json(run, output_dir)
    write_summary_csv(runs, output_dir / "summary.csv")
    write_metrics_json(runs, output_dir / "metrics.json")
    return runs


def run_scenario(scenario_path: Path, root: Path = ROOT) -> ExperimentRun:
    started_at = datetime.now(UTC)
    scenario = _load_scenario(scenario_path)
    try:
        initial = _load_state(root, scenario.initial_state_fixture)
        resulting = _load_state(
            root, scenario.resulting_state_fixture or scenario.initial_state_fixture
        )
        events = _load_events(root, scenario.event_fixture_set)

        deltas = DeltaEngine().diff(initial, resulting)
        reconciliation_engine = ReconciliationEngine()
        authorization = AuthorizationService(root / "config" / "authorized-state.example.yaml")
        risk = RiskEngine(root / "config" / "risk-rules.yaml")
        findings: list[Finding] = []
        reconciliations: list[ReconciliationResult] = []

        for delta in deltas:
            result = reconciliation_engine.reconcile_delta(delta, events)
            decision = authorization.evaluate_delta(delta)
            risk_score = risk.score_delta(delta, result, decision.status)
            finding = Finding(
                host_id=delta.host_id,
                observation_kind=ObservationKind.STATE_DELTA,
                delta_id=delta.delta_id,
                category=delta.category,
                object_key=delta.object_key,
                reconciliation=result,
                authorization_status=decision.status,
                authorization_reason=decision.reason,
                risk=risk_score,
                created_at=delta.created_at,
                metadata={
                    "scenario_id": scenario.scenario_id,
                    "matched_rule": decision.matched_rule,
                },
            )
            findings.append(finding)
            reconciliations.append(result)

        transients = reconciliation_engine.derive_event_only_transients(events, deltas)
        for transient in transients:
            result = ReconciliationResult(
                host_id=transient.host_id,
                status=ReconciliationStatus.NOT_APPLICABLE,
                matched_evidence_ids=[transient.event_id],
                match_reasons=[
                    {
                        "event_id": transient.event_id,
                        "event_type": transient.normalized_type,
                        "reason": transient.reason,
                    },
                ],
                missing_expected_evidence_types=[],
                observation_window=TimeWindow(start=transient.event_time, end=transient.event_time),
                confidence=1.0,
                metadata={"transient_id": transient.transient_id},
            )
            findings.append(
                Finding(
                    host_id=transient.host_id,
                    observation_kind=ObservationKind.EVENT_ONLY,
                    transient_id=transient.transient_id,
                    category="event_only",
                    object_key=transient.target.get("key"),
                    reconciliation=result,
                    authorization_status=AuthorizationStatus.UNKNOWN,
                    authorization_reason="event-only observation has no authorized-state object",
                    risk=risk.score_transient(result),
                    created_at=transient.event_time,
                    metadata={"scenario_id": scenario.scenario_id},
                ),
            )
            reconciliations.append(result)

        status_values = [result.status for result in reconciliations]
        expected_deltas_present = _expected_deltas_present(scenario, deltas)
        expected_reconciliation_met = (
            scenario.expected_reconciliation in status_values
            if status_values
            else scenario.expected_reconciliation == ReconciliationStatus.NOT_APPLICABLE
        )
        success = expected_deltas_present and expected_reconciliation_met
        event_only_detected = fixture_event_detection(
            events,
            scenario.expected_deltas,
            host_id=initial.host_id,
            window=TimeWindow(
                start=resulting.built_at - timedelta(seconds=900),
                end=resulting.built_at + timedelta(seconds=900),
            ),
        )
        telemetry_inconsistency_detected = bool(deltas) and any(
            result.status
            in {ReconciliationStatus.PARTIALLY_EXPLAINED, ReconciliationStatus.UNEXPLAINED}
            for result in reconciliations
        )

        ended_at = datetime.now(UTC)
        run = ExperimentRun(
            scenario_id=scenario.scenario_id,
            host_id=initial.host_id,
            ground_truth_classification=scenario.classification,
            started_at=started_at,
            ended_at=ended_at,
            provider_configuration={
                "state_provider": "fixture",
                "event_provider": "fixture",
                "initial_state_fixture": scenario.initial_state_fixture,
                "resulting_state_fixture": scenario.resulting_state_fixture,
                "event_fixture_set": scenario.event_fixture_set,
                "telemetry_condition": scenario.telemetry_condition,
                "event_source_status": scenario.event_source_status,
                "telemetry_study": bool(scenario.metadata.get("telemetry_study", False)),
            },
            expected_observations={
                "expected_deltas": scenario.expected_deltas,
                "expected_reconciliation": scenario.expected_reconciliation.value,
                "ground_truth_notes": scenario.ground_truth_notes,
            },
            actual_observations={
                "delta_count": len(deltas),
                "deltas": [delta.model_dump(mode="json") for delta in deltas],
                "event_count": len(events),
                "events": [event.model_dump(mode="json") for event in events],
                "transient_count": len(transients),
                "findings": [finding.model_dump(mode="json") for finding in findings],
                "csg_state_detected": bool(deltas),
                "event_only_baseline_detected": event_only_detected,
                "telemetry_inconsistency_detected": telemetry_inconsistency_detected,
            },
            reconciliation_result={
                "statuses": [status.value for status in status_values],
                "results": [result.model_dump(mode="json") for result in reconciliations],
            },
            risk_score={
                "scores": [finding.risk.model_dump(mode="json") for finding in findings],
                "max_score": max((finding.risk.total for finding in findings), default=0),
            },
            detection_timestamps={
                "first_delta": deltas[0].created_at.isoformat() if deltas else None,
                "first_finding": findings[0].created_at.isoformat() if findings else None,
            },
            success=success,
            failure_reason=None
            if success
            else "expected deltas or reconciliation status were not met",
        )
        run.metrics = per_run_metrics(scenario, run)
        return run
    except Exception as exc:
        ended_at = datetime.now(UTC)
        return ExperimentRun(
            scenario_id=scenario.scenario_id,
            host_id="unknown",
            ground_truth_classification=scenario.classification,
            started_at=started_at,
            ended_at=ended_at,
            success=False,
            failure_reason=f"{type(exc).__name__}: {exc}",
            provider_configuration={"state_provider": "fixture", "event_provider": "fixture"},
        )


def per_run_metrics(scenario: ExperimentScenario, run: ExperimentRun) -> dict[str, Any]:
    findings = run.actual_observations.get("findings", [])
    expected_transients = int(scenario.metadata.get("expected_transients", 0))
    actual_transients = int(run.actual_observations.get("transient_count", 0))
    findings_count = len(findings)
    severe_benign_findings = [
        finding
        for finding in findings
        if finding.get("risk", {}).get("severity") in {"MEDIUM", "HIGH", "CRITICAL"}
        and finding.get("authorization_status") != AuthorizationStatus.APPROVED_CHANGE.value
    ]
    return {
        "detection": {
            "numerator": 1 if findings_count else 0,
            "denominator": 1,
            "definition": "scenario produced at least one finding or transient observation",
        },
        "false_positive_for_benign": {
            "numerator": int(bool(severe_benign_findings))
            if scenario.classification == "benign"
            else 0,
            "denominator": 1 if scenario.classification == "benign" else 0,
            "definition": "benign scenario produced unapproved MEDIUM-or-higher risk findings",
        },
        "transient_recovery": {
            "numerator": min(actual_transients, expected_transients),
            "denominator": expected_transients,
            "definition": "expected event-only transient observations were recovered",
        },
        "csg_state_detection": {
            "numerator": 1 if run.actual_observations.get("csg_state_detected") else 0,
            "denominator": 1,
            "definition": "persistent state plane observed at least one state delta",
        },
        "event_only_baseline_detection": {
            "numerator": 1 if run.actual_observations.get("event_only_baseline_detected") else 0,
            "denominator": 1,
            "definition": "event-only baseline retained a normalized state-change event",
        },
        "telemetry_inconsistency": {
            "numerator": 1
            if run.actual_observations.get("telemetry_inconsistency_detected")
            else 0,
            "denominator": 1
            if scenario.metadata.get("expect_telemetry_inconsistency", False)
            else 0,
            "definition": (
                "state delta persisted while primary supporting event evidence was missing"
            ),
        },
        "record_counts": {
            "events": run.actual_observations.get("event_count", 0),
            "deltas": run.actual_observations.get("delta_count", 0),
            "findings": findings_count,
        },
    }


def replay_events_at_origin(
    events: list[NormalizedEvent],
    origin: datetime,
) -> list[NormalizedEvent]:
    if not events:
        return []
    origin = ensure_utc(origin)
    first_event_time = min(event.event_time for event in events)
    replayed: list[NormalizedEvent] = []
    for event in events:
        shifted_time = origin + (event.event_time - first_event_time)
        replayed.append(
            event.model_copy(
                update={
                    "event_time": shifted_time,
                    "metadata": {
                        **event.metadata,
                        "replayed": True,
                        "original_event_time": event.event_time.isoformat(),
                    },
                },
            ),
        )
    return replayed


def aggregate_metrics(runs: list[ExperimentRun]) -> dict[str, Any]:
    total = len(runs)
    successful = sum(1 for run in runs if run.success)
    detection_denominator = sum(
        1
        for run in runs
        if run.ground_truth_classification in {"suspicious", "malicious-simulation"}
    )
    detection_numerator = sum(
        1
        for run in runs
        if run.ground_truth_classification in {"suspicious", "malicious-simulation"}
        and run.actual_observations.get("findings")
    )
    benign_denominator = sum(1 for run in runs if run.ground_truth_classification == "benign")
    benign_false_positive_numerator = sum(
        run.metrics.get("false_positive_for_benign", {}).get("numerator", 0) for run in runs
    )
    expected_transient_denominator = sum(
        run.metrics.get("transient_recovery", {}).get("denominator", 0) for run in runs
    )
    transient_numerator = sum(
        run.metrics.get("transient_recovery", {}).get("numerator", 0) for run in runs
    )
    telemetry_failure_denominator = sum(
        run.metrics.get("telemetry_inconsistency", {}).get("denominator", 0) for run in runs
    )
    telemetry_failure_numerator = sum(
        run.metrics.get("telemetry_inconsistency", {}).get("numerator", 0)
        for run in runs
        if run.metrics.get("telemetry_inconsistency", {}).get("denominator", 0)
    )
    state_detection_numerator = sum(
        run.metrics.get("csg_state_detection", {}).get("numerator", 0) for run in runs
    )
    baseline_detection_numerator = sum(
        run.metrics.get("event_only_baseline_detection", {}).get("numerator", 0) for run in runs
    )
    durations_ms = [
        (run.ended_at - run.started_at).total_seconds() * 1000
        for run in runs
        if run.ended_at is not None
    ]
    telemetry_runs = [
        run for run in runs if run.provider_configuration.get("telemetry_study", False)
    ]
    telemetry_state_numerator = sum(
        1 for run in telemetry_runs if run.actual_observations.get("csg_state_detected")
    )
    telemetry_baseline_numerator = sum(
        1 for run in telemetry_runs if run.actual_observations.get("event_only_baseline_detected")
    )

    return {
        "scenario_success": {
            "numerator": successful,
            "denominator": total,
            "rate": _rate(successful, total),
        },
        "detection_rate": {
            "numerator": detection_numerator,
            "denominator": detection_denominator,
            "rate": _rate(detection_numerator, detection_denominator),
        },
        "false_positive_rate_for_benign": {
            "numerator": benign_false_positive_numerator,
            "denominator": benign_denominator,
            "rate": _rate(benign_false_positive_numerator, benign_denominator),
        },
        "reconciliation_accuracy": {
            "numerator": successful,
            "denominator": total,
            "rate": _rate(successful, total),
        },
        "transient_recovery_rate": {
            "numerator": transient_numerator,
            "denominator": expected_transient_denominator,
            "rate": _rate(transient_numerator, expected_transient_denominator),
        },
        "telemetry_inconsistency_detection_rate": {
            "numerator": telemetry_failure_numerator,
            "denominator": telemetry_failure_denominator,
            "rate": _rate(telemetry_failure_numerator, telemetry_failure_denominator),
            "definition": "expected state/event inconsistencies identified by reconciliation",
        },
        "state_vs_event_only_detection": {
            "csg_state_plane": {
                "numerator": state_detection_numerator,
                "denominator": total,
                "rate": _rate(state_detection_numerator, total),
            },
            "event_only_baseline": {
                "numerator": baseline_detection_numerator,
                "denominator": total,
                "rate": _rate(baseline_detection_numerator, total),
            },
        },
        "telemetry_degradation_study": {
            "conditions": len(telemetry_runs),
            "csg_state_plane_detection_rate": _rate(telemetry_state_numerator, len(telemetry_runs)),
            "event_only_baseline_detection_rate": _rate(
                telemetry_baseline_numerator, len(telemetry_runs)
            ),
            "per_condition": [
                {
                    "scenario_id": run.scenario_id,
                    "condition": run.provider_configuration.get("telemetry_condition"),
                    "event_source_status": run.provider_configuration.get("event_source_status"),
                    "csg_state_detected": run.actual_observations.get("csg_state_detected", False),
                    "event_only_baseline_detected": run.actual_observations.get(
                        "event_only_baseline_detected", False
                    ),
                    "telemetry_inconsistency_detected": run.actual_observations.get(
                        "telemetry_inconsistency_detected", False
                    ),
                }
                for run in telemetry_runs
            ],
        },
        "execution_time_ms": {
            "mean": round(statistics.mean(durations_ms), 3) if durations_ms else None,
            "median": round(statistics.median(durations_ms), 3) if durations_ms else None,
            "stdev": round(statistics.stdev(durations_ms), 3)
            if len(durations_ms) > 1
            else 0.0
            if durations_ms
            else None,
            "samples": len(durations_ms),
        },
        "record_counts": {
            "events": sum(run.actual_observations.get("event_count", 0) for run in runs),
            "deltas": sum(run.actual_observations.get("delta_count", 0) for run in runs),
            "findings": sum(len(run.actual_observations.get("findings", [])) for run in runs),
        },
    }


def write_run_json(run: ExperimentRun, output_dir: Path) -> Path:
    path = output_dir / "runs" / run.run_id / "run.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(run.model_dump(mode="json"), handle, indent=2)
        handle.write("\n")
    return path


def write_summary_csv(runs: list[ExperimentRun], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "run_id",
                "scenario_id",
                "ground_truth_classification",
                "success",
                "delta_count",
                "event_count",
                "finding_count",
                "max_risk_score",
                "telemetry_condition",
                "event_source_status",
                "csg_state_detected",
                "event_only_baseline_detected",
                "telemetry_inconsistency_detected",
                "failure_reason",
            ],
        )
        writer.writeheader()
        for run in runs:
            writer.writerow(
                {
                    "run_id": run.run_id,
                    "scenario_id": run.scenario_id,
                    "ground_truth_classification": run.ground_truth_classification,
                    "success": run.success,
                    "delta_count": run.actual_observations.get("delta_count", 0),
                    "event_count": run.actual_observations.get("event_count", 0),
                    "finding_count": len(run.actual_observations.get("findings", [])),
                    "max_risk_score": run.risk_score.get("max_score", 0),
                    "telemetry_condition": run.provider_configuration.get(
                        "telemetry_condition", "complete"
                    ),
                    "event_source_status": run.provider_configuration.get(
                        "event_source_status", "available"
                    ),
                    "csg_state_detected": run.actual_observations.get("csg_state_detected", False),
                    "event_only_baseline_detected": run.actual_observations.get(
                        "event_only_baseline_detected", False
                    ),
                    "telemetry_inconsistency_detected": run.actual_observations.get(
                        "telemetry_inconsistency_detected", False
                    ),
                    "failure_reason": run.failure_reason,
                },
            )


def write_metrics_json(runs: list[ExperimentRun], path: Path) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(aggregate_metrics(runs), handle, indent=2)
        handle.write("\n")


def _load_scenario(path: Path) -> ExperimentScenario:
    with path.open("r", encoding="utf-8") as handle:
        return ExperimentScenario.model_validate(json.load(handle))


def _load_state(root: Path, fixture_name: str) -> StateSnapshot:
    path = root / "experiments" / "fixtures" / "state" / fixture_name
    with path.open("r", encoding="utf-8") as handle:
        return StateSnapshot.model_validate(json.load(handle))


def _load_events(root: Path, fixture_set: str) -> list[NormalizedEvent]:
    path = root / "experiments" / "fixtures" / "events" / f"{fixture_set}.json"
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return [NormalizedEvent.model_validate(row) for row in payload.get("events", [])]


def _expected_deltas_present(scenario: ExperimentScenario, deltas) -> bool:
    actual = {(delta.category, delta.delta_type.value, delta.object_key) for delta in deltas}
    expected = {
        (row["category"], row["delta_type"], row["object_key"]) for row in scenario.expected_deltas
    }
    return expected.issubset(actual)


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CyberStateGuardian synthetic scenarios")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "experiments" / "results")
    parser.add_argument("--repetitions", type=int, default=1)
    args = parser.parse_args()
    runs = run_all(output_dir=args.output_dir, repetitions=args.repetitions)
    metrics = aggregate_metrics(runs)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
