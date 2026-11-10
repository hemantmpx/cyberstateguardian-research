from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from csg.domain.models import CategoryStatus, StateObject, StateSnapshot, StateTransitionRecord
from csg.services.trajectories import StateTrajectoryBuilder
from csg.state.diff import DeltaEngine

ROOT = Path(__file__).resolve().parents[2]
HOST_ID = "fixture-transition-host"
SERVICE_KEY = "service:csg-research-fixture"


def _snapshot(
    snapshot_id: str,
    at: datetime,
    attributes: dict | None,
) -> StateSnapshot:
    return StateSnapshot(
        snapshot_id=snapshot_id,
        host_id=HOST_ID,
        built_at=at,
        source="fixture",
        category_statuses=[
            CategoryStatus(category="service", status="healthy", source="fixture", observed_at=at)
        ],
        objects=(
            [
                StateObject(
                    category="service",
                    object_key=SERVICE_KEY,
                    attributes=attributes,
                    source_timestamp=at,
                )
            ]
            if attributes is not None
            else []
        ),
    )


def _transition(
    transition_id: str,
    at: datetime,
    before: dict | None,
    after: dict | None,
    transition_type: str,
) -> StateTransitionRecord:
    return StateTransitionRecord(
        transition_id=transition_id,
        host_id=HOST_ID,
        category="service",
        object_key=SERVICE_KEY,
        transition_type=transition_type,
        observed_at=at,
        window_start=at,
        window_end=at,
        old_state=before,
        new_state=after,
        changed_fields=(
            ["$object"]
            if before is None or after is None
            else sorted(
                key for key in before.keys() | after.keys() if before.get(key) != after.get(key)
            )
        ),
        source="fixture",
        capture_method="deterministic_fixture",
        collector_health="HEALTHY",
    )


def _cases() -> list[dict]:
    manual = {"service_name": "CSGResearchFixture", "start_mode": "manual", "status": "stopped"}
    automatic = {**manual, "start_mode": "auto"}
    running = {**manual, "status": "running"}
    temporary = {"service_name": "CSGResearchTemporary", "start_mode": "auto", "status": "stopped"}
    return [
        {
            "condition": "durable",
            "expected_trajectory": "DURABLE",
            "before": manual,
            "after": automatic,
            "transitions": [("SERVICE_START_MODE_CHANGED", manual, automatic, 10)],
            "coverage": "HEALTHY",
        },
        {
            "condition": "reverted",
            "expected_trajectory": "REVERTED",
            "before": manual,
            "after": manual,
            "transitions": [
                ("SERVICE_START_MODE_CHANGED", manual, automatic, 10),
                ("SERVICE_START_MODE_CHANGED", automatic, manual, 20),
            ],
            "coverage": "HEALTHY",
        },
        {
            "condition": "transient_object",
            "expected_trajectory": "TRANSIENT_OBJECT",
            "before": None,
            "after": None,
            "transitions": [
                ("SERVICE_CREATED", None, temporary, 10),
                ("SERVICE_DELETED", temporary, None, 20),
            ],
            "coverage": "HEALTHY",
        },
        {
            "condition": "snapshot_only_capture_gap",
            "expected_trajectory": "TRANSITION_CAPTURE_GAP",
            "before": manual,
            "after": automatic,
            "transitions": [],
            "coverage": "OFFLINE",
        },
        {
            "condition": "no_change",
            "expected_trajectory": "STABLE",
            "before": manual,
            "after": manual,
            "transitions": [],
            "coverage": "HEALTHY",
        },
        {
            "condition": "non_persistent_runtime_transition",
            "expected_trajectory": "NON_PERSISTENT_TRANSITION",
            "before": manual,
            "after": running,
            "transitions": [("SERVICE_RUNTIME_STATUS_CHANGED", manual, running, 10)],
            "coverage": "HEALTHY",
        },
        {
            "condition": "inconsistent_chain_negative_control",
            "expected_trajectory": "INCONSISTENT",
            "before": manual,
            "after": manual,
            "transitions": [
                ("SERVICE_START_MODE_CHANGED", manual, automatic, 10),
                ("SERVICE_START_MODE_CHANGED", {**manual, "start_mode": "disabled"}, manual, 20),
            ],
            "coverage": "HEALTHY",
        },
    ]


def run_campaign(output_root: Path, *, repetitions: int = 1) -> dict:
    campaign_id = (
        f"transition-fixtures-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    )
    campaign_dir = output_root / campaign_id
    campaign_dir.mkdir(parents=True, exist_ok=False)
    started = datetime.now(UTC)
    script_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    validations = []
    manifest = {
        "schema_version": "1.0",
        "campaign_id": campaign_id,
        "experiment_family": "transition_capture",
        "execution_kind": "deterministic_fixture_software_validation",
        "started_at": started.isoformat(),
        "host_environment": platform.platform(),
        "python_version": platform.python_version(),
        "runner_sha256": script_hash,
        "wazuh_reconciliation": "not_evaluated_fixture_only",
        "independent_windows_probe": False,
        "limitations": [
            "This campaign validates deterministic trajectory logic, not Windows capture "
            "reliability.",
            "No Wazuh events are queried and no live endpoint mutation is performed.",
            "Live Windows trials must be run separately using the Windows experiment script.",
        ],
        "runs": [],
    }
    builder = StateTrajectoryBuilder()
    for repetition in range(1, max(1, repetitions) + 1):
        for case in _cases():
            run_id = f"{case['condition']}-{repetition:03d}"
            run_dir = campaign_dir / run_id
            run_dir.mkdir()
            interval_start = started + timedelta(seconds=repetition * 60)
            interval_end = interval_start + timedelta(seconds=30)
            before = _snapshot(f"{run_id}-before", interval_start, case["before"])
            after = _snapshot(f"{run_id}-after", interval_end, case["after"])
            transitions = [
                _transition(
                    f"{run_id}-transition-{index:02d}",
                    interval_start + timedelta(seconds=offset),
                    old,
                    new,
                    kind,
                )
                for index, (kind, old, new, offset) in enumerate(case["transitions"], start=1)
            ]
            trajectory = builder.build_interval(
                before,
                after,
                transitions,
                coverage_by_category={"service": case["coverage"]},
                category="service",
                object_key=SERVICE_KEY,
                include_stable=True,
            )[0]
            deltas = DeltaEngine().diff(before, after)
            expected_delta_count = (
                1 if case["condition"] in {"durable", "snapshot_only_capture_gap"} else 0
            )
            passed = (
                trajectory.trajectory_type.value == case["expected_trajectory"]
                and len(deltas) == expected_delta_count
                and len(trajectory.transitions) == len(transitions)
            )
            run_record = {
                "schema_version": "1.0",
                "campaign_id": campaign_id,
                "run_id": run_id,
                "condition": case["condition"],
                "repetition": repetition,
                "execution_kind": manifest["execution_kind"],
                "started_at": datetime.now(UTC).isoformat(),
                "host_id": HOST_ID,
                "target": {"category": "service", "object_key": SERVICE_KEY},
                "snapshot_before": before.model_dump(mode="json"),
                "snapshot_after": after.model_dump(mode="json"),
                "snapshot_deltas": [delta.model_dump(mode="json") for delta in deltas],
                "transition_records": [item.model_dump(mode="json") for item in transitions],
                "trajectory": trajectory.model_dump(mode="json"),
                "monitor_coverage": case["coverage"],
                "event_plane": {"status": "NOT_EVALUATED_FIXTURE_ONLY", "evidence": []},
                "wazuh_reconciliation": "NOT_EVALUATED_FIXTURE_ONLY",
                "expected_trajectory": case["expected_trajectory"],
            }
            validation = {
                "schema_version": "1.0",
                "run_id": run_id,
                "validation_status": "PASS" if passed else "FAIL",
                "checks": {
                    "trajectory_classification": {
                        "status": "PASS"
                        if trajectory.trajectory_type.value == case["expected_trajectory"]
                        else "FAIL",
                        "expected": case["expected_trajectory"],
                        "actual": trajectory.trajectory_type.value,
                    },
                    "net_delta_count": {
                        "status": "PASS" if len(deltas) == expected_delta_count else "FAIL",
                        "expected": expected_delta_count,
                        "count": len(deltas),
                    },
                    "transition_count": {
                        "status": "PASS"
                        if len(trajectory.transitions) == len(transitions)
                        else "FAIL",
                        "expected": len(transitions),
                        "actual": len(trajectory.transitions),
                    },
                },
            }
            _write_json(run_dir / "run.json", run_record)
            _write_json(run_dir / "validation.json", validation)
            validations.append(validation)
            manifest["runs"].append(
                {
                    "run_id": run_id,
                    "condition": case["condition"],
                    "validation": validation["validation_status"],
                }
            )

    ended = datetime.now(UTC)
    manifest["ended_at"] = ended.isoformat()
    manifest["duration_seconds"] = (ended - started).total_seconds()
    _write_json(campaign_dir / "campaign-manifest.json", manifest)
    condition_summary = {}
    for condition in sorted({item["condition"] for item in manifest["runs"]}):
        runs = [item for item in manifest["runs"] if item["condition"] == condition]
        condition_summary[condition] = {
            "runs": len(runs),
            "passed": sum(item["validation"] == "PASS" for item in runs),
            "failed": sum(item["validation"] != "PASS" for item in runs),
        }
    summary = {
        "schema_version": "1.0",
        "campaign_id": campaign_id,
        "execution_kind": manifest["execution_kind"],
        "run_count": len(validations),
        "passed": sum(item["validation_status"] == "PASS" for item in validations),
        "failed": sum(item["validation_status"] != "PASS" for item in validations),
        "conditions": condition_summary,
        "claims_supported": ["deterministic trajectory classifications match the encoded fixtures"],
        "claims_not_supported": [
            "Windows monitor capture sensitivity or reliability",
            "Wazuh event availability or reconciliation",
            "real-world detection accuracy or false-positive rate",
        ],
    }
    _write_json(campaign_dir / "aggregate.json", summary)
    (campaign_dir / "README.md").write_text(
        "# Transition Capture Fixture Campaign\n\n"
        f"Campaign `{campaign_id}` ran {summary['run_count']} deterministic "
        "software-validation cases.\n\n"
        "This is not a live Windows experiment. It validates how persisted transition records are "
        "classified against snapshot boundaries. It does not validate Windows capture, Wazuh, "
        "telemetry loss, or endpoint performance. Each run contains `run.json` and "
        "`validation.json`.\n",
        encoding="utf-8",
    )
    checksums = []
    for path in sorted(item for item in campaign_dir.rglob("*") if item.is_file()):
        if path.name == "SHA256SUMS.txt":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        checksums.append(f"{digest}  {path.relative_to(campaign_dir).as_posix()}")
    (campaign_dir / "SHA256SUMS.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    return {**summary, "campaign_directory": str(campaign_dir)}


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run deterministic transition-capture fixture checks"
    )
    parser.add_argument("--output", type=Path, help="Campaign output directory")
    parser.add_argument("--repetitions", type=int, default=1)
    args = parser.parse_args()
    output_root = (
        args.output
        or ROOT
        / "experiments"
        / "results"
        / "runs"
        / datetime.now(UTC).strftime("%Y%m%d")
        / "transition-capture-fixtures"
    )
    result = run_campaign(output_root, repetitions=max(1, args.repetitions))
    print(json.dumps(result, indent=2))
    if result["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
