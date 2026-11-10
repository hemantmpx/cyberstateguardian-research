"""Evaluate identical state evidence under approved, unknown, and violating policy."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from csg.domain.enums import AuthorizationStatus, DeltaType
from csg.domain.models import StateDelta, StateObject, TimeWindow
from csg.services.authorization import AuthorizationService

ROOT = Path(__file__).resolve().parents[1]


def _delta() -> StateDelta:
    created = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    return StateDelta(
        host_id="authorization-lab",
        category="service",
        object_key="service:csgresearch-authorization",
        delta_type=DeltaType.ADD,
        after=StateObject(
            category="service",
            object_key="service:csgresearch-authorization",
            attributes={
                "service_name": "CSGResearch-Authorization",
                "binary_path": "c:/windows/system32/cmd.exe",
                "start_mode": "demand",
            },
            source_timestamp=created,
        ),
        observation_window=TimeWindow(start=created, end=created),
        created_at=created,
    )


def evaluate_authorization_classes() -> dict[str, object]:
    delta = _delta()
    base = {
        "version": "authorization-study-v1",
        "hosts": {
            "authorization-lab": {
                "expected_services": [],
                "approved_changes": [],
                "violating_objects": [],
            }
        },
    }
    policies = {
        "approved": {
            **base,
            "hosts": {
                "authorization-lab": {
                    "expected_services": [],
                    "approved_changes": [
                        {
                            "change_id": "approved-research-service",
                            "category": "service",
                            "object_key": delta.object_key,
                            "valid_from": "2026-09-22T11:00:00Z",
                            "valid_until": "2026-09-22T13:00:00Z",
                            "allowed_after": delta.after.attributes,
                            "reason": "approved controlled research change",
                        }
                    ],
                    "violating_objects": [],
                }
            },
        },
        "unknown": base,
        "violation": {
            **base,
            "hosts": {
                "authorization-lab": {
                    "expected_services": [],
                    "approved_changes": [],
                    "violating_objects": [
                        {
                            "category": "service",
                            "object_key": delta.object_key,
                            "reason": "service is explicitly prohibited in this trial",
                        }
                    ],
                }
            },
        },
    }
    observations = {}
    with TemporaryDirectory(prefix="csg-authorization-") as directory:
        for label, policy in policies.items():
            path = Path(directory) / f"{label}.yaml"
            path.write_text(yaml.safe_dump(policy), encoding="utf-8")
            decision = AuthorizationService(path).evaluate_delta(delta)
            observations[label] = {
                "status": decision.status.value,
                "reason": decision.reason,
                "matched_rule": decision.matched_rule,
            }
    expected = {
        "approved": AuthorizationStatus.APPROVED_CHANGE.value,
        "unknown": AuthorizationStatus.UNKNOWN.value,
        "violation": AuthorizationStatus.VIOLATION.value,
    }
    return {
        "schema_version": "csg-authorization-study-v1",
        "same_delta": delta.model_dump(mode="json"),
        "observations": observations,
        "expected_statuses": expected,
        "all_expected_statuses_observed": all(
            observations[label]["status"] == status for label, status in expected.items()
        ),
        "research_question": (
            "Can identical technical state evidence receive different triage outcomes solely from "
            "authorization context?"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate CSG authorization classes")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = evaluate_authorization_classes()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
