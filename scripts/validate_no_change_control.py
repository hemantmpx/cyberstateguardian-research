"""Validate a Windows no-change control without applying service-drift rules."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": passed, "detail": detail})

    add(
        "condition_is_no_change",
        payload.get("telemetry_condition") == "no_change",
        "the run declares the no-change control condition",
    )
    add(
        "no_findings",
        not payload.get("findings"),
        "no state delta or finding was produced",
    )
    event_plane = payload.get("event_plane_status") or {}
    add(
        "event_plane_status",
        event_plane.get("event_query_status") == "COMPLETE"
        and event_plane.get("endpoint_collection_status") == "AVAILABLE"
        and event_plane.get("central_index_status") == "AVAILABLE"
        and event_plane.get("expected_event_status") == "ABSENT",
        "query completed, endpoint and index were available, and no expected event was required",
    )

    sync = next(
        (
            item.get("response")
            for item in payload.get("timeline", [])
            if item.get("phase") == "no_change_control_sync"
        ),
        None,
    )
    categories = ((sync or {}).get("cross_validation") or {}).get("categories") or {}
    identity_checks = []
    for category in ("process", "listener"):
        value = categories.get(category) or {}
        identity_checks.append(
            value.get("comparable") is False
            and value.get("comparison_status") == "identity_schema_incompatible"
            and value.get("jaccard_similarity") is None
        )
    add(
        "incompatible_identity_policy",
        bool(identity_checks) and all(identity_checks),
        "process and listener comparisons use comparable=false and null Jaccard",
    )

    passed = all(check["passed"] for check in checks)
    return {
        "schema_version": "csg-no-change-control-validation-v1",
        "run_id": payload.get("run_id"),
        "trial_id": payload.get("trial_id"),
        "host_id": payload.get("host_id"),
        "passed": passed,
        "checks": checks,
        "interpretation": (
            "The no-change control passed: CSG observed no change, produced no finding, "
            "and applied "
            "the uniform incompatible-identity policy."
            if passed
            else "The no-change control is not valid for publication until every check passes."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.loads(args.result.read_text(encoding="utf-8-sig"))
    validation = validate(payload)
    output = json.dumps(validation, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    print(output, end="")


if __name__ == "__main__":
    main()
