#!/usr/bin/env python3
"""Capture read-only CSG API evidence for a frozen Windows Event 4698 campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


def get_json(url: str, timeout: float) -> tuple[Any, str]:
    request = Request(url, headers={"Accept": "application/json"})
    with urlopen(request, timeout=timeout) as response:
        raw = response.read()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def raw_trial_ids(manifest_path: Path, assignment: dict[str, Any]) -> dict[str, Any]:
    """Recover exact delta/finding IDs from immutable runner output if the manifest omitted them."""
    order = assignment.get("order")
    if not isinstance(order, int):
        return {"delta_id": None, "finding_id": None, "status": "MISSING_ORDER"}
    runner_path = manifest_path.parent / f"trial-{order:02d}" / "runner" / "run.json"
    if not runner_path.is_file():
        return {"delta_id": None, "finding_id": None, "status": "RAW_RUN_MISSING"}

    run = json.loads(runner_path.read_text(encoding="utf-8-sig"))
    task_name = str(assignment.get("target_task_name") or "").strip().casefold()
    expected_key = f"scheduled_task:\\{task_name}" if task_name else None
    scenarios = [
        scenario
        for scenario in run.get("scenarios", [])
        if scenario.get("kind") == "scheduled_task"
        and scenario.get("expected_object_key") == expected_key
    ]
    if len(scenarios) != 1:
        return {
            "delta_id": None,
            "finding_id": None,
            "status": "TARGET_SCENARIO_NOT_UNIQUE",
            "scenario_count": len(scenarios),
        }

    scenario = scenarios[0]
    additions = [
        delta
        for delta in scenario.get("deltas", [])
        if delta.get("delta_type") == "ADD" and delta.get("object_key") == expected_key
    ]
    linked = [
        finding
        for finding in scenario.get("findings", [])
        if len(additions) == 1 and finding.get("delta_id") == additions[0].get("delta_id")
    ]
    return {
        "delta_id": additions[0].get("delta_id") if len(additions) == 1 else None,
        "finding_id": linked[0].get("finding_id") if len(linked) == 1 else None,
        "status": (
            "EXACT_LINKED_IDS_FOUND"
            if len(additions) == len(linked) == 1
            else "IDS_NOT_UNIQUE"
        ),
        "exact_add_count": len(additions),
        "linked_finding_count": len(linked),
        "runner_path": str(runner_path),
        "runner_sha256": hashlib.sha256(runner_path.read_bytes()).hexdigest(),
    }


def audit(manifest_path: Path, output_path: Path, api_base: str, timeout: float) -> dict[str, Any]:
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    host_id = str(manifest["host_id"])
    host_path = quote(host_id, safe="")
    trials = []

    for assignment in manifest.get("trials", []):
        task_name = assignment.get("target_task_name")
        object_key = f"scheduled_task:\\{str(task_name).lower()}" if task_name else None
        raw_ids = raw_trial_ids(manifest_path, assignment)
        finding_id = assignment.get("finding_id") or raw_ids.get("finding_id")
        delta_id = assignment.get("delta_id") or raw_ids.get("delta_id")
        trial: dict[str, Any] = {
            "order": assignment.get("order"),
            "assignment_id": assignment.get("assignment_id"),
            "target_task_name": task_name,
            "expected_object_key": object_key,
            "campaign_finding_id": assignment.get("finding_id"),
            "campaign_delta_id": assignment.get("delta_id"),
            "effective_finding_id": finding_id,
            "effective_delta_id": delta_id,
            "raw_artifact_id_recovery": raw_ids,
            "api_errors": [],
        }

        if object_key:
            params = urlencode({"limit": 500, "object_key": object_key})
            delta_url = f"{api_base.rstrip('/')}/api/hosts/{host_path}/deltas?{params}"
            try:
                response, digest = get_json(delta_url, timeout)
                matching = [
                    delta
                    for delta in response
                    if delta.get("object_key") == object_key
                ]
                trial["current_deltas"] = matching
                trial["delta_response_sha256"] = digest
                trial["current_add_delta_count"] = sum(
                    delta.get("delta_type") == "ADD" for delta in matching
                )
            except (HTTPError, URLError, TimeoutError, ValueError) as exc:
                trial["api_errors"].append(f"delta_query: {type(exc).__name__}: {exc}")
                trial["current_deltas"] = None
                trial["current_add_delta_count"] = None

        if finding_id:
            history_url = (
                f"{api_base.rstrip('/')}/api/findings/{finding_id}/reconciliations"
            )
            try:
                history, digest = get_json(history_url, timeout)
                trial["current_reconciliation_history"] = history
                trial["reconciliation_response_sha256"] = digest
                trial["latest_reconciliation"] = history[-1] if history else None
            except (HTTPError, URLError, TimeoutError, ValueError) as exc:
                trial["api_errors"].append(
                    f"reconciliation_query: {type(exc).__name__}: {exc}"
                )
                trial["current_reconciliation_history"] = None
                trial["latest_reconciliation"] = None
        else:
            trial["current_reconciliation_history"] = []
            trial["latest_reconciliation"] = None
        trials.append(trial)

    result = {
        "schema_version": "csg-scheduled-task-event-filter-api-audit-v1",
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "api_base": api_base.rstrip("/"),
        "campaign_id": manifest.get("campaign_id"),
        "host_id": host_id,
        "campaign_manifest_path": str(manifest_path),
        "campaign_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "assigned_trial_count": len(manifest.get("trials", [])),
        "trial_count_with_api_errors": sum(bool(item["api_errors"]) for item in trials),
        "trials": trials,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--api-base", default="http://127.0.0.1:8000")
    parser.add_argument("--timeout", type=float, default=45)
    args = parser.parse_args()
    result = audit(args.manifest, args.output, args.api_base, args.timeout)
    print(json.dumps({
        "campaign_id": result["campaign_id"],
        "assigned_trial_count": result["assigned_trial_count"],
        "trial_count_with_api_errors": result["trial_count_with_api_errors"],
        "output": str(args.output),
    }, indent=2))


if __name__ == "__main__":
    main()
