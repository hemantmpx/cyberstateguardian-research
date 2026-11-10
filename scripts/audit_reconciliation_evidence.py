"""Audit stored reconciliation matches for exact Windows service identity."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

Json = dict[str, Any]


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def audit_run(run: Json, events_by_id: dict[str, Json]) -> Json:
    matches: list[Json] = []
    for finding in run.get("findings", []):
        object_key = str(finding.get("object_key", ""))
        if not object_key.startswith("service:"):
            continue
        expected_name = object_key.removeprefix("service:").lower()
        reconciliation = finding.get("reconciliation") or {}
        expected_types = {
            row.get("event_type")
            for row in reconciliation.get("match_reasons", [])
            if row.get("event_type")
        }
        for event_id in reconciliation.get("matched_evidence_ids", []):
            event = events_by_id.get(event_id)
            actual_name = str((event or {}).get("attributes", {}).get("service_name", ""))
            actual_target = str((event or {}).get("target", {}).get("key", ""))
            identity_match = actual_name.lower() == expected_name or (
                actual_target.lower() == object_key.lower()
            )
            host_match = bool(event) and event.get("host_id") == run.get("host_id")
            type_match = bool(event) and event.get("normalized_type") in expected_types
            window = reconciliation.get("observation_window") or {}
            time_match = bool(event) and bool(window) and (
                window["start"] <= event["event_time"] <= window["end"]
            )
            matches.append(
                {
                    "finding_id": finding.get("finding_id"),
                    "object_key": object_key,
                    "expected_service_name": expected_name,
                    "event_id": event_id,
                    "event_found": bool(event),
                    "actual_service_name": actual_name or None,
                    "actual_target_key": actual_target or None,
                    "normalized_type": (event or {}).get("normalized_type"),
                    "identity_match": identity_match,
                    "host_match": host_match,
                    "type_match": type_match,
                    "time_match": time_match,
                    "valid_exact_match": (
                        identity_match and host_match and type_match and time_match
                    ),
                }
            )

    return {
        "run_id": run.get("run_id"),
        "source_file": run.get("_source_file"),
        "service_name": run.get("service_name"),
        "telemetry_condition": run.get("telemetry_condition"),
        "reported_statuses": [
            finding.get("reconciliation", {}).get("status")
            for finding in run.get("findings", [])
            if finding.get("object_key", "").startswith("service:")
        ],
        "matches": matches,
        "all_matches_exact": bool(matches) and all(row["valid_exact_match"] for row in matches),
    }


def audit(run_dir: Path, events_path: Path) -> Json:
    event_rows = load_json(events_path)
    if isinstance(event_rows, dict):
        event_rows = event_rows.get("events", [])
    events_by_id = {row["event_id"]: row for row in event_rows if row.get("event_id")}
    runs = []
    for path in sorted(run_dir.rglob("*.json")):
        run = load_json(path)
        if "findings" not in run or "host_id" not in run:
            continue
        run["_source_file"] = str(path)
        runs.append(audit_run(run, events_by_id))

    reuse: dict[str, set[str]] = defaultdict(set)
    for run in runs:
        for match in run["matches"]:
            reuse[match["event_id"]].add(match["object_key"])
    reused = {
        event_id: sorted(object_keys)
        for event_id, object_keys in reuse.items()
        if len(object_keys) > 1
    }
    all_matches = [match for run in runs for match in run["matches"]]
    valid = sum(match["valid_exact_match"] for match in all_matches)
    return {
        "schema_version": "1",
        "audit_type": "strict_reconciliation_evidence_identity",
        "audit_rule": (
            "A service match is valid only when host, expected event type, observation window, "
            "and internal service identity (or exact target key) all match. A display name alone "
            "is not an identity."
        ),
        "source_events": str(events_path),
        "source_runs": str(run_dir),
        "event_count": len(events_by_id),
        "run_count": len(runs),
        "match_count": len(all_matches),
        "valid_exact_match_count": valid,
        "invalid_match_count": len(all_matches) - valid,
        "cross_object_reused_evidence_ids": reused,
        "runs": runs,
        "conclusion": (
            "Prior stored service reconciliations are superseded for object-specific claims. "
            "A verified rerun is required."
            if any(not match["valid_exact_match"] for match in all_matches) or reused
            else "All audited service matches satisfy the strict identity rule."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.run_dir, args.events)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in (
        "run_count", "match_count", "valid_exact_match_count", "invalid_match_count",
        "cross_object_reused_evidence_ids", "conclusion",
    )}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
