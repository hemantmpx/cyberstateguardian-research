"""Summarize live Windows telemetry-condition records without changing them."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def summarize_record(path: Path) -> dict[str, Any]:
    record = json.loads(path.read_text(encoding="utf-8-sig"))
    reconciliations = []
    for histories in (record.get("reconciliation_histories") or {}).values():
        for wrapper in histories:
            reconciliations.extend(wrapper.get("value", []))
    status_counts = Counter(item.get("status") for item in reconciliations)
    proof = record.get("capture_drop_proof") or {}
    bounded = proof.get("bounded_observation") or {}
    recovered = proof.get("post_restore_recovery") or {}

    def statuses(snapshot: dict[str, Any]) -> list[str | None]:
        return [
            (finding.get("reconciliation") or {}).get("status")
            for finding in snapshot.get("findings", [])
            if finding.get("category") == "service"
        ]

    transition_statuses: dict[str, str | None] = {}
    for finding in record.get("findings", []):
        reconciliation = finding.get("reconciliation") or {}
        if reconciliation.get("status") == "NOT_APPLICABLE":
            continue
        evidence_types = {
            row.get("event_type")
            for row in reconciliation.get("match_reasons", [])
            if row.get("event_type")
        }
        evidence_types.update(reconciliation.get("missing_expected_evidence_types") or [])
        if "service_created" in evidence_types:
            transition_statuses["ADD"] = reconciliation.get("status")
        elif "service_modified" in evidence_types or reconciliation.get("metadata", {}).get(
            "transition_mismatches"
        ) is not None:
            transition_statuses["MODIFY"] = reconciliation.get("status")

    return {
        "file": str(path),
        "run_id": record.get("run_id"),
        "service_name": record.get("service_name"),
        "telemetry_condition": record.get("telemetry_condition"),
        "started_at": record.get("started_at"),
        "ended_at": record.get("ended_at"),
        "finding_count": len(record.get("findings", [])),
        "timeline_phases": [item.get("phase") for item in record.get("timeline", [])],
        "reconciliation_status_counts": dict(
            sorted(status_counts.items(), key=lambda item: str(item[0]))
        ),
        "finalized_reconciliation_count": sum(
            1 for item in reconciliations if item.get("finalized") is True
        ),
        "event_source_restored_in_record": any(
            "event_source_restored" in str(item.get("phase"))
            or "source_restored" in str(item.get("phase"))
            for item in record.get("timeline", [])
        ),
        "capture_drop_recovery_recorded": bool(bounded and recovered),
        "capture_drop_bounded_statuses": statuses(bounded),
        "capture_drop_post_restore_statuses": statuses(recovered),
        "transition_event_status": record.get("event_plane_status", {}).get(
            "transition_event_status", {}
        ),
        "expected_event_status": record.get("event_plane_status", {}).get(
            "expected_event_status"
        ),
        "latency_measurements_valid": (record.get("latency_measurements") or {}).get(
            "valid"
        ),
        "final_transition_reconciliation": transition_statuses,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records = []
    for path in sorted(args.directory.rglob("*.json")):
        if path.name in {"campaign-manifest.json", "summary.json"}:
            continue
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        if not payload.get("telemetry_condition") or "findings" not in payload:
            continue
        records.append(summarize_record(path))
    payload = {
        "schema_version": "csg-live-telemetry-campaign-summary-v1",
        "execution_kind": "live_windows_service_drift",
        "trial_count": len(records),
        "conditions": records,
        "interpretation": [
            "Complete and delayed_reconciliation trials keep Wazuh collection available; "
            "delayed_reconciliation delays the CSG query/re-evaluation boundary rather than "
            "endpoint event delivery.",
            "telemetry_delay pauses WazuhSvc while the native probe remains active and "
            "measures whether events recover after restoration; recovery must be observed, "
            "not assumed.",
            "Buffered Wazuh events after restoration demonstrate recovery/latency handling, "
            "not permanent event loss.",
            "Permanent event-loss claims require an additional controlled capture-drop condition.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
