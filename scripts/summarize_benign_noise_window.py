"""Summarize long benign-observation windows without calling them accuracy tests."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

Json = dict[str, Any]
SKIP_NAMES = {
    "aggregate.json",
    "campaign-manifest.json",
    "campaign-validation.json",
    "summary.json",
    "validation.json",
}


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp must include a timezone: {value}")
    return parsed.astimezone(UTC)


def _load_records(directory: Path) -> list[tuple[Path, Json]]:
    records: list[tuple[Path, Json]] = []
    for path in sorted(directory.rglob("*.json")):
        if path.name in SKIP_NAMES or "validation" in path.stem:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict) or not payload.get("run_id"):
            continue
        if not isinstance(payload.get("findings"), list):
            continue
        records.append((path, payload))
    return records


def _finding_scope(finding: Json) -> str:
    metadata = finding.get("metadata") or {}
    reconciliation = finding.get("reconciliation") or {}
    reconciliation_metadata = reconciliation.get("metadata") or {}
    return str(
        metadata.get("trial_id")
        or reconciliation_metadata.get("trial_id")
        or finding.get("finding_id")
        or "unknown"
    )


def _finding_semantics(finding: Json) -> str:
    reconciliation = finding.get("reconciliation") or {}
    metadata = reconciliation.get("metadata") or {}
    return str(
        metadata.get("reconciliation_semantics")
        or reconciliation.get("status")
        or "UNKNOWN"
    )


def _authorization_status(finding: Json) -> str:
    authorization = finding.get("authorization") or {}
    return str(
        finding.get("authorization_status")
        or authorization.get("status")
        or "UNKNOWN"
    ).upper()


def _severity(finding: Json) -> str:
    risk = finding.get("risk") or {}
    return str(risk.get("severity") or "UNKNOWN").upper()


def summarize(
    directory: Path,
    *,
    window_hours: float | None = None,
    window_start: str | None = None,
    window_end: str | None = None,
) -> Json:
    records = _load_records(directory)
    parsed_records: list[tuple[Path, Json, datetime, datetime]] = []
    for path, record in records:
        started = _parse_time(record.get("started_at"))
        ended = _parse_time(record.get("ended_at")) or started
        if started is not None and ended is not None and ended >= started:
            parsed_records.append((path, record, started, ended))

    observed_start = min((item[2] for item in parsed_records), default=None)
    observed_end = max((item[3] for item in parsed_records), default=None)
    start = _parse_time(window_start) or observed_start
    end = _parse_time(window_end) or observed_end
    if start is None:
        raise ValueError("records must contain timezone-aware started_at timestamps")
    if window_hours is not None:
        if window_hours <= 0:
            raise ValueError("window-hours must be positive")
        end = start + timedelta(hours=window_hours)
    if end is None or end <= start:
        raise ValueError("window must have a positive duration")

    findings: list[Json] = []
    source_records: list[Json] = []
    for path, record, record_start, record_end in parsed_records:
        if record_end < start or record_start > end:
            continue
        source_records.append(
            {
                "file": str(path),
                "run_id": record.get("run_id"),
                "trial_id": record.get("trial_id"),
                "condition": record.get("telemetry_condition") or record.get("condition"),
                "started_at": record.get("started_at"),
                "ended_at": record.get("ended_at"),
            }
        )
        findings.extend(item for item in record.get("findings", []) if isinstance(item, dict))

    unique_findings: dict[str, Json] = {}
    for finding in findings:
        key = str(finding.get("finding_id") or f"{_finding_scope(finding)}:{len(unique_findings)}")
        unique_findings.setdefault(key, finding)
    findings = list(unique_findings.values())
    semantics = Counter(_finding_semantics(finding) for finding in findings)
    categories = Counter(str(finding.get("category") or "UNKNOWN") for finding in findings)
    authorization = Counter(_authorization_status(finding) for finding in findings)
    severities = Counter(_severity(finding) for finding in findings)
    escalated = [
        finding
        for finding in findings
        if _severity(finding) in {"MEDIUM", "HIGH", "CRITICAL"}
    ]
    potentially_false_escalated = [
        finding
        for finding in escalated
        if _authorization_status(finding) in {"AUTHORIZED", "APPROVED"}
    ]
    duration_hours = (end - start).total_seconds() / 3600

    def rate(count: int) -> float:
        return round(count / duration_hours, 6)

    return {
        "schema_version": "csg-benign-noise-window-summary-v1",
        "measurement_kind": "benign_noise_window",
        "interpretation": (
            "This measures alert and escalation volume during a bounded observation window. "
            "It is not a false-positive rate unless every observed action has an independent "
            "benign ground-truth label."
        ),
        "window": {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "duration_hours": duration_hours,
            "duration_source": (
                "explicit_window_hours" if window_hours is not None else "record_bounds"
            ),
        },
        "source_records": source_records,
        "counts": {
            "records": len(source_records),
            "unique_findings": len(findings),
            "reconciliation_semantics": dict(sorted(semantics.items())),
            "categories": dict(sorted(categories.items())),
            "authorization_status": dict(sorted(authorization.items())),
            "severity": dict(sorted(severities.items())),
            "medium_or_higher": len(escalated),
            "potentially_false_escalations": len(potentially_false_escalated),
        },
        "rates_per_hour": {
            "findings": rate(len(findings)),
            "unexplained_or_uncorroborated": rate(
                sum(
                    1
                    for finding in findings
                    if _finding_semantics(finding)
                    in {
                        "UNEXPLAINED",
                        "UNCORROBORATED_HEALTHY",
                        "UNCORROBORATED_DEGRADED",
                    }
                )
            ),
            "medium_or_higher": rate(len(escalated)),
            "potentially_false_escalations": rate(len(potentially_false_escalated)),
        },
        "audit_rows": [
            {
                "finding_id": finding.get("finding_id"),
                "trial_id": _finding_scope(finding),
                "category": finding.get("category"),
                "severity": _severity(finding),
                "authorization_status": _authorization_status(finding),
                "reconciliation_semantics": _finding_semantics(finding),
            }
            for finding in findings
        ],
        "limitations": [
            "A short no-change control is target-specific and cannot establish a long-window "
            "false-positive rate.",
            "Potentially false escalation is a review queue, not a confirmed false positive.",
            "Use independently labeled benign activity to estimate false-positive and "
            "false-escalation rates.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="directory containing per-run JSON artifacts")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--window-hours", type=float)
    parser.add_argument("--window-start")
    parser.add_argument("--window-end")
    args = parser.parse_args()
    payload = summarize(
        args.directory,
        window_hours=args.window_hours,
        window_start=args.window_start,
        window_end=args.window_end,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
