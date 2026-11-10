"""Summarize measured receipt times; never substitute event timestamps for ingestion times."""

from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

STAGES = ("state_received_at", "event_received_at", "finding_received_at", "finalized_received_at")


class Measurement(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trial_id: str = Field(min_length=1)
    condition: str = Field(min_length=1)
    action_at: datetime
    state_received_at: datetime | None = None
    event_received_at: datetime | None = None
    finding_received_at: datetime | None = None
    finalized_received_at: datetime | None = None
    failure_reason: str | None = None

    @field_validator("action_at", *STAGES)
    @classmethod
    def explicit_timezone(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("timestamps require an explicit timezone")
        return value


def summarize(rows: list[Measurement]) -> dict:
    if len({row.trial_id for row in rows}) != len(rows):
        raise ValueError("duplicate trial IDs")
    summaries = {}
    for condition in sorted({row.condition for row in rows}):
        subset = [row for row in rows if row.condition == condition]
        stages = {}
        for field in STAGES:
            durations = [
                (getattr(row, field) - row.action_at).total_seconds()
                for row in subset
                if getattr(row, field) is not None
            ]
            valid = sorted(value for value in durations if value >= 0)
            stages[field] = {
                "n": len(valid),
                "missing": len(subset) - len(durations),
                "negative_clock_or_label_errors": sum(value < 0 for value in durations),
                "mean_seconds": statistics.mean(valid) if valid else None,
                "median_seconds": statistics.median(valid) if valid else None,
                "min_seconds": min(valid) if valid else None,
                "max_seconds": max(valid) if valid else None,
                "stdev_seconds": statistics.stdev(valid) if len(valid) > 1 else None,
            }
        summaries[condition] = {
            "trials": len(subset),
            "failed_trials": sum(bool(row.failure_reason) for row in subset),
            "stages": stages,
        }
    return {
        "schema_version": "csg-latency-summary-v1",
        "conditions": summaries,
        "measurements": [row.model_dump(mode="json") for row in rows],
        "warning": "Input must use independently recorded UTC receipt times, not source event "
        "timestamps or snapshot-derived finding.created_at. Missing arrivals remain "
        "missing; report censoring and clock/polling uncertainty.",
    }


def main():
    parser = argparse.ArgumentParser(description="Summarize per-trial receipt-time measurements")
    parser.add_argument("measurements", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = summarize(
        [Measurement.model_validate(row) for row in json.loads(args.measurements.read_text())]
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
