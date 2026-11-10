#!/usr/bin/env python3
"""Summarize a live CSG service-transition dwell campaign without hiding failures."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from statistics import NormalDist
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8-sig") as handle:
        return json.load(handle)


def wilson_interval(successes: int, trials: int, confidence: float = 0.95) -> list[float] | None:
    if trials == 0:
        return None
    z = NormalDist().inv_cdf(0.5 + confidence / 2)
    p = successes / trials
    denominator = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * trials)) / trials) / denominator
    return [max(0.0, center - margin), min(1.0, center + margin)]


def summarize(campaign_dir: Path) -> dict[str, Any]:
    manifest = read_json(campaign_dir / "campaign-manifest.json")
    runs = [read_json(path) for path in sorted(campaign_dir.glob("trial-*/run.json"))]
    groups: dict[tuple[str, float], list[dict[str, Any]]] = defaultdict(list)
    for run in runs:
        condition = str(run.get("condition", "unknown"))
        dwell = float(run.get("planned_dwell_seconds", 0))
        groups[(condition, dwell)].append(run)

    rows: list[dict[str, Any]] = []
    for (condition, dwell), trials in sorted(
        groups.items(), key=lambda item: (item[0][0], item[0][1])
    ):
        outcomes = Counter(
            (trial.get("validation") or {}).get("outcome", "MISSING") for trial in trials
        )
        if condition == "dwell":
            valid = [
                trial
                for trial in trials
                if (trial.get("validation") or {}).get("outcome") in {"CAPTURED", "NOT_CAPTURED"}
            ]
            captured = sum(
                (trial.get("validation") or {}).get("outcome") == "CAPTURED" for trial in valid
            )
            measured = [
                float(trial["actual_dwell_seconds"])
                for trial in valid
                if trial.get("actual_dwell_seconds") is not None
            ]
            numerator_name = "exact_auto_transition_captured"
            numerator = captured
            denominator = len(valid)
            rate = captured / denominator if denominator else None
            ci = wilson_interval(captured, denominator)
            false_transitions = None
        else:
            valid = [
                trial
                for trial in trials
                if (trial.get("validation") or {}).get("outcome")
                in {"CONTROL_NO_FALSE_TRANSITION", "CONTROL_FALSE_TRANSITION"}
            ]
            false_transitions = sum(
                (trial.get("validation") or {}).get("outcome") == "CONTROL_FALSE_TRANSITION"
                for trial in valid
            )
            numerator_name = "stable_controls_without_false_transition"
            numerator = len(valid) - false_transitions
            denominator = len(valid)
            rate = numerator / denominator if denominator else None
            ci = wilson_interval(numerator, denominator)
            measured = []
        rows.append(
            {
                "condition": condition,
                "planned_dwell_seconds": dwell,
                "scheduled": len(trials),
                "evaluable": denominator,
                "incomplete_or_integrity_failures": len(trials) - denominator,
                "outcomes": dict(sorted(outcomes.items())),
                "primary_numerator_name": numerator_name,
                "primary_numerator": numerator,
                "primary_denominator": denominator,
                "primary_rate": rate,
                "wilson_95_percent_interval": ci,
                "false_transitions": false_transitions,
                "actual_dwell_seconds": {
                    "n": len(measured),
                    "mean": statistics.mean(measured) if measured else None,
                    "median": statistics.median(measured) if measured else None,
                    "min": min(measured) if measured else None,
                    "max": max(measured) if measured else None,
                    "stdev": statistics.stdev(measured) if len(measured) > 1 else None,
                },
            }
        )

    result = {
        "schema_version": "1.0",
        "campaign_id": manifest.get("campaign_id"),
        "campaign_status": manifest.get("status"),
        "host_id": manifest.get("host_id"),
        "interpretation": (
            "Exploratory single-host sampling calibration; not security-detection accuracy "
            "or cross-host reliability."
        ),
        "scheduled_trials": manifest.get("scheduled_trials"),
        "completed_trials": manifest.get("completed_trials"),
        "not_run_trials": manifest.get("not_run_trials"),
        "stop_reason": manifest.get("stop_reason"),
        "condition_summaries": rows,
        "all_trial_outcomes": dict(
            sorted(
                Counter(
                    (trial.get("validation") or {}).get("outcome", "MISSING") for trial in runs
                ).items()
            )
        ),
        "cleanup_failures": [
            trial.get("trial_id")
            for trial in runs
            if (trial.get("cleanup") or {}).get("attempted")
            and not (trial.get("cleanup") or {}).get("completed")
        ],
        "artifacts_analyzed": len(runs),
    }
    return result


def markdown_report(result: dict[str, Any]) -> str:
    lines = [
        "# Service Transition Dwell-Response Calibration",
        "",
        f"Campaign: `{result['campaign_id']}`  ",
        f"Status: **{result['campaign_status']}**  ",
        f"Host: `{result['host_id']}`  ",
        f"Trial artifacts: {result['artifacts_analyzed']} / {result['scheduled_trials']} scheduled",
        "",
        (
            "> Exploratory measurement on one Windows 11 ARM64 VM. This is not an attack-"
            "detection result, a cross-host reliability estimate, or conference-ready evidence "
            "by itself."
        ),
        "",
        "## Results",
        "",
        (
            "| Condition | Scheduled | Evaluable | Captured / no false transition | Rate | "
            "Wilson 95% interval | Incomplete / integrity |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in result["condition_summaries"]:
        rate = "n/a" if row["primary_rate"] is None else f"{row['primary_rate']:.3f}"
        interval = row["wilson_95_percent_interval"]
        ci = "n/a" if interval is None else f"[{interval[0]:.3f}, {interval[1]:.3f}]"
        lines.append(
            f"| {row['condition']} / {row['planned_dwell_seconds']:g}s | "
            f"{row['scheduled']} | {row['primary_denominator']} | "
            f"{row['primary_numerator']} / {row['primary_denominator']} | "
            f"{rate} | {ci} | {row['incomplete_or_integrity_failures']} |"
        )
    lines.extend(
        [
            "",
            "## Actual dwell timing",
            "",
            "| Planned dwell | n | Mean s | Median s | Min s | Max s | SD s |",
            "|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in result["condition_summaries"]:
        stats = row["actual_dwell_seconds"]
        if stats["n"]:

            def fmt(value: float | None) -> str:
                return "n/a" if value is None else f"{value:.4f}"

            lines.append(
                f"| {row['planned_dwell_seconds']:g} | {stats['n']} | {fmt(stats['mean'])} | "
                f"{fmt(stats['median'])} | {fmt(stats['min'])} | {fmt(stats['max'])} | "
                f"{fmt(stats['stdev'])} |"
            )
    lines.extend(
        [
            "",
            "## Accounting and interpretation",
            "",
            (
                f"- Campaign accounting: {result['completed_trials']} completed, "
                f"{result['not_run_trials']} not run; {result['artifacts_analyzed']} "
                "per-trial JSON files analyzed."
            ),
            f"- Outcome counts: `{json.dumps(result['all_trial_outcomes'], sort_keys=True)}`.",
            f"- Cleanup failures: `{json.dumps(result['cleanup_failures'])}`.",
            f"- Stop reason: `{result['stop_reason']}`.",
            (
                "- A `CAPTURED` result means an exact target-object `SERVICE_START_MODE_CHANGED` "
                "record reported Automatic during the measured interval. It does not mean Wazuh "
                "detected an attack."
            ),
            (
                "- A control false transition and every incomplete trial remain visible; "
                "incomplete trials are excluded only from the corresponding evaluable denominator "
                "and are separately counted."
            ),
            (
                "- Wilson intervals are descriptive. With only 10 scheduled repetitions per "
                "condition, uncertainty remains substantial."
            ),
            (
                "- Review the raw `trial-*/run.json` files and campaign manifest before using "
                "any aggregate in a paper."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("campaign_dir", type=Path)
    args = parser.parse_args()
    result = summarize(args.campaign_dir)
    analysis_dir = args.campaign_dir / "analysis"
    analysis_dir.mkdir(exist_ok=True)
    (analysis_dir / "aggregate.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (analysis_dir / "RESULTS.md").write_text(markdown_report(result), encoding="utf-8")
    print(analysis_dir / "RESULTS.md")


if __name__ == "__main__":
    main()
