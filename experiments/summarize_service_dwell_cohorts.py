#!/usr/bin/env python3
"""Validate and summarize repeated Windows service dwell-response cohorts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from experiments.analyze_service_dwell_campaign import wilson_interval

DWELL_LEVELS = (0.25, 2.0, 6.0, 12.0)


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8-sig") as handle:
        return json.load(handle)


def _condition_row(aggregate: dict[str, Any], condition: str, dwell: float) -> dict[str, Any]:
    matches = [
        row
        for row in aggregate["condition_summaries"]
        if row["condition"] == condition
        and float(row["planned_dwell_seconds"]) == dwell
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected one summary for {condition}/{dwell:g}s")
    return matches[0]


def load_cohort(campaign_dir: Path) -> dict[str, Any]:
    manifest = read_json(campaign_dir / "campaign-manifest.json")
    aggregate = read_json(campaign_dir / "analysis" / "aggregate.json")
    audit = read_json(campaign_dir / "analysis" / "raw-evidence-audit.json")
    visibility = read_json(
        campaign_dir / "analysis" / "wazuh-visibility-posthoc" / "summary.json"
    )

    if manifest.get("status") != "COMPLETED" or aggregate.get("campaign_status") != "COMPLETED":
        raise ValueError(f"Campaign {manifest.get('campaign_id')} is not complete")
    if manifest.get("scheduled_trials") != 50 or manifest.get("completed_trials") != 50:
        raise ValueError(
            f"Campaign {manifest.get('campaign_id')} is not a complete 50-trial cohort"
        )
    if audit.get("integrity_status") != "PASS" or audit.get("raw_run_files") != 50:
        raise ValueError(f"Raw evidence audit failed for {manifest.get('campaign_id')}")
    if audit.get("duplicate_wazuh_evidence_across_objects"):
        raise ValueError(f"Reused Wazuh evidence IDs in {manifest.get('campaign_id')}")
    if audit.get("duplicate_windows_system_record_ids_across_objects"):
        raise ValueError(f"Reused Windows event IDs in {manifest.get('campaign_id')}")
    if audit.get("unique_service_objects") != 50:
        raise ValueError("Each trial must refer to a distinct service object")
    reconciliation_statuses = audit.get("reconciliation_status_counts", {})
    if not reconciliation_statuses or set(reconciliation_statuses) != {"CORROBORATED"}:
        raise ValueError("Raw audit contains non-corroborated or missing reconciliation records")
    if visibility.get("campaign_id") != manifest.get("campaign_id"):
        raise ValueError("Post-hoc visibility summary belongs to a different campaign")
    if visibility.get("duplicate_exact_wazuh_event_ids_across_services"):
        raise ValueError("Post-hoc query reused exact Wazuh event IDs across services")

    query_counts = visibility["query_status_counts_by_condition"]
    treatment_queries = query_counts["dwell"]
    control_queries = query_counts["stable_no_change"]
    if treatment_queries.get("COMPLETE") != 40 or treatment_queries.get("exact_events_2") != 40:
        raise ValueError("Treatment trials do not all have two exact events from complete queries")
    if control_queries.get("COMPLETE") != 10 or control_queries.get("exact_events_0") != 10:
        raise ValueError("Stable controls do not all have complete queries with zero exact events")
    if visibility.get("unique_exact_wazuh_event_ids") != 80:
        raise ValueError("Expected 80 distinct exact Wazuh event IDs in treatment trials")
    windows_events = visibility.get("windows_system_7040_counts_by_condition", {})
    if windows_events.get("dwell") != 80 or windows_events.get("stable_no_change") != 0:
        raise ValueError("Windows System event counts do not match the treatment/control design")
    overlap = visibility.get("reconciliation_event_id_overlap", {})
    if overlap.get("matched") != overlap.get("reconciliation_ids"):
        raise ValueError("One or more reconciliation evidence IDs do not overlap exact query IDs")

    dwell_rows: dict[str, dict[str, Any]] = {}
    for dwell in DWELL_LEVELS:
        row = _condition_row(aggregate, "dwell", dwell)
        if row["scheduled"] != 10 or row["evaluable"] != 10:
            raise ValueError(f"Unexpected denominator for {dwell:g}s in {manifest['campaign_id']}")
        dwell_rows[str(dwell)] = row
    control = _condition_row(aggregate, "stable_no_change", 12.0)
    if control["scheduled"] != 10 or control["false_transitions"] != 0:
        raise ValueError("Stable no-change control is incomplete or has false transitions")

    return {
        "campaign_id": manifest["campaign_id"],
        "random_seed": manifest.get("random_seed"),
        "protocol_sha256": manifest.get("protocol_sha256"),
        "implementation_sha256": manifest.get("implementation_sha256"),
        "host_id": manifest.get("host_id"),
        "windows": manifest.get("windows"),
        "probe": manifest.get("probe"),
        "dwell_rows": dwell_rows,
        "control_row": control,
        "audit": audit,
        "visibility": visibility,
    }


def _check_comparable(cohorts: list[dict[str, Any]]) -> None:
    if len(cohorts) != 2:
        raise ValueError("Exactly two cohorts are required for this frozen comparison")
    for key, label in (
        ("host_id", "host"),
        ("implementation_sha256", "runner implementation"),
    ):
        if not cohorts[0][key] or cohorts[0][key] != cohorts[1][key]:
            raise ValueError(f"Cohorts differ in {label}")
    if cohorts[0]["windows"] != cohorts[1]["windows"]:
        raise ValueError("Cohorts differ in Windows version or architecture")
    p1, p2 = cohorts[0]["probe"], cohorts[1]["probe"]
    for key in (
        "settings_sha256",
        "poll_interval_seconds",
        "transition_enabled",
        "services_enabled",
    ):
        if p1.get(key) != p2.get(key):
            raise ValueError(f"Cohorts differ in probe setting {key}")
    if cohorts[0]["protocol_sha256"] == cohorts[1]["protocol_sha256"]:
        raise ValueError("Expected separately frozen cohort protocols and random seeds")
    if cohorts[0]["random_seed"] == cohorts[1]["random_seed"]:
        raise ValueError("Cohorts must use distinct predeclared random seeds")


def summarize_cohorts(campaign_dirs: list[Path]) -> dict[str, Any]:
    cohorts = [load_cohort(path) for path in campaign_dirs]
    _check_comparable(cohorts)

    pooled_dwell: list[dict[str, Any]] = []
    for dwell in DWELL_LEVELS:
        rows = [cohort["dwell_rows"][str(dwell)] for cohort in cohorts]
        successes = sum(int(row["primary_numerator"]) for row in rows)
        trials = sum(int(row["primary_denominator"]) for row in rows)
        pooled_dwell.append(
            {
                "planned_dwell_seconds": dwell,
                "captured": successes,
                "trials": trials,
                "rate": successes / trials,
                "wilson_95_interval": wilson_interval(successes, trials),
                "cohort_results": [
                    {
                        "campaign_id": cohort["campaign_id"],
                        "captured": int(row["primary_numerator"]),
                        "trials": int(row["primary_denominator"]),
                        "rate": float(row["primary_rate"]),
                        "wilson_95_interval": row["wilson_95_percent_interval"],
                    }
                    for cohort, row in zip(cohorts, rows, strict=True)
                ],
            }
        )

    controls_passed = sum(
        int(cohort["control_row"]["primary_numerator"]) for cohort in cohorts
    )
    controls_total = sum(int(cohort["control_row"]["primary_denominator"]) for cohort in cohorts)
    unique_events = sum(int(c["visibility"]["unique_exact_wazuh_event_ids"]) for c in cohorts)
    exact_reconciliation_matches = sum(
        int(c["visibility"]["reconciliation_event_id_overlap"]["matched"]) for c in cohorts
    )
    treatment_queries = [
        c["visibility"]["query_status_counts_by_condition"]["dwell"] for c in cohorts
    ]
    control_queries = [
        c["visibility"]["query_status_counts_by_condition"]["stable_no_change"]
        for c in cohorts
    ]
    treatment_complete = sum(int(q["COMPLETE"]) for q in treatment_queries)
    treatment_two_events = sum(int(q["exact_events_2"]) for q in treatment_queries)
    all_queries_complete = treatment_complete + sum(int(q["COMPLETE"]) for q in control_queries)
    windows_event_total = sum(
        int(c["visibility"]["windows_system_7040_counts_by_condition"]["dwell"])
        for c in cohorts
    )

    return {
        "schema_version": "1.0",
        "study": "single-host randomized service startup-mode dwell-response calibration",
        "pooling_policy": (
            "Two complete cohorts pooled descriptively only after protocol, host, runner, and "
            "probe-setting checks. Cohort 2 is a post-v2 extension after v2 outcomes were "
            "observed, "
            "not an independent untouched holdout. Keep cohort estimates alongside pooled values."
        ),
        "comparability_checks": {
            "same_host": True,
            "same_runner_sha256": True,
            "same_probe_settings_sha256": True,
            "same_poll_interval_seconds": cohorts[0]["probe"]["poll_interval_seconds"],
            "different_frozen_protocols": True,
            "distinct_random_seeds": True,
            "raw_audits_passed": all(c["audit"]["integrity_status"] == "PASS" for c in cohorts),
            "object_specific_wazuh_queries_passed": True,
        },
        "cohorts": [
            {
                "campaign_id": c["campaign_id"],
                "random_seed": c["random_seed"],
                "protocol_sha256": c["protocol_sha256"],
                "implementation_sha256": c["implementation_sha256"],
                "host_id": c["host_id"],
                "raw_trials": c["audit"]["raw_run_files"],
                "unique_service_objects": c["audit"]["unique_service_objects"],
                "unique_exact_wazuh_event_ids": c["visibility"]["unique_exact_wazuh_event_ids"],
                "exact_reconciliation_id_matches": c["visibility"]
                ["reconciliation_event_id_overlap"],
                "dwell_capture": [
                    {
                        "planned_dwell_seconds": dwell,
                        "captured": c["dwell_rows"][str(dwell)]["primary_numerator"],
                        "trials": c["dwell_rows"][str(dwell)]["primary_denominator"],
                    }
                    for dwell in DWELL_LEVELS
                ],
                "stable_controls_without_false_transition": {
                    "passed": c["control_row"]["primary_numerator"],
                    "trials": c["control_row"]["primary_denominator"],
                    "target_wazuh_events": c["visibility"]["query_status_counts_by_condition"]
                    ["stable_no_change"]["exact_events_0"],
                },
            }
            for c in cohorts
        ],
        "pooled_dwell_capture": pooled_dwell,
        "pooled_stable_no_change_control": {
            "no_false_transition": controls_passed,
            "trials": controls_total,
            "rate": controls_passed / controls_total,
            "wilson_95_interval": wilson_interval(controls_passed, controls_total),
            "exact_target_wazuh_events": 0,
            "complete_provider_queries": controls_total,
        },
        "pooled_wazuh_visibility": {
            "treatment_trials_with_two_exact_target_events": treatment_two_events,
            "treatment_trials_queried": treatment_complete,
            "exact_target_events": unique_events,
            "complete_provider_queries_total": all_queries_complete,
            "treatment_windows_system_7040_events": windows_event_total,
            "exact_reconciliation_evidence_id_overlap_total": exact_reconciliation_matches,
            "duplicate_event_ids_across_service_objects": 0,
            "scope": (
                "Post-hoc provider queries, secondary endpoint; not permanent event-loss testing."
            ),
        },
        "interpretation_boundary": (
            "This estimates how often a 5-second native state poll sampled a transient benign "
            "service startup-mode change at specified dwell durations, while exact Wazuh service "
            "events were available. It does not establish malicious-activity detection, "
            "superiority "
            "to Wazuh, capture under permanent telemetry loss, or reliability on another host."
        ),
    }


def markdown_report(result: dict[str, Any]) -> str:
    lines = [
        "# Service Dwell-Response Study: Two-Cohort Summary",
        "",
        "> Exploratory single-host sampling calibration, not an attack-detection evaluation.",
        "",
        "## Pooled Native-Probe Capture",
        "",
        "| Temporary state dwell | Captured | Trials | Rate | Wilson 95% interval |",
        "|---:|---:|---:|---:|---:|",
    ]
    for row in result["pooled_dwell_capture"]:
        low, high = row["wilson_95_interval"]
        lines.append(
            f"| {row['planned_dwell_seconds']:g}s | {row['captured']} | {row['trials']} | "
            f"{row['rate']:.3f} | [{low:.3f}, {high:.3f}] |"
        )
    lines.extend(
        [
            "",
            "## Cohort Results",
            "",
            "| Cohort | 0.25s | 2s | 6s | 12s | Stable controls without false transition |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for cohort in result["cohorts"]:
        values = [f"{r['captured']}/{r['trials']}" for r in cohort["dwell_capture"]]
        control = cohort["stable_controls_without_false_transition"]
        lines.append(
            f"| `{cohort['campaign_id']}` | "
            + " | ".join(values)
            + f" | {control['passed']}/{control['trials']} |"
        )
    controls = result["pooled_stable_no_change_control"]
    wazuh = result["pooled_wazuh_visibility"]
    lines.extend(
        [
            "",
            "## Exact Wazuh Object Evidence",
            "",
            (
                f"Post-hoc provider queries found two exact target-service events in "
                f"{wazuh['treatment_trials_with_two_exact_target_events']}/"
                f"{wazuh['treatment_trials_queried']} treatment trials; all "
                f"{wazuh['complete_provider_queries_total']} treatment/control queries completed. "
                f"Across the cohorts, {wazuh['exact_target_events']} unique exact target events "
                f"were returned, with {wazuh['duplicate_event_ids_across_service_objects']} "
                "event-ID reuse across different service objects."
            ),
            (
                f"{controls['no_false_transition']}/{controls['trials']} stable controls had no "
                "false CSG transition and zero exact target Wazuh events."
            ),
            "",
            "## Design and Limits",
            "",
            result["pooling_policy"],
            "",
            result["interpretation_boundary"],
            "",
            (
                "The extension cohort was planned and frozen before its trials, but it followed "
                "inspection of the first cohort. Therefore it is a repeated extension, not a "
                "blinded independent holdout. Wilson intervals are descriptive and do not address "
                "same-host dependence or generalization."
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("campaign_dirs", nargs=2, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    result = summarize_cohorts(args.campaign_dirs)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "pooled-summary.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.output_dir / "RESULTS.md").write_text(markdown_report(result), encoding="utf-8")
    print(args.output_dir / "RESULTS.md")


if __name__ == "__main__":
    main()
