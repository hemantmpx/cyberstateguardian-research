"""Summarize independently audited Registry object-match cohorts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def wilson(successes: int, trials: int, z: float = 1.959963984540054) -> list[float] | None:
    if trials == 0:
        return None
    p = successes / trials
    denominator = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    radius = z * ((p * (1 - p) / trials + z * z / (4 * trials * trials)) ** 0.5) / denominator
    return [max(0.0, center - radius), min(1.0, center + radius)]


def summarize(inputs: list[tuple[str, Path, Path]]) -> dict[str, Any]:
    if len(inputs) != 2:
        raise ValueError("Exactly two separately audited cohorts (V78 and V79) are required.")

    cohorts: list[dict[str, Any]] = []
    all_trials: list[dict[str, Any]] = []
    seeds: set[int] = set()
    for label, campaign_dir, audit_path in inputs:
        audit = read_json(audit_path)
        manifest = read_json(campaign_dir / "campaign-manifest.json")
        if audit.get("audit_status") != "PASS" or manifest.get("status") != "COMPLETED":
            raise ValueError(f"{label}: independent audit and campaign must both pass/complete.")
        if audit.get("campaign_manifest_sha256") != sha256(campaign_dir / "campaign-manifest.json"):
            raise ValueError(f"{label}: audit does not cover the supplied campaign manifest.")
        seed = int(manifest["random_seed"])
        if seed in seeds:
            raise ValueError("Cohorts must have distinct randomization seeds.")
        seeds.add(seed)
        integrity = audit.get("campaign_integrity_checks", [])
        if not integrity or any(check.get("status") != "PASS" for check in integrity):
            raise ValueError(f"{label}: cross-trial integrity audit is incomplete or failed.")
        expected = {"registry_competing_event": 10, "registry_no_change": 10}
        for condition, n in expected.items():
            bucket = audit.get("counts_by_condition", {}).get(condition, {})
            if any(bucket.get(key) != n for key in ("assigned", "completed", "passed", "audited_pass")):
                raise ValueError(f"{label}: {condition} is not a fully audited 10/10 cohort.")
        trial_rows = audit.get("trials", [])
        if len(trial_rows) != 20 or any(row.get("audit_status") != "PASS" for row in trial_rows):
            raise ValueError(f"{label}: expected 20 independently passing trial audits.")
        for row in trial_rows:
            row = {**row, "cohort": label}
            all_trials.append(row)
        cohorts.append({
            "cohort": label,
            "campaign_id": manifest.get("experiment_id"),
            "seed": seed,
            "campaign_manifest_sha256": sha256(campaign_dir / "campaign-manifest.json"),
            "audit_sha256": sha256(audit_path),
            "planned_trials": audit.get("planned_trials"),
            "observed_artifacts": audit.get("observed_artifacts"),
            "audit_status": audit.get("audit_status"),
            "competing_event": audit["counts_by_condition"]["registry_competing_event"],
            "no_change": audit["counts_by_condition"]["registry_no_change"],
        })

    competing = [row for row in all_trials if row.get("condition") == "registry_competing_event"]
    controls = [row for row in all_trials if row.get("condition") == "registry_no_change"]
    if len(competing) != 20 or len(controls) != 20:
        raise ValueError("Combined trial counts must be 20 competing-event and 20 no-change.")

    target_ids = [event for row in competing for event in row.get("target_event_ids", [])]
    distractor_ids = [event for row in competing for event in row.get("distractor_event_ids", [])]
    matched_ids = [event for row in competing for event in row.get("matched_evidence_ids", [])]
    record_ids = [event for row in competing for event in row.get("target_local_record_ids", []) + row.get("distractor_local_record_ids", [])]
    target_names = [row["target_name"] for row in competing]
    distractor_names = [row["distractor_name"] for row in competing]
    delta_ids = [row["target_delta_id"] for row in competing]

    object_match_successes = sum(
        row.get("reconciliation_status") == "CONSISTENT"
        and set(row.get("matched_evidence_ids", [])) == set(row.get("target_event_ids", []))
        and not set(row.get("matched_evidence_ids", [])).intersection(row.get("distractor_event_ids", []))
        and row.get("distractor_in_window") is True
        for row in competing
    )
    no_change_successes = sum(
        any(check.get("check") == "no_target_delta_or_finding" and check.get("status") == "PASS"
            for check in row.get("checks", []))
        for row in controls
    )
    integrity_checks = {
        "all_target_wazuh_ids_unique": len(target_ids) == len(set(target_ids)) == 20,
        "all_distractor_wazuh_ids_unique": len(distractor_ids) == len(set(distractor_ids)) == 20,
        "target_and_distractor_wazuh_ids_disjoint": not set(target_ids).intersection(distractor_ids),
        "all_local_event_record_ids_unique": len(record_ids) == len(set(record_ids)) == 40,
        "all_target_names_unique": len(target_names) == len(set(target_names)) == 20,
        "all_distractor_names_unique": len(distractor_names) == len(set(distractor_names)) == 20,
        "all_target_delta_ids_unique": len(delta_ids) == len(set(delta_ids)) == 20,
        "matched_ids_equal_all_target_ids": set(matched_ids) == set(target_ids),
        "no_change_controls_have_no_findings": no_change_successes == 20,
    }
    if not all(integrity_checks.values()):
        raise ValueError(f"Combined-cohort integrity failure: {integrity_checks}")

    return {
        "schema_version": "1.0",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "analysis_scope": "two independently randomized cohorts on the same single Windows 11 ARM endpoint; one benign Registry behavior family",
        "cohorts": cohorts,
        "combined": {
            "competing_event": {
                "successes": object_match_successes,
                "trials": len(competing),
                "rate": object_match_successes / len(competing),
                "wilson_95": wilson(object_match_successes, len(competing)),
                "distractors_inside_target_window": sum(row.get("distractor_in_window") is True for row in competing),
                "wrong_object_ids_matched": sum(bool(set(row.get("matched_evidence_ids", [])).intersection(row.get("distractor_event_ids", []))) for row in competing),
                "unique_target_wazuh_events": len(set(target_ids)),
                "unique_distractor_wazuh_events": len(set(distractor_ids)),
                "unique_local_event_record_ids": len(set(record_ids)),
                "unique_target_deltas": len(set(delta_ids)),
            },
            "no_change": {
                "successful_quiet_windows": no_change_successes,
                "trials": len(controls),
                "rate": no_change_successes / len(controls),
                "wilson_95": wilson(no_change_successes, len(controls)),
            },
            "integrity_checks": integrity_checks,
        },
        "limitations": [
            "Both cohorts are repeated trials on the same Windows endpoint, not independent host replications.",
            "The mutation is benign current-user Registry Run-key data; no payload was executed.",
            "This tests exact-object reconciliation and no-change behavior, not malicious-activity detection efficacy.",
            "There is no matched Wazuh-only baseline and no second host in this analysis.",
        ],
        "trials": all_trials,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", action="append", nargs=3, metavar=("LABEL", "CAMPAIGN_DIR", "AUDIT_JSON"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    inputs = [(label, Path(campaign_dir), Path(audit_path)) for label, campaign_dir, audit_path in args.cohort]
    result = summarize(inputs)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "aggregate.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    fields = ["cohort", "trial_id", "condition", "audit_status", "target_name", "distractor_name",
              "target_delta_id", "target_event_ids", "distractor_event_ids", "matched_evidence_ids",
              "reconciliation_status", "distractor_in_window"]
    with (args.output_dir / "trial-summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in result["trials"]:
            writer.writerow({key: json.dumps(row[key]) if isinstance(row.get(key), list) else row.get(key) for key in fields})
    print(json.dumps({"combined": result["combined"], "cohort_ids": [c["campaign_id"] for c in result["cohorts"]]}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
