"""Post-hoc matched baseline decomposition for the frozen WFP listener campaign."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from experiments.analyze_listener_wfp5154_campaign import verify_frozen_inputs
from experiments.run_listener_wfp5154_campaign import verify_freeze

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CAMPAIGN = (
    ROOT / "experiments/results/runs/20261016/listener-wfp5154-randomized-three-arm-v1"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_campaign_checksums(campaign_dir: Path) -> int:
    checksum_file = campaign_dir / "SHA256SUMS.txt"
    verified = 0
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", maxsplit=1)
        artifact = campaign_dir / relative
        if not artifact.is_file() or sha256(artifact) != expected:
            raise RuntimeError(f"Campaign artifact hash failed: {relative}")
        verified += 1
    if not verified:
        raise RuntimeError("Campaign checksum catalog is empty.")
    return verified


def confusion_matrix(actual: list[bool], predicted: list[bool]) -> dict[str, int]:
    if len(actual) != len(predicted):
        raise ValueError("Actual and predicted vectors must have equal length.")
    counts: Counter[str] = Counter()
    for truth, prediction in zip(actual, predicted, strict=True):
        if truth and prediction:
            counts["true_positive"] += 1
        elif truth:
            counts["false_negative"] += 1
        elif prediction:
            counts["false_positive"] += 1
        else:
            counts["true_negative"] += 1
    return {
        key: counts[key]
        for key in ("true_positive", "false_negative", "false_positive", "true_negative")
    }


def derive_rows(campaign_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    freeze, schedule = verify_freeze(campaign_dir)
    verify_frozen_inputs(campaign_dir, freeze)
    checksum_count = verify_campaign_checksums(campaign_dir)
    audit = load(campaign_dir / "analysis/audit.json")
    if not audit.get("all_slots_completed") or not audit.get("all_predeclared_gates_passed"):
        raise RuntimeError("Primary frozen audit is incomplete or has failed gates.")
    if audit.get("evaluable_trials") != len(schedule):
        raise RuntimeError("Primary audit and frozen schedule have different trial counts.")

    audited = {row["trial_id"]: row for row in audit["trial_results"]}
    schedule_by_id = {row["trial_id"]: row for row in schedule}
    if audited.keys() != schedule_by_id.keys():
        raise RuntimeError("Trial IDs differ between the frozen schedule and primary audit.")

    rows: list[dict[str, Any]] = []
    expected_arm_sizes = Counter()
    for trial_id, assigned in schedule_by_id.items():
        result = audited[trial_id]
        if not result.get("all_predeclared_gates_passed"):
            raise RuntimeError(f"Primary audit gate failed for {trial_id}.")
        if any(
            result.get(field) != assigned.get(field)
            for field in ("slot", "block", "condition", "target_port", "distractor_port")
        ):
            raise RuntimeError(f"Frozen assignment mismatch for {trial_id}.")

        condition = assigned["condition"]
        expected_arm_sizes[condition] += 1
        target_event_ids = result.get("target_wazuh_ids_physically_linked", [])
        distractor_event_ids = result.get("distractor_wazuh_ids_physically_linked", [])
        matched_ids = set(result.get("target_matched_evidence_ids", []))
        truth = condition != "no_change_with_distractor"
        state_detected = result.get("target_state_add_count", 0) == 1
        exact_event_detected = bool(target_event_ids)
        distractor_only = bool(distractor_event_ids) and not exact_event_detected

        if condition == "complete_exact":
            valid_result = result.get("target_reconciliation_status") == "CONSISTENT"
            valid_result = (
                valid_result and bool(matched_ids) and matched_ids <= set(target_event_ids)
            )
        elif condition == "target_event_absent_with_distractor":
            valid_result = result.get("target_reconciliation_status") == "UNEXPLAINED"
            valid_result = valid_result and not matched_ids
        else:
            valid_result = (
                result.get("target_delta_count") == 0 and result.get("target_finding_count") == 0
            )

        if state_detected != truth:
            raise RuntimeError(f"State-only comparator disagrees with assigned action: {trial_id}")
        if not valid_result:
            raise RuntimeError(f"Full CSG outcome disagrees with the frozen condition: {trial_id}")

        rows.append(
            {
                "trial_id": trial_id,
                "block": assigned["block"],
                "condition": condition,
                "target_action_performed": truth,
                "probe_state_add": state_detected,
                "exact_target_wazuh_event": exact_event_detected,
                "same_host_physical_distractor": bool(distractor_event_ids),
                "identity_blind_wrong_object_candidate": (
                    distractor_only and condition != "complete_exact"
                ),
                "identity_blind_ambiguous_target_and_distractor": (
                    bool(target_event_ids) and bool(distractor_event_ids)
                ),
                "csg_status": result.get("target_reconciliation_status"),
                "csg_matched_target_evidence_count": len(matched_ids),
                "csg_outcome_matches_condition": valid_result,
                "primary_gates_passed": result["all_predeclared_gates_passed"],
                "target_evidence_ids": ";".join(sorted(target_event_ids)),
                "distractor_evidence_ids": ";".join(sorted(distractor_event_ids)),
            }
        )

    if set(expected_arm_sizes.values()) != {10} or len(rows) != 30:
        raise RuntimeError("The campaign is not balanced at 10 trials per frozen condition.")

    truth = [row["target_action_performed"] for row in rows]
    state = [row["probe_state_add"] for row in rows]
    event = [row["exact_target_wazuh_event"] for row in rows]
    csg_visibility = [row["csg_status"] in {"CONSISTENT", "UNEXPLAINED"} for row in rows]
    by_condition: dict[str, dict[str, int]] = {}
    for condition in (
        "complete_exact",
        "target_event_absent_with_distractor",
        "no_change_with_distractor",
    ):
        arm = [row for row in rows if row["condition"] == condition]
        by_condition[condition] = {
            "assigned": len(arm),
            "target_actions": sum(row["target_action_performed"] for row in arm),
            "probe_state_adds": sum(row["probe_state_add"] for row in arm),
            "exact_target_wazuh_events": sum(row["exact_target_wazuh_event"] for row in arm),
            "physical_distractor_events": sum(row["same_host_physical_distractor"] for row in arm),
            "csg_consistent": sum(row["csg_status"] == "CONSISTENT" for row in arm),
            "csg_unexplained": sum(row["csg_status"] == "UNEXPLAINED" for row in arm),
            "false_target_findings": sum(
                row["csg_status"] not in {None, "NOT_APPLICABLE"}
                for row in arm
                if not row["target_action_performed"]
            ),
        }

    summary = {
        "schema_version": "csg-listener-baseline-decomposition-v1",
        "analysis_status": "POST_HOC_EXPLORATORY_NOT_PREDECLARED",
        "study_id": freeze["study_id"],
        "ground_truth_definition": {
            "positive": "the assigned benign target-listener action was performed",
            "negative": "the randomized no-change condition was assigned",
            "security_label": False,
            "maliciousness_evaluated": False,
        },
        "host_id": freeze["endpoint_id"],
        "trial_count": len(rows),
        "source_checksum_entries_verified_before_analysis": checksum_count,
        "comparators": {
            "probe_state_only_target_change_visibility": confusion_matrix(truth, state),
            "strict_exact_target_event_only_visibility": confusion_matrix(truth, event),
            "csg_full_pipeline_target_change_visibility": confusion_matrix(truth, csg_visibility),
            "csg_full_pipeline_status_counts": {
                status: sum(row["csg_status"] == status for row in rows)
                for status in ("CONSISTENT", "UNEXPLAINED")
            },
        },
        "identity_blind_counterfactual": {
            "rule": (
                "same host, listener_created event type, and trial observation window; "
                "ignore target port/object identity"
            ),
            "wrong_object_candidate_trials": sum(
                row["identity_blind_wrong_object_candidate"] for row in rows
            ),
            "ambiguous_trials_with_target_and_distractor": sum(
                row["identity_blind_ambiguous_target_and_distractor"] for row in rows
            ),
            "interpretation": (
                "A candidate is not evidence that an actual Wazuh detector would alert. This is a "
                "post-hoc association counterfactual using the assigned same-host distractors."
            ),
        },
        "by_condition": by_condition,
        "trial_results": rows,
        "limits": [
            "This is a post-hoc decomposition of the frozen 30-trial benign listener campaign.",
            "The label is assigned target action performed, not malicious activity or an attack.",
            (
                "The event-only comparator requires the exact target object and physical "
                "EventRecordID; it is not a configured Wazuh detection rule."
            ),
            (
                "The state-only comparator detects a state transition but cannot corroborate "
                "its cause or infer intent."
            ),
            (
                "The identity-blind comparator is counterfactual and must not be presented "
                "as measured Wazuh false-alarm performance."
            ),
            (
                "All trials share one Windows VM; no host-level generalization or population "
                "performance is estimated."
            ),
            "No inferential p-values or pooled cross-category estimates are computed.",
        ],
        "analysis_source_sha256": sha256(Path(__file__).resolve()),
    }
    return rows, summary


def render_report(summary: dict[str, Any]) -> str:
    comparators = summary["comparators"]
    state = comparators["probe_state_only_target_change_visibility"]
    event = comparators["strict_exact_target_event_only_visibility"]
    csg = comparators["csg_full_pipeline_target_change_visibility"]
    blind = summary["identity_blind_counterfactual"]
    return "\n".join(
        [
            "# Post-hoc Matched Baseline Decomposition: WFP 5154 Listener Campaign",
            "",
            f"**Study:** `{summary['study_id']}`  ",
            f"**Trials:** {summary['trial_count']} on one Windows VM  ",
            "**Status:** exploratory post-hoc analysis; not part of the frozen primary protocol  ",
            (
                "**Ground truth:** assigned benign target-listener action, not "
                "attack/maliciousness labels"
            ),
            "",
            "## Matched outcomes",
            "",
            "| Comparator/output | TP | FN | FP | TN | Interpretation |",
            "|---|---:|---:|---:|---:|---|",
            (
                f"| Probe state only | {state['true_positive']} | "
                f"{state['false_negative']} | {state['false_positive']} | "
                f"{state['true_negative']} | State-change visibility |"
            ),
            (
                f"| Exact-target Wazuh event only | {event['true_positive']} | "
                f"{event['false_negative']} | {event['false_positive']} | "
                f"{event['true_negative']} | Exact target event visibility |"
            ),
            (
                f"| Full CSG transition visibility | {csg['true_positive']} | "
                f"{csg['false_negative']} | {csg['false_positive']} | "
                f"{csg['true_negative']} | State delta retained with reconciliation status |"
            ),
            "",
            (
                "Full CSG produced "
                f"`{comparators['csg_full_pipeline_status_counts']['CONSISTENT']}` "
                f"`CONSISTENT` and "
                f"`{comparators['csg_full_pipeline_status_counts']['UNEXPLAINED']}` "
                "`UNEXPLAINED` outcomes. The complete arm was corroborated; the deliberately "
                "audit-disabled target arm remained visible but uncorroborated. The ten "
                "no-change trials had no target finding."
            ),
            "",
            "## Object-identity counterfactual",
            "",
            (
                "Every trial contained a physically verified same-host distractor. In "
                f"{blind['wrong_object_candidate_trials']}/30 trials without a target event "
                "(the ten audit-disabled target actions plus ten no-change controls), a "
                "comparator using only host, event type, and time would have had a wrong-object "
                "candidate. In "
                f"{blind['ambiguous_trials_with_target_and_distractor']}/30 complete trials, "
                "both target and distractor candidates were present. These are counterfactual "
                "association opportunities, not measured Wazuh alerts or false-alarm rates."
            ),
            "",
            "## Interpretation boundary",
            "",
            (
                "The paired decomposition shows that the native probe saw the benign target "
                "state change in cases where the exact Wazuh target event was unavailable, "
                "while full CSG kept the result `UNEXPLAINED` rather than claiming "
                "corroboration from the distractor. The binary change-visibility count for "
                "full CSG is the same as the probe-only state signal; the demonstrated "
                "contribution here is evidence attribution and uncertainty status, not "
                "additional state detection. The exact-event-only comparator is a strict "
                "object-keyed visibility baseline, not a configured Wazuh detector. This result "
                "does not establish malicious-activity detection efficacy, Wazuh superiority, "
                "permanent event loss, or generalization beyond this single VM and Event 5154 "
                "listener behavior."
            ),
            "",
            "## Reproduction",
            "",
            (
                "Run the archived script `source/analyze_listener_wfp5154_baselines.py` from "
                "this directory with `--campaign-dir <path-to-frozen-campaign>`. It verifies "
                "the frozen inputs and campaign SHA-256 catalog before producing the "
                "JSON/CSV/Markdown outputs."
            ),
            "",
        ]
    )


def self_test() -> int:
    assert confusion_matrix([True, True, False], [True, False, False]) == {
        "true_positive": 1,
        "false_negative": 1,
        "false_positive": 0,
        "true_negative": 1,
    }
    print("Baseline-analysis self-test passed: confusion-matrix counts and denominators.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-dir", type=Path, default=DEFAULT_CAMPAIGN)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()

    campaign_dir = args.campaign_dir.resolve()
    output_dir = campaign_dir / "posthoc" / "baseline-comparison"
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SystemExit(f"Refusing to overwrite existing post-hoc output: {output_dir}")
    rows, summary = derive_rows(campaign_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    archived_source = output_dir / "source" / Path(__file__).name
    archived_source.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(Path(__file__).resolve(), archived_source)
    summary["analysis_source_sha256"] = sha256(archived_source)

    json_path = output_dir / "baseline-comparison.json"
    json_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    csv_path = output_dir / "trial-baselines.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    report_path = output_dir / "baseline-comparison.md"
    report_path.write_text(render_report(summary), encoding="utf-8")
    source_manifest = [json_path, csv_path, report_path, archived_source]
    (output_dir / "SHA256SUMS.txt").write_text(
        "".join(
            f"{sha256(path)}  {path.relative_to(output_dir).as_posix()}\n"
            for path in source_manifest
        ),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "output_dir": str(output_dir),
                "trials": summary["trial_count"],
                "probe_state_only": summary["comparators"][
                    "probe_state_only_target_change_visibility"
                ],
                "exact_event_only": summary["comparators"][
                    "strict_exact_target_event_only_visibility"
                ],
                "csg_full_pipeline": summary["comparators"][
                    "csg_full_pipeline_target_change_visibility"
                ],
                "identity_blind_wrong_object_candidates": summary["identity_blind_counterfactual"][
                    "wrong_object_candidate_trials"
                ],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
