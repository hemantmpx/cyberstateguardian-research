"""Create a post-hoc, block-wise synthesis of the V14 and V16 service cohorts."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any

ARMS = (
    "complete",
    "target_event_drop",
    "target_no_change_with_wrong_object_event",
)
FROZEN_FILES = {
    "assignment_sha256": "assignment.json",
    "generator_sha256": "generate_assignment.py",
    "protocol_sha256": "PROTOCOL.md",
    "controller_sha256": "run_cohort_windows.ps1",
    "complete_runner_sha256": "run_complete_control.ps1",
    "drop_runner_sha256": "run_target_event_drop.ps1",
    "no_change_runner_sha256": "run_no_change_control.ps1",
}


def clopper_pearson(successes: int, trials: int, alpha: float = 0.05) -> list[float]:
    if trials <= 0 or not 0 <= successes <= trials:
        raise ValueError("Require trials > 0 and 0 <= successes <= trials")

    def pmf(index: int, probability: float) -> float:
        return math.comb(trials, index) * probability**index * (1 - probability) ** (trials - index)

    tail = alpha / 2
    if successes == 0:
        lower = 0.0
    else:
        left, right = 0.0, 1.0
        for _ in range(80):
            middle = (left + right) / 2
            if sum(pmf(i, middle) for i in range(successes, trials + 1)) < tail:
                left = middle
            else:
                right = middle
        lower = (left + right) / 2
    if successes == trials:
        upper = 1.0
    else:
        left, right = 0.0, 1.0
        for _ in range(80):
            middle = (left + right) / 2
            if sum(pmf(i, middle) for i in range(successes + 1)) > tail:
                left = middle
            else:
                right = middle
        upper = (left + right) / 2
    return [lower, upper]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_manifest(run_dir: Path) -> dict[str, Any]:
    manifest_path = run_dir / "analysis" / "artifact-manifest.json"
    manifest = read_json(manifest_path)
    failures = []
    for item in manifest["files"]:
        path = run_dir / item["path"]
        if not path.is_file() or path.stat().st_size != item["bytes"] or sha256(path) != item["sha256"]:
            failures.append(item["path"])
    tool = manifest.get("analysis_tool")
    if tool:
        tool_path = Path(tool["path"])
        if not tool_path.is_file() or sha256(tool_path) != tool["sha256"]:
            failures.append(str(tool_path))
    if failures:
        raise ValueError(f"Artifact manifest verification failed for {run_dir}: {failures[:8]}")
    return {"manifest_path": manifest_path.as_posix(), "files_verified": len(manifest["files"]), "manifest_sha256": sha256(manifest_path)}


def verify_source_freeze(run_dir: Path, freeze: dict[str, Any]) -> None:
    failures = []
    for field, filename in FROZEN_FILES.items():
        path = run_dir / filename
        if not path.is_file() or sha256(path) != freeze.get(field):
            failures.append(filename)
    postflight_hash = freeze.get("postflight_script_sha256")
    if postflight_hash and not any(
        path.is_file() and sha256(path) == postflight_hash
        for path in run_dir.glob("postflight*.ps1")
    ):
        failures.append("postflight*.ps1")
    if failures:
        raise ValueError(f"Frozen source hash mismatch for {run_dir}: {failures}")


def trial_success(condition: str, row: dict[str, Any]) -> bool:
    if condition == "complete":
        return bool(
            row["trial_pass"]
            and row["target_state_add_observed"]
            and row["target_exact_wazuh_event_count"] == 1
            and row["distractor_exact_wazuh_event_count"] >= 1
            and row["target_event_record_id_linked"]
            and row["distractor_event_record_id_linked"]
            and row["reconciliation_status"] == "CONSISTENT"
            and row["reconciliation_finalized"]
            and row["matched_only_target_evidence"]
        )
    if condition == "target_event_drop":
        return bool(
            row["trial_pass"]
            and row["target_state_add_observed"]
            and row["target_exact_wazuh_event_count"] == 0
            and row["distractor_exact_wazuh_event_count"] >= 1
            and row["distractor_event_record_id_linked"]
            and row["reconciliation_status"] == "UNEXPLAINED"
            and row["reconciliation_finalized"]
            and not row["matched_evidence_ids"]
        )
    return bool(
        row["trial_pass"]
        and row["target_absent_no_change_control"]
        and not row["target_state_add_observed"]
        and row["target_exact_wazuh_event_count"] == 0
        and row["distractor_exact_wazuh_event_count"] >= 1
        and row["distractor_event_record_id_linked"]
        and row["reconciliation_status"] == "NO_FINDING_EXPECTED"
        and row["finding_id"] is None
        and row["delta_id"] is None
    )


def get_run_events(run: dict[str, Any], side: str) -> list[dict[str, Any]]:
    events = run["provider_query"][f"{side}_exact_service_created_events"]
    if not isinstance(events, list):
        raise ValueError(f"Expected an event list for {side}")
    return events


def validate_raw_trial(
    raw: dict[str, Any], trial: dict[str, Any], host_id: str
) -> list[str]:
    failures = []
    condition = trial["condition"]
    target_name = trial["target_service_name"]
    distractor_name = trial["distractor_service_name"]
    if (
        raw.get("trial_id") != trial["trial_id"]
        or raw.get("service_name") != target_name
        or raw.get("distractor_service_name") != distractor_name
        or raw.get("host_id") != host_id
    ):
        failures.append("raw runner identity does not match assignment")

    provider = raw.get("provider_query") or {}
    if not (
        provider.get("query_complete")
        and provider.get("coverage_status") == "COMPLETE"
        and provider.get("endpoint_collection_status") == "AVAILABLE"
        and provider.get("index_status") == "AVAILABLE"
    ):
        failures.append("raw Wazuh query/collection health gates did not pass")

    def verify_events(side: str, name: str, local_record: dict[str, Any] | None) -> list[str]:
        events = get_run_events(raw, side)
        event_failures = []
        for event in events:
            identity = (event.get("metadata") or {}).get("windows_event_identity") or {}
            if not (
                event.get("host_id") == host_id
                and event.get("source") == "wazuh"
                and event.get("normalized_type") == "service_created"
                and (event.get("target") or {}).get("key") == f"service:{name.lower()}"
                and (event.get("attributes") or {}).get("service_name") == name
                and str((event.get("attributes") or {}).get("event_code")) == "7045"
            ):
                event_failures.append(f"{side} event failed exact host/type/object identity")
                continue
            if local_record is None or local_record.get("service_name") != name or str(
                local_record.get("event_record_id")
            ) != str(identity.get("event_record_id")):
                event_failures.append(f"{side} Wazuh event did not link to its local EventRecordID")
        return event_failures

    target_events = get_run_events(raw, "target")
    distractor_events = get_run_events(raw, "distractor")
    target_local = (raw.get("target") or {}).get("local_7045")
    distractor_local = (raw.get("distractor") or {}).get("local_7045")
    failures.extend(verify_events("target", target_name, target_local))
    failures.extend(verify_events("distractor", distractor_name, distractor_local))
    expected_target_events = 1 if condition == "complete" else 0
    if len(target_events) != expected_target_events or len(distractor_events) != 1:
        failures.append("raw exact target/distractor event counts differ from the assigned arm")

    raw_deltas = raw.get("target_delta")
    if raw_deltas is None:
        raw_deltas = raw.get("target_deltas", [])
    if not isinstance(raw_deltas, list):
        raw_deltas = [raw_deltas]
    findings = raw.get("target_findings") or []
    if condition == "target_no_change_with_wrong_object_event":
        if raw_deltas or findings or raw.get("outcome") != "NO_TARGET_FINDING":
            failures.append("no-change raw artifact contains a target delta/finding")
    else:
        if len(raw_deltas) != 1 or raw_deltas[0].get("delta_type") != "ADD" or raw_deltas[0].get(
            "object_key"
        ) != f"service:{target_name.lower()}":
            failures.append("raw target state ADD is missing or has the wrong object identity")
        if len(findings) != 1:
            failures.append("raw target finding count is not exactly one")
        else:
            reconciliation = findings[0].get("reconciliation") or {}
            wanted = "CONSISTENT" if condition == "complete" else "UNEXPLAINED"
            matched = set(reconciliation.get("matched_evidence_ids") or [])
            target_ids = {event["event_id"] for event in target_events}
            if reconciliation.get("status") != wanted or not reconciliation.get("finalized"):
                failures.append(f"raw reconciliation was not finalized {wanted}")
            if condition == "complete" and (not matched or not matched.issubset(target_ids)):
                failures.append("complete raw finding did not cite only its exact target event")
            if condition == "target_event_drop" and matched:
                failures.append("filtered target raw finding unexpectedly cites event evidence")
    return failures


def summarize_cohort(run_dir: Path, expected_version: str) -> dict[str, Any]:
    assignment = read_json(run_dir / "assignment.json")
    freeze = read_json(run_dir / "source-freeze.json")
    analysis = read_json(run_dir / "analysis" / "analysis.json")
    if not assignment["experiment_id"].endswith(expected_version):
        raise ValueError(f"Unexpected cohort in {run_dir}")
    if analysis["audit_status"] != "PASS" or analysis["audit_failures"]:
        raise ValueError(f"Independent analyzer audit did not pass for {expected_version}")
    if analysis["assigned_trials"] != 30 or analysis["analyzed_raw_trials"] != 30:
        raise ValueError(f"Incomplete source analyzer result for {expected_version}")
    verify_source_freeze(run_dir, freeze)
    manifest = verify_manifest(run_dir)

    assigned_counts = {arm: sum(t["condition"] == arm for t in assignment["trials"]) for arm in ARMS}
    if assigned_counts != {arm: 10 for arm in ARMS} or analysis["condition_counts"] != assigned_counts:
        raise ValueError(f"Assignment arm counts differ for {expected_version}")
    if assignment["endpoint"] != "WIN-RLP1P9E9TO9" or assignment["host_id"] != "win11-arm-lab":
        raise ValueError(f"Unexpected Windows endpoint for {expected_version}")

    by_id = {row["trial_id"]: row for row in analysis["trial_results"]}
    if len(by_id) != 30 or set(by_id) != {t["trial_id"] for t in assignment["trials"]}:
        raise ValueError(f"Trial result IDs do not match frozen assignment for {expected_version}")
    successes: dict[str, int] = {}
    evidence_ids: dict[str, str] = {}
    rows = []
    raw_failures = []
    for trial in assignment["trials"]:
        row = by_id[trial["trial_id"]]
        if row["condition"] != trial["condition"]:
            raise ValueError(f"Condition mismatch for {trial['trial_id']}")
        if not trial_success(trial["condition"], row):
            raise ValueError(f"Independent outcome checks failed for {trial['trial_id']}")
        raw_path = (
            run_dir
            / "remote-capture"
            / assignment["experiment_id"]
            / "trials"
            / trial["trial_id"]
            / "run.json"
        )
        if not raw_path.is_file():
            raise ValueError(f"Raw Windows run is missing: {raw_path}")
        raw = read_json(raw_path)
        raw_failures.extend(
            f"{trial['trial_id']}: {failure}"
            for failure in validate_raw_trial(raw, trial, assignment["host_id"])
        )
        for role, key in (("target", "target_evidence_ids"), ("distractor", "distractor_evidence_ids")):
            service_name = trial["target_service_name"] if role == "target" else trial["distractor_service_name"]
            for evidence_id in row[key]:
                owner = f"{service_name}:{role}"
                if evidence_id in evidence_ids and evidence_ids[evidence_id] != owner:
                    raise ValueError(f"Evidence ID reused across objects: {evidence_id}")
                evidence_ids[evidence_id] = owner
        rows.append(row)
    if raw_failures:
        raise ValueError(f"Raw Windows artifact re-audit failed: {raw_failures[:10]}")
    for arm in ARMS:
        successes[arm] = sum(
            trial_success(arm, by_id[trial["trial_id"]])
            for trial in assignment["trials"]
            if trial["condition"] == arm
        )

    return {
        "experiment_id": assignment["experiment_id"],
        "assignment_seed": assignment["assignment_seed"],
        "host_id": assignment["host_id"],
        "endpoint": assignment["endpoint"],
        "baseline_wazuh_config_sha256": freeze["baseline_wazuh_config_sha256"],
        "assigned_trials": len(assignment["trials"]),
        "raw_trials_reaudited": len(assignment["trials"]),
        "arm_counts": assigned_counts,
        "arm_successes": successes,
        "unique_exact_evidence_ids": sorted(evidence_ids),
        "analysis_audit_status": analysis["audit_status"],
        "artifact_integrity": manifest,
        "timings": analysis["timings"],
        "trial_rows": rows,
    }


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# V14/V16 Block-Wise Within-Host Synthesis",
        "",
        "**Analysis status:** post-hoc descriptive synthesis; V14 and V16 remain separate campaign blocks.  ",
        "**Endpoint scope:** one Windows 11 ARM64 VM. This does not provide independent-host replication.",
        "",
        "## Why These Cohorts Are Presented Together",
        "",
        "Both frozen assignments use the same three conditions, service behavior, target/distractor identity rules, endpoint, and baseline Wazuh configuration. V16 differs operationally by replacing the synchronous Wazuh service restart with bounded SCM state/PID polling after V15's service-control timeout. Each cohort is audited and reported separately first; the summary below is a within-host block synthesis, not a new confirmatory experiment or a population-level estimate.",
        "",
        "## Results By Campaign Block",
        "",
        "| Campaign | Complete target-only `CONSISTENT` | Filtered target retained + `UNEXPLAINED` | No-change target quiet with distractor | Raw audit |",
        "|---|---:|---:|---:|---|",
    ]
    for cohort in result["cohorts"]:
        successes = cohort["arm_successes"]
        lines.append(
            f"| `{cohort['experiment_id']}` | {successes['complete']}/10 | {successes['target_event_drop']}/10 | {successes['target_no_change_with_wrong_object_event']}/10 | {cohort['analysis_audit_status']} |"
        )
    lines.extend(
        [
            "",
            "## Within-Host Combined Counts",
            "",
            "| Condition | Observed result | Naive exact 95% interval* |",
            "|---|---:|---:|",
        ]
    )
    for arm, label in (
        ("complete", "Target-only `CONSISTENT` with exact target event"),
        ("target_event_drop", "State retained; filtered target `UNEXPLAINED`; distractor rejected"),
        ("target_no_change_with_wrong_object_event", "No target finding with wrong-object event"),
    ):
        metric = result["combined_by_arm"][arm]
        low, high = metric["naive_ci_95_clopper_pearson"]
        lines.append(f"| {label} | {metric['successes']}/{metric['trials']} ({metric['proportion']:.1%}) | {low:.1%}-{high:.1%} |")
    lines.extend(
        [
            "",
            "*The intervals are naive exact binomial intervals treating trials as independent Bernoulli observations. Because trials share one host and campaigns are two temporal blocks on that same host, host/block dependence is unmodeled; do not interpret these intervals as fleet-level uncertainty or independent-host evidence. The primary reporting remains the separate V14 and V16 rows above (10 trials per condition per block).",
            "",
            "## Evidence And Integrity",
            "",
            f"- Total assigned trials: {result['total_trials']}; all source-cohort raw-artifact audits passed.",
            f"- Exact Wazuh evidence IDs: {result['unique_evidence_ids']}; overlap between the V14 and V16 exact-object evidence sets: {result['cross_cohort_evidence_id_overlap'] }.",
            f"- Assigned service identities: {result['unique_service_names']} unique across the two blocks; no identity reuse.",
            f"- Same host/endpoint: `{result['host_id']}` / `{result['endpoint']}`; baseline config SHA-256 matches across blocks: `{result['same_baseline_config']}`.",
            "- V15 is not included: it is an incomplete service-control failure before target mutation, not a completed cohort.",
            "",
            "## Limits And Claim",
            "",
            "This synthesis strengthens repeatability evidence for exact-object service-state reconciliation on this configured Windows VM. It does not establish that CSG detects malicious activity more accurately than Wazuh, does not test natural or permanent telemetry loss (the target event is deliberately filtered), and does not establish performance on another endpoint. The service mutation is benign and inert. Conference-level validation still requires an independently provisioned Windows host, prospectively labeled security behaviors and controls, a fair configured Wazuh-only baseline on those same trials, and reproducible cross-host analysis. No cross-platform claim is made.",
            "",
            "## Source Artifacts",
            "",
            "- [V14 detailed analysis](../service-install-randomized-three-arm-v14/analysis/analysis.md) and [raw/frozen bundle](../service-install-randomized-three-arm-v14/)",
            "- [V16 detailed analysis](../service-install-randomized-three-arm-v16/analysis/analysis.md) and [raw/frozen bundle](../service-install-randomized-three-arm-v16/)",
            "- [V16 SCM transition audit](../service-install-randomized-three-arm-v16/analysis/service-control-audit.json)",
            "- [V15 interruption record](../service-install-randomized-three-arm-v15/EXECUTION_NOTE.md)",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    v14_dir = args.results_root / "service-install-randomized-three-arm-v14"
    v16_dir = args.results_root / "service-install-randomized-three-arm-v16"
    cohorts = [summarize_cohort(v14_dir, "v14"), summarize_cohort(v16_dir, "v16")]
    if cohorts[0]["host_id"] != cohorts[1]["host_id"] or cohorts[0]["endpoint"] != cohorts[1]["endpoint"]:
        raise SystemExit("Cohorts are not from the same declared host; synthesis refused")
    if cohorts[0]["baseline_wazuh_config_sha256"] != cohorts[1]["baseline_wazuh_config_sha256"]:
        raise SystemExit("Baseline Wazuh configuration differs; synthesis refused")
    assignments = [read_json(path / "assignment.json") for path in (v14_dir, v16_dir)]
    if assignments[0]["conditions"] != assignments[1]["conditions"]:
        raise SystemExit("Condition definitions differ; synthesis refused")
    if assignments[0]["assignment_seed"] == assignments[1]["assignment_seed"]:
        raise SystemExit("Assignment seeds are not distinct")
    names = {
        name
        for assignment in assignments
        for trial in assignment["trials"]
        for name in (trial["target_service_name"], trial["distractor_service_name"])
    }
    if len(names) != 120:
        raise SystemExit("Assigned service identities collide between V14 and V16")

    combined: dict[str, Any] = {}
    for arm in ARMS:
        successes = sum(cohort["arm_successes"][arm] for cohort in cohorts)
        trials = sum(cohort["arm_counts"][arm] for cohort in cohorts)
        combined[arm] = {
            "successes": successes,
            "trials": trials,
            "proportion": successes / trials,
            "naive_ci_95_clopper_pearson": clopper_pearson(successes, trials),
            "interval_assumption": "Naive independent Bernoulli trials; does not model shared endpoint or campaign-block dependence.",
        }
    evidence_sets = [set(cohort["unique_exact_evidence_ids"]) for cohort in cohorts]
    result = {
        "schema_version": "csg-service-install-within-host-block-synthesis-v1",
        "analysis_status": "POST_HOC_DESCRIPTIVE_BLOCK_SYNTHESIS",
        "included_experiments": [cohort["experiment_id"] for cohort in cohorts],
        "excluded_experiment": "service-install-randomized-three-arm-v15 (incomplete service-control failure before target mutation)",
        "host_id": cohorts[0]["host_id"],
        "endpoint": cohorts[0]["endpoint"],
        "same_baseline_config": cohorts[0]["baseline_wazuh_config_sha256"] == cohorts[1]["baseline_wazuh_config_sha256"],
        "total_trials": sum(cohort["assigned_trials"] for cohort in cohorts),
        "unique_service_names": len(names),
        "unique_evidence_ids": len(evidence_sets[0] | evidence_sets[1]),
        "cross_cohort_evidence_id_overlap": len(evidence_sets[0] & evidence_sets[1]),
        "cohorts": cohorts,
        "combined_by_arm": combined,
        "limitations": [
            "Post-hoc synthesis after both frozen cohort results were observed.",
            "Both campaigns use the same single Windows endpoint; no independent-host replication.",
            "The deliberate target-specific filter is not natural or permanent telemetry loss.",
            "The service registrations are benign and inert; no malicious detection efficacy claim.",
            "Naive exact binomial intervals do not account for within-host or temporal-block dependence.",
            "No cross-platform claim.",
        ],
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "synthesis.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "synthesis.md").write_text(render_markdown(result), encoding="utf-8")
    print(
        "SYNTHESIS=PASS; COHORTS=2; TRIALS={}; ARMS=20/20/20; EVIDENCE_IDS={}; OVERLAP={}".format(
            result["total_trials"], result["unique_evidence_ids"], result["cross_cohort_evidence_id_overlap"]
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
