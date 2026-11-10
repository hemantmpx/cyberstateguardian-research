"""Audit the frozen v47 scheduled-task complete-telemetry campaign."""

# Human-readable report paragraphs intentionally exceed the source line limit.
# ruff: noqa: E501

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from datetime import datetime
from pathlib import Path
from statistics import median
from typing import Any


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical(value: Any) -> str:
    text = str(value or "").strip().casefold().replace("\\", "/")
    while "//" in text:
        text = text.replace("//", "/")
    return text.replace(":/", "/")


def seconds_between(start: Any, end: Any) -> float | None:
    if not isinstance(start, str) or not isinstance(end, str):
        return None
    try:
        left = datetime.fromisoformat(start.replace("Z", "+00:00"))
        right = datetime.fromisoformat(end.replace("Z", "+00:00"))
    except ValueError:
        return None
    value = (right - left).total_seconds()
    return value if value >= 0 else None


def wilson(successes: int, trials: int) -> list[float] | None:
    if trials == 0:
        return None
    z = 1.959963984540054
    p = successes / trials
    denominator = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    radius = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return [max(0.0, center - radius), min(1.0, center + radius)]


def summarize(values: list[float | None]) -> dict[str, Any]:
    present = sorted(float(value) for value in values if value is not None)
    if not present:
        return {"n": 0, "minimum": None, "median": None, "maximum": None}
    return {
        "n": len(present),
        "minimum": round(present[0], 4),
        "median": round(median(present), 4),
        "maximum": round(present[-1], 4),
    }


def verify_freeze(run_dir: Path, freeze: dict[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    entries = {
        "protocol": run_dir / "PROTOCOL.md",
        "schedule": run_dir / "schedule.json",
        "runner_v13": run_dir / "source/run_windows_category_same_window_distractor_v13.ps1",
        "preflight": run_dir / "source/preflight_windows_task_campaign.ps1",
        "campaign_controller_v2": run_dir
        / "source/run_windows_scheduled_task_complete_replicates_v2.ps1",
    }
    for key, path in entries.items():
        expected = freeze.get("protocol", {}).get("sha256") if key == "protocol" else None
        if key == "schedule":
            expected = freeze.get("schedule", {}).get("sha256")
        if key in freeze.get("source_files", {}):
            expected = freeze["source_files"][key].get("sha256")
        actual = sha256(path) if path.is_file() else None
        checks.append(
            {
                "artifact": str(path.relative_to(run_dir)),
                "expected": expected,
                "actual": actual,
                "passed": actual is not None and actual == expected,
            }
        )
    provider = (run_dir / freeze["source_files"]["wazuh_provider"]["path"]).resolve()
    expected_provider = freeze["source_files"]["wazuh_provider"]["sha256"]
    actual_provider = sha256(provider) if provider.is_file() else None
    checks.append(
        {
            "artifact": freeze["source_files"]["wazuh_provider"]["path"],
            "expected": expected_provider,
            "actual": actual_provider,
            "passed": actual_provider == expected_provider,
        }
    )
    return checks


def analyze_trial(
    run_path: Path, controller_trial: dict[str, Any], expected_config_hash: str
) -> dict[str, Any]:
    run = read_json(run_path)
    scenarios = run.get("scenarios") or []
    scenario = next(
        (item for item in scenarios if item.get("scenario_id") == "scheduled-task-persistence"), {}
    )
    name = str(controller_trial.get("target_task_name") or "")
    expected_key = canonical(scenario.get("expected_object_key"))
    exact_events = scenario.get("event_plane", {}).get("exact_matches") or []
    local_events = scenario.get("local_source_evidence", {}).get("exact_events") or []
    local_exact = [
        event
        for event in local_events
        if event.get("event_id") == 4698
        and event.get("exact_identity_match") is True
        and canonical(event.get("event_data", {}).get("TaskName")) == canonical("\\" + name)
    ]
    physical_identities = {
        "|".join(
            str(event.get("windows_event_identity", {}).get(key, "")).casefold()
            for key in ("agent_id", "channel", "event_record_id", "event_code", "provider_name")
        )
        for event in exact_events
    }
    expected_local_identity = None
    if len(local_exact) == 1:
        expected_local_identity = "|".join(
            (
                "001",
                "security",
                str(local_exact[0].get("record_id")),
                "4698",
                "microsoft-windows-security-auditing",
            )
        )
    exact_ids = {str(event.get("event_id")) for event in exact_events if event.get("event_id")}
    matching_events = [
        event
        for event in exact_events
        if event.get("host_id") == "win11-arm-lab"
        and event.get("source") == "wazuh"
        and event.get("normalized_type") == "scheduled_task_created"
        and canonical(event.get("target", {}).get("key")) == expected_key
        and canonical(event.get("attributes", {}).get("task_name")) == canonical("\\" + name)
    ]
    recon = scenario.get("csg_reconciliation") or {}
    recon_history = recon.get("history") or []
    if isinstance(recon_history, dict):
        recon_history = [recon_history]
    finalized = [item for item in recon_history if item.get("finalized") is True]
    final = max(finalized, key=lambda item: item.get("version", 0), default={})
    matched_ids = {str(value) for value in final.get("matched_evidence_ids", [])}
    state = scenario.get("state_plane") or {}
    before = state.get("before_action_observation") or {}
    after = state.get("after_action_observation") or {}
    direct_after = state.get("after_action_observed") or []
    probe_found = any(
        canonical(item.get("task_name")) == canonical("\\" + name) for item in direct_after
    )
    direct = state.get("direct_windows_verification") or {}
    controller_ok = (
        controller_trial.get("runner_status") == "ALL_REQUIRED_POSITIVE_CONTROLS_PASSED"
        and controller_trial.get("positive_control_passed") is True
        and controller_trial.get("preflight_target_absent") is True
        and controller_trial.get("postflight_target_absent") is True
        and controller_trial.get("cleanup_verified") is True
        and controller_trial.get("error") is None
    )
    retrieval = scenario.get("event_plane", {}).get("retrieval") or {}
    same_local_identity = expected_local_identity is not None and physical_identities == {
        expected_local_identity
    }
    checks = {
        "controller_gate_and_cleanup": controller_ok,
        "target_absent_before_action": state.get("target_absent_before_action") is True
        and len(before.get("target_items") or []) == 0,
        "probe_observed_exact_target_after_action": probe_found,
        "probe_cleanup_absent": state.get("cleanup_removed_from_probe") is True
        and direct.get("target_absent_after_cleanup") is True,
        "exact_local_security_4698": len(local_exact) == 1,
        "complete_wazuh_retrieval": scenario.get("event_plane", {}).get("query_complete") is True
        and retrieval.get("query_complete") is True
        and retrieval.get("coverage_status") == "COMPLETE"
        and retrieval.get("endpoint_collection_status") == "AVAILABLE"
        and retrieval.get("transport_status") == "AVAILABLE"
        and retrieval.get("index_status") == "AVAILABLE",
        "one_physical_exact_wazuh_event": len(physical_identities) == 1
        and len(exact_events) >= 1
        and len(matching_events) == len(exact_events),
        "wazuh_identity_matches_local_record": same_local_identity,
        "finalized_consistent_exact_evidence_ids": final.get("status") == "CONSISTENT"
        and bool(exact_ids)
        and matched_ids == exact_ids,
        "csg_exact_target_claim": recon.get("matched_only_exact_target_events") is True,
        "unchanged_agent_config": expected_config_hash.lower()
        == str(controller_trial.get("agent_config_sha256", expected_config_hash)).lower(),
        "no_action_error": scenario.get("action", {}).get("error") is None,
    }
    action = scenario.get("action") or {}
    local_time = local_exact[0].get("event_time_utc") if len(local_exact) == 1 else None
    wazuh_time = exact_events[0].get("event_time") if exact_events else None
    probe_time = after.get("observed_at")
    category_time = after.get("category_observed_at")
    final_time = final.get("finalized_at")
    unique_refs = {
        (
            str(event.get("source_reference", {}).get("index")),
            str(event.get("source_reference", {}).get("document_id")),
        )
        for event in exact_events
    }
    return {
        "trial_id": str(controller_trial.get("trial_id")),
        "task_name": name,
        "passed": all(checks.values()),
        "checks": checks,
        "failed_checks": [key for key, value in checks.items() if not value],
        "probe_target_absent_before": state.get("target_absent_before_action"),
        "probe_target_present_after": probe_found,
        "probe_target_absent_after_cleanup": direct.get("target_absent_after_cleanup"),
        "local_windows_record_id": local_exact[0].get("record_id")
        if len(local_exact) == 1
        else None,
        "local_event_time_utc": local_time,
        "wazuh_physical_event_identity": next(iter(physical_identities), None),
        "wazuh_document_event_ids": sorted(exact_ids),
        "wazuh_document_count": len(exact_events),
        "wazuh_source_indexes": sorted({index for index, _ in unique_refs}),
        "csg_matched_evidence_ids": sorted(matched_ids),
        "final_reconciliation_status": final.get("status"),
        "final_reconciliation_version": final.get("version"),
        "final_reconciliation_time_utc": final_time,
        "delta_id": final.get("delta_id"),
        "finding_id": final.get("finding_id"),
        "action_started_at_utc": action.get("started_at"),
        "probe_category_observed_at_utc": category_time,
        "probe_snapshot_available_at_utc": probe_time,
        "wazuh_event_timestamp_utc": wazuh_time,
        "action_to_probe_category_seconds": seconds_between(
            action.get("started_at"), category_time
        ),
        "action_to_probe_snapshot_seconds": seconds_between(action.get("started_at"), probe_time),
        "action_to_local_event_timestamp_seconds": seconds_between(
            action.get("started_at"), local_time
        ),
        "action_to_wazuh_event_timestamp_seconds": seconds_between(
            action.get("started_at"), wazuh_time
        ),
        "action_to_reconciliation_finalization_seconds": seconds_between(
            action.get("started_at"), final_time
        ),
        "local_to_wazuh_event_timestamp_seconds": seconds_between(local_time, wazuh_time),
        "event_document_aliases": len(exact_events) - len(physical_identities),
        "exact_wazuh_event_ids": sorted(exact_ids),
        "event_references": [event.get("source_reference") for event in exact_events],
    }


def render_report(analysis: dict[str, Any]) -> str:
    rows = []
    for item in analysis["trials"]:
        rows.append(
            "| {trial} | `{name}` | {record} | {docs} | `{wids}` | {recon} | {probe} | {final} | {gate} |".format(
                trial=item["trial_id"],
                name=item["task_name"],
                record=item["local_windows_record_id"],
                docs=item["wazuh_document_count"],
                wids="; ".join(item["exact_wazuh_event_ids"]),
                recon=item["final_reconciliation_status"],
                probe=f"{item['action_to_probe_snapshot_seconds']:.2f}"
                if item["action_to_probe_snapshot_seconds"] is not None
                else "n/a",
                final=f"{item['action_to_reconciliation_finalization_seconds']:.2f}"
                if item["action_to_reconciliation_finalization_seconds"] is not None
                else "n/a",
                gate="PASS" if item["passed"] else "FAIL",
            )
        )
    ci = analysis["descriptive_95pct_wilson_interval"]
    metrics = analysis["latency_summaries_seconds"]
    lines = [
        "# V47 Scheduled-Task Complete-Telemetry Replication Results",
        "",
        f"**Classification:** `{analysis['classification']}`  ",
        f"**Assigned/attempted/passed:** {analysis['assigned_trials']}/{analysis['attempted_trials']}/{analysis['passed_trials']}  ",
        f"**Full-gate rate:** {analysis['passed_trials']}/{analysis['assigned_trials']} = {analysis['gate_rate']:.1%}; descriptive 95% Wilson interval [{ci[0]:.3f}, {ci[1]:.3f}].",
        "",
        "## Question and design",
        "",
        "This campaign tested whether the direct CSG Windows probe independently observed a newly created scheduled-task state and whether deterministic reconciliation linked that transition to the exact same-host Windows Security EventID 4698 collected by Wazuh. Ten task names were assigned before execution and run serially on one Windows 11 ARM VM. Each task was benign, one-time, and invoked only `cmd.exe /c exit 0`; it was removed after the observation interval.",
        "",
        "The frozen positive-control gate required: target absent before mutation; target observed by the probe after mutation; exact local Security 4698; complete/available Wazuh retrieval; exact target identity; finalized CSG `CONSISTENT` with matched evidence IDs drawn only from those exact target events; and verified cleanup. The controller also required per-trial preflight and postflight checks.",
        "",
        "## Results",
        "",
        f"All {analysis['assigned_trials']} assigned trials were attempted; {analysis['passed_trials']} passed every gate. The probe observed the target absent/present/absent in {analysis['state_absent_present_absent']}/{analysis['assigned_trials']} trials. Exact local Windows Security 4698 was available in {analysis['local_4698_trials']}/{analysis['assigned_trials']}; a complete healthy Wazuh query returned an exact target event in {analysis['exact_physical_wazuh_trials']}/{analysis['assigned_trials']}; and finalized reconciliation was exact-target `CONSISTENT` in {analysis['exact_consistent_trials']}/{analysis['assigned_trials']}. Per-trial cleanup and campaign pre/postflight passed in {analysis['cleanup_trials']}/{analysis['assigned_trials']}.",
        "",
        f"The 95% Wilson interval is descriptive for repeated trials on this single VM; the trials are not independent hosts. The interval is [{ci[0]:.3f}, {ci[1]:.3f}] and must not be interpreted as fleet reliability.",
        "",
        "## Trial audit",
        "",
        "| Trial | Target task | Local 4698 record | Wazuh docs | Wazuh event ID(s) | Final CSG | Probe snapshot (s) | Reconciliation final (s) | Gate |",
        "|---|---|---:|---:|---|---|---:|---:|---|",
        *rows,
        "",
        "## Duplicate-index handling",
        "",
        f"The Wazuh query returned {analysis['wazuh_document_count_total']} target-matching documents for {analysis['unique_physical_wazuh_event_count']} unique Windows event identities. In {analysis['trials_with_alert_archive_aliases']} trials, the same `(agent, channel, EventRecordID, EventID, provider)` appeared in both `wazuh-alerts-*` and `wazuh-archives-*`, yielding two CSG event IDs for one physical Windows record. These are index representations of one event, not independent corroborations. The raw artifacts retain both references; aggregate physical-event availability counts each Windows identity once. CSG matched only IDs in the exact target event set, but its stored evidence count is duplicated in those cases. This must remain explicit and should be addressed with identity-level event deduplication before any study that treats evidence multiplicity as an outcome.",
        "",
        "## Descriptive timings",
        "",
        "Times below are action-start-to-timestamp intervals, not sensor delivery latency. `Wazuh event timestamp` is the event's source timestamp; it does not measure index ingestion. Reconciliation time is time to the finalized record and is conditional on this pipeline/runtime.",
        "",
        "| Interval | Valid n | Minimum | Median | Maximum |",
        "|---|---:|---:|---:|---:|",
    ]
    labels = {
        "action_to_probe_category_seconds": "Probe category observed_at",
        "action_to_probe_snapshot_seconds": "Probe snapshot available",
        "action_to_local_event_timestamp_seconds": "Local Windows 4698 timestamp",
        "action_to_wazuh_event_timestamp_seconds": "Wazuh event timestamp",
        "action_to_reconciliation_finalization_seconds": "Reconciliation finalized",
        "local_to_wazuh_event_timestamp_seconds": "Local-to-Wazuh event timestamp difference",
    }
    for key, label in labels.items():
        value = metrics[key]
        lines.append(
            f"| {label} | {value['n']} | {value['minimum']} | {value['median']} | {value['maximum']} |"
        )
    lines.extend(
        [
            "",
            "## Reproducibility and artifacts",
            "",
            f"The schedule, scripts, endpoint preflight, and Wazuh provider hashes were rechecked against the pre-mutation source freeze: {analysis['freeze_checks_passed']}/{analysis['freeze_checks_total']} passed. Raw Windows outputs, probe snapshots, local event XML/data, CSG deltas/findings/reconciliation histories, query metadata, stdout/stderr, and cleanup pre/postflights are retained below `executions/campaign-01/`. `artifact-sha256.json` catalogs each transferred campaign artifact; `analysis.json` and `trial-summary.csv` are derived audits, not replacements for raw files.",
            "",
            "## Claim boundary and limitations",
            "",
            "- This is repeated mechanism validation on one Windows 11 ARM64 VM, not independent-host replication.",
            "- The scheduled tasks are benign; this does not measure malicious-activity detection accuracy, precision/recall, or superiority to a tuned Wazuh baseline.",
            "- This is the complete-telemetry positive condition only. It does not establish behavior under capture drop, same-host wrong-object distractors, or no-change controls for this category.",
            "- The 180-second reconciliation grace and 60-second evidence wait are the frozen conditions; timings are descriptive, not general service-level claims.",
            "- Five trials had duplicate alert/archive representations of one Windows record. Physical events were counted by stable Windows identity, not by Wazuh document count.",
            "- The confidence interval is descriptive of repeatability on this one endpoint and does not support generalization.",
            "",
            "This strengthens the evidence that the tested CSG probe and exact-object reconciliation path can repeatedly observe and corroborate benign scheduled-task creation in the recorded environment. It is one component of the research evidence, not a complete conference submission result.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    args = parser.parse_args()
    run_dir = args.run_directory.resolve()
    freeze = read_json(run_dir / "source-freeze.json")
    schedule = read_json(run_dir / "schedule.json")
    campaign_root = run_dir / "executions/campaign-01"
    campaign = read_json(campaign_root / "campaign-summary.json")
    freeze_checks = verify_freeze(run_dir, freeze)
    controller_trials = campaign.get("trials") or []
    trials = [
        analyze_trial(
            campaign_root / record["trial_id"] / "windows-raw/run.json",
            record,
            campaign.get("agent_config_sha256", ""),
        )
        for record in controller_trials
    ]
    names = [item["task_name"] for item in trials]
    local_ids = [str(item["local_windows_record_id"]) for item in trials]
    physical_ids = [item["wazuh_physical_event_identity"] for item in trials]
    passed = sum(item["passed"] for item in trials)
    latency_fields = [
        "action_to_probe_category_seconds",
        "action_to_probe_snapshot_seconds",
        "action_to_local_event_timestamp_seconds",
        "action_to_wazuh_event_timestamp_seconds",
        "action_to_reconciliation_finalization_seconds",
        "local_to_wazuh_event_timestamp_seconds",
    ]
    latencies = {field: summarize([item[field] for item in trials]) for field in latency_fields}
    physical_count = sum(bool(item["wazuh_physical_event_identity"]) for item in trials)
    recon_count = sum(item["checks"]["finalized_consistent_exact_evidence_ids"] for item in trials)
    state_count = sum(
        item["checks"]["target_absent_before_action"]
        and item["checks"]["probe_observed_exact_target_after_action"]
        and item["checks"]["probe_cleanup_absent"]
        for item in trials
    )
    artifact_files = sorted(path for path in campaign_root.rglob("*") if path.is_file())
    artifact_manifest = {
        "schema_version": "csg-artifact-sha256-v1",
        "campaign_id": campaign.get("experiment_id"),
        "files": {str(path.relative_to(run_dir)): sha256(path) for path in artifact_files},
    }
    analysis = {
        "schema_version": "csg-scheduled-task-complete-replicates-analysis-v1",
        "campaign_id": campaign.get("experiment_id"),
        "classification": "SINGLE_HOST_BENIGN_COMPLETE_TELEMETRY_POSITIVE_CONTROL",
        "host_id": campaign.get("host_id"),
        "assigned_trials": len(schedule.get("trials") or []),
        "attempted_trials": campaign.get("attempted_trial_count"),
        "passed_trials": passed,
        "gate_rate": passed / len(trials) if trials else 0.0,
        "descriptive_95pct_wilson_interval": wilson(passed, len(trials)),
        "state_absent_present_absent": state_count,
        "local_4698_trials": sum(item["checks"]["exact_local_security_4698"] for item in trials),
        "exact_physical_wazuh_trials": physical_count,
        "exact_consistent_trials": recon_count,
        "cleanup_trials": sum(item["checks"]["controller_gate_and_cleanup"] for item in trials),
        "unique_target_names": len(set(names)) == len(names),
        "unique_local_record_ids": len(set(local_ids)) == len(local_ids),
        "unique_physical_wazuh_events": len(set(physical_ids)) == len(physical_ids),
        "wazuh_document_count_total": sum(item["wazuh_document_count"] for item in trials),
        "unique_physical_wazuh_event_count": len(set(physical_ids)),
        "trials_with_alert_archive_aliases": sum(
            item["event_document_aliases"] > 0 for item in trials
        ),
        "freeze_checks_passed": sum(bool(item["passed"]) for item in freeze_checks),
        "freeze_checks_total": len(freeze_checks),
        "freeze_checks": freeze_checks,
        "latency_definitions": {
            "action_to_probe_category_seconds": "Runner action start to the probe's category_observed_at timestamp; bounded by collection behavior, not exact kernel mutation time.",
            "action_to_probe_snapshot_seconds": "Runner action start to the probe observation's observed_at timestamp.",
            "action_to_local_event_timestamp_seconds": "Runner action start to the local Windows Security 4698 source timestamp; not collection latency.",
            "action_to_wazuh_event_timestamp_seconds": "Runner action start to Wazuh event source timestamp; not index-ingestion latency.",
            "action_to_reconciliation_finalization_seconds": "Runner action start to finalized CSG reconciliation timestamp.",
            "local_to_wazuh_event_timestamp_seconds": "Difference between local Security event timestamp and normalized Wazuh event timestamp; not delivery latency.",
        },
        "latency_summaries_seconds": latencies,
        "trials": trials,
        "limitations": [
            "All ten trials ran on one Windows VM; they are repeated measures, not independent-host replications.",
            "The scheduled task action was benign and does not measure malicious detection accuracy.",
            "Only the complete-telemetry positive condition was evaluated in this campaign.",
            "Five trials yielded alert and archive documents for the same physical Windows event identity; they are counted once as a physical event.",
            "The Wilson interval is descriptive at this single endpoint and is not a fleet/generalization interval.",
        ],
    }
    run_dir.joinpath("artifact-sha256.json").write_text(
        json.dumps(artifact_manifest, indent=2) + "\n", encoding="utf-8"
    )
    run_dir.joinpath("analysis.json").write_text(
        json.dumps(analysis, indent=2) + "\n", encoding="utf-8"
    )
    columns = [
        "trial_id",
        "task_name",
        "passed",
        "local_windows_record_id",
        "wazuh_physical_event_identity",
        "wazuh_document_count",
        "wazuh_document_event_ids",
        "wazuh_source_indexes",
        "final_reconciliation_status",
        "final_reconciliation_version",
        "delta_id",
        "finding_id",
        *latency_fields,
    ]
    with run_dir.joinpath("trial-summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for trial in trials:
            row = {key: trial.get(key) for key in columns}
            row["wazuh_document_event_ids"] = ";".join(trial["exact_wazuh_event_ids"])
            row["wazuh_source_indexes"] = ";".join(trial["wazuh_source_indexes"])
            writer.writerow(row)
    run_dir.joinpath("RESULTS.md").write_text(render_report(analysis), encoding="utf-8")
    print(
        json.dumps(
            {
                "classification": analysis["classification"],
                "passed_trials": passed,
                "assigned_trials": analysis["assigned_trials"],
                "freeze_checks": f"{analysis['freeze_checks_passed']}/{analysis['freeze_checks_total']}",
                "duplicate_index_alias_trials": analysis["trials_with_alert_archive_aliases"],
                "results": str(run_dir / "RESULTS.md"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
