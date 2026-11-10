#!/usr/bin/env python3
"""Validate and summarize the frozen ten-trial Windows Event 4698 omission study."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import datetime
from pathlib import Path
from statistics import median
from typing import Any


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8-sig") as stream:
        return json.load(stream)


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total == 0:
        return None
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    radius = z * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total)) / denominator
    return [round(max(0.0, center - radius), 4), round(min(1.0, center + radius), 4)]


def latency_summary(values: list[float]) -> dict[str, Any]:
    ordered = sorted(values)
    if not ordered:
        return {"n_valid": 0, "median_seconds": None, "p95_seconds": None, "max_seconds": None}
    p95_index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return {
        "n_valid": len(ordered),
        "median_seconds": round(median(ordered), 4),
        "p95_seconds": round(ordered[p95_index], 4),
        "max_seconds": round(ordered[-1], 4),
    }


def event_store_gate(scenario: dict[str, Any]) -> bool:
    evidence = (scenario.get("state_plane") or {}).get("creation_delta_reconciliation_before_cleanup") or {}
    return (
        evidence.get("event_store_readback_complete") is True
        and not (evidence.get("provider_exact_target_event_ids") or [])
        and not (evidence.get("event_store_readback_ids") or [])
    )


def analyze(run_dir: Path) -> tuple[dict[str, Any], str]:
    manifest_path = run_dir / "campaign-manifest.json"
    manifest = read_json(manifest_path)
    assignments = manifest.get("trials") or []
    trial_records: list[dict[str, Any]] = []
    latency_values: dict[str, list[float]] = {
        "probe_detection": [],
        "local_event_record": [],
        "reconciliation_finalization_after_evidence_deadline": [],
    }
    gate_names = (
        "native_probe_absent_present_absent",
        "exact_local_security_4698",
        "complete_wazuh_query_sources_available",
        "no_exact_target_in_wazuh_or_csg_event_store",
        "post_restore_queries_complete_and_no_recovery",
        "finalized_unexplained_with_no_evidence",
        "configuration_health_and_cleanup_restored",
    )
    gate_counts = {name: 0 for name in gate_names}

    for assignment in assignments:
        trial_path = run_dir / f"trial-{assignment.get('order', 0):02d}" / "result.json"
        if not trial_path.is_file():
            trial_records.append({
                "assignment_id": assignment.get("assignment_id"),
                "status": "MISSING_ARTIFACT",
                "gates": {name: False for name in gate_names},
                "artifact_path": str(trial_path.relative_to(run_dir)),
            })
            continue

        result = read_json(trial_path)
        runner = result.get("runner_result") or {}
        scenarios = runner.get("scenarios") or []
        scenario = scenarios[0] if len(scenarios) == 1 else {}
        state = scenario.get("state_plane") or {}
        direct = state.get("direct_windows_verification") or {}
        event_plane = scenario.get("event_plane") or {}
        retrieval = event_plane.get("retrieval") or {}
        local_evidence = scenario.get("local_source_evidence") or {}
        local_events = [
            event for event in (local_evidence.get("exact_events") or [])
            if event.get("event_id") == 4698 and event.get("exact_identity_match") is True
        ]
        task_name = result.get("target_task_name")
        local_names = [
            (event.get("event_data") or {}).get("TaskName")
            for event in local_events
        ]
        local_identity_ok = bool(local_events) and all(
            isinstance(name, str) and name.rstrip("\\").split("\\")[-1].casefold() == str(task_name).casefold()
            for name in local_names
        )
        probe_gate = all(direct.get(key) is True for key in (
            "target_absent_before_action", "target_present_after_action", "target_absent_after_cleanup"
        ))
        local_gate = local_evidence.get("query_status") == "COMPLETE" and local_identity_ok
        query_gate = (
            event_plane.get("query_completed") is True
            and retrieval.get("query_complete") is True
            and retrieval.get("coverage_status") == "COMPLETE"
            and retrieval.get("endpoint_collection_status") == "AVAILABLE"
            and retrieval.get("transport_status") == "AVAILABLE"
            and retrieval.get("index_status") == "AVAILABLE"
        )
        no_event_gate = not (event_plane.get("exact_matches") or []) and event_store_gate(scenario)

        post_queries = result.get("post_restore_provider_queries") or []
        post_query_gate = bool(post_queries) and all(
            query.get("query_complete") is True
            and query.get("coverage_status") == "COMPLETE"
            and query.get("endpoint_collection_status") == "AVAILABLE"
            and query.get("transport_status") == "AVAILABLE"
            and query.get("index_status") == "AVAILABLE"
            and not (query.get("exact_target_event_ids") or [])
            for query in post_queries
        )
        history = assignment.get("reconciliation_history") or []
        final_reconciliation = history[-1] if history else {}
        reconciliation_gate = (
            assignment.get("final_reconciliation_passed") is True
            and final_reconciliation.get("status") == "UNEXPLAINED"
            and final_reconciliation.get("finalized") is True
            and not (final_reconciliation.get("matched_evidence_ids") or [])
        )
        source_health = result.get("source_health_after_restore") or {}
        services = source_health.get("services") or []
        wazuh_running = any(
            service.get("name") == "WazuhSvc" and service.get("state") == "Running"
            for service in services
        )
        cleanup_gate = (
            result.get("restored_hash_matches_original") is True
            and result.get("original_agent_config_sha256") == result.get("restored_agent_config_sha256")
            and source_health.get("csg_api_healthy") is True
            and source_health.get("wazuh_server_api_healthy") is True
            and source_health.get("wazuh_indexer_healthy") is True
            and source_health.get("endpoint_agent_status") == "active"
            and wazuh_running
            and result.get("security_log_enabled_after") is True
            and result.get("cleanup_verified") is True
            and not (result.get("residual_study_tasks") or [])
            and (scenario.get("action") or {}).get("cleanup_completed") is True
        )
        gates = {
            "native_probe_absent_present_absent": probe_gate,
            "exact_local_security_4698": local_gate,
            "complete_wazuh_query_sources_available": query_gate,
            "no_exact_target_in_wazuh_or_csg_event_store": no_event_gate,
            "post_restore_queries_complete_and_no_recovery": post_query_gate,
            "finalized_unexplained_with_no_evidence": reconciliation_gate,
            "configuration_health_and_cleanup_restored": cleanup_gate,
        }
        for name, passed in gates.items():
            gate_counts[name] += int(passed)

        action = scenario.get("action") or {}
        state_observed = (state.get("after_action_observation") or {}).get("observed_at")
        local_event_time = local_events[0].get("event_time_utc") if local_events else None
        timings = {
            "probe_detection_seconds": (action.get("started_at"), state_observed),
            "local_event_record_seconds": (action.get("started_at"), local_event_time),
            "reconciliation_finalization_after_evidence_deadline_seconds": (
                ((final_reconciliation.get("metadata") or {}).get("evidence_deadline")),
                final_reconciliation.get("finalized_at"),
            ),
        }
        trial_latencies: dict[str, float | None] = {}
        for name, (start_text, end_text) in timings.items():
            start, end = parse_time(start_text), parse_time(end_text)
            value = (end - start).total_seconds() if start and end else None
            if value is not None and value >= 0:
                rounded = round(value, 4)
                trial_latencies[name] = rounded
                latency_values[
                    "probe_detection" if name == "probe_detection_seconds" else
                    "local_event_record" if name == "local_event_record_seconds" else
                    "reconciliation_finalization_after_evidence_deadline"
                ].append(value)
            else:
                trial_latencies[name] = None

        deltas = scenario.get("deltas") or []
        add_delta = next((delta for delta in reversed(deltas) if delta.get("delta_type") == "ADD"), {})
        trial_records.append({
            "assignment_id": assignment.get("assignment_id"),
            "order": assignment.get("order"),
            "task_name": task_name,
            "task_object_key": scenario.get("expected_object_key"),
            "status": "PASS" if all(gates.values()) else "VALIDITY_GAP",
            "gates": gates,
            "local_event_record_ids": [event.get("record_id") for event in local_events],
            "local_event_task_names": local_names,
            "probe_observation_ids": {
                "before": (state.get("before_action_observation") or {}).get("observation_id"),
                "after": (state.get("after_action_observation") or {}).get("observation_id"),
                "after_cleanup": (state.get("after_cleanup_observation") or {}).get("observation_id"),
            },
            "delta_id": add_delta.get("delta_id"),
            "finding_id": assignment.get("finding_id"),
            "reconciliation_id": final_reconciliation.get("reconciliation_id"),
            "final_reconciliation_status": final_reconciliation.get("status"),
            "matched_evidence_ids": final_reconciliation.get("matched_evidence_ids") or [],
            "post_restore_query_count": len(post_queries),
            "reconciliation_lag_seconds": trial_latencies[
                "reconciliation_finalization_after_evidence_deadline_seconds"
            ],
            "latencies_seconds": trial_latencies,
            "artifact_sha256": sha256(trial_path),
        })

    assigned = len(assignments)
    passes = sum(record.get("status") == "PASS" for record in trial_records)
    completed = sum(record.get("status") != "MISSING_ARTIFACT" for record in trial_records)
    campaign_status = manifest.get("status")
    valid_series = assigned == 10 and completed == 10 and passes == 10 and campaign_status == "COMPLETED_ALL_TRIAL_GATES_PASSED"
    analysis = {
        "schema_version": "csg-scheduled-task-event-filter-analysis-v1",
        "campaign_id": manifest.get("campaign_id"),
        "classification": "VALID_10_TRIAL_SAME_HOST_MECHANISM_SERIES" if valid_series else "INCOMPLETE_OR_VALIDITY_GAPS",
        "research_readiness": "CONTROLLED_SINGLE_HOST_EVIDENCE_NOT_CONFERENCE_READY_ALONE",
        "host_id": manifest.get("host_id"),
        "assigned_trials": assigned,
        "trial_artifacts_present": completed,
        "all_gates_passed": passes,
        "same_host_pass_proportion": passes / assigned if assigned else None,
        "descriptive_95_percent_wilson_interval": wilson_interval(passes, assigned),
        "interval_scope_warning": "Repeated trials on one Windows VM are not independent hosts; this interval is descriptive and is not a fleet/generalization interval.",
        "campaign_controller_status": campaign_status,
        "gate_counts": {name: {"passed": count, "assigned": assigned} for name, count in gate_counts.items()},
        "latencies": {
            name: latency_summary(values) for name, values in latency_values.items()
        },
        "trial_results": trial_records,
        "claim_boundary": [
            "The experiment tests a deliberately configured endpoint collection-policy omission for Windows Security Event ID 4698.",
            "It tests whether CSG's native probe retains the persistent state transition and whether deterministic reconciliation finalizes it as UNEXPLAINED without exact target evidence.",
            "The benign scheduled task is not an attack; this is not evidence of malicious-activity detection or improved attack-detection accuracy.",
            "Historical complete/no-change cohorts are not randomized/interleaved pairs and must not be treated as such.",
            "The result is conditional on one Windows 11 ARM VM, the recorded Wazuh profile, and scheduled-task creation events."
        ],
    }
    report = render_report(analysis)
    (run_dir / "analysis.json").write_text(json.dumps(analysis, indent=2) + "\n", encoding="utf-8")
    (run_dir / "RESULTS.md").write_text(report, encoding="utf-8")
    return analysis, report


def render_report(analysis: dict[str, Any]) -> str:
    assigned = analysis["assigned_trials"]
    lines = [
        "# Scheduled-Task Event 4698 Filter-Omission Series v2 Results",
        "",
        f"**Classification:** `{analysis['classification']}`  ",
        f"**Campaign controller status:** `{analysis['campaign_controller_status']}`  ",
        f"**Trials:** {analysis['all_gates_passed']}/{assigned} passed every prespecified gate; {analysis['trial_artifacts_present']}/{assigned} raw trial artifacts present.",
        "",
        "## What This Tested",
        "",
        "The Windows Security log and Wazuh agent remained enabled. During each trial, the endpoint Wazuh configuration intentionally excluded Security Event ID 4698. A benign randomized scheduled task was created and removed. CSG's independent Windows probe was expected to observe the persistent task state even though the corresponding Wazuh event was intentionally not collected. After restoration, bounded Wazuh queries checked whether the exact event later appeared; CSG reconciliation was then checked for a finalized `UNEXPLAINED` result with no matched evidence IDs.",
        "",
        "This evaluates controlled state visibility and reconciliation under one configured collection omission. It does not test malware or prove improved malicious-activity detection.",
        "",
        "## Aggregate",
        "",
        "| Prespecified gate | Passed / assigned |",
        "|---|---:|",
    ]
    labels = {
        "native_probe_absent_present_absent": "Native probe absent / present / absent",
        "exact_local_security_4698": "Exact local Security Event 4698",
        "complete_wazuh_query_sources_available": "Complete Wazuh query and sources available",
        "no_exact_target_in_wazuh_or_csg_event_store": "No target event in Wazuh or CSG event store",
        "post_restore_queries_complete_and_no_recovery": "Post-restore queries complete; no recovered target event",
        "finalized_unexplained_with_no_evidence": "Finalized UNEXPLAINED; zero evidence IDs",
        "configuration_health_and_cleanup_restored": "Config, health, and cleanup restored",
    }
    for key, values in analysis["gate_counts"].items():
        lines.append(f"| {labels[key]} | {values['passed']} / {values['assigned']} |")
    interval = analysis.get("descriptive_95_percent_wilson_interval")
    interval_text = "not estimable" if interval is None else f"[{interval[0]:.3f}, {interval[1]:.3f}]"
    lines.extend([
        "",
        f"All-gates pass proportion: {analysis['all_gates_passed']}/{assigned}. Descriptive 95% Wilson interval: {interval_text}. This interval describes repeated trials on this one VM; it is not an independent-host or fleet interval.",
        "",
        "## Per-Trial Audit Table",
        "",
        "| Slot | Random task | Local 4698 record | Delta | Finding | Reconciliation | Probe latency (s) | Reconciliation lag (s) | Gates |",
        "|---:|---|---:|---|---|---|---:|---:|---:|",
    ])
    for trial in analysis["trial_results"]:
        latency = trial.get("latencies_seconds") or {}
        local_ids = ", ".join(str(value) for value in trial.get("local_event_record_ids", [])) or "-"
        lines.append(
            "| {slot} | `{task}` | {local} | `{delta}` | `{finding}` | `{recon}` | {probe} | {lag} | {passed}/{total} |".format(
                slot=trial.get("order", "-"),
                task=trial.get("task_name") or "MISSING",
                local=local_ids,
                delta=trial.get("delta_id") or "-",
                finding=trial.get("finding_id") or "-",
                recon=trial.get("final_reconciliation_status") or "-",
                probe=latency.get("probe_detection_seconds") if latency.get("probe_detection_seconds") is not None else "n/a",
                lag=latency.get("reconciliation_finalization_after_evidence_deadline_seconds") if latency.get("reconciliation_finalization_after_evidence_deadline_seconds") is not None else "n/a",
                passed=sum(bool(value) for value in (trial.get("gates") or {}).values()),
                total=len(trial.get("gates") or {}),
            )
        )
    lines.extend([
        "",
        "## Latency Summaries",
        "",
        "| Measure | Valid n | Median (s) | P95 (s) | Maximum (s) |",
        "|---|---:|---:|---:|---:|",
    ])
    latency_labels = {
        "probe_detection": "Action start to probe observation",
        "local_event_record": "Action start to local Event 4698 timestamp",
        "reconciliation_finalization_after_evidence_deadline": "Evidence deadline to reconciliation finalization",
    }
    for key, summary in analysis["latencies"].items():
        lines.append(
            f"| {latency_labels[key]} | {summary['n_valid']} | {summary['median_seconds']} | {summary['p95_seconds']} | {summary['max_seconds']} |"
        )
    lines.extend([
        "",
        "Negative or unparsable intervals are excluded from latency aggregates and appear as `n/a` in the trial table. They do not alter gate denominators.",
        "",
        "## Limits And Correct Interpretation",
        "",
    ])
    lines.extend(f"- {claim}" for claim in analysis["claim_boundary"])
    lines.extend([
        "",
        "The evidence supports a mechanism demonstration under a deliberate, narrowly scoped Event 4698 collection filter. A top-tier conference submission would still need stronger controls, independent replication, and a broader evaluation tied directly to the paper's claims.",
        "",
        "## Provenance",
        "",
        "The adjacent `source-freeze.json` records the frozen protocol and implementation hashes. `campaign-manifest.json` records assignments, per-trial safety checks, and reconciliation histories. Each `trial-NN/` directory retains the Windows wrapper output and CSG runner evidence used for the analysis.",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    args = parser.parse_args()
    analysis, _ = analyze(args.run_directory.resolve())
    print(json.dumps({
        "classification": analysis["classification"],
        "all_gates_passed": analysis["all_gates_passed"],
        "assigned_trials": analysis["assigned_trials"],
        "results": str(args.run_directory / "RESULTS.md"),
    }, indent=2))


if __name__ == "__main__":
    main()
