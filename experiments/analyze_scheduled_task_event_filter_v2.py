#!/usr/bin/env python3
"""Analyze retained artifacts from a scheduled-task Event ID 4698 omission run."""

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


def wilson_interval(successes: int, total: int) -> list[float] | None:
    if not total:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    radius = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [round(max(0.0, center - radius), 4), round(min(1.0, center + radius), 4)]


def summarize(values: list[float]) -> dict[str, Any]:
    values.sort()
    if not values:
        return {"n_valid": 0, "median_seconds": None, "p95_seconds": None, "max_seconds": None}
    return {
        "n_valid": len(values),
        "median_seconds": round(median(values), 4),
        "p95_seconds": round(values[max(0, math.ceil(0.95 * len(values)) - 1)], 4),
        "max_seconds": round(values[-1], 4),
    }


def locate_manifest(run_dir: Path) -> Path:
    direct = run_dir / "campaign-manifest.json"
    if direct.is_file():
        return direct
    candidates = sorted(run_dir.glob("windows/raw/*/campaign-manifest.json"))
    if len(candidates) != 1:
        raise FileNotFoundError(
            f"Expected one campaign manifest under {run_dir}; got {len(candidates)}"
        )
    return candidates[0]


def exact_name_match(value: Any, target: str) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().replace("/", "\\").casefold().rstrip("\\")
    target_name = target.strip().replace("/", "\\").casefold().lstrip("\\").rstrip("\\")
    return normalized.split("\\")[-1] == target_name.split("\\")[-1]


def elapsed(start_value: Any, end_value: Any) -> float | None:
    start, end = parse_time(start_value), parse_time(end_value)
    if start is None or end is None:
        return None
    value = (end - start).total_seconds()
    return value if value >= 0 else None


def analyze(run_dir: Path, api_audit_path: Path, provider_audit_path: Path) -> dict[str, Any]:
    manifest_path = locate_manifest(run_dir)
    manifest = read_json(manifest_path)
    raw_root = manifest_path.parent
    api_audit = read_json(api_audit_path) if api_audit_path.is_file() else {"trials": []}
    provider_audit = (
        read_json(provider_audit_path) if provider_audit_path.is_file() else {"trials": []}
    )
    api_by_order = {item.get("order"): item for item in api_audit.get("trials", [])}
    provider_by_order = {item.get("order"): item for item in provider_audit.get("trials", [])}
    provider_by_assignment = {
        item.get("assignment_id"): item for item in provider_audit.get("trials", [])
    }

    gate_names = (
        "probe_absent_present_absent",
        "exact_local_security_4698",
        "complete_provider_query_and_no_exact_match",
        "event_absent_from_csg_store_during_omission",
        "post_restore_and_late_queries_show_no_recovery",
        "exact_creation_add_and_linked_finding",
        "finalized_unexplained_with_zero_evidence",
        "configuration_health_and_cleanup_restored",
    )
    gate_counts = {name: 0 for name in gate_names}
    trial_rows = []
    latency_samples: dict[str, list[float]] = {
        "probe_detection": [],
        "local_event_record": [],
        "provider_query": [],
        "reconciliation_finalization": [],
    }

    for assignment in manifest.get("trials", []):
        order = assignment.get("order")
        trial_dir = raw_root / f"trial-{int(order):02d}"
        result_path = trial_dir / "result.json"
        runner_path = trial_dir / "runner" / "run.json"
        if not result_path.is_file() or not runner_path.is_file():
            trial_rows.append(
                {
                    "order": order,
                    "task_name": assignment.get("target_task_name"),
                    "status": "MISSING_RAW_ARTIFACT",
                    "gates": {name: False for name in gate_names},
                    "artifact_paths": {
                        "wrapper": str(result_path.relative_to(run_dir)),
                        "runner": str(runner_path.relative_to(run_dir)),
                    },
                }
            )
            continue

        wrapper = read_json(result_path)
        runner = read_json(runner_path)
        scenarios = runner.get("scenarios") or []
        scenario = next((item for item in scenarios if item.get("kind") == "scheduled_task"), {})
        task_name = str(assignment.get("target_task_name") or wrapper.get("target_task_name") or "")
        object_key = (
            scenario.get("expected_object_key") or f"scheduled_task:\\{task_name.casefold()}"
        )
        state = scenario.get("state_plane") or {}
        direct = state.get("direct_windows_verification") or {}
        action = scenario.get("action") or {}
        local_source = scenario.get("local_source_evidence") or {}
        local_events = [
            event
            for event in local_source.get("exact_events", [])
            if event.get("event_id") == 4698
            and event.get("exact_identity_match") is True
            and exact_name_match((event.get("event_data") or {}).get("TaskName"), task_name)
        ]
        event_plane = scenario.get("event_plane") or {}
        retrieval = event_plane.get("retrieval") or {}
        capture = state.get("creation_delta_reconciliation_before_cleanup") or {}
        trial_api = api_by_order.get(order) or {}
        trial_provider = provider_by_order.get(order) or provider_by_assignment.get(
            assignment.get("assignment_id"), {}
        )
        late_query = trial_provider.get("late_provider_requery") or {}
        current_deltas = trial_api.get("current_deltas") or []
        current_adds = [
            delta
            for delta in current_deltas
            if delta.get("delta_type") == "ADD" and delta.get("object_key") == object_key
        ]
        raw_deltas = scenario.get("deltas") or []
        raw_adds = [
            delta
            for delta in raw_deltas
            if delta.get("delta_type") == "ADD" and delta.get("object_key") == object_key
        ]
        linked_findings = [
            finding
            for finding in (scenario.get("findings") or [])
            if any(delta.get("delta_id") == finding.get("delta_id") for delta in raw_adds)
        ]
        latest = trial_api.get("latest_reconciliation") or {}
        post_restore_queries = wrapper.get("post_restore_provider_queries") or []
        post_restore_gate = (
            wrapper.get("target_event_absent_after_restore") is True
            and len(post_restore_queries) >= 2
            and all(
                query.get("query_complete") is True
                and query.get("coverage_status") == "COMPLETE"
                and query.get("transport_status") == "AVAILABLE"
                and query.get("index_status") == "AVAILABLE"
                and query.get("exact_target_event_count") == 0
                and not (query.get("exact_target_event_ids") or [])
                for query in post_restore_queries
            )
        )
        late_query_gate = (
            late_query.get("query_complete") is True
            and late_query.get("coverage_status") == "COMPLETE"
            and late_query.get("transport_status") == "AVAILABLE"
            and late_query.get("index_status") == "AVAILABLE"
            and late_query.get("exact_target_event_count") == 0
            and not (late_query.get("exact_target_events") or [])
        )
        probe_gate = all(
            direct.get(key) is True
            for key in (
                "target_absent_before_action",
                "target_present_after_action",
                "target_absent_after_cleanup",
            )
        )
        local_gate = local_source.get("query_status") == "COMPLETE" and len(local_events) == 1
        query_gate = (
            event_plane.get("query_completed") is True
            and retrieval.get("query_complete") is True
            and retrieval.get("coverage_status") == "COMPLETE"
            and retrieval.get("transport_status") == "AVAILABLE"
            and retrieval.get("index_status") == "AVAILABLE"
            and not (event_plane.get("exact_matches") or [])
            and not (retrieval.get("exact_target_event_ids") or [])
        )
        store_gate = (
            capture.get("event_store_readback_complete") is True
            and not (capture.get("provider_exact_target_event_ids") or [])
            and not (capture.get("event_store_readback_ids") or [])
        )
        restoration = wrapper.get("source_health_after_restore") or {}
        services = restoration.get("services") or []
        gates = {
            "probe_absent_present_absent": probe_gate,
            "exact_local_security_4698": local_gate,
            "complete_provider_query_and_no_exact_match": query_gate,
            "event_absent_from_csg_store_during_omission": store_gate,
            "post_restore_and_late_queries_show_no_recovery": post_restore_gate and late_query_gate,
            "exact_creation_add_and_linked_finding": len(current_adds) == 1
            and len(raw_adds) == 1
            and len(linked_findings) == 1,
            "finalized_unexplained_with_zero_evidence": latest.get("status") == "UNEXPLAINED"
            and latest.get("finalized") is True
            and not (latest.get("matched_evidence_ids") or []),
            "configuration_health_and_cleanup_restored": (
                wrapper.get("restored_hash_matches_original") is True
                and wrapper.get("original_agent_config_sha256")
                == wrapper.get("restored_agent_config_sha256")
                and wrapper.get("security_log_enabled_after") is True
                and wrapper.get("cleanup_verified") is True
                and not (wrapper.get("residual_study_tasks") or [])
                and restoration.get("csg_api_healthy") is True
                and restoration.get("wazuh_server_api_healthy") is True
                and restoration.get("wazuh_indexer_healthy") is True
                and restoration.get("endpoint_agent_status") == "active"
                and any(
                    service.get("name") == "WazuhSvc" and service.get("state") == "Running"
                    for service in services
                )
                and (action.get("cleanup_completed") is True)
            ),
        }
        for name, passed in gates.items():
            gate_counts[name] += int(passed)

        local_event_time = local_events[0].get("event_time_utc") if local_events else None
        after_state = state.get("after_action_observation") or {}
        state_time = after_state.get("category_observed_at") or after_state.get("observed_at")
        event_latency = elapsed(action.get("started_at"), local_event_time)
        state_latency = elapsed(action.get("started_at"), state_time)
        provider_latency = retrieval.get("client_elapsed_seconds")
        final_latency = elapsed(
            (latest.get("metadata") or {}).get("evidence_deadline"), latest.get("finalized_at")
        )
        for name, value in (
            ("probe_detection", state_latency),
            ("local_event_record", event_latency),
            (
                "provider_query",
                provider_latency
                if isinstance(provider_latency, (int, float)) and provider_latency >= 0
                else None,
            ),
            ("reconciliation_finalization", final_latency),
        ):
            if value is not None:
                latency_samples[name].append(float(value))

        trial_rows.append(
            {
                "order": order,
                "assignment_id": assignment.get("assignment_id"),
                "task_name": task_name,
                "object_key": object_key,
                "status": "PASS" if all(gates.values()) else "VALIDITY_GAP",
                "gates": gates,
                "local_event_ids": [event.get("record_id") for event in local_events],
                "probe_observation_ids": {
                    "before": (state.get("before_action_observation") or {}).get("observation_id"),
                    "after": after_state.get("observation_id"),
                    "after_cleanup": state.get("after_cleanup_observation_id"),
                },
                "raw_add_delta_ids": [delta.get("delta_id") for delta in raw_adds],
                "current_add_delta_ids": [delta.get("delta_id") for delta in current_adds],
                "creation_finding_ids": [finding.get("finding_id") for finding in linked_findings],
                "latest_reconciliation": {
                    "status": latest.get("status"),
                    "version": latest.get("version"),
                    "finalized": latest.get("finalized"),
                    "finalized_at": latest.get("finalized_at"),
                    "matched_evidence_ids": latest.get("matched_evidence_ids") or [],
                    "semantics": (latest.get("metadata") or {}).get("reconciliation_semantics"),
                    "endpoint_collection_status": (
                        (latest.get("metadata") or {}).get("event_plane") or {}
                    ).get("endpoint_collection_status"),
                },
                "wazuh_query": {
                    "complete": retrieval.get("query_complete"),
                    "coverage": retrieval.get("coverage_status"),
                    "transport": retrieval.get("transport_status"),
                    "index": retrieval.get("index_status"),
                    "candidate_count": retrieval.get("candidate_count"),
                    "exact_match_count": len(event_plane.get("exact_matches") or []),
                    "late_exact_match_count": late_query.get("exact_target_event_count"),
                },
                "latencies_seconds": {
                    "action_to_probe_category_sample": round(state_latency, 4)
                    if state_latency is not None
                    else None,
                    "action_to_local_4698": round(event_latency, 4)
                    if event_latency is not None
                    else None,
                    "provider_query": round(float(provider_latency), 4)
                    if isinstance(provider_latency, (int, float)) and provider_latency >= 0
                    else None,
                    "evidence_deadline_to_final_reconciliation": round(final_latency, 4)
                    if final_latency is not None
                    else None,
                },
                "source_artifacts": {
                    "wrapper": str(result_path.relative_to(run_dir)),
                    "wrapper_sha256": sha256(result_path),
                    "runner": str(runner_path.relative_to(run_dir)),
                    "runner_sha256": sha256(runner_path),
                },
            }
        )

    assigned = len(manifest.get("trials", []))
    passed = sum(row.get("status") == "PASS" for row in trial_rows)
    postrun_late_queries = [
        (provider_by_assignment.get(item.get("assignment_id")) or {}).get(
            "late_provider_requery"
        )
        or {}
        for item in manifest.get("trials", [])
    ]
    postrun_reconciliations = [
        (api_by_order.get(item.get("order")) or {}).get("latest_reconciliation") or {}
        for item in manifest.get("trials", [])
    ]
    controller_wait_seconds = elapsed(
        manifest.get("final_reconciliation_wait_started_at_utc"),
        manifest.get("final_reconciliation_wait_ended_at_utc"),
    )
    archive_paths = sorted((run_dir / "windows" / "raw").glob("*.zip"))
    repository_root = Path(__file__).resolve().parent.parent
    windows_audit_script = (
        repository_root / "scripts" / "audit_scheduled_task_event_filter_campaign_windows.ps1"
    )
    result = {
        "schema_version": "csg-eventid-filter-campaign-analysis-v1",
        "campaign_id": manifest.get("campaign_id"),
        "host_id": manifest.get("host_id"),
        "campaign_controller_status": manifest.get("status"),
        "campaign_started_at_utc": manifest.get("started_at_utc"),
        "campaign_ended_at_utc": manifest.get("ended_at_utc"),
        "manifest_path": str(manifest_path.relative_to(run_dir)),
        "manifest_sha256": sha256(manifest_path),
        "assigned_trials": assigned,
        "trial_artifacts_present": len(trial_rows),
        "trials_passing_all_gates": passed,
        "descriptive_95_percent_wilson_interval": wilson_interval(passed, assigned),
        "interval_warning": (
            "Repeated trials on one VM are not independent endpoint replications; "
            "interval is descriptive only."
        ),
        "gate_counts": {
            name: {"passed": count, "assigned": assigned} for name, count in gate_counts.items()
        },
        "controller_discrepancy": {
            "manifest_status": manifest.get("status"),
            "slots_marked_validity_gap": sum(
                item.get("status") == "COMPLETED_WITH_VALIDITY_GAP"
                for item in manifest.get("trials", [])
            ),
            "slots_missing_controller_add_count": sum(
                item.get("creation_add_delta_count") != 1
                for item in manifest.get("trials", [])
            ),
            "slots_missing_controller_finding_id": sum(
                not item.get("finding_id") for item in manifest.get("trials", [])
            ),
            "configured_wait_seconds": (manifest.get("parameters") or {}).get(
                "reconciliation_wait_seconds"
            ),
            "controller_wait_elapsed_seconds": round(controller_wait_seconds, 4)
            if controller_wait_seconds is not None
            else None,
            "postrun_audit_captured_at_utc": provider_audit.get("captured_at_utc"),
            "postrun_late_queries_complete": sum(
                item.get("query_complete") is True
                and item.get("coverage_status") == "COMPLETE"
                and item.get("transport_status") == "AVAILABLE"
                and item.get("index_status") == "AVAILABLE"
                for item in postrun_late_queries
            ),
            "postrun_exact_target_events": sum(
                item.get("exact_target_event_count") or 0 for item in postrun_late_queries
            ),
            "postrun_same_type_candidates": sum(
                item.get("candidate_scheduled_task_event_count") or 0
                for item in postrun_late_queries
            ),
            "postrun_finalized_reconciliations": sum(
                item.get("finalized") is True for item in postrun_reconciliations
            ),
            "postrun_unexplained_reconciliations": sum(
                item.get("status") == "UNEXPLAINED" for item in postrun_reconciliations
            ),
            "postrun_zero_evidence_reconciliations": sum(
                item.get("finalized") is True
                and not (item.get("matched_evidence_ids") or [])
                for item in postrun_reconciliations
            ),
            "api_audit_errors": sum(
                len(item.get("api_errors") or []) for item in api_audit.get("trials", [])
            ),
            "provider_audit_errors": sum(
                len(item.get("errors") or []) for item in provider_audit.get("trials", [])
            ),
            "analysis_code_frozen_before_result_inspection": False,
            "analysis_code_note": (
                "The campaign freeze still marked its analysis script as to-be-frozen when "
                "results were first inspected. The current analysis hash is recorded, but the "
                "analysis is post-hoc rather than preregistered."
            ),
            "interpretation": (
                "The frozen controller failed to retain single-result PowerShell pipeline IDs; "
                "the original manifest remains unchanged. Exact IDs and final histories were "
                "reconstructed from archived runner output and read-only API responses."
            ),
        },
        "artifact_provenance": {
            "analysis_script_path": str(
                Path(__file__).resolve().relative_to(
                    run_dir.parent.parent.parent.parent
                )
            ),
            "analysis_script_sha256": sha256(Path(__file__).resolve()),
            "api_audit_sha256": sha256(api_audit_path) if api_audit_path.is_file() else None,
            "provider_audit_sha256": sha256(provider_audit_path)
            if provider_audit_path.is_file()
            else None,
            "windows_postrun_audit_script_path": str(
                windows_audit_script.relative_to(repository_root)
            ),
            "windows_postrun_audit_script_sha256": sha256(windows_audit_script)
            if windows_audit_script.is_file()
            else None,
            "windows_raw_archive": str(archive_paths[0].relative_to(run_dir))
            if len(archive_paths) == 1
            else None,
            "windows_raw_archive_sha256": sha256(archive_paths[0])
            if len(archive_paths) == 1
            else None,
        },
        "latency_summaries": {name: summarize(values) for name, values in latency_samples.items()},
        "api_audit": str(api_audit_path.relative_to(run_dir)) if api_audit_path.is_file() else None,
        "provider_audit": str(provider_audit_path.relative_to(run_dir))
        if provider_audit_path.is_file()
        else None,
        "interpretation_limits": [
            (
                "This deliberately suppresses one benign scheduled-task creation event by "
                "changing the endpoint collection query; it is not malware or attack detection."
            ),
            (
                "The native probe retains state visibility; an exact event absence is interpreted "
                "only with complete query and source metadata."
            ),
            "Only one Windows 11 ARM VM and one event family are evaluated.",
            "Historical complete/no-change controls are not randomized or interleaved with this "
            "campaign.",
            "The analysis implementation was not frozen before first result inspection; its "
            "current hash is recorded, but this is a post-hoc analysis.",
            "No same-type Wazuh candidates occurred in the delayed exact-object queries; this "
            "campaign does not test rejection of a wrong-object distractor.",
            "Do not claim conference readiness from this campaign alone; it is one controlled "
            "mechanism/reliability study.",
        ],
        "trial_results": trial_rows,
    }
    return result


def render_report(result: dict[str, Any]) -> str:
    assigned = result["assigned_trials"]
    lines = [
        "# Scheduled-Task Event 4698 Filter-Omission Campaign Results",
        "",
        f"**Campaign:** `{result['campaign_id']}`  ",
        f"**Controller status:** `{result['campaign_controller_status']}`  ",
        f"**Complete-gate trials:** {result['trials_passing_all_gates']}/{assigned}  ",
        f"**Windows host:** `{result['host_id']}`",
        "",
        "## Finding In Brief",
        "",
        (
            "The intervention excludes Windows Security Event ID 4698 from the Wazuh endpoint "
            "collection query while leaving the Security log and the independent CSG probe "
            "enabled. "
            "Every assigned task name is unique. The result tests state visibility and exact "
            "event/state reconciliation under this configured omission; it does not test an attack."
        ),
        "",
        "## Gate Results",
        "",
        "| Gate | Passed / assigned |",
        "|---|---:|",
    ]
    labels = {
        "probe_absent_present_absent": "Probe confirmed absent / present / absent",
        "exact_local_security_4698": "Exact local Security Event 4698 record",
        "complete_provider_query_and_no_exact_match": "Complete Wazuh query; no exact target event",
        "event_absent_from_csg_store_during_omission": (
            "Exact target absent from CSG event-store readback"
        ),
        "post_restore_and_late_queries_show_no_recovery": (
            "Post-restore and late queries complete; no recovery"
        ),
        "exact_creation_add_and_linked_finding": "Exactly one creation ADD and linked finding",
        "finalized_unexplained_with_zero_evidence": (
            "Finalized UNEXPLAINED; zero matched evidence IDs"
        ),
        "configuration_health_and_cleanup_restored": (
            "Original config, service health, and cleanup restored"
        ),
    }
    for key, count in result["gate_counts"].items():
        lines.append(f"| {labels[key]} | {count['passed']} / {count['assigned']} |")
    interval = result.get("descriptive_95_percent_wilson_interval")
    interval_text = (
        "not estimable" if interval is None else f"[{interval[0]:.3f}, {interval[1]:.3f}]"
    )
    lines.extend(
        [
            "",
            (
                f"All-gate pass proportion: {result['trials_passing_all_gates']}/{assigned}; "
                f"descriptive 95% Wilson interval {interval_text}. It is not a population or "
                "independent-host interval."
            ),
            "",
            "## Controller and Independent Audit",
            "",
        ]
    )
    discrepancy = result["controller_discrepancy"]
    lines.extend(
        [
            (
                f"The original Windows controller recorded `{discrepancy['manifest_status']}` and "
                f"marked {discrepancy['slots_marked_validity_gap']}/{assigned} slots as validity "
                "gaps. The raw per-trial runner records nevertheless contain the exact ADD and "
                "linked creation finding for each target; a separate read-only audit recovered "
                "those IDs and queried their API histories. The original campaign manifest was "
                "not edited."
            ),
            "",
            (
                "Cause: the frozen PowerShell controller assigned a conditional pipeline result "
                "to a variable and then read `.Count`. For a single match, PowerShell unwrapped "
                "the result to a scalar, leaving the controller's count and finding ID null. "
                "Consequently, the controller's configured 1,800-second reconciliation poll "
                f"actually ran for {discrepancy['controller_wait_elapsed_seconds']} seconds."
            ),
            "",
            (
                f"The independent post-run audit was captured at "
                f"`{discrepancy['postrun_audit_captured_at_utc']}`. It found "
                f"{discrepancy['postrun_late_queries_complete']}/{assigned} complete late exact-"
                f"window queries, {discrepancy['postrun_exact_target_events']} exact Wazuh events, "
                f"and {discrepancy['postrun_same_type_candidates']} same-type candidates. API "
                f"histories showed {discrepancy['postrun_finalized_reconciliations']}/{assigned} "
                f"finalized reconciliations, {discrepancy['postrun_unexplained_reconciliations']} "
                "`UNEXPLAINED`, with zero matched evidence IDs in "
                f"{discrepancy['postrun_zero_evidence_reconciliations']}/{assigned}."
            ),
            "",
            (
                f"Read-only audit errors: API {discrepancy['api_audit_errors']}; provider "
                f"{discrepancy['provider_audit_errors']}. No same-type candidate occurred, so "
                "this campaign does not establish wrong-object distractor rejection."
            ),
            "",
            (
                "Analysis was post-hoc: the frozen source metadata still marked the analysis "
                "script as awaiting freeze when results were first inspected. The current script "
                "hash is recorded, but this is not a preregistered confirmatory analysis."
            ),
            "",
            "## Trial Audit",
            "",
            (
                "| Slot | Random task | Local 4698 | Current ADD | Final reconciliation | "
                "Evidence IDs | Pass gates |"
            ),
            "|---:|---|---:|---|---|---:|---:|",
        ]
    )
    for row in result["trial_results"]:
        reconciliation = row.get("latest_reconciliation") or {}
        gates = row.get("gates") or {}
        lines.append(
            f"| {row.get('order', '-')} | `{row.get('task_name') or 'missing'}` | "
            f"{', '.join(map(str, row.get('local_event_ids') or [])) or '-'} | "
            f"{', '.join(row.get('current_add_delta_ids') or []) or '-'} | "
            f"{reconciliation.get('status') or '-'} v{reconciliation.get('version') or '-'} | "
            f"{len(reconciliation.get('matched_evidence_ids') or [])} | "
            f"{sum(bool(value) for value in gates.values())}/{len(gates)} |"
        )
    lines.extend(
        [
            "",
            "## Latency",
            "",
            "| Measure | Valid n | Median (s) | P95 (s) | Maximum (s) |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    latency_labels = {
        "probe_detection": "Action start to scheduled-task category sample",
        "local_event_record": "Action start to local Event 4698 time",
        "provider_query": "Wazuh provider query duration",
        "reconciliation_finalization": "Evidence deadline to final reconciliation",
    }
    for key, summary in result["latency_summaries"].items():
        lines.append(
            f"| {latency_labels[key]} | {summary['n_valid']} | {summary['median_seconds']} | "
            f"{summary['p95_seconds']} | {summary['max_seconds']} |"
        )
    lines.extend(
        [
            "",
            (
                "Negative or unparsable intervals are omitted from latency summaries and do not "
                "change trial denominators."
            ),
            "",
            "## Limits",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in result["interpretation_limits"])
    lines.extend(
        [
            "",
            "## Provenance",
            "",
            (
                "The run directory retains the frozen protocol/source hashes, Windows campaign "
                "manifest, per-trial Windows wrapper and runner JSON, raw stdout/stderr, the "
                "post-run exact Wazuh provider queries, and a separate read-only CSG API audit. "
                "The API audit stores each exact-object delta response and each reconciliation "
                "history with a SHA-256 of the returned response bytes. The raw Windows ZIP and "
                "the two audit JSON files are hashed in `analysis.json`; the original controller "
                "manifest and its `COMPLETED_WITH_VALIDITY_GAPS` status are preserved as captured."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("--api-audit", type=Path)
    parser.add_argument("--provider-audit", type=Path)
    args = parser.parse_args()
    run_dir = args.run_directory.resolve()
    api_audit = (args.api_audit or (run_dir / "api-post-run-audit-20261012.json")).resolve()
    provider_audit = (args.provider_audit or (run_dir / "post-run-audit.json")).resolve()
    result = analyze(run_dir, api_audit, provider_audit)
    (run_dir / "analysis.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (run_dir / "RESULTS.md").write_text(render_report(result), encoding="utf-8")
    print(
        json.dumps(
            {
                "campaign_id": result["campaign_id"],
                "trials_passing_all_gates": result["trials_passing_all_gates"],
                "assigned_trials": result["assigned_trials"],
                "results": str(run_dir / "RESULTS.md"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
