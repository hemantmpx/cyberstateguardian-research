#!/usr/bin/env python3
"""Validate and summarize one controlled Windows Security Event 4698 filter pilot."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8-sig") as stream:
        return json.load(stream)


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def normalize_query(value: str | None) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def analyze(run_dir: Path) -> tuple[dict[str, Any], str]:
    raw_dir = run_dir / "windows" / "raw"
    result_path = raw_dir / "result.json"
    runner_path = raw_dir / "run.json"
    trial_path = raw_dir / "trial-01-scheduled-task-persistence.json"
    preflight_path = raw_dir / "preflight.json"
    result = read_json(result_path)
    runner = read_json(runner_path)
    trial = read_json(trial_path)
    preflight = read_json(preflight_path)
    source_freeze = read_json(run_dir / "source-freeze.json")
    scenarios = runner.get("scenarios") or []
    if len(scenarios) != 1:
        raise ValueError(f"Expected one scheduled-task scenario, found {len(scenarios)}")
    scenario = scenarios[0]

    local = trial.get("local_source_evidence") or {}
    local_events = [
        event
        for event in local.get("exact_events", [])
        if event.get("event_id") == 4698 and event.get("exact_identity_match") is True
    ]
    event_plane = scenario.get("event_plane") or {}
    retrieval = event_plane.get("retrieval") or {}
    recon = result.get("final_target_reconciliation") or {}
    recon_meta = recon.get("metadata") or {}
    post_queries = result.get("post_restore_provider_queries") or []
    task_name = scenario.get("object_name")
    direct_state = (scenario.get("state_plane") or {}).get("direct_windows_verification") or {}
    action = scenario.get("action") or {}
    final_health = result.get("source_health_after_restore") or {}
    service_rows = final_health.get("services") or []
    wazuh_running = any(
        row.get("name") == "WazuhSvc" and row.get("state") == "Running"
        for row in service_rows
    )
    restored_hash = result.get("restored_agent_config_sha256")
    original_hash = result.get("original_agent_config_sha256")
    local_task_names = [
        (event.get("event_data") or {}).get("TaskName") for event in local_events
    ]
    target_key = scenario.get("expected_object_key")
    state_pass = all(
        direct_state.get(name) is True
        for name in (
            "target_absent_before_action",
            "target_present_after_action",
            "target_absent_after_cleanup",
        )
    )
    frozen_filter = source_freeze.get("security_eventchannel_filter") or {}
    filter_preflight_pass = (
        preflight.get("original_agent_config_sha256")
        == frozen_filter.get("original_agent_config_sha256")
        and original_hash == frozen_filter.get("original_agent_config_sha256")
        and normalize_query(preflight.get("security_query_before"))
        == normalize_query(frozen_filter.get("baseline_query"))
        and normalize_query(preflight.get("security_query_after"))
        == normalize_query(frozen_filter.get("intervention_query"))
    )
    query_pass = (
        event_plane.get("query_completed") is True
        and retrieval.get("query_complete") is True
        and retrieval.get("coverage_status") == "COMPLETE"
        and retrieval.get("endpoint_collection_status") == "AVAILABLE"
        and retrieval.get("transport_status") == "AVAILABLE"
        and retrieval.get("index_status") == "AVAILABLE"
    )
    no_target_event_during_filter = not (event_plane.get("exact_matches") or [])
    recon_pass = (
        recon.get("status") == "UNEXPLAINED"
        and recon.get("finalized") is True
        and not (recon.get("matched_evidence_ids") or [])
    )
    post_queries_complete = bool(post_queries) and all(
        item.get("query_complete") is True
        and item.get("coverage_status") == "COMPLETE"
        for item in post_queries
    )
    recovered_ids = sorted(
        {
            event_id
            for item in post_queries
            for event_id in (item.get("exact_target_event_ids") or [])
        }
    )
    absent_after_restore = post_queries_complete and not recovered_ids
    restoration_pass = (
        result.get("configuration_mutation_attempted") is True
        and result.get("restored_hash_matches_original") is True
        and original_hash == restored_hash
    )
    health_pass = (
        final_health.get("csg_api_healthy") is True
        and final_health.get("wazuh_server_api_healthy") is True
        and final_health.get("wazuh_indexer_healthy") is True
        and final_health.get("endpoint_agent_status") == "active"
        and wazuh_running
        and result.get("security_log_enabled_after") is True
    )
    cleanup_pass = (
        result.get("cleanup_verified") is True
        and not (result.get("residual_study_tasks") or [])
        and scenario.get("action", {}).get("cleanup_completed") is True
    )
    checks = {
        "probe_observed_absent_present_absent": state_pass,
        "frozen_filter_and_original_hash_verified": filter_preflight_pass,
        "exact_local_security_4698_present": bool(local_events),
        "central_event_query_complete_and_sources_available": query_pass,
        "exact_wazuh_target_event_absent_during_filter": no_target_event_during_filter,
        "csg_finalized_unexplained_with_zero_evidence": recon_pass,
        "post_restore_queries_complete": post_queries_complete,
        "target_event_not_recovered_after_restore": absent_after_restore,
        "original_config_hash_restored": restoration_pass,
        "endpoint_and_services_healthy": health_pass,
        "study_task_cleanup_verified": cleanup_pass,
    }
    mechanism_demonstrated = all(checks.values())

    action_start = parse_time(action.get("started_at"))
    state_observed = parse_time(
        ((scenario.get("state_plane") or {}).get("after_action_observation") or {}).get(
            "observed_at"
        )
    )
    local_event_time = parse_time(local_events[0].get("event_time_utc")) if local_events else None
    final_at = parse_time(recon.get("finalized_at"))
    evidence_deadline = parse_time(recon_meta.get("evidence_deadline"))
    finalization_lag = (
        round((final_at - evidence_deadline).total_seconds(), 3)
        if final_at and evidence_deadline
        else None
    )
    state_latency = (
        round((state_observed - action_start).total_seconds(), 3)
        if state_observed and action_start
        else None
    )
    event_latency = (
        round((local_event_time - action_start).total_seconds(), 3)
        if local_event_time and action_start
        else None
    )

    wrapper_count = result.get("local_windows_4698_exact_count")
    wrapper_status_false_negative = (
        mechanism_demonstrated
        and result.get("status") != "PASS_CONTROLLED_EVENT_FILTER_OMISSION"
        and wrapper_count != len(local_events)
    )
    hashes = {
        path.name: digest(path)
        for path in (result_path, runner_path, trial_path, preflight_path)
    }
    analysis = {
        "schema_version": "csg-scheduled-task-eventid-filter-analysis-v1",
        "run_id": run_dir.name,
        "classification": (
            "VALID_SINGLE_TRIAL_MECHANISM_DEMONSTRATION"
            if mechanism_demonstrated
            else "INCOMPLETE_OR_INVALID"
        ),
        "research_readiness": "PILOT_ONLY_NOT_CONFERENCE_GRADE",
        "n": 1,
        "host_id": result.get("host_id"),
        "task_name": task_name,
        "task_object_key": target_key,
        "event": {
            "local_event_id": 4698,
            "local_event_record_ids": [event.get("record_id") for event in local_events],
            "local_event_times_utc": [event.get("event_time_utc") for event in local_events],
            "local_event_task_names": local_task_names,
            "exact_wazuh_event_ids_during_filter": [],
            "exact_wazuh_event_ids_after_restore": recovered_ids,
        },
        "csg": {
            "observation_ids": {
                "before": ((scenario.get("state_plane") or {}).get("before_action_observation") or {}).get("observation_id"),
                "after": ((scenario.get("state_plane") or {}).get("after_action_observation") or {}).get("observation_id"),
                "after_cleanup": ((scenario.get("state_plane") or {}).get("after_cleanup_observation") or {}).get("observation_id"),
            },
            "delta_id": scenario.get("csg_reconciliation", {}).get("delta_id"),
            "finding_id": scenario.get("csg_reconciliation", {}).get("finding_id"),
            "final_reconciliation_id": recon.get("reconciliation_id"),
            "final_reconciliation_version": recon.get("version"),
            "status": recon.get("status"),
            "finalized": recon.get("finalized"),
            "matched_evidence_ids": recon.get("matched_evidence_ids") or [],
            "evidence_deadline_utc": recon_meta.get("evidence_deadline"),
            "finalized_at_utc": recon.get("finalized_at"),
            "finalization_lag_after_deadline_seconds": finalization_lag,
        },
        "state_event_plane": {
            "state_transition_seen": state_pass,
            "local_security_log_query_status": local.get("query_status"),
            "local_exact_event_count": len(local_events),
            "provider_query_complete": retrieval.get("query_complete"),
            "provider_coverage_status": retrieval.get("coverage_status"),
            "endpoint_collection_status": retrieval.get("endpoint_collection_status"),
            "transport_status": retrieval.get("transport_status"),
            "index_status": retrieval.get("index_status"),
            "provider_returned_event_count": retrieval.get("retrieved_count"),
            "exact_target_wazuh_event_count": len(event_plane.get("exact_matches") or []),
        },
        "restoration": {
            "original_config_sha256": original_hash,
            "filtered_config_sha256": result.get("filtered_agent_config_sha256"),
            "restored_config_sha256": restored_hash,
            "hash_matches": restoration_pass,
            "post_restore_query_count": len(post_queries),
            "post_restore_queries_complete": post_queries_complete,
            "exact_target_event_recovered": bool(recovered_ids),
            "post_restore_query_summaries": [
                {
                    "queried_at_utc": item.get("queried_at_utc"),
                    "returned_event_count": item.get("returned_event_count"),
                    "query_complete": item.get("query_complete"),
                    "coverage_status": item.get("coverage_status"),
                    "exact_target_event_ids": item.get("exact_target_event_ids") or [],
                }
                for item in post_queries
            ],
        },
        "latency_observations_seconds": {
            "action_to_first_probe_observation": state_latency,
            "action_to_local_event_timestamp": event_latency,
            "reconciliation_finalization_after_deadline": finalization_lag,
            "scope_note": "Single-trial descriptive timing only; do not present as a population estimate.",
        },
        "validity_checks": checks,
        "wrapper_diagnostic": {
            "raw_wrapper_status": result.get("status"),
            "wrapper_local_event_count": wrapper_count,
            "independently_counted_local_exact_events": len(local_events),
            "false_negative_status_due_to_count_serialization": wrapper_status_false_negative,
            "explanation": (
                "The wrapper's one-item PowerShell collection count serialized as null; the raw "
                "runner artifact independently contains the exact local 4698, and all other "
                "validity conditions are assessed from the captured evidence."
                if wrapper_status_false_negative
                else None
            ),
        },
        "deviations": [
            "Three earlier attempts were preflight refusals with no endpoint mutation and n=0.",
            "The capture-drop mechanism was exercised by an explicit reversible eventchannel collection filter, not by stopping the Wazuh agent.",
            "One endpoint and one task category; results are a pilot, not a broad performance estimate.",
        ],
        "input_artifact_sha256": hashes,
    }

    report = f"""# Scheduled-Task Event 4698 Filter Pilot: Results

## Outcome

**{analysis['classification']} (n=1).** This pilot demonstrates a controlled collection-policy omission: Windows retained a task-creation event locally, the independent CSG probe observed the persistent task transition, the healthy Wazuh query returned no exact matching task event, and CSG finalized the state change as `UNEXPLAINED` with no matched evidence. This is useful mechanism evidence, not a conference-grade estimate or an attack-detection claim.

## What Happened

- Host: `{result.get('host_id')}`; task: `{task_name}`; object key: `{target_key}`.
- CSG observed the task absent before the action, present afterward, and absent after cleanup: **{state_pass}**.
- Windows Security contained **{len(local_events)}** exact Event 4698 record(s), record ID(s): `{[event.get('record_id') for event in local_events]}`.
- Wazuh query completed with coverage `{retrieval.get('coverage_status')}` and endpoint/transport/index status `{retrieval.get('endpoint_collection_status')}/{retrieval.get('transport_status')}/{retrieval.get('index_status')}`; exact target events returned during the filter: **{len(event_plane.get('exact_matches') or [])}**.
- Final CSG reconciliation: **{recon.get('status')}**, finalized `{recon.get('finalized')}`, evidence IDs `{recon.get('matched_evidence_ids') or []}`.
- After restoring the original agent configuration, **{len(post_queries)}** complete provider queries over the target interval found no exact target event. This supports only the bounded statement that the configured collection filter prevented later visibility in the queried Wazuh store during this observation period.

## Timing

- Action to first post-action probe observation: {state_latency} seconds.
- Action to local Security event timestamp: {event_latency} seconds.
- Reconciliation finalization occurred {finalization_lag} seconds after the recorded evidence deadline. This delayed finalization should be reported as observed and investigated; it is not a latency benchmark.

## Integrity And Cleanup

- Original config SHA-256 restored exactly: `{restored_hash}` (**{restoration_pass}**).
- CSG API, Wazuh server API, indexer, endpoint agent, Wazuh service, and Security log health checks passed: **{health_pass}**.
- Scheduled-task cleanup and residual-task checks passed: **{cleanup_pass}**.
- All validity checks passed: **{mechanism_demonstrated}**.

## Tooling Deviation

The raw wrapper labeled the run `INCOMPLETE_OR_INVALID` because its one-item PowerShell event collection produced a null `.Count`. The raw positive-runner artifact contains the exact local Event 4698, and the independent checks above derive the event count from that source. The wrapper was corrected for future runs. The raw Windows artifact is preserved unchanged; do not replace its original status.

Three earlier executions stopped during preflight because the wrapper did not initially reflect the VM's pre-existing Security query exactly. Those attempts made no configuration or endpoint mutation and are excluded (`n=0`). The final pilot preserved every baseline exclusion and appended only the Event 4698 exclusion.

## Limits And Next Work

This is one benign scheduled-task action on one Windows host. Wazuh remained available and the event was intentionally filtered at collection; this does not test an agent outage, natural event loss, malicious behavior, other event classes, or general detection accuracy. Repeat the frozen protocol with fresh randomized task identities, include matched complete-profile controls and no-change controls, and investigate the multi-minute finalization lag before making a latency claim. See `analysis.json` for machine-readable checks, identifiers, and source artifact hashes.
"""
    return analysis, report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    analysis, report = analyze(run_dir)
    (run_dir / "analysis.json").write_text(
        json.dumps(analysis, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )
    (run_dir / "RESULTS.md").write_text(report, encoding="utf-8")
    print(
        json.dumps(
            {
                "classification": analysis["classification"],
                "all_validity_checks_passed": all(analysis["validity_checks"].values()),
                "wrapper_false_negative": analysis["wrapper_diagnostic"]["false_negative_status_due_to_count_serialization"],
                "local_event_count": len(analysis["event"]["local_event_record_ids"]),
                "post_restore_queries": analysis["restoration"]["post_restore_query_count"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
