# ruff: noqa: E501
"""Audit and summarize the controlled service-install event-drop cohort."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any

EXPERIMENT_ID = "service-install-object-drop-replication-v8"
REMOTE_CAPTURE = "remote-capture/service-install-object-drop-replication-v8"


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def elapsed_seconds(start: Any, end: Any) -> float | None:
    start_time = parse_time(start)
    end_time = parse_time(end)
    if start_time is None or end_time is None:
        return None
    return (end_time - start_time).total_seconds()


def exact_binomial_interval(
    successes: int, trials: int, alpha: float = 0.05
) -> tuple[float, float]:
    """Two-sided Clopper-Pearson interval, solved from binomial tails."""
    if trials <= 0 or not 0 <= successes <= trials:
        raise ValueError("Require 0 <= successes <= trials and trials > 0")

    def probability(index: int, p: float) -> float:
        return math.comb(trials, index) * p**index * (1.0 - p) ** (trials - index)

    tail = alpha / 2.0
    if successes == 0:
        lower = 0.0
    else:
        lo, hi = 0.0, 1.0
        for _ in range(80):
            mid = (lo + hi) / 2.0
            upper_tail = sum(probability(i, mid) for i in range(successes, trials + 1))
            if upper_tail < tail:
                lo = mid
            else:
                hi = mid
        lower = (lo + hi) / 2.0

    if successes == trials:
        upper = 1.0
    else:
        lo, hi = 0.0, 1.0
        for _ in range(80):
            mid = (lo + hi) / 2.0
            lower_tail = sum(probability(i, mid) for i in range(successes + 1))
            if lower_tail > tail:
                lo = mid
            else:
                hi = mid
        upper = (lo + hi) / 2.0
    return lower, upper


def metric(successes: int, trials: int) -> dict[str, Any]:
    low, high = exact_binomial_interval(successes, trials)
    return {
        "successes": successes,
        "trials": trials,
        "rate": successes / trials if trials else None,
        "ci_95_clopper_pearson": [low, high],
    }


def percentile_summary(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"n": 0, "median": None, "min": None, "max": None}
    return {
        "n": len(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def require(condition: bool, message: str, failures: list[str]) -> bool:
    if not condition:
        failures.append(message)
    return condition


def validate_trial(
    trial: dict[str, Any], run: dict[str, Any], slot: dict[str, Any], baseline_hash: str
) -> dict[str, Any]:
    failures: list[str] = []
    target_name = trial["target_service_name"]
    distractor_name = trial["distractor_service_name"]
    target_key = f"service:{target_name.lower()}"
    distractor_key = f"service:{distractor_name.lower()}"

    target_add = (run.get("target") or {}).get("probe_observation", {}).get("add_delta") or {}
    target_local = (run.get("target") or {}).get("local_7045") or {}
    distractor_local = (run.get("distractor") or {}).get("local_7045") or {}
    provider = run.get("provider_query") or {}
    suppression = run.get("suppression") or {}
    target_events = as_list(provider.get("target_exact_service_created_events"))
    distractor_events = as_list(provider.get("distractor_exact_service_created_events"))
    findings = as_list(run.get("target_findings"))
    finding = findings[0] if len(findings) == 1 else {}
    reconciliation = finding.get("reconciliation") or {}
    matched_evidence = as_list(reconciliation.get("matched_evidence_ids"))
    restoration = run.get("restoration") or {}
    cleanup = run.get("cleanup") or {}
    target_remove = cleanup.get("target_remove_delta") or {}
    distractor_remove = cleanup.get("distractor_remove_delta") or {}

    state_observed = require(
        run.get("host_id") == trial.get("host_id", run.get("host_id"))
        and target_add.get("host_id") == run.get("host_id")
        and target_add.get("object_key") == target_key
        and target_add.get("delta_type") == "ADD"
        and (target_add.get("after") or {}).get("attributes", {}).get("service_name")
        == target_name,
        "missing or mismatched direct-probe target ADD",
        failures,
    )
    local_target_event = require(
        target_local.get("event_id") == 7045 and target_local.get("service_name") == target_name,
        "missing or mismatched local target System Event 7045",
        failures,
    )
    retrieval = (provider.get("metadata") or {}).get("retrieval") or {}
    retrieval_sources = retrieval.get("sources") or {}
    query_healthy = require(
        provider.get("query_complete") is True
        and provider.get("endpoint_collection_status") == "AVAILABLE"
        and provider.get("transport_status") == "AVAILABLE"
        and provider.get("index_status") == "AVAILABLE"
        and provider.get("coverage_status") == "COMPLETE",
        "Wazuh provider query/endpoint/index health was not complete and available",
        failures,
    )
    for source_name in ("wazuh_alert", "wazuh_archive"):
        source_status = retrieval_sources.get(source_name) or {}
        require(
            source_status.get("status") == "AVAILABLE" and source_status.get("complete") is True,
            f"Wazuh {source_name} retrieval was not complete and available",
            failures,
        )
    expected_query = (
        f"Event[System/EventID != 7045 or EventData/Data[@Name='ServiceName'] != '{target_name}']"
    )
    expected_registry_ignore = (
        "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\" + target_name
    )
    filter_scoped = require(
        suppression.get("query") == expected_query
        and suppression.get("ignored_registry_path") == expected_registry_ignore
        and suppression.get("xml_readback_passed") is True
        and suppression.get("original_config_sha256") == baseline_hash
        and suppression.get("filtered_config_sha256") != baseline_hash,
        "Wazuh telemetry suppression was not verified as target-specific by XML readback and hashes",
        failures,
    )
    no_target_event = require(
        len(target_events) == 0,
        f"expected zero target Wazuh service-created events, got {len(target_events)}",
        failures,
    )

    exact_distractor_events = [
        event
        for event in distractor_events
        if event.get("host_id") == run.get("host_id")
        and event.get("source") == "wazuh"
        and event.get("normalized_type") == "service_created"
        and (event.get("target") or {}).get("key") == distractor_key
        and (event.get("attributes") or {}).get("service_name") == distractor_name
    ]
    matching_record_events = [
        event
        for event in exact_distractor_events
        if str(
            ((event.get("metadata") or {}).get("windows_event_identity") or {}).get(
                "event_record_id"
            )
        )
        == str(distractor_local.get("event_record_id"))
    ]
    require(
        len(exact_distractor_events) >= 1 and len(matching_record_events) >= 1,
        "no exact same-host distractor Wazuh event matched the local Windows Event 7045 record ID",
        failures,
    )
    finding_valid = require(
        len(findings) == 1
        and finding.get("host_id") == run.get("host_id")
        and finding.get("object_key") == target_key
        and finding.get("delta_id") == target_add.get("delta_id"),
        "target finding is missing, ambiguous, or not tied to the exact target delta",
        failures,
    )
    unexplained = require(
        finding_valid
        and reconciliation.get("status") == "UNEXPLAINED"
        and reconciliation.get("finalized") is True
        and len(matched_evidence) == 0,
        "target reconciliation was not final UNEXPLAINED with zero matched evidence IDs",
        failures,
    )
    restored = require(
        restoration.get("exact_hash_match") is True
        and restoration.get("original_hash") == baseline_hash
        and restoration.get("restored_hash") == baseline_hash
        and (restoration.get("healthy_after_restart") or {}).get("wazuh_service_status")
        == "Running",
        "original Wazuh configuration was not hash-identically restored and healthy",
        failures,
    )

    def exact_remove(delta: dict[str, Any], name: str, key: str) -> bool:
        return (
            delta.get("host_id") == run.get("host_id")
            and delta.get("object_key") == key
            and delta.get("delta_type") == "REMOVE"
            and (delta.get("before") or {}).get("attributes", {}).get("service_name") == name
        )

    cleanup_valid = require(
        cleanup.get("target_windows_absent") is True
        and cleanup.get("distractor_windows_absent") is True
        and cleanup.get("target_probe_absent") is True
        and cleanup.get("distractor_probe_absent") is True
        and exact_remove(target_remove, target_name, target_key)
        and exact_remove(distractor_remove, distractor_name, distractor_key),
        "Windows or probe cleanup/removal evidence is incomplete",
        failures,
    )
    controller_valid = require(
        slot.get("status") == "COMPLETED_GATES_PASSED"
        and slot.get("research_outcome_gate") is True
        and slot.get("restoration_gate") is True
        and slot.get("cleanup_gate") is True
        and slot.get("target_event_count") == 0
        and slot.get("distractor_event_count", 0) >= 1,
        "controller slot did not pass all independent gate fields",
        failures,
    )
    require(run.get("outcome") == "CAPTURED", "runner did not report CAPTURED", failures)
    require(run.get("error") is None, "runner artifact contains an error", failures)
    require(run.get("experiment_id") == EXPERIMENT_ID, "experiment ID mismatch", failures)
    require(run.get("trial_id") == trial["trial_id"], "trial ID mismatch", failures)
    require(run.get("service_name") == target_name, "target name differs from assignment", failures)
    require(
        run.get("distractor_service_name") == distractor_name,
        "distractor name differs from assignment",
        failures,
    )

    action_at = (run.get("target") or {}).get("action_started_at_utc")
    target_delta_latency = elapsed_seconds(action_at, target_add.get("created_at"))
    target_observation_latency = elapsed_seconds(
        action_at, (target_add.get("after") or {}).get("source_timestamp")
    )
    target_local_event_latency = elapsed_seconds(action_at, target_local.get("event_time_utc"))
    distractor_event_time_delta = elapsed_seconds(
        distractor_local.get("event_time_utc"),
        (matching_record_events[0] if matching_record_events else {}).get("event_time"),
    )
    final_polls = [
        poll
        for poll in as_list(run.get("reconciliation_polls"))
        if poll.get("finalized") is True
        and poll.get("target_reconciliation_status") == "UNEXPLAINED"
    ]
    reconciliation_finalized_latency = elapsed_seconds(
        action_at, final_polls[0].get("at_utc") if final_polls else None
    )
    numeric_timings = [
        target_delta_latency,
        target_observation_latency,
        target_local_event_latency,
        reconciliation_finalized_latency,
        run.get("duration_seconds"),
    ]
    for value in numeric_timings:
        if value is not None:
            require(value >= 0, f"negative latency/duration recorded: {value}", failures)

    return {
        "trial_id": trial["trial_id"],
        "target_service_name": target_name,
        "distractor_service_name": distractor_name,
        "runner_outcome": run.get("outcome"),
        "controller_status": slot.get("status"),
        "direct_probe_target_add": state_observed,
        "local_target_7045": local_target_event,
        "wazuh_query_healthy": query_healthy,
        "target_filter_scope_verified": filter_scoped,
        "target_wazuh_event_count": len(target_events),
        "target_wazuh_event_absent": no_target_event,
        "distractor_wazuh_exact_event_count": len(exact_distractor_events),
        "distractor_record_id_matches_local_7045": bool(matching_record_events),
        "target_finding_exactly_tied_to_delta": finding_valid,
        "final_unexplained_zero_match": unexplained,
        "target_reconciliation_status": reconciliation.get("status"),
        "config_restored_and_healthy": restored,
        "windows_and_probe_cleanup": cleanup_valid,
        "controller_gates": controller_valid,
        "trial_pass": not failures,
        "failure_reasons": failures,
        "target_delta_persist_seconds_after_action": target_delta_latency,
        "target_probe_observation_seconds_after_action": target_observation_latency,
        "target_local_7045_seconds_after_action": target_local_event_latency,
        "wazuh_distractor_timestamp_minus_local_7045_seconds": distractor_event_time_delta,
        "final_reconciliation_seconds_after_action": reconciliation_finalized_latency,
        "trial_duration_seconds": run.get("duration_seconds"),
        "target_delta_id": target_add.get("delta_id"),
        "target_local_event_record_id": target_local.get("event_record_id"),
        "distractor_local_event_record_id": distractor_local.get("event_record_id"),
        "distractor_wazuh_event_ids": [event.get("event_id") for event in exact_distractor_events],
        "target_finding_id": finding.get("finding_id"),
        "matched_evidence_ids": matched_evidence,
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repository_path(path: Path) -> str:
    return Path(os.path.relpath(path.resolve(), Path.cwd().resolve())).as_posix()


def write_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    rows = [
        "# V8 Service-Install Object-Specific Event-Drop Results",
        "",
        f"**Audit status:** `{result['audit_status']}`  ",
        f"**Assigned trials:** {summary['assigned_trials']}  ",
        f"**All required gates passed:** {summary['all_gates_passed']['successes']}/{summary['all_gates_passed']['trials']}  ",
        f"**Exact two-sided 95% Clopper-Pearson interval:** {format_ci(summary['all_gates_passed'])}",
        "",
        "## What Was Tested",
        "",
        "For each assigned trial, the Windows endpoint registered two inert, never-started demand-start services. CSG's direct probe observed the target service. The Wazuh agent was deliberately configured to filter only the target service's Event 7045 and exact service-registry FIM key, while collecting the same-host distractor. The test asks whether CSG keeps the target state change visible and refuses to explain it with the distractor's event.",
        "",
        "This is an object-specific reconciliation challenge under deliberate, target-scoped telemetry filtering. It is not a malicious-activity test, natural Wazuh-loss test, or broad attack-detection evaluation.",
        "",
        "## Aggregate Results",
        "",
        "| Measure | Result | Exact two-sided 95% CI |",
        "|---|---:|---:|",
    ]
    labels = [
        ("direct_probe_target_add", "Target state ADD observed"),
        ("local_target_7045", "Exact local target Event 7045 captured"),
        ("target_filter_scope_verified", "Target-only Wazuh filter verified by config readback"),
        ("target_wazuh_event_absent", "Target Wazuh event absent under filter"),
        ("wazuh_query_healthy", "Wazuh alert/archive retrieval complete and healthy"),
        (
            "distractor_record_id_matches_local_7045",
            "Distractor Wazuh event matched local record ID",
        ),
        ("final_unexplained_zero_match", "Final UNEXPLAINED; zero matched evidence"),
        ("config_restored_and_healthy", "Wazuh config restored and healthy"),
        ("windows_and_probe_cleanup", "Windows and probe cleanup complete"),
        ("all_gates_passed", "All predeclared trial gates passed"),
    ]
    for key, label in labels:
        value = summary[key]
        rows.append(
            f"| {label} | {value['successes']}/{value['trials']} ({value['rate']:.1%}) | {format_ci(value)} |"
        )
    false_consistent = summary["false_consistent_under_target_event_filter"]
    rows.append(
        f"| False CONSISTENT despite target event absent | {false_consistent['successes']}/{false_consistent['trials']} ({false_consistent['rate']:.1%}) | {format_ci(false_consistent)} |"
    )
    rows.extend(
        [
            "",
            "## Per-Trial Results",
            "",
            "| Trial | Target | Distractor | Probe ADD | Target Wazuh events | Distractor record match | Final reconciliation | Restore/cleanup | Duration (s) |",
            "|---|---|---|---:|---:|---:|---|---|---:|",
        ]
    )
    for trial in result["trials"]:
        rows.append(
            "| {trial_id} | `{target_service_name}` | `{distractor_service_name}` | {add} | {target_events} | {record_match} | {recon} | {restore}/{cleanup} | {duration:.2f} |".format(
                **trial,
                add="yes" if trial["direct_probe_target_add"] else "no",
                target_events=trial["target_wazuh_event_count"],
                record_match="yes" if trial["distractor_record_id_matches_local_7045"] else "no",
                recon="final UNEXPLAINED" if trial["final_unexplained_zero_match"] else "FAIL",
                restore="pass" if trial["config_restored_and_healthy"] else "fail",
                cleanup="pass" if trial["windows_and_probe_cleanup"] else "fail",
                duration=trial["trial_duration_seconds"] or 0,
            )
        )
    rows.extend(["", "## Latency Summary", ""])
    rows.append(
        "Latency values are derived from timestamps retained in the per-trial raw JSON. The Wazuh value is the normalized event timestamp minus the endpoint's local 7045 timestamp; it is **not** an index-ingestion-latency measurement."
    )
    rows.append("")
    rows.append("| Measure | n | Median seconds | Min | Max |")
    rows.append("|---|---:|---:|---:|---:|")
    latency_labels = [
        ("target_delta_persist_seconds_after_action", "Action to CSG ADD persistence"),
        ("target_probe_observation_seconds_after_action", "Action to probe observation timestamp"),
        ("target_local_7045_seconds_after_action", "Action to local Event 7045 timestamp"),
        (
            "wazuh_distractor_timestamp_minus_local_7045_seconds",
            "Wazuh event timestamp minus local distractor 7045",
        ),
        ("final_reconciliation_seconds_after_action", "Action to final reconciliation poll"),
        ("trial_duration_seconds", "Full trial wall duration"),
    ]
    for key, label in latency_labels:
        stats = summary["latencies"][key]

        def render(value: float | None) -> str:
            return "n/a" if value is None else f"{value:.3f}"

        rows.append(
            f"| {label} | {stats['n']} | {render(stats['median'])} | {render(stats['min'])} | {render(stats['max'])} |"
        )
    rows.extend(
        [
            "",
            "## Interpretation And Limitations",
            "",
            "The observed mechanism is that persistent target state remained visible to the independent CSG probe while the target's corresponding Wazuh event was deliberately filtered. A correctly identified same-host distractor event was present, yet the target finding finalized as `UNEXPLAINED` with no matched evidence. This supports object-specific matching for this controlled service-registration case on this endpoint.",
            "",
            "The sample is ten repeated trials on one Windows 11 ARM64 UTM VM. The exact binomial intervals assume exchangeable independent trials; same-host repetition does not provide independent host replication, so those intervals are descriptive and may understate shared-environment uncertainty. The intervention deliberately filters target telemetry; it does not establish natural sensor failure or permanent loss in an unmodified Wazuh deployment. The services are benign test mutations. No claim about malicious detection accuracy, recall on attacks, cross-host generalization, or conference readiness follows from this cohort alone.",
            "",
            f"Final endpoint postflight passed: `{result['final_postflight']['postflight_pass']}` at `{result['final_postflight']['checked_at_utc']}`. The original Wazuh config hash matched; Wazuh, API, indexer, agent, and probe were healthy; all assigned test services were absent.",
            "",
            "V5-V7 are not pooled with V8. V7 stopped before target mutation after a runner cardinality bug; see its separate `EXECUTION_NOTE.md`.",
            "",
            "## Reproducibility",
            "",
            "The frozen input SHA-256 values are checked against `source-freeze.json`. `artifact-manifest.json` records hashes of the copied Windows cohort checkpoint, preflight, final postflight, all ten raw per-trial records, the analysis code, and the derived reports (the manifest excludes itself). The raw records are retained under `remote-capture/service-install-object-drop-replication-v8/trials/`.",
            "",
        ]
    )
    return "\n".join(rows)


def format_ci(value: dict[str, Any]) -> str:
    low, high = value["ci_95_clopper_pearson"]
    return f"[{low:.1%}, {high:.1%}]"


def self_test() -> None:
    low, high = exact_binomial_interval(10, 10)
    assert abs(low - 0.6915028922) < 1e-8 and high == 1.0
    low, high = exact_binomial_interval(0, 10)
    assert low == 0.0 and abs(high - 0.3084971078) < 1e-8
    assert as_list(None) == [] and as_list({"id": 1}) == [{"id": 1}]
    assert elapsed_seconds("2026-10-16T00:00:00Z", "2026-10-16T00:00:01Z") == 1.0


def analyze(run_dir: Path) -> dict[str, Any]:
    freeze = read_json(run_dir / "source-freeze.json")
    assignment = read_json(run_dir / "assignment.json")
    capture_dir = run_dir / REMOTE_CAPTURE
    cohort = read_json(capture_dir / "cohort-execution.json")
    failures: list[str] = []

    frozen_files = {
        "protocol_sha256": "PROTOCOL.md",
        "assignment_sha256": "assignment.json",
        "runner_sha256": "run_service_install_object_drop_replication_windows.ps1",
        "controller_sha256": "run_cohort_windows.ps1",
    }
    for freeze_field, filename in frozen_files.items():
        actual = sha256(run_dir / filename)
        if actual != freeze.get(freeze_field):
            failures.append(f"frozen input hash mismatch: {filename}")

    if (
        assignment.get("experiment_id") != EXPERIMENT_ID
        or freeze.get("experiment_id") != EXPERIMENT_ID
    ):
        failures.append("experiment ID mismatch in assignment or source freeze")
    if cohort.get("experiment_id") != EXPERIMENT_ID:
        failures.append("remote cohort experiment ID mismatch")
    assigned = assignment.get("trials") or []
    slots = {slot.get("trial_id"): slot for slot in cohort.get("completed_slots", [])}
    if cohort.get("assigned_trial_count") != len(assigned) or len(assigned) != 10:
        failures.append("assigned denominator is not exactly ten")
    if (
        cohort.get("execution_status")
        != "ALL_ASSIGNED_TRIALS_COMPLETED_WITH_RESTORE_AND_CLEANUP_GATES"
    ):
        failures.append("controller did not complete every assigned slot")
    if len(slots) != len(assigned):
        failures.append("cohort checkpoint slot count does not equal assignment count")

    preflight = read_json(capture_dir / "dry-run-preflight.json")
    if not preflight.get("frozen_hashes_match") or not preflight.get("all_assigned_names_absent"):
        failures.append("remote preflight did not verify frozen hashes and all names absent")
    if not preflight.get("cardinality_self_test_passed"):
        failures.append("remote controller cardinality self-test did not pass")
    if preflight.get("baseline_wazuh_config_sha256") != freeze.get("baseline_wazuh_config_sha256"):
        failures.append("remote preflight Wazuh configuration hash differs from frozen baseline")
    postflight = read_json(capture_dir / "postflight-final.json")
    postflight_valid = (
        postflight.get("postflight_pass") is True
        and postflight.get("experiment_id") == EXPERIMENT_ID
        and postflight.get("wazuh_config_sha256") == freeze.get("baseline_wazuh_config_sha256")
        and postflight.get("wazuh_service_status") == "Running"
        and postflight.get("api_ok") is True
        and postflight.get("indexer_ok") is True
        and postflight.get("active_agent_count") == 1
        and postflight.get("probe_task_state") == "Running"
        and postflight.get("latest_service_category_status") == "healthy"
        and not as_list(postflight.get("assigned_experimental_services_remaining"))
    )
    if not postflight_valid:
        failures.append("final endpoint postflight failed or did not verify the clean lab state")

    trial_results = []
    for trial in assigned:
        trial_id = trial["trial_id"]
        run_path = capture_dir / "trials" / trial_id / "run.json"
        if not run_path.is_file():
            failures.append(f"missing raw run artifact: {trial_id}")
            continue
        slot = slots.get(trial_id, {})
        run = read_json(run_path)
        result = validate_trial(
            {**trial, "host_id": assignment.get("host_id")},
            run,
            slot,
            freeze["baseline_wazuh_config_sha256"],
        )
        trial_results.append(result)
        failures.extend(f"{trial_id}: {message}" for message in result["failure_reasons"])

    n = len(assigned)

    def count(key: str) -> int:
        return sum(bool(trial.get(key)) for trial in trial_results)

    rate_keys = [
        "direct_probe_target_add",
        "local_target_7045",
        "target_filter_scope_verified",
        "target_wazuh_event_absent",
        "wazuh_query_healthy",
        "distractor_record_id_matches_local_7045",
        "final_unexplained_zero_match",
        "config_restored_and_healthy",
        "windows_and_probe_cleanup",
        "trial_pass",
    ]
    summary = {
        "assigned_trials": n,
        "analyzed_raw_trials": len(trial_results),
        **{key: metric(count(key), n) for key in rate_keys},
        "target_wazuh_event_count_total": sum(t["target_wazuh_event_count"] for t in trial_results),
        "distractor_wazuh_exact_event_count_total": sum(
            t["distractor_wazuh_exact_event_count"] for t in trial_results
        ),
        "final_endpoint_postflight_pass": postflight_valid,
        "wrong_consistent_count": sum(
            1
            for t in trial_results
            if t["target_wazuh_event_count"] == 0
            and t["target_reconciliation_status"] == "CONSISTENT"
        ),
        "latencies": {},
    }
    latency_keys = [
        "target_delta_persist_seconds_after_action",
        "target_probe_observation_seconds_after_action",
        "target_local_7045_seconds_after_action",
        "wazuh_distractor_timestamp_minus_local_7045_seconds",
        "final_reconciliation_seconds_after_action",
        "trial_duration_seconds",
    ]
    for key in latency_keys:
        values = [float(t[key]) for t in trial_results if t.get(key) is not None]
        summary["latencies"][key] = percentile_summary(values)
    summary["all_gates_passed"] = summary.pop("trial_pass")
    summary["false_consistent_under_target_event_filter"] = metric(
        summary["wrong_consistent_count"], n
    )

    raw_files = sorted(capture_dir.rglob("*"))
    manifest_items = [
        {"path": repository_path(path), "sha256": sha256(path), "size_bytes": path.stat().st_size}
        for path in raw_files
        if path.is_file()
    ]
    manifest_items.extend(
        {
            "path": repository_path(run_dir / filename),
            "sha256": sha256(run_dir / filename),
            "size_bytes": (run_dir / filename).stat().st_size,
        }
        for filename in [
            "source-freeze.json",
            "assignment.json",
            "PROTOCOL.md",
            "run_service_install_object_drop_replication_windows.ps1",
            "run_cohort_windows.ps1",
        ]
    )
    analyzer_path = Path("experiments/analyze_service_install_object_drop_cohort.py")
    manifest_items.append(
        {
            "path": repository_path(analyzer_path),
            "sha256": sha256(analyzer_path),
            "size_bytes": analyzer_path.stat().st_size,
        }
    )
    audit_status = (
        "PASS" if not failures and summary["all_gates_passed"]["successes"] == n else "FAIL"
    )
    return {
        "schema_version": "csg-service-install-object-drop-analysis-v1",
        "experiment_id": EXPERIMENT_ID,
        "analyzed_at_utc": datetime.now().astimezone().isoformat(),
        "audit_status": audit_status,
        "audit_failures": failures,
        "summary": summary,
        "final_postflight": postflight,
        "trials": trial_results,
        "artifact_manifest": manifest_items,
        "statistical_note": "Exact two-sided 95% Clopper-Pearson intervals are descriptive. The calculation assumes exchangeable Bernoulli trials; repetition on a single VM does not provide independent host replication.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=Path(
            "experiments/results/runs/20261016/service-install-object-drop-replication-v8"
        ),
    )
    args = parser.parse_args()
    self_test()
    print("ANALYSIS_SELF_TEST=PASS")
    result = analyze(args.run_dir)
    analysis_json_path = args.run_dir / "analysis.json"
    analysis_markdown_path = args.run_dir / "analysis.md"
    analysis_json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    analysis_markdown_path.write_text(write_markdown(result), encoding="utf-8")
    manifest_items = list(result["artifact_manifest"])
    for path in (analysis_json_path, analysis_markdown_path):
        manifest_items.append(
            {
                "path": repository_path(path),
                "sha256": sha256(path),
                "size_bytes": path.stat().st_size,
            }
        )
    manifest = {
        "schema_version": "csg-experiment-artifact-manifest-v1",
        "experiment_id": EXPERIMENT_ID,
        "path_base": "repository root",
        "manifest_excludes_itself": True,
        "artifacts": manifest_items,
    }
    (args.run_dir / "artifact-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"AUDIT_STATUS={result['audit_status']}")
    print(
        f"ASSIGNED={result['summary']['assigned_trials']}; RAW_ANALYZED={result['summary']['analyzed_raw_trials']}"
    )
    print(
        f"ALL_GATES={result['summary']['all_gates_passed']['successes']}/{result['summary']['all_gates_passed']['trials']} CI95={format_ci(result['summary']['all_gates_passed'])}"
    )
    print(
        f"FALSE_CONSISTENT={result['summary']['false_consistent_under_target_event_filter']['successes']}/{result['summary']['false_consistent_under_target_event_filter']['trials']} CI95={format_ci(result['summary']['false_consistent_under_target_event_filter'])}"
    )
    print(f"AUDIT_FAILURES={len(result['audit_failures'])}")
    return 0 if result["audit_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
