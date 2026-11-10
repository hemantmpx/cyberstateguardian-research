# ruff: noqa: E501
"""Independently audit the V9 unfiltered exact-object reconciliation cohort."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any

EXPERIMENT_ID = "service-install-object-exact-match-control-v9"
CAPTURE_DIR = "remote-capture/service-install-object-exact-match-control-v9"


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def elapsed(start: Any, end: Any) -> float | None:
    first, last = parse_time(start), parse_time(end)
    return (last - first).total_seconds() if first and last else None


def clopper_pearson(successes: int, trials: int) -> list[float]:
    if trials <= 0 or not 0 <= successes <= trials:
        raise ValueError("Require 0 <= successes <= trials and trials > 0")

    def pmf(index: int, p: float) -> float:
        return math.comb(trials, index) * p**index * (1 - p) ** (trials - index)

    tail = 0.025
    if successes == 0:
        low = 0.0
    else:
        left, right = 0.0, 1.0
        for _ in range(80):
            middle = (left + right) / 2
            if sum(pmf(i, middle) for i in range(successes, trials + 1)) < tail:
                left = middle
            else:
                right = middle
        low = (left + right) / 2
    if successes == trials:
        high = 1.0
    else:
        left, right = 0.0, 1.0
        for _ in range(80):
            middle = (left + right) / 2
            if sum(pmf(i, middle) for i in range(successes + 1)) > tail:
                left = middle
            else:
                right = middle
        high = (left + right) / 2
    return [low, high]


def rate(successes: int, trials: int) -> dict[str, Any]:
    return {
        "successes": successes,
        "trials": trials,
        "proportion": successes / trials if trials else None,
        "ci_95_clopper_pearson": clopper_pearson(successes, trials) if trials else None,
    }


def distribution(values: list[float]) -> dict[str, Any]:
    return {
        "n": len(values),
        "median_seconds": statistics.median(values) if values else None,
        "minimum_seconds": min(values) if values else None,
        "maximum_seconds": max(values) if values else None,
        "values_seconds": values,
    }


def event_is_exact(event: dict[str, Any], host_id: str, service_name: str) -> bool:
    return (
        event.get("host_id") == host_id
        and event.get("source") == "wazuh"
        and event.get("normalized_type") == "service_created"
        and (event.get("target") or {}).get("key") == f"service:{service_name.lower()}"
        and (event.get("attributes") or {}).get("service_name", "").lower()
        == service_name.lower()
        and str((event.get("attributes") or {}).get("event_code")) == "7045"
        and bool(event.get("event_id"))
    )


def event_record_id(event: dict[str, Any]) -> str | None:
    value = ((event.get("metadata") or {}).get("windows_event_identity") or {}).get(
        "event_record_id"
    )
    return str(value) if value is not None else None


def audit_trial(
    assigned: dict[str, Any], run: dict[str, Any], slot: dict[str, Any], host_id: str, baseline: str
) -> dict[str, Any]:
    failures: list[str] = []

    def check(condition: bool, reason: str) -> bool:
        if not condition:
            failures.append(reason)
        return condition

    target = assigned["target_service_name"]
    distractor = assigned["distractor_service_name"]
    target_key, distractor_key = f"service:{target.lower()}", f"service:{distractor.lower()}"
    target_observation = (run.get("target") or {}).get("probe_observation") or {}
    target_delta = target_observation.get("add_delta") or {}
    target_local = (run.get("target") or {}).get("local_7045") or {}
    distractor_local = (run.get("distractor") or {}).get("local_7045") or {}
    provider = run.get("provider_query") or {}
    target_events = as_list(provider.get("target_exact_service_created_events"))
    distractor_events = as_list(provider.get("distractor_exact_service_created_events"))
    target_events = [event for event in target_events if isinstance(event, dict)]
    distractor_events = [event for event in distractor_events if isinstance(event, dict)]
    exact_target = [event for event in target_events if event_is_exact(event, host_id, target)]
    exact_distractor = [
        event for event in distractor_events if event_is_exact(event, host_id, distractor)
    ]
    target_record = str(target_local.get("event_record_id", ""))
    distractor_record = str(distractor_local.get("event_record_id", ""))
    target_record_matches = [
        event for event in exact_target if event_record_id(event) == target_record and target_record
    ]
    distractor_record_matches = [
        event
        for event in exact_distractor
        if event_record_id(event) == distractor_record and distractor_record
    ]

    findings = as_list(run.get("target_findings"))
    finding = findings[0] if len(findings) == 1 and isinstance(findings[0], dict) else {}
    reconciliation = finding.get("reconciliation") or {}
    matched = [str(value) for value in as_list(reconciliation.get("matched_evidence_ids"))]
    target_ids = {str(event["event_id"]) for event in exact_target}
    distractor_ids = {str(event["event_id"]) for event in exact_distractor}
    evidence_only_target = bool(matched) and set(matched) <= target_ids and not (
        set(matched) & distractor_ids
    )
    cleanup = run.get("cleanup") or {}
    target_remove = cleanup.get("target_remove_delta") or {}
    distractor_remove = cleanup.get("distractor_remove_delta") or {}
    restoration = run.get("restoration") or {}
    policy = run.get("collection_policy") or {}
    retrieval = ((provider.get("metadata") or {}).get("retrieval") or {})
    retrieval_sources = retrieval.get("sources") or {}
    query_healthy = (
        provider.get("query_complete") is True
        and provider.get("endpoint_collection_status") == "AVAILABLE"
        and provider.get("transport_status") == "AVAILABLE"
        and provider.get("index_status") == "AVAILABLE"
        and provider.get("coverage_status") == "COMPLETE"
        and all(
            (retrieval_sources.get(source) or {}).get("status") == "AVAILABLE"
            and (retrieval_sources.get(source) or {}).get("complete") is True
            for source in ("wazuh_alert", "wazuh_archive")
        )
    )
    state_ok = check(
        target_delta.get("host_id") == host_id
        and target_delta.get("object_key") == target_key
        and target_delta.get("delta_type") == "ADD"
        and (target_delta.get("after") or {}).get("attributes", {}).get("service_name")
        == target,
        "direct probe did not retain the exact target ADD delta",
    )
    check(
        target_local.get("event_id") == 7045
        and target_local.get("service_name", "").lower() == target.lower()
        and bool(target_record),
        "local Windows target Event 7045 or EventRecordID is missing/mismatched",
    )
    check(
        distractor_local.get("event_id") == 7045
        and distractor_local.get("service_name", "").lower() == distractor.lower()
        and bool(distractor_record),
        "local Windows distractor Event 7045 or EventRecordID is missing/mismatched",
    )
    check(query_healthy, "Wazuh query/endpoint/transport/index or source completeness failed")
    check(
        policy.get("mode") == "UNFILTERED_BASELINE"
        and policy.get("agent_config_sha256_before") == baseline
        and policy.get("no_eventchannel_query_added") is True
        and policy.get("no_registry_ignore_added") is True
        and restoration.get("observed_hash") == baseline,
        "trial did not use the unchanged unfiltered Wazuh baseline configuration",
    )
    check(len(exact_target) >= 1, "no exact target Wazuh service-created event")
    check(len(exact_distractor) >= 1, "no exact same-host distractor Wazuh event")
    check(bool(target_record_matches), "target Wazuh event did not match local EventRecordID")
    check(
        bool(distractor_record_matches),
        "distractor Wazuh event did not match local EventRecordID",
    )
    finding_ok = check(
        len(findings) == 1
        and finding.get("host_id") == host_id
        and finding.get("object_key") == target_key
        and finding.get("delta_id") == target_delta.get("delta_id"),
        "target finding missing, ambiguous, or detached from the exact target delta",
    )
    check(
        finding_ok
        and reconciliation.get("status") == "CONSISTENT"
        and reconciliation.get("finalized") is True
        and evidence_only_target,
        "target reconciliation was not final CONSISTENT with target-only matched evidence",
    )
    check(
        set(matched).isdisjoint(distractor_ids),
        "target reconciliation cited the same-host distractor evidence",
    )
    check(
        restoration.get("exact_hash_match") is True
        and restoration.get("baseline_hash") == baseline
        and restoration.get("observed_hash") == baseline
        and restoration.get("configuration_changed") is False
        and restoration.get("wazuh_service_status") == "Running"
        and restoration.get("api_ok") is True
        and restoration.get("indexer_ok") is True,
        "baseline Wazuh configuration/health integrity check failed",
    )

    def exact_remove(delta: dict[str, Any], name: str, key: str) -> bool:
        return (
            delta.get("host_id") == host_id
            and delta.get("object_key") == key
            and delta.get("delta_type") == "REMOVE"
            and (delta.get("before") or {}).get("attributes", {}).get("service_name") == name
        )

    cleanup_ok = check(
        cleanup.get("target_windows_absent") is True
        and cleanup.get("distractor_windows_absent") is True
        and cleanup.get("target_probe_absent") is True
        and cleanup.get("distractor_probe_absent") is True
        and exact_remove(target_remove, target, target_key)
        and exact_remove(distractor_remove, distractor, distractor_key),
        "Windows services or exact probe REMOVE evidence are incomplete",
    )
    slot_ok = check(
        slot.get("status") == "COMPLETED_GATES_PASSED"
        and slot.get("research_outcome_gate") is True
        and slot.get("restoration_gate") is True
        and slot.get("cleanup_gate") is True
        and slot.get("target_record_id_verified") is True
        and slot.get("distractor_record_id_verified") is True
        and slot.get("matched_only_target_evidence") is True,
        "controller checkpoint does not confirm every predeclared pass gate",
    )
    check(run.get("outcome") == "CAPTURED", "runner outcome is not CAPTURED")
    check(run.get("error") is None, "runner retained an error")
    check(run.get("experiment_id") == EXPERIMENT_ID, "run experiment ID mismatch")
    check(run.get("trial_id") == assigned.get("trial_id"), "run trial ID mismatch")
    check(run.get("service_name") == target, "run target name differs from assignment")
    check(
        run.get("distractor_service_name") == distractor,
        "run distractor name differs from assignment",
    )
    validation = run.get("runner_validation") or {}
    check(
        validation.get("api_list_unwrap_smoke_pass") is True
        and validation.get("singleton_delta_array_smoke_pass") is True
        and validation.get("exact_object_and_record_id_smoke_pass") is True,
        "runner's pre-mutation collection/identity self-tests failed",
    )

    action_at = (run.get("target") or {}).get("action_started_at_utc")
    matching_poll = next(
        (
            poll
            for poll in as_list(run.get("reconciliation_polls"))
            if poll.get("finalized") is True and poll.get("target_reconciliation_status") == "CONSISTENT"
        ),
        None,
    )
    timings = {
        "action_to_probe_add_persist_seconds": elapsed(action_at, target_delta.get("created_at")),
        "action_to_probe_observation_timestamp_seconds": elapsed(
            action_at, (target_delta.get("after") or {}).get("source_timestamp")
        ),
        "action_to_local_event_7045_seconds": elapsed(
            action_at, target_local.get("event_time_utc")
        ),
        "action_to_final_consistent_poll_seconds": elapsed(
            action_at, matching_poll.get("at_utc") if matching_poll else None
        ),
        "trial_duration_seconds": run.get("duration_seconds"),
        "wazuh_target_timestamp_minus_local_7045_seconds": elapsed(
            target_local.get("event_time_utc"),
            target_record_matches[0].get("event_time") if target_record_matches else None,
        ),
        "wazuh_distractor_timestamp_minus_local_7045_seconds": elapsed(
            distractor_local.get("event_time_utc"),
            distractor_record_matches[0].get("event_time") if distractor_record_matches else None,
        ),
    }
    for label, seconds in timings.items():
        if isinstance(seconds, (int, float)):
            check(seconds >= 0, f"invalid negative timing {label}={seconds}")

    return {
        "trial_id": assigned["trial_id"],
        "target_service_name": target,
        "distractor_service_name": distractor,
        "trial_pass": not failures,
        "controller_status": slot.get("status"),
        "runner_outcome": run.get("outcome"),
        "direct_probe_target_add": state_ok,
        "wazuh_query_healthy": query_healthy,
        "local_target_event_record_id": target_record,
        "local_distractor_event_record_id": distractor_record,
        "target_wazuh_event_count": len(exact_target),
        "distractor_wazuh_event_count": len(exact_distractor),
        "target_record_id_linked": bool(target_record_matches),
        "distractor_record_id_linked": bool(distractor_record_matches),
        "target_wazuh_evidence_ids": sorted(target_ids),
        "distractor_wazuh_evidence_ids": sorted(distractor_ids),
        "target_finding_id": finding.get("finding_id"),
        "target_delta_id": target_delta.get("delta_id"),
        "reconciliation_status": reconciliation.get("status"),
        "reconciliation_finalized": reconciliation.get("finalized"),
        "matched_evidence_ids": matched,
        "matched_evidence_only_from_target": evidence_only_target,
        "distractor_evidence_cited": bool(set(matched) & distractor_ids),
        "baseline_configuration_unchanged": restoration.get("observed_hash") == baseline,
        "cleanup_verified": cleanup_ok,
        "controller_gates_verified": slot_ok,
        "timings": timings,
        "failure_reasons": failures,
    }


def ci_text(metric: dict[str, Any]) -> str:
    low, high = metric["ci_95_clopper_pearson"]
    return f"[{low:.1%}, {high:.1%}]"


def write_report(result: dict[str, Any]) -> str:
    summary = result["summary"]
    all_gates = summary["metrics"]["all_gates_passed"]
    lines = [
        "# V9 Complete-Telemetry Exact-Match Positive-Control Results",
        "",
        f"**Audit:** `{result['audit_status']}`.  **Assigned:** {summary['assigned_trials']}.  **Analyzed:** {summary['analyzed_raw_trials']}.  **All gates:** {all_gates['successes']}/{all_gates['trials']} (95% exact CI {ci_text(all_gates)}).",
        "",
        "## Research Question And Scope",
        "",
        "This ten-trial positive-control cohort tests whether CSG reconciles a probed Windows service state addition to the exact corresponding Wazuh service-created event when a same-host, same-type service distractor event is also present. Both services are benign, demand-start, and never started. The Wazuh agent uses its unmodified baseline collection configuration.",
        "",
        "The primary identity chain is local Windows System Event 7045 `EventRecordID` -> Wazuh normalized event `metadata.windows_event_identity.event_record_id` -> Wazuh evidence ID -> finalized CSG reconciliation `matched_evidence_ids`. This is a within-host mechanism/positive-control result, not evidence of malicious-activity detection, natural telemetry loss, attack-detection improvement, cross-host generalization, or conference readiness.",
        "",
        "V9 is sequential and separate from the V8 deliberate target-event-filter/drop cohort. They were not randomized or interleaved, so their rates must not be presented as a causal treatment comparison. Repetition on one VM does not supply independent host replication.",
        "",
        "## Aggregate Results",
        "",
        "| Measure | Pass / assigned | Rate | Exact 95% CI |",
        "|---|---:|---:|---:|",
    ]
    labels = [
        ("native_state_add", "Native probe captured exact target ADD"),
        ("healthy_complete_query", "Wazuh alert/archive query complete and healthy"),
        ("target_event_present", "Exact target Wazuh service event present"),
        ("distractor_event_present", "Exact same-host distractor event present"),
        ("target_record_id_match", "Target Wazuh event linked to local EventRecordID"),
        ("distractor_record_id_match", "Distractor Wazuh event linked to local EventRecordID"),
        ("final_consistent_target_only", "Final CONSISTENT, target evidence cited only"),
        ("no_distractor_citation", "No distractor evidence cited by target finding"),
        ("config_and_health_integrity", "Baseline Wazuh config unchanged and healthy"),
        ("cleanup", "Windows cleanup and probe REMOVE records verified"),
        ("all_gates_passed", "All preassigned per-trial gates passed"),
    ]
    for key, label in labels:
        value = summary["metrics"][key]
        lines.append(
            f"| {label} | {value['successes']}/{value['trials']} | {value['proportion']:.1%} | {ci_text(value)} |"
        )
    lines.extend(
        [
            "",
            "The exact intervals are binomial descriptive intervals; with ten repetitions on one host, they do not capture host-level or shared-environment uncertainty.",
            "",
            "## Trial-Level Evidence",
            "",
        ]
    )
    for trial in result["trials"]:
        lines.extend(
            [
                f"### {trial['trial_id']}: {'PASS' if trial['trial_pass'] else 'FAIL'}",
                "",
                f"- Target `{trial['target_service_name']}` / distractor `{trial['distractor_service_name']}`.",
                f"- Local Windows EventRecordIDs: target `{trial['local_target_event_record_id']}`, distractor `{trial['local_distractor_event_record_id']}`.",
                f"- Wazuh target evidence: {', '.join(f'`{value}`' for value in trial['target_wazuh_evidence_ids']) or 'none'}; distractor evidence: {', '.join(f'`{value}`' for value in trial['distractor_wazuh_evidence_ids']) or 'none'}.",
                f"- Target reconciliation: `{trial['reconciliation_status']}` finalized={trial['reconciliation_finalized']}; matched IDs: {', '.join(f'`{value}`' for value in trial['matched_evidence_ids']) or 'none'}; distractor cited={trial['distractor_evidence_cited']}.",
                f"- Probe delta `{trial['target_delta_id']}`, finding `{trial['target_finding_id']}`; cleanup verified={trial['cleanup_verified']}.",
                f"- Timing (seconds): action-to-probe-persist `{trial['timings']['action_to_probe_add_persist_seconds']}`, action-to-local-7045 `{trial['timings']['action_to_local_event_7045_seconds']}`, action-to-final-consistent-poll `{trial['timings']['action_to_final_consistent_poll_seconds']}`, full trial `{trial['timings']['trial_duration_seconds']}`.",
            ]
        )
        if trial["failure_reasons"]:
            lines.append(f"- Audit exceptions: {'; '.join(trial['failure_reasons'])}.")
        lines.append("")
    lines.extend(
        [
            "## Timing Summary",
            "",
            "| Timing measure | n | Median seconds | Min | Max |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for key, label in summary["timings"].items():
        value = label
        med = "n/a" if value["median_seconds"] is None else f"{value['median_seconds']:.3f}"
        minimum = "n/a" if value["minimum_seconds"] is None else f"{value['minimum_seconds']:.3f}"
        maximum = "n/a" if value["maximum_seconds"] is None else f"{value['maximum_seconds']:.3f}"
        lines.append(f"| {key.replace('_', ' ')} | {value['n']} | {med} | {minimum} | {maximum} |")
    lines.extend(
        [
            "",
            "Wazuh normalized event timestamp minus the local Event 7045 timestamp is a timestamp difference, not index-ingestion latency. No causal claim is made from the sequential V8/V9 ordering.",
            "",
            "## Reproducibility And Postflight",
            "",
            f"- Final endpoint postflight: `{result['postflight']['postflight_pass']}` at `{result['postflight']['checked_at_utc']}`.",
            f"- Baseline Wazuh config SHA-256: `{result['postflight']['wazuh_config_sha256']}`; expected `{result['freeze']['baseline_wazuh_config_sha256']}`.",
            f"- Wazuh service `{result['postflight']['wazuh_service_status']}` (PID {result['postflight']['wazuh_service_pid']}); API/indexer `{result['postflight']['api_ok']}`/`{result['postflight']['indexer_ok']}`; active endpoint agent count {result['postflight']['active_agent_count']}; probe task `{result['postflight']['probe_task_state']}`; latest service collection `{result['postflight']['latest_service_category_status']}`.",
            f"- Remaining assigned test services: {len(result['postflight']['assigned_experimental_services_remaining'])}.",
            "- Frozen protocol, assignment, runner, and controller SHA-256 values are verified by the independent analyzer. Every raw `run.json`, cohort checkpoint, dry-run preflight, and final postflight is retained in the run folder and hashed in `artifact-manifest.json`.",
            "",
            "## Limitations And Next Evidence Needed",
            "",
            "This control demonstrates that the tested CSG version can associate the exact Windows service transition with the matching Wazuh event under a healthy complete-telemetry query, despite a same-host wrong-object event. It does not show that reconciliation improves attack detection: the mutations are benign service registrations, there are no labeled attacks, and Wazuh itself already reports the service-created event. V8's target-filter challenge is a separate cohort and must not be pooled as if randomized against V9. The next stronger design is a prospectively randomized/interleaved complete-vs-target-drop-vs-wrong-object/no-change set, followed by repeated independent Windows hosts and adjudicated security behaviors.",
            "",
        ]
    )
    return "\n".join(lines)


def analyze(run_dir: Path) -> dict[str, Any]:
    freeze = read_json(run_dir / "source-freeze.json")
    assignment = read_json(run_dir / "assignment.json")
    capture = run_dir / CAPTURE_DIR
    cohort = read_json(capture / "cohort-execution.json")
    preflight = read_json(capture / "dry-run-preflight.json")
    postflight = read_json(capture / "postflight-final.json")
    failures: list[str] = []

    for field, filename in (
        ("protocol_sha256", "PROTOCOL.md"),
        ("assignment_sha256", "assignment.json"),
        ("runner_sha256", freeze["runner_path"]),
        ("controller_sha256", freeze["controller_path"]),
    ):
        if sha256(run_dir / filename) != freeze.get(field):
            failures.append(f"frozen source hash mismatch: {filename}")
    if assignment.get("experiment_id") != EXPERIMENT_ID or freeze.get("experiment_id") != EXPERIMENT_ID:
        failures.append("experiment ID mismatch in assignment or source freeze")
    if cohort.get("experiment_id") != EXPERIMENT_ID:
        failures.append("remote cohort experiment ID mismatch")
    trials = assignment.get("trials") or []
    slots = {slot.get("trial_id"): slot for slot in cohort.get("completed_slots", [])}
    if len(trials) != 10 or assignment.get("assigned_trial_count") != 10:
        failures.append("frozen denominator is not ten")
    if (
        cohort.get("execution_status")
        != "ALL_ASSIGNED_TRIALS_COMPLETED_WITH_RESTORE_AND_CLEANUP_GATES"
        or len(slots) != 10
    ):
        failures.append("cohort did not complete all ten assigned unique slots")
    if (
        preflight.get("frozen_hashes_match") is not True
        or preflight.get("all_assigned_names_absent") is not True
        or preflight.get("baseline_wazuh_config_sha256")
        != freeze.get("baseline_wazuh_config_sha256")
        or preflight.get("dry_run") is not True
        or preflight.get("assigned_trials") != 10
    ):
        failures.append("remote no-mutation dry-run preflight failed or is incomplete")
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
        and postflight.get("completed_slot_count") == 10
        and postflight.get("all_gated_slots_passed") == 10
    )
    if not postflight_valid:
        failures.append("final endpoint postflight is failed or incomplete")

    audited: list[dict[str, Any]] = []
    for assigned in trials:
        path = capture / "trials" / assigned["trial_id"] / "run.json"
        if not path.is_file():
            failures.append(f"missing raw run: {assigned['trial_id']}")
            continue
        item = audit_trial(
            assigned,
            read_json(path),
            slots.get(assigned["trial_id"], {}),
            assignment["host_id"],
            freeze["baseline_wazuh_config_sha256"],
        )
        audited.append(item)
        failures.extend(f"{assigned['trial_id']}: {message}" for message in item["failure_reasons"])

    n = len(trials)

    def successes(key: str) -> int:
        return sum(bool(item.get(key)) for item in audited)

    metrics = {
        "native_state_add": rate(successes("direct_probe_target_add"), n),
        "healthy_complete_query": rate(successes("wazuh_query_healthy"), n),
        "target_event_present": rate(
            sum(item["target_wazuh_event_count"] > 0 for item in audited), n
        ),
        "distractor_event_present": rate(
            sum(item["distractor_wazuh_event_count"] > 0 for item in audited), n
        ),
        "target_record_id_match": rate(successes("target_record_id_linked"), n),
        "distractor_record_id_match": rate(successes("distractor_record_id_linked"), n),
        "final_consistent_target_only": rate(
            sum(
                item["reconciliation_status"] == "CONSISTENT"
                and item["reconciliation_finalized"] is True
                and item["matched_evidence_only_from_target"]
                for item in audited
            ),
            n,
        ),
        "no_distractor_citation": rate(
            sum(not item["distractor_evidence_cited"] for item in audited), n
        ),
        "config_and_health_integrity": rate(
            sum(item["baseline_configuration_unchanged"] for item in audited), n
        ),
        "cleanup": rate(successes("cleanup_verified"), n),
        "all_gates_passed": rate(successes("trial_pass"), n),
    }
    timing_keys = sorted({key for item in audited for key in item["timings"]})
    timings: dict[str, Any] = {}
    for key in timing_keys:
        values = [
            float(item["timings"][key])
            for item in audited
            if isinstance(item["timings"].get(key), (float, int))
        ]
        timings[key] = distribution(values)
    status = "PASS" if not failures and metrics["all_gates_passed"]["successes"] == n else "FAIL"
    return {
        "schema_version": "csg-service-install-exact-match-analysis-v1",
        "experiment_id": EXPERIMENT_ID,
        "analyzed_at_utc": datetime.now().astimezone().isoformat(),
        "audit_status": status,
        "audit_failures": failures,
        "freeze": freeze,
        "summary": {
            "assigned_trials": n,
            "analyzed_raw_trials": len(audited),
            "metrics": metrics,
            "target_wazuh_events_total": sum(item["target_wazuh_event_count"] for item in audited),
            "distractor_wazuh_events_total": sum(item["distractor_wazuh_event_count"] for item in audited),
            "target_reconciliation_false_distractor_citation_count": sum(
                item["distractor_evidence_cited"] for item in audited
            ),
            "final_endpoint_postflight_pass": postflight_valid,
            "timings": timings,
        },
        "preflight": preflight,
        "postflight": postflight,
        "trials": audited,
        "statistical_note": "Two-sided 95% Clopper-Pearson intervals are descriptive and assume exchangeable Bernoulli trials. All trials used one Windows 11 ARM64 VM; these intervals do not capture independent-host variability.",
    }


def test() -> None:
    assert abs(clopper_pearson(10, 10)[0] - 0.6915028922) < 1e-8
    assert abs(clopper_pearson(0, 10)[1] - 0.3084971078) < 1e-8
    assert as_list(None) == [] and as_list({"x": 1}) == [{"x": 1}]
    assert elapsed("2026-10-16T00:00:00Z", "2026-10-16T00:00:01Z") == 1
    exact = {
        "event_id": "wazuh-one",
        "host_id": "host",
        "source": "wazuh",
        "normalized_type": "service_created",
        "target": {"key": "service:alpha"},
        "attributes": {"service_name": "Alpha", "event_code": "7045"},
    }
    assert event_is_exact(exact, "host", "Alpha")
    assert not event_is_exact(exact, "host", "Beta")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=Path(
            "experiments/results/runs/20261016/service-install-object-exact-match-control-v9"
        ),
    )
    args = parser.parse_args()
    test()
    print("ANALYZER_SELF_TEST=PASS")
    result = analyze(args.run_dir)
    json_path = args.run_dir / "analysis.json"
    markdown_path = args.run_dir / "analysis.md"
    json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(write_report(result), encoding="utf-8")
    files = sorted(path for path in args.run_dir.rglob("*") if path.is_file())
    manifest = {
        "schema_version": "csg-experiment-artifact-manifest-v1",
        "experiment_id": EXPERIMENT_ID,
        "path_base": "repository root",
        "manifest_excludes_itself": True,
        "artifacts": [
            {
                "path": path.resolve().relative_to(Path.cwd().resolve()).as_posix(),
                "sha256": sha256(path),
                "size_bytes": path.stat().st_size,
            }
            for path in files
            if path.name != "artifact-manifest.json"
        ],
    }
    (args.run_dir / "artifact-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"AUDIT_STATUS={result['audit_status']}")
    print(
        "ALL_GATES="
        f"{result['summary']['metrics']['all_gates_passed']['successes']}/"
        f"{result['summary']['metrics']['all_gates_passed']['trials']}"
    )
    print(f"FALSE_DISTRACTOR_CITATIONS={result['summary']['target_reconciliation_false_distractor_citation_count']}/{len(result['trials'])}")
    print(f"AUDIT_FAILURES={len(result['audit_failures'])}")
    return 0 if result["audit_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
