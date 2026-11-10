"""Independently audit randomized three-arm Windows service campaigns."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any

CONDITIONS = {
    "complete": "CONSISTENT",
    "target_event_drop": "UNEXPLAINED",
    "target_no_change_with_wrong_object_event": "NO_FINDING_EXPECTED",
}
RUNNER_EXPERIMENT_IDS = {
    "complete": "service-install-object-exact-match-control-v9",
    "target_event_drop": "service-install-object-drop-replication-v8",
}
SOURCE_HASH_FIELDS = {
    "assignment_sha256": "assignment.json",
    "generator_sha256": "generate_assignment.py",
    "protocol_sha256": "PROTOCOL.md",
    "controller_sha256": "run_cohort_windows.ps1",
    "complete_runner_sha256": "run_complete_control.ps1",
    "drop_runner_sha256": "run_target_event_drop.ps1",
    "no_change_runner_sha256": "run_no_change_control.ps1",
    "postflight_script_sha256": None,
}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def elapsed(start: Any, end: Any) -> float | None:
    first, last = parse_time(start), parse_time(end)
    return (last - first).total_seconds() if first and last else None


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


def rate(successes: int, trials: int) -> dict[str, Any]:
    return {
        "successes": successes,
        "trials": trials,
        "proportion": successes / trials if trials else None,
        "ci_95_clopper_pearson": clopper_pearson(successes, trials) if trials else None,
    }


def event_is_exact(event: dict[str, Any], host_id: str, service_name: str) -> bool:
    attributes = event.get("attributes") or {}
    return (
        event.get("host_id") == host_id
        and event.get("source") == "wazuh"
        and event.get("normalized_type") == "service_created"
        and (event.get("target") or {}).get("key") == f"service:{service_name.lower()}"
        and str(attributes.get("service_name", "")).casefold() == service_name.casefold()
        and str(attributes.get("event_code")) == "7045"
        and bool(event.get("event_id"))
    )


def event_record_id(event: dict[str, Any]) -> str | None:
    value = ((event.get("metadata") or {}).get("windows_event_identity") or {}).get(
        "event_record_id"
    )
    return str(value) if value is not None else None


def exact_delta(delta: Any, host_id: str, name: str, kind: str) -> bool:
    key = f"service:{name.lower()}"
    return (
        isinstance(delta, dict)
        and delta.get("host_id") == host_id
        and delta.get("object_key") == key
        and delta.get("delta_type") == kind
        and (delta.get("after") or delta.get("before") or {}).get("attributes", {}).get(
            "service_name"
        )
        == name
    )


def audit_trial(
    assigned: dict[str, Any],
    run: dict[str, Any],
    slot: dict[str, Any],
    host_id: str,
    baseline: str,
    cohort_experiment_id: str,
) -> dict[str, Any]:
    failures: list[str] = []

    def check(condition: bool, reason: str) -> bool:
        if not condition:
            failures.append(reason)
        return condition

    condition = assigned["condition"]
    target, distractor = assigned["target_service_name"], assigned["distractor_service_name"]
    target_key, distractor_key = f"service:{target.lower()}", f"service:{distractor.lower()}"
    target_state = (run.get("target") or {}).get("probe_observation") or {}
    target_add = target_state.get("add_delta")
    target_local = (run.get("target") or {}).get("local_7045") or {}
    distractor = assigned["distractor_service_name"]
    distractor_run = run.get("distractor") or {}
    distractor_local = distractor_run.get("local_7045") or {}
    provider = run.get("provider_query") or {}
    target_events = [
        event for event in as_list(provider.get("target_exact_service_created_events"))
        if isinstance(event, dict)
    ]
    distractor_events = [
        event for event in as_list(provider.get("distractor_exact_service_created_events"))
        if isinstance(event, dict)
    ]
    exact_target = [event for event in target_events if event_is_exact(event, host_id, target)]
    exact_distractor = [
        event for event in distractor_events if event_is_exact(event, host_id, distractor)
    ]
    target_record = str(target_local.get("event_record_id", ""))
    distractor_record = str(distractor_local.get("event_record_id", ""))
    target_record_linked = any(
        event_record_id(event) == target_record and target_record for event in exact_target
    )
    distractor_record_linked = any(
        event_record_id(event) == distractor_record and distractor_record
        for event in exact_distractor
    )
    findings = [item for item in as_list(run.get("target_findings")) if isinstance(item, dict)]
    finding = findings[0] if len(findings) == 1 else {}
    reconciliation = finding.get("reconciliation") or {}
    matched_ids = [str(item) for item in as_list(reconciliation.get("matched_evidence_ids"))]
    target_ids = {str(event["event_id"]) for event in exact_target}
    distractor_ids = {str(event["event_id"]) for event in exact_distractor}
    cleanup = run.get("cleanup") or {}
    restoration = run.get("restoration") or {}
    retrieval = ((provider.get("metadata") or {}).get("retrieval") or {})
    retrieval_sources = retrieval.get("sources") or {}
    query_ok = (
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

    expected_runner_id = RUNNER_EXPERIMENT_IDS.get(condition, cohort_experiment_id)
    check(run.get("experiment_id") == expected_runner_id, "raw runner experiment ID mismatch")
    check(run.get("trial_id") == assigned["trial_id"], "raw trial ID mismatch")
    check(run.get("host_id") == host_id, "raw host ID mismatch")
    check(run.get("service_name") == target, "raw target name differs from assignment")
    check(run.get("distractor_service_name") == distractor, "raw distractor name mismatch")
    check(run.get("error") is None, "runner retained an error")
    check(query_ok, "Wazuh query or alert/archive source completeness failed")
    check(len(exact_distractor) >= 1, "no exact same-host Wazuh distractor event")
    check(distractor_local.get("event_id") == 7045, "local distractor Event 7045 missing")
    check(
        str(distractor_local.get("service_name", "")).casefold() == distractor.casefold()
        and distractor_record,
        "local distractor object or EventRecordID mismatch",
    )
    check(distractor_record_linked, "distractor Wazuh evidence does not link to local EventRecordID")
    check(
        cleanup.get("target_windows_absent") is True
        and cleanup.get("target_probe_absent") is True
        and cleanup.get("distractor_windows_absent") is True
        and cleanup.get("distractor_probe_absent") is True
        and not cleanup.get("errors"),
        "service cleanup or exact probe removal gate failed",
    )
    check(
        exact_delta(cleanup.get("distractor_remove_delta"), host_id, distractor, "REMOVE"),
        "exact distractor REMOVE delta is missing",
    )
    check(
        slot.get("status") == "COMPLETED_GATES_PASSED"
        and slot.get("research_outcome_gate") is True
        and slot.get("config_integrity_gate") is True
        and slot.get("cleanup_gate") is True,
        "controller checkpoint reports a failed gate",
    )

    expected_status = CONDITIONS[condition]
    state_ok = False
    exact_target_linked = False
    target_absent = False
    cited_only_target = False
    if condition in ("complete", "target_event_drop"):
        state_ok = exact_delta(target_add, host_id, target, "ADD")
        check(state_ok, "direct probe did not capture exact target ADD")
        check(target_local.get("event_id") == 7045, "local target Event 7045 missing")
        check(
            str(target_local.get("service_name", "")).casefold() == target.casefold()
            and bool(target_record),
            "local target object or EventRecordID mismatch",
        )
        check(len(findings) == 1, "expected exactly one target finding")
        check(
            finding.get("host_id") == host_id
            and finding.get("object_key") == target_key
            and finding.get("delta_id") == (target_add or {}).get("delta_id"),
            "target finding is detached from assigned host/object/state delta",
        )
        check(reconciliation.get("finalized") is True, "target reconciliation is not finalized")
        check(reconciliation.get("status") == expected_status, "target reconciliation status mismatch")
        if condition == "complete":
            check(run.get("outcome") == "CAPTURED", "complete runner did not report CAPTURED")
            check(len(exact_target) >= 1, "complete arm lacks exact target Wazuh evidence")
            exact_target_linked = any(
                event_record_id(event) == target_record and target_record for event in exact_target
            )
            check(exact_target_linked, "target Wazuh event does not link to local EventRecordID")
            cited_only_target = bool(matched_ids) and set(matched_ids) <= target_ids and not (
                set(matched_ids) & distractor_ids
            )
            check(cited_only_target, "CONSISTENT finding did not cite target-only exact evidence")
            policy = run.get("collection_policy") or {}
            check(
                policy.get("mode") == "UNFILTERED_BASELINE"
                and policy.get("agent_config_sha256_before") == baseline
                and policy.get("no_eventchannel_query_added") is True
                and policy.get("no_registry_ignore_added") is True,
                "complete arm did not use frozen unfiltered Wazuh config",
            )
        else:
            suppression = run.get("suppression") or {}
            expected_query = (
                "Event[System/EventID != 7045 or EventData/Data[@Name='ServiceName'] != '"
                + target
                + "']"
            )
            expected_ignore = "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\" + target
            check(run.get("outcome") == "CAPTURED", "drop runner did not report CAPTURED")
            check(len(exact_target) == 0, "target event was present in event-drop arm")
            check(
                suppression.get("query") == expected_query
                and suppression.get("ignored_registry_path") == expected_ignore
                and suppression.get("xml_readback_passed") is True
                and suppression.get("original_config_sha256") == baseline
                and suppression.get("filtered_config_sha256") != baseline,
                "target-specific event suppression was not verified",
            )
            check(
                not matched_ids,
                "unexplained target finding contains matched evidence IDs",
            )
    else:
        target_absent = (
            run.get("preflight", {}).get("target_absent") is True
            and run.get("outcome") == "NO_TARGET_FINDING"
            and len(as_list(run.get("target_deltas"))) == 0
            and len(as_list(run.get("target_findings"))) == 0
            and len(target_events) == 0
        )
        check(target_absent, "no-change target was mutated, emitted evidence, or generated a finding")
        search = distractor_run.get("event_log_search") or {}
        check(
            search.get("status") == "FOUND" and int(search.get("attempt_count", 0)) >= 1,
            "no-change runner did not capture a bounded local Event 7045 search result",
        )
        distractor_add = distractor_run.get("probe_add_delta") or {}
        check(
            exact_delta(distractor_add, host_id, distractor, "ADD"),
            "no-change distractor was not observed by the direct probe",
        )
        check(
            restoration.get("exact_hash_match") is True
            and restoration.get("observed_hash") == baseline
            and restoration.get("configuration_changed") is False
            and restoration.get("wazuh_service_status") == "Running"
            and restoration.get("api_ok") is True
            and restoration.get("indexer_ok") is True,
            "no-change arm did not preserve baseline Wazuh configuration and health",
        )

    if condition == "complete":
        baseline_config = restoration.get("observed_hash") == baseline
    elif condition == "target_event_drop":
        healthy = restoration.get("healthy_after_restart") or {}
        baseline_config = (
            restoration.get("exact_hash_match") is True
            and restoration.get("original_hash") == baseline
            and restoration.get("restored_hash") == baseline
            and healthy.get("wazuh_service_status") == "Running"
            and healthy.get("api_ok") is True
            and healthy.get("indexer_ok") is True
        )
    else:
        baseline_config = restoration.get("observed_hash") == baseline
    check(baseline_config, "baseline Wazuh config hash or restoration health failed")
    if condition != "target_no_change_with_wrong_object_event":
        check(
            exact_delta(cleanup.get("target_remove_delta"), host_id, target, "REMOVE"),
            "exact target REMOVE delta is missing",
        )

    action_at = (
        ((run.get("target") or {}).get("action_started_at_utc"))
        if condition != "target_no_change_with_wrong_object_event"
        else distractor_run.get("action_started_at_utc")
    )
    final_time = reconciliation.get("finalized_at")
    timings = {
        "action_to_probe_add_persist_seconds": elapsed(action_at, (target_add or {}).get("created_at"))
        if condition != "target_no_change_with_wrong_object_event"
        else elapsed(action_at, (distractor_run.get("probe_add_delta") or {}).get("created_at")),
        "action_to_local_event_record_seconds": elapsed(
            action_at,
            target_local.get("event_time_utc") if condition != "target_no_change_with_wrong_object_event" else distractor_local.get("event_time_utc"),
        ),
        "action_to_final_reconciliation_seconds": elapsed(action_at, final_time)
        if condition != "target_no_change_with_wrong_object_event"
        else None,
        "provider_query_duration_seconds": retrieval.get("duration_seconds"),
        "trial_duration_seconds": run.get("duration_seconds"),
    }
    invalid_timings = [key for key, value in timings.items() if isinstance(value, (int, float)) and value < 0]
    for key in invalid_timings:
        failures.append(f"negative or reversed timestamp ordering for {key}; value excluded")

    return {
        "trial_id": assigned["trial_id"],
        "condition": condition,
        "target_service_name": target,
        "distractor_service_name": distractor,
        "trial_pass": not failures,
        "controller_status": slot.get("status"),
        "runner_outcome": run.get("outcome"),
        "target_state_add_observed": state_ok,
        "target_absent_no_change_control": target_absent,
        "target_exact_wazuh_event_count": len(exact_target),
        "distractor_exact_wazuh_event_count": len(exact_distractor),
        "target_local_event_record_id": target_record or None,
        "distractor_local_event_record_id": distractor_record or None,
        "target_event_record_id_linked": target_record_linked,
        "distractor_event_record_id_linked": distractor_record_linked,
        "target_evidence_ids": sorted(target_ids),
        "distractor_evidence_ids": sorted(distractor_ids),
        "finding_id": finding.get("finding_id"),
        "delta_id": (target_add or {}).get("delta_id") if target_add else None,
        "reconciliation_status": reconciliation.get("status") if reconciliation else expected_status,
        "reconciliation_finalized": reconciliation.get("finalized") if reconciliation else None,
        "matched_evidence_ids": matched_ids,
        "matched_only_target_evidence": cited_only_target,
        "baseline_configuration_restored": baseline_config,
        "cleanup_verified": slot.get("cleanup_gate") is True and not cleanup.get("errors"),
        "timing_object_role": "distractor" if condition == "target_no_change_with_wrong_object_event" else "target",
        "timing_object_name": distractor if condition == "target_no_change_with_wrong_object_event" else target,
        "timings": timings,
        "failure_reasons": failures,
    }


def summarize_timings(audits: list[dict[str, Any]]) -> dict[str, Any]:
    keys = (
        "action_to_probe_add_persist_seconds",
        "action_to_local_event_record_seconds",
        "action_to_final_reconciliation_seconds",
        "provider_query_duration_seconds",
        "trial_duration_seconds",
    )
    result: dict[str, Any] = {}
    for condition in CONDITIONS:
        items = [item for item in audits if item["condition"] == condition]
        result[condition] = {}
        for key in keys:
            values = [
                float(value)
                for item in items
                if isinstance((value := item["timings"].get(key)), (int, float)) and value >= 0
            ]
            result[condition][key] = {
                "n": len(values),
                "median_seconds": statistics.median(values) if values else None,
                "p95_nearest_rank_seconds": sorted(values)[math.ceil(0.95 * len(values)) - 1]
                if values
                else None,
                "minimum_seconds": min(values) if values else None,
                "maximum_seconds": max(values) if values else None,
                "values_seconds": values,
            }
    return result


def analyze(run_dir: Path) -> dict[str, Any]:
    freeze = read_json(run_dir / "source-freeze.json")
    assignment = read_json(run_dir / "assignment.json")
    capture = run_dir / "remote-capture" / run_dir.name
    cohort = read_json(capture / "cohort-execution.json")
    preflight = read_json(capture / "dry-run-preflight.json")
    postflight = read_json(capture / "postflight-final.json")
    failures: list[str] = []
    for field, filename in SOURCE_HASH_FIELDS.items():
        actual_file = filename or next(
            (path.name for path in run_dir.glob("postflight_v*.ps1")), ""
        )
        if not actual_file or sha256(run_dir / actual_file) != freeze.get(field):
            failures.append(f"frozen source hash mismatch: {actual_file or field}")
    baseline = freeze["baseline_wazuh_config_sha256"]
    assigned = assignment.get("trials") or []
    slots = {slot.get("trial_id"): slot for slot in cohort.get("completed_slots", [])}
    names = [
        trial[key]
        for trial in assigned
        for key in ("target_service_name", "distractor_service_name")
    ]
    if len(assigned) != 30 or assignment.get("assigned_trial_count") != 30:
        failures.append("frozen assignment is not 30 trials")
    if len(set(names)) != 60:
        failures.append("assignment does not contain 60 unique service names")
    for condition in CONDITIONS:
        if sum(item.get("condition") == condition for item in assigned) != 10:
            failures.append(f"assignment does not contain ten {condition} trials")
    if freeze.get("experiment_id") != assignment.get("experiment_id"):
        failures.append("source freeze and assignment experiment IDs differ")
    if cohort.get("experiment_id") != assignment.get("experiment_id"):
        failures.append("remote cohort experiment ID differs from assignment")
    if (
        cohort.get("execution_status") != "ALL_ASSIGNED_TRIALS_COMPLETED_WITH_GATES_PASSED"
        or len(slots) != 30
    ):
        failures.append("remote cohort did not complete all 30 assigned slots")
    if (
        preflight.get("frozen_hashes_match") is not True
        or preflight.get("dry_run") is not True
        or preflight.get("all_60_assigned_names_absent") is not True
        or preflight.get("baseline_wazuh_config_sha256") != baseline
        or preflight.get("controller_exact_event_identity_self_test") is not True
    ):
        failures.append("remote frozen-source dry-run preflight failed")
    if (
        postflight.get("postflight_pass") is not True
        or postflight.get("wazuh_config_sha256") != baseline
        or postflight.get("wazuh_service_status") != "Running"
        or postflight.get("api_ok") is not True
        or postflight.get("indexer_ok") is not True
        or postflight.get("probe_task_state") != "Running"
        or postflight.get("latest_service_category_status") != "healthy"
        or postflight.get("completed_slot_count") != 30
        or postflight.get("all_gated_slots_passed") != 30
        or as_list(postflight.get("assigned_experimental_services_remaining"))
    ):
        failures.append("final Windows endpoint postflight failed or incomplete")

    audits: list[dict[str, Any]] = []
    for trial in assigned:
        raw_path = capture / "trials" / trial["trial_id"] / "run.json"
        if not raw_path.is_file():
            failures.append(f"missing raw run: {trial['trial_id']}")
            continue
        audit = audit_trial(
            trial,
            read_json(raw_path),
            slots.get(trial["trial_id"], {}),
            assignment["host_id"],
            baseline,
            assignment["experiment_id"],
        )
        audits.append(audit)
        failures.extend(f"{trial['trial_id']}: {reason}" for reason in audit["failure_reasons"])

    evidence_owner: dict[str, tuple[str, str]] = {}
    duplicate_evidence: list[dict[str, str]] = []
    for item in audits:
        for field, name_field in (
            ("target_evidence_ids", "target_service_name"),
            ("distractor_evidence_ids", "distractor_service_name"),
        ):
            for evidence_id in item[field]:
                owner = (item["trial_id"], item[name_field])
                previous = evidence_owner.setdefault(evidence_id, owner)
                if previous != owner:
                    duplicate_evidence.append(
                        {"evidence_id": evidence_id, "first_owner": str(previous), "second_owner": str(owner)}
                    )
    if duplicate_evidence:
        failures.append("a Wazuh evidence ID was reused for different assigned service objects")

    counts = {
        condition: [item for item in audits if item["condition"] == condition]
        for condition in CONDITIONS
    }
    passed_by_arm = {
        condition: rate(sum(item["trial_pass"] for item in items), len(items))
        for condition, items in counts.items()
    }
    plane_visibility_by_arm = {
        condition: {
            "assigned_trials": len(items),
            "target_probe_add_observed": sum(item["target_state_add_observed"] for item in items),
            "target_absent_confirmed_in_no_change_trials": sum(
                item["target_absent_no_change_control"] for item in items
            ),
            "trials_with_exact_target_wazuh_event": sum(
                item["target_exact_wazuh_event_count"] > 0 for item in items
            ),
            "trials_with_exact_distractor_wazuh_event": sum(
                item["distractor_exact_wazuh_event_count"] > 0 for item in items
            ),
            "expected_csg_outcome": CONDITIONS[condition],
            "trials_with_expected_csg_outcome": sum(item["trial_pass"] for item in items),
        }
        for condition, items in counts.items()
    }
    metrics = {
        "all_predeclared_trial_gates": rate(sum(item["trial_pass"] for item in audits), len(assigned)),
        "complete_exact_consistency": rate(
            sum(item["trial_pass"] and item["reconciliation_status"] == "CONSISTENT" for item in counts["complete"]),
            len(counts["complete"]),
        ),
        "drop_retained_state_and_unexplained": rate(
            sum(item["trial_pass"] and item["target_state_add_observed"] and item["reconciliation_status"] == "UNEXPLAINED" for item in counts["target_event_drop"]),
            len(counts["target_event_drop"]),
        ),
        "no_change_no_target_finding_despite_distractor": rate(
            sum(item["trial_pass"] and item["target_absent_no_change_control"] for item in counts["target_no_change_with_wrong_object_event"]),
            len(counts["target_no_change_with_wrong_object_event"]),
        ),
        "same_host_distractor_exact_record_link": rate(
            sum(item["distractor_event_record_id_linked"] for item in audits), len(audits)
        ),
        "complete_target_event_record_link": rate(
            sum(item["target_event_record_id_linked"] for item in counts["complete"]),
            len(counts["complete"]),
        ),
        "complete_reconciliation_target_only_citation": rate(
            sum(item["matched_only_target_evidence"] for item in counts["complete"]),
            len(counts["complete"]),
        ),
    }
    result = {
        "schema_version": "csg-randomized-three-arm-analysis-v1",
        "experiment_id": assignment.get("experiment_id"),
        "assignment_seed": assignment.get("assignment_seed"),
        "campaign_label": assignment.get("experiment_id", "").rsplit("-", 1)[-1].upper(),
        "audit_status": "PASS" if not failures else "FAIL",
        "scope": "single Windows 11 ARM64 VM; benign inert service registrations; controlled target-event suppression",
        "independent_hosts": 1,
        "cross_platform_claim": False,
        "malicious_detection_claim": False,
        "assigned_trials": len(assigned),
        "analyzed_raw_trials": len(audits),
        "condition_counts": {condition: len(items) for condition, items in counts.items()},
        "arm_gate_rates": passed_by_arm,
        "evidence_plane_visibility_by_arm": plane_visibility_by_arm,
        "metrics": metrics,
        "timings": summarize_timings(audits),
        "unique_exact_wazuh_evidence_ids": len(evidence_owner),
        "duplicate_evidence_id_cross_object_conflicts": duplicate_evidence,
        "baseline_wazuh_config_sha256": baseline,
        "final_postflight": postflight,
        "preflight": preflight,
        "trial_results": audits,
        "audit_failures": failures,
        "interpretation_boundary": (
            "This controlled single-host study tests object-specific reconciliation and retained state visibility under deliberate target-event suppression. "
            "It does not establish attack detection accuracy, real-world false-positive rates, permanent or natural telemetry loss, Wazuh superiority, or generalization to other hosts."
        ),
    }
    return result


def percent(metric: dict[str, Any]) -> str:
    low, high = metric["ci_95_clopper_pearson"]
    return f"{metric['successes']}/{metric['trials']} ({metric['proportion']:.1%}; 95% exact CI {low:.1%}-{high:.1%})"


def report_text(result: dict[str, Any]) -> str:
    lines = [
        f"# {result['campaign_label']} Randomized Three-Arm Service Reconciliation Study",
        "",
        f"**Independent raw-artifact audit:** `{result['audit_status']}`. **Trials:** {result['analyzed_raw_trials']}/{result['assigned_trials']}. **Passed predeclared gates:** {percent(result['metrics']['all_predeclared_trial_gates'])}.",
        "",
        "## Study In Plain Terms",
        "",
        "Each trial used a fresh randomized service name on one Windows 11 ARM64 VM. The native CSG probe supplied persistent-state observations; Wazuh supplied the event plane. Every intervention also created a different same-host distractor service, so a service-created event of the right type but wrong object was available as a negative matching challenge. Services used an inert command path, stayed demand-start/stopped, and were removed after observation.",
        "",
        "## Design And Conditions",
        "",
        f"The 30 assignments were generated from seed `{result['assignment_seed']}`, frozen before mutation, and executed in their randomized order. There were ten trials per arm:",
        "",
        "| Arm | Intervention | Expected result |",
        "|---|---|---|",
        "| Complete telemetry | Create target and distractor; retain normal event collection | Exact target state/event match; `CONSISTENT`; do not cite distractor |",
        "| Target event drop | Create target and distractor; temporarily suppress only target service Event 7045/FIM collection | Target remains state-observable; no exact target Wazuh event; finalized `UNEXPLAINED`; distractor remains visible |",
        "| No-change + wrong-object event | Leave assigned target absent; create only the distinct distractor | No target delta/finding/event despite exact same-host distractor event |",
        "",
        "The drop arm is a controlled, target-specific collection filter. It is not a simulation of permanent/natural telemetry loss and is not a broad Wazuh outage experiment.",
        "",
        "## Results",
        "",
        "| Outcome | Result |",
        "|---|---|",
        f"| All assigned trial gates | {percent(result['metrics']['all_predeclared_trial_gates'])} |",
        f"| Complete arm exact `CONSISTENT` with target-only citations | {percent(result['metrics']['complete_exact_consistency'])} |",
        f"| Drop arm retained state + finalized `UNEXPLAINED` | {percent(result['metrics']['drop_retained_state_and_unexplained'])} |",
        f"| No-change arm produced no target finding with wrong-object event present | {percent(result['metrics']['no_change_no_target_finding_despite_distractor'])} |",
        f"| Exact distractor Wazuh event linked to its local Windows EventRecordID, all arms | {percent(result['metrics']['same_host_distractor_exact_record_link'])} |",
        f"| Complete-arm target Wazuh EventRecordID linked to local Windows Event 7045 | {percent(result['metrics']['complete_target_event_record_link'])} |",
        f"| Complete-arm reconciliation cited only target evidence | {percent(result['metrics']['complete_reconciliation_target_only_citation'])} |",
        "",
        "### Evidence-Plane Comparison By Assigned Arm",
        "",
        "This table keeps the randomized arms separate and reports the observations that answer the",
        "mechanism question. It is not a pooled accuracy score or a malicious-detection estimate.",
        "",
        "| Assigned arm | Probe target ADD | Exact target Wazuh event | Exact distractor event | CSG outcome met |",
        "|---|---:|---:|---:|---:|",
    ]
    for condition, label in (
        ("complete", "Complete telemetry"),
        ("target_event_drop", "Target event filtered"),
        ("target_no_change_with_wrong_object_event", "No target change; wrong-object event"),
    ):
        item = result["evidence_plane_visibility_by_arm"][condition]
        probe_value = (
            f"{item['target_probe_add_observed']}/{item['assigned_trials']}"
            if condition != "target_no_change_with_wrong_object_event"
            else f"target absent {item['target_absent_confirmed_in_no_change_trials']}/{item['assigned_trials']}"
        )
        lines.append(
            f"| {label} | {probe_value} | {item['trials_with_exact_target_wazuh_event']}/{item['assigned_trials']} | "
            f"{item['trials_with_exact_distractor_wazuh_event']}/{item['assigned_trials']} | "
            f"`{item['expected_csg_outcome']}` {item['trials_with_expected_csg_outcome']}/{item['assigned_trials']} |"
        )
    lines.extend(
        [
        "",
        "Intervals are two-sided 95% Clopper-Pearson exact binomial intervals. With n=10 per arm, even 10/10 has a lower bound near 69%; do not read 100% observed success as 100% underlying reliability.",
        "",
        "### Latency",
        "",
        "Latency uses recorded timestamps from the assigned action, direct-probe delta persistence, local Windows Event 7045, and finalized CSG reconciliation. It does not treat Wazuh event timestamps as ingestion/receipt times. In the no-change arm, the assigned target is deliberately absent; the action-to-probe and action-to-event measures refer to the distractor, not the target. No-change trials therefore have no target detection or reconciliation latency.",
        "",
        "| Condition | Measure | n | Median s | P95 s | Min-max s |",
        "|---|---|---:|---:|---:|---:|",
        ]
    )
    labels = {
        "action_to_probe_add_persist_seconds": "Action to probe ADD persistence",
        "action_to_local_event_record_seconds": "Action to local Windows 7045 time",
        "action_to_final_reconciliation_seconds": "Action to final CSG reconciliation",
        "provider_query_duration_seconds": "Wazuh index-query duration (not ingestion latency)",
        "trial_duration_seconds": "Runner trial duration",
    }
    for condition, measures in result["timings"].items():
        for key, label in labels.items():
            item = measures[key]
            if condition == "target_no_change_with_wrong_object_event" and key in (
                "action_to_probe_add_persist_seconds",
                "action_to_local_event_record_seconds",
            ):
                label = label.replace("Action", "Distractor action")
            if item["n"]:
                lines.append(
                    f"| `{condition}` | {label} | {item['n']} | {item['median_seconds']:.3f} | {item['p95_nearest_rank_seconds']:.3f} | {item['minimum_seconds']:.3f}-{item['maximum_seconds']:.3f} |"
                )
            else:
                lines.append(f"| `{condition}` | {label} | 0 | N/A | N/A | N/A |")
    lines.extend(
        [
            "",
            "## Trial-Level Audit",
            "",
            "The companion CSV has one row per assigned trial. The JSON retains all exact evidence IDs, local EventRecordIDs, timing values, and independent check failures. The raw Windows/Wazuh/CSG captures remain under `remote-capture/`.",
            "",
            "| Trial | Condition | Target state | Target Wazuh events | Distractor Wazuh events | Reconciliation | Target-only citation | Audit |",
            "|---|---|---:|---:|---:|---|---:|---|",
        ]
    )
    for item in result["trial_results"]:
        lines.append(
            f"| `{item['trial_id']}` | `{item['condition']}` | {'yes' if item['target_state_add_observed'] else ('absent' if item['target_absent_no_change_control'] else 'no')} | {item['target_exact_wazuh_event_count']} | {item['distractor_exact_wazuh_event_count']} | `{item['reconciliation_status']}` | {'yes' if item['matched_only_target_evidence'] else 'n/a'} | {'PASS' if item['trial_pass'] else 'FAIL'} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation And Limits",
            "",
            "The result supports a narrow mechanism claim: under this tested one-host setup, CSG's direct state plane retained the target service ADD when its corresponding Wazuh event was deliberately filtered, and deterministic reconciliation distinguished that target from a same-host wrong-object service event. Under complete collection, it linked the exact target event and did not cite the distractor. The no-change arm tests that the distractor alone did not create a target finding.",
            "",
            "It does not show that CSG detects malicious behavior more accurately than Wazuh. These are benign, scripted service registrations on one VM, not independently labeled attacks. The event-drop arm is an artificial target-specific filter; it does not test naturally missing or permanently lost telemetry. The sample is small, host-level replication is absent, and outcomes are not independent across machines. Treat this as stronger mechanism evidence, not conference-ready validation of broad security efficacy.",
            "",
            f"{result['campaign_label']} independently audited `{result['unique_exact_wazuh_evidence_ids']}` exact Wazuh evidence IDs. Cross-object evidence-ID conflicts: `{len(result['duplicate_evidence_id_cross_object_conflicts'])}`. Final endpoint postflight passed: `{result['final_postflight'].get('postflight_pass')}`; baseline configuration SHA-256 `{result['baseline_wazuh_config_sha256']}`.",
            "",
            "## Audit Failures",
            "",
        ]
    )
    if result["audit_failures"]:
        lines.extend(f"- {failure}" for failure in result["audit_failures"])
    else:
        lines.append("None.")
    lines.append("")
    return "\n".join(lines)


def write_outputs(run_dir: Path, result: dict[str, Any]) -> None:
    output = run_dir / "analysis"
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "analysis.json", result)
    (output / "analysis.md").write_text(report_text(result), encoding="utf-8")
    columns = [
            "trial_id", "condition", "target_service_name", "distractor_service_name", "timing_object_role",
            "timing_object_name", "trial_pass",
            "target_state_add_observed", "target_absent_no_change_control", "target_exact_wazuh_event_count",
            "distractor_exact_wazuh_event_count", "target_local_event_record_id", "distractor_local_event_record_id",
            "target_event_record_id_linked", "distractor_event_record_id_linked", "finding_id", "delta_id",
            "reconciliation_status", "reconciliation_finalized", "action_to_probe_add_persist_seconds",
            "action_to_local_event_record_seconds", "action_to_final_reconciliation_seconds",
            "provider_query_duration_seconds", "trial_duration_seconds", "matched_evidence_ids", "failure_reasons",
    ]
    with (output / "trial-results.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for item in result["trial_results"]:
            row = {key: item.get(key) for key in columns}
            row["matched_evidence_ids"] = ";".join(item["matched_evidence_ids"])
            row["failure_reasons"] = "; ".join(item["failure_reasons"])
            writer.writerow(row)
    catalog: list[dict[str, Any]] = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_file() and path.name != "artifact-manifest.json":
            catalog.append(
                {
                    "path": path.relative_to(run_dir).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": sha256(path),
                }
            )
    write_json(
        output / "artifact-manifest.json",
        {
            "schema_version": "csg-run-artifact-manifest-v1",
            "experiment_id": result["experiment_id"],
            "generated_at_utc": datetime.now().astimezone().isoformat(),
            "analysis_tool": {
                "path": "experiments/analyze_service_install_randomized_three_arm.py",
                "sha256": sha256(Path(__file__).resolve()),
            },
            "files": catalog,
            "manifest_self_hash_excluded": True,
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        assert len(clopper_pearson(10, 10)) == 2
        assert 0.69 < clopper_pearson(10, 10)[0] < 0.70
        assert rate(10, 10)["successes"] == 10
        assert event_is_exact(
            {
                "event_id": "wazuh-test",
                "host_id": "win11-arm-lab",
                "source": "wazuh",
                "normalized_type": "service_created",
                "target": {"key": "service:csgqual0000000001"},
                "attributes": {"service_name": "CSGQUAL0000000001", "event_code": 7045},
            },
            "win11-arm-lab",
            "CSGQUAL0000000001",
        )
        print("ANALYZER_SELF_TEST=PASS")
    result = analyze(args.run_dir)
    write_outputs(args.run_dir, result)
    print(
        f"AUDIT={result['audit_status']}; TRIALS={result['analyzed_raw_trials']}/{result['assigned_trials']}; "
        f"GATES={result['metrics']['all_predeclared_trial_gates']['successes']}/{result['metrics']['all_predeclared_trial_gates']['trials']}; "
        f"CONFLICTING_EVIDENCE_IDS={len(result['duplicate_evidence_id_cross_object_conflicts'])}"
    )
    if result["audit_failures"]:
        for failure in result["audit_failures"]:
            print(f"AUDIT_FAILURE={failure}")
    return 0 if result["audit_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
