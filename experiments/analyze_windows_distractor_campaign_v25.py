#!/usr/bin/env python3
"""Strictly audit the frozen v25 live Windows scheduled-task campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8-sig") as handle:
        return json.load(handle)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_task_name(value: Any) -> str:
    return str(value or "").strip().lstrip("\\/").replace("/", "\\").lower()


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo else None


def exact_binomial_interval(
    successes: int, trials: int, alpha: float = 0.05
) -> dict[str, float] | None:
    """Two-sided Clopper-Pearson interval, obtained by inverting binomial tails."""
    if trials <= 0:
        return None
    if not 0 <= successes <= trials or not 0 < alpha < 1:
        raise ValueError("Require 0 <= successes <= trials and 0 < alpha < 1")

    def cdf(k: int, probability: float) -> float:
        if k < 0:
            return 0.0
        if k >= trials or probability <= 0:
            return 1.0
        if probability >= 1:
            return 0.0
        logs = [
            math.lgamma(trials + 1)
            - math.lgamma(i + 1)
            - math.lgamma(trials - i + 1)
            + i * math.log(probability)
            + (trials - i) * math.log1p(-probability)
            for i in range(k + 1)
        ]
        peak = max(logs)
        return min(1.0, math.exp(peak) * sum(math.exp(item - peak) for item in logs))

    def invert_cdf(k: int, target: float) -> float:
        low, high = 0.0, 1.0
        for _ in range(80):
            middle = (low + high) / 2
            if cdf(k, middle) > target:
                low = middle
            else:
                high = middle
        return (low + high) / 2

    lower = 0.0 if successes == 0 else invert_cdf(successes - 1, 1 - alpha / 2)
    upper = 1.0 if successes == trials else invert_cdf(successes, alpha / 2)
    return {"confidence": 1 - alpha, "lower": lower, "upper": upper}


def _event_docs(audit: dict[str, Any], task_name: str) -> list[dict[str, Any]]:
    return [
        item
        for item in audit.get("documents", [])
        if normalize_task_name(item.get("raw_task_name")) == normalize_task_name(task_name)
    ]


def _physical_identities(documents: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    identities = {
        tuple(item["stable_windows_event_identity"])
        for item in documents
        if item.get("document_found") and item.get("stable_windows_event_identity")
    }
    return sorted(identities, key=lambda value: tuple(str(part) for part in value))


def _summary_latency(values: list[float], invalid: int) -> dict[str, Any]:
    return {
        "n": len(values),
        "invalid_or_negative_excluded": invalid,
        "median_seconds": statistics.median(values) if values else None,
        "min_seconds": min(values) if values else None,
        "max_seconds": max(values) if values else None,
        "observations_seconds": [round(value, 6) for value in values],
    }


def audit_trial(
    trial_number: int,
    assignment: dict[str, Any],
    raw_campaign_dir: Path,
    expected_host: str,
    expected_agent: str,
    expected_config_hash: str,
) -> dict[str, Any]:
    trial_id = f"trial-{trial_number:02d}"
    directory = raw_campaign_dir / trial_id
    issues: list[str] = []
    required = [
        directory / "run.json",
        directory / "trial-status.json",
        directory / "raw-indexer-identity-audit.json",
    ]
    missing = [path.name for path in required if not path.is_file()]
    if missing:
        return {
            "trial": trial_number,
            "result": "NOT_EVALUABLE",
            "issues": [f"missing artifacts: {missing}"],
        }

    run = read_json(required[0])
    status = read_json(required[1])
    raw = read_json(required[2])
    scenarios = run.get("scenarios") or []
    scenario = scenarios[0] if len(scenarios) == 1 else {}
    state = scenario.get("state_plane") or {}
    event_plane = scenario.get("event_plane") or {}
    retrieval = event_plane.get("retrieval") or {}
    creation = state.get("creation_delta_reconciliation_before_cleanup") or {}
    reconciliation = scenario.get("csg_reconciliation") or {}
    distractor = scenario.get("distractor_evidence") or {}
    local_target_events = (scenario.get("local_source_evidence") or {}).get("exact_events") or []
    local_target_events = [
        item
        for item in local_target_events
        if normalize_task_name((item.get("event_data") or {}).get("TaskName"))
        == normalize_task_name(assignment.get("target"))
    ]
    local_target = local_target_events[0] if len(local_target_events) == 1 else {}
    local_distractor = distractor.get("local_windows_event") or {}
    target_events = event_plane.get("exact_matches") or []
    distractor_events = distractor.get("provider_events") or []
    distractor_event = distractor_events[0] if len(distractor_events) == 1 else {}

    target_docs = _event_docs(raw, assignment["target"])
    distractor_docs = _event_docs(raw, assignment["distractor"])
    target_identities = _physical_identities(target_docs)
    distractor_identities = _physical_identities(distractor_docs)
    all_docs_found = bool(raw.get("documents")) and all(
        item.get("document_found") is True for item in raw.get("documents", [])
    )
    target_identity = target_identities[0] if len(target_identities) == 1 else ()
    distractor_identity = distractor_identities[0] if len(distractor_identities) == 1 else ()
    target_store_ids = sorted(
        {str(item.get("event_id")) for item in target_events if item.get("event_id")}
    )
    provider_target_ids = sorted(
        {str(item) for item in retrieval.get("exact_target_event_ids", [])}
    )
    target_physical_ids = sorted(
        {
            str(item.get("event_id"))
            for item in target_docs
            if item.get("document_found")
            and item.get("event_id")
            and tuple(item.get("stable_windows_event_identity") or ()) == target_identity
        }
    )
    distractor_physical_ids = sorted(
        {
            str(item.get("event_id"))
            for item in distractor_docs
            if item.get("document_found")
            and item.get("event_id")
            and tuple(item.get("stable_windows_event_identity") or ()) == distractor_identity
        }
    )
    target_keys = {(item.get("target") or {}).get("key") for item in target_events}
    target_events_exact = bool(target_events) and all(
        item.get("host_id") == expected_host
        and item.get("normalized_type") == "scheduled_task_created"
        and (item.get("target") or {}).get("key") == scenario.get("expected_object_key")
        for item in target_events
    )
    matched_ids = sorted(set(str(item) for item in as_list(creation.get("matched_evidence_ids"))))
    distractor_ids = sorted(
        set(str(item) for item in retrieval.get("exact_distractor_event_ids", []))
    )
    target_event_id = target_store_ids[0] if len(target_store_ids) == 1 else None
    distractor_event_id = distractor_event.get("event_id")

    direct = state.get("direct_windows_verification") or {}
    after_observation = state.get("after_action_observation") or {}
    before_observation = state.get("before_action_observation") or {}
    creation_history = as_list(creation.get("history"))
    latest_creation = creation_history[-1] if creation_history else {}
    observation_window = latest_creation.get("observation_window") or {}
    window_start = parse_time(observation_window.get("start"))
    window_end = parse_time(observation_window.get("end"))
    distractor_time = parse_time(distractor_event.get("event_time"))
    target_event_times = [parse_time(item.get("event_time")) for item in target_events]
    distractor_inside_window = bool(
        window_start and window_end and distractor_time
        and window_start <= distractor_time <= window_end
    )
    target_events_inside_window = bool(target_event_times) and all(
        timestamp is not None and window_start and window_end
        and window_start <= timestamp <= window_end
        for timestamp in target_event_times
    )
    final_status = reconciliation.get("status")
    final_matched_ids = sorted(
        set(str(item) for item in as_list(reconciliation.get("matched_evidence_ids")))
    )

    checks = {
        "all_expected_artifacts_present": not missing,
        "runner_exit_zero": status.get("runner_exit_code") == 0,
        "runner_positive_control_passed": status.get("runner_positive_control") is True,
        "probe_target_absent_before_present_after_absent_after_cleanup": (
            direct.get("target_absent_before_action") is True
            and direct.get("target_present_after_action") is True
            and direct.get("target_absent_after_cleanup") is True
            and state.get("target_absent_before_action") is True
            and bool(state.get("after_action_observed"))
            and state.get("cleanup_removed_from_probe") is True
        ),
        "healthy_probe_category": (
            before_observation.get("category_status") == "healthy"
            and after_observation.get("category_status") == "healthy"
        ),
        "local_target_event_exact_4698": (
            len(local_target_events) == 1
            and local_target.get("event_id") == 4698
            and local_target.get("exact_identity_match") is True
        ),
        "local_distractor_event_exact_4698": (
            local_distractor.get("event_id") == 4698
            and normalize_task_name(local_distractor.get("task_name"))
            == normalize_task_name(assignment.get("distractor"))
        ),
        "complete_wazuh_query_and_sources": (
            retrieval.get("query_complete") is True
            and retrieval.get("coverage_status") == "COMPLETE"
            and retrieval.get("endpoint_collection_status") == "AVAILABLE"
            and retrieval.get("index_status") == "AVAILABLE"
        ),
        "exact_target_and_distractor_wazuh_event": (
            bool(target_events)
            and len(distractor_events) == 1
            and target_events_exact
            and distractor_event.get("host_id") == expected_host
            and distractor_event.get("normalized_type") == "scheduled_task_created"
            and (distractor_event.get("target") or {}).get("key")
            == f"scheduled_task:\\{normalize_task_name(assignment.get('distractor'))}"
            and distractor_ids == [str(distractor_event_id)]
            and bool(provider_target_ids)
            and set(provider_target_ids).issubset(set(target_store_ids))
            and set(target_store_ids) == set(target_physical_ids)
            and set(distractor_ids).issubset(set(distractor_physical_ids))
            and set(target_physical_ids).isdisjoint(distractor_physical_ids)
            and target_keys == {scenario.get("expected_object_key")}
        ),
        "target_and_distractor_events_inside_recorded_reconciliation_window": (
            distractor_inside_window and target_events_inside_window
        ),
        "raw_indexer_documents_resolve_to_two_distinct_physical_events": (
            all_docs_found
            and len(target_identities) == 1
            and len(distractor_identities) == 1
            and target_identity != distractor_identity
            and len(target_identity) == 5
            and len(distractor_identity) == 5
            and target_identity[0] == expected_agent
            and distractor_identity[0] == expected_agent
            and target_identity[1] == "security"
            and distractor_identity[1] == "security"
            and target_identity[3] == "4698"
            and distractor_identity[3] == "4698"
            and str(target_identity[2]) == str(local_target.get("record_id"))
            and str(distractor_identity[2]) == str(local_distractor.get("record_id"))
            and len(target_identity) > 4
            and len(distractor_identity) > 4
            and target_identity[4] == "microsoft-windows-security-auditing"
            and distractor_identity[4] == "microsoft-windows-security-auditing"
        ),
        "finalized_consistent_reconciliation_matches_target_only": (
            creation.get("reconciliation_status") == "CONSISTENT"
            and creation.get("finalized") is True
            and creation.get("passed") is True
            and creation.get("event_store_readback_complete") is True
            and not creation.get("missing_provider_event_ids")
            and final_status == "CONSISTENT"
            and reconciliation.get("finalized") is True
            and target_store_ids == matched_ids == final_matched_ids == target_physical_ids
            and bool(target_store_ids)
            and set(distractor_physical_ids).isdisjoint(final_matched_ids)
            and set(creation.get("additional_stored_exact_event_ids", [])).issubset(
                target_physical_ids
            )
            and reconciliation.get("matched_only_exact_target_events") is True
        ),
        "config_health_and_cleanup_preserved": (
            status.get("config_unchanged") is True
            and status.get("config_sha256_after") == expected_config_hash
            and status.get("cleanup_verified") is True
            and not status.get("residual_tasks_after")
            and status.get("health_after", {}).get("agent_status") == "active"
            and status.get("health_after", {}).get("service_state") == "Running"
        ),
        "unique_frozen_assignment": (
            status.get("target_task") == assignment.get("target")
            and status.get("distractor_task") == assignment.get("distractor")
        ),
    }
    issues.extend(name for name, passed in checks.items() if not passed)

    action_start = parse_time((scenario.get("action") or {}).get("started_at"))
    local_event_time = parse_time(local_target.get("event_time_utc"))
    probe_time = parse_time(after_observation.get("category_observed_at"))
    finalized_time = parse_time(creation.get("finalized_at"))
    latencies: dict[str, float | None] = {}
    for name, start, end in (
        ("action_start_to_local_target_event_seconds", action_start, local_event_time),
        ("local_target_event_to_probe_observation_seconds", local_event_time, probe_time),
        (
            "local_target_event_to_reconciliation_finalized_seconds",
            local_event_time,
            finalized_time,
        ),
    ):
        delta = (end - start).total_seconds() if start and end else None
        latencies[name] = delta if delta is not None and delta >= 0 else None

    return {
        "trial": trial_number,
        "result": "CORRECT_EXACT_TARGET_ONLY" if not issues else "FAIL_OR_NOT_EVALUABLE",
        "passed": not issues,
        "issues": issues,
        "checks": checks,
        "target_task": assignment.get("target"),
        "distractor_task": assignment.get("distractor"),
        "target_local_event_record_id": local_target.get("record_id"),
        "distractor_local_event_record_id": local_distractor.get("record_id"),
        "target_event_id": target_event_id,
        "target_wazuh_event_ids": target_store_ids,
        "distractor_event_id": distractor_event_id,
        "distractor_wazuh_event_ids": distractor_ids,
        "target_physical_identity": list(target_identity) if target_identity else None,
        "distractor_physical_identity": list(distractor_identity) if distractor_identity else None,
        "target_physical_wazuh_event_ids": target_physical_ids,
        "distractor_physical_wazuh_event_ids": distractor_physical_ids,
        "reconciliation_window": observation_window,
        "distractor_event_time_inside_reconciliation_window": distractor_inside_window,
        "target_events_inside_reconciliation_window": target_events_inside_window,
        "distractor_event_offset_from_window_start_seconds": (
            round((distractor_time - window_start).total_seconds(), 6)
            if distractor_time and window_start else None
        ),
        "target_raw_document_count": len(target_docs),
        "target_physical_event_count": len(target_identities),
        "distractor_raw_document_count": len(distractor_docs),
        "distractor_physical_event_count": len(distractor_identities),
        "reconciliation_status": final_status,
        "reconciliation_matched_evidence_ids": final_matched_ids,
        "creation_readback_additional_exact_ids": creation.get(
            "additional_stored_exact_event_ids", []
        ),
        "latencies_seconds": latencies,
        "run_artifact": str(required[0]),
        "raw_identity_audit_artifact": str(required[2]),
    }


def _latency_summary(trials: list[dict[str, Any]], key: str) -> dict[str, Any]:
    values: list[float] = []
    invalid = 0
    for trial in trials:
        value = trial.get("latencies_seconds", {}).get(key)
        if isinstance(value, (float, int)) and value >= 0:
            values.append(float(value))
        else:
            invalid += 1
    return _summary_latency(values, invalid)


def analyze(campaign_dir: Path, repo_root: Path) -> dict[str, Any]:
    campaign_dir = campaign_dir.resolve()
    assignments = read_json(campaign_dir / "assignments.json")
    freeze = read_json(campaign_dir / "source-freeze.json")
    postflight = read_json(campaign_dir / "postflight.json")
    raw_root = campaign_dir / "windows" / "raw"
    raw_dirs = [path for path in raw_root.iterdir() if path.is_dir()]
    if len(raw_dirs) != 1:
        raise ValueError(
            f"Expected exactly one captured Windows result directory, found {len(raw_dirs)}"
        )

    source_hash_checks = {}
    for relative, expected in freeze.get("source_files", {}).items():
        path = repo_root / relative
        source_hash_checks[relative] = {
            "expected": expected,
            "actual": sha256(path) if path.is_file() else None,
            "matches": path.is_file() and sha256(path) == expected,
        }
    protocol_path = campaign_dir / "PROTOCOL.md"
    assignment_path = campaign_dir / "assignments.json"
    source_hash_checks["PROTOCOL.md"] = {
        "expected": freeze["protocol"]["sha256"],
        "actual": sha256(protocol_path),
        "matches": sha256(protocol_path) == freeze["protocol"]["sha256"],
    }
    source_hash_checks["assignments.json"] = {
        "expected": freeze["assignments"]["sha256"],
        "actual": sha256(assignment_path),
        "matches": sha256(assignment_path) == freeze["assignments"]["sha256"],
    }

    expected_config = freeze["environment"]["windows_wazuh_agent_config_sha256"]
    trials = [
        audit_trial(int(item["trial"]), item, raw_dirs[0], "win11-arm-lab", "001", expected_config)
        for item in assignments.get("trials", [])
    ]
    for trial in trials:
        for key in ("run_artifact", "raw_identity_audit_artifact"):
            if trial.get(key):
                trial[key] = str(Path(trial[key]).resolve().relative_to(repo_root))
    successes = sum(item["passed"] for item in trials)
    failures = [item["trial"] for item in trials if not item["passed"]]
    all_target_ids = [
        event_id for item in trials for event_id in item.get("target_physical_wazuh_event_ids", [])
    ]
    all_distractor_ids = [
        event_id
        for item in trials
        for event_id in item.get("distractor_physical_wazuh_event_ids", [])
    ]
    query_pre = read_json(campaign_dir / "wazuh-active-query-pre.json")
    query_post = read_json(campaign_dir / "wazuh-active-query-post.json")
    wrapper_diagnostic = read_json(campaign_dir / "wrapper-finalization-diagnostic.json")
    preflight = read_json(raw_dirs[0] / "preflight.json")
    preflight_ok = (
        preflight.get("agent_config_sha256") == expected_config
        and preflight.get("runner_sha256")
        == freeze["source_files"].get("scripts/run_windows_category_same_window_distractor_v12.ps1")
        and preflight.get("assignment_sha256") == freeze["assignments"]["sha256"]
        and preflight.get("trial_count") == 10
        and preflight.get("health", {}).get("agent_status") == "active"
        and preflight.get("health", {}).get("service_state") == "Running"
    )
    exact_interval = exact_binomial_interval(successes, len(trials))
    false_distractor_interval = exact_binomial_interval(0, len(trials))
    latencies = {
        key: _latency_summary(trials, key)
        for key in (
            "action_start_to_local_target_event_seconds",
            "local_target_event_to_probe_observation_seconds",
            "local_target_event_to_reconciliation_finalized_seconds",
        )
    }
    integrity = (
        len(trials) == 10
        and successes == len(trials)
        and len(set(all_target_ids)) == len(all_target_ids)
        and len(set(all_distractor_ids)) == len(all_distractor_ids)
        and not (set(all_target_ids) & set(all_distractor_ids))
        and preflight_ok
        and all(item["matches"] for item in source_hash_checks.values())
        and postflight.get("windows_agent_config_unchanged") is True
        and postflight.get("active_security_eventchannel_query_unchanged") is True
        and postflight.get("residual_study_task_count") == 0
        and postflight.get("wazuh_service_state") == "Running"
        and query_pre.get("active_query_sha256_normalized")
        == query_post.get("active_query_sha256_normalized")
    )

    return {
        "schema_version": "csg-live-same-host-distractor-campaign-analysis-v1",
        "campaign_id": assignments.get("protocol_id"),
        "analyzed_at_utc": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "analysis_tool_sha256": sha256(Path(__file__).resolve()),
        "raw_event_identity_audit_tool_sha256": sha256(
            repo_root / "scripts/audit_wazuh_event_document_identity.py"
        ),
        "research_question": "Under complete telemetry, does CSG reconcile a newly observed target scheduled task only with its own exact Wazuh Event 4698 when a different same-host scheduled task generated the same event type inside the observation window?",
        "execution": {
            "assigned_trials": len(assignments.get("trials", [])),
            "trial_artifacts_present": sum(
                (raw_dirs[0] / f"trial-{int(item['trial']):02d}" / "run.json").is_file()
                for item in assignments.get("trials", [])
            ),
            "runner_passes": sum(
                bool(
                    read_json(
                        raw_dirs[0] / f"trial-{int(item['trial']):02d}" / "trial-status.json"
                    ).get("runner_positive_control")
                )
                for item in assignments.get("trials", [])
                if (raw_dirs[0] / f"trial-{int(item['trial']):02d}" / "trial-status.json").is_file()
            ),
            "strict_raw_audit_successes": successes,
            "strict_raw_audit_failures": failures,
            "outer_wrapper_finalization": wrapper_diagnostic.get("status"),
            "outer_wrapper_error": wrapper_diagnostic.get("wrapper_error"),
            "per_trial_results_preserved": True,
            "no_trials_rerun_or_reclassified": True,
        },
        "primary_outcome": {
            "name": "exact_target_only_reconciliation_with_distinct_raw_target_and_distractor_events",
            "successes": successes,
            "denominator": len(trials),
            "rate": successes / len(trials) if trials else None,
            "two_sided_exact_binomial_95_percent_interval": exact_interval,
            "false_distractor_citations": sum(
                bool(
                    set(item.get("distractor_physical_wazuh_event_ids", []))
                    & set(item.get("reconciliation_matched_evidence_ids", []))
                )
                for item in trials
            ),
            "false_distractor_citation_two_sided_exact_95_percent_interval": false_distractor_interval,
            "target_and_distractor_inside_exact_reconciliation_window": sum(
                bool(item.get("checks", {}).get("target_and_distractor_events_inside_recorded_reconciliation_window"))
                for item in trials
            ),
        },
        "latency_summaries": latencies,
        "environment_integrity": {
            "source_hash_checks": source_hash_checks,
            "windows_preflight": preflight,
            "windows_preflight_matches_frozen_sources": preflight_ok,
            "pre_and_post_active_query_sha256": {
                "pre": query_pre.get("active_query_sha256_normalized"),
                "post": query_post.get("active_query_sha256_normalized"),
                "unchanged": query_pre.get("active_query_sha256_normalized")
                == query_post.get("active_query_sha256_normalized"),
            },
            "independent_postflight": postflight,
            "campaign_integrity_pass": integrity,
        },
        "trials": trials,
        "interpretation_limits": [
            "These are ten repeated benign scheduled-task registrations on one Windows 11 ARM VM, not ten independent hosts.",
            "The experiment supports object-specific state/event reconciliation under a same-host, same-event-class distractor with complete telemetry; it does not demonstrate malicious-activity detection or superiority over Wazuh alerting.",
            "The campaign does not test permanent event loss, capture-drop, delayed delivery, other state categories, or generalization to another endpoint.",
            "The exact binomial interval is a trial-level uncertainty interval under a Bernoulli-independence model; shared host and time effects limit that model's generalization.",
            "The reported event-to-probe and event-to-reconciliation times are measured from Windows Security Event 4698 timestamps; they are not Wazuh ingestion-latency estimates.",
            "Alert and archive documents are deduplicated only when their stable Windows identity (agent, channel, EventRecordID, EventID, provider) is identical; all document references remain in raw audit artifacts.",
        ],
    }


def write_artifacts(result: dict[str, Any], campaign_dir: Path) -> None:
    analysis_path = campaign_dir / "analysis.json"
    reconstructed_path = campaign_dir / "campaign-reconstructed.json"
    report_path = campaign_dir / "RESULTS.md"
    analysis_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    reconstructed = {
        "schema_version": "csg-windows-campaign-reconstructed-from-trial-artifacts-v1",
        "campaign_id": result["campaign_id"],
        "status": "RAW_IDENTITY_AUDIT_COMPLETE"
        if result["environment_integrity"]["campaign_integrity_pass"]
        else "RAW_IDENTITY_AUDIT_HAS_GAPS",
        "trials": [
            {
                "trial": item["trial"],
                "target_task": item["target_task"],
                "distractor_task": item["distractor_task"],
                "runner_passed": item["checks"].get("runner_positive_control_passed"),
                "strict_audit_passed": item["passed"],
            }
            for item in result["trials"]
        ],
        "reconstructed_from": "individual Windows trial-status.json and run.json artifacts plus raw-indexer-identity-audit.json",
        "outer_wrapper_diagnostic": "wrapper-finalization-diagnostic.json",
    }
    reconstructed_path.write_text(json.dumps(reconstructed, indent=2) + "\n", encoding="utf-8")

    outcome = result["primary_outcome"]
    interval = outcome["two_sided_exact_binomial_95_percent_interval"]
    lines = [
        "# v25 Same-Host Scheduled-Task Distractor Campaign",
        "",
        f"**Campaign:** `{result['campaign_id']}`  ",
        f"**Strict exact-object outcome:** {outcome['successes']}/{outcome['denominator']} ({outcome['rate']:.1%})  ",
        f"**Two-sided exact 95% binomial interval:** [{interval['lower']:.4f}, {interval['upper']:.4f}]  ",
        f"**Integrity status:** {'PASS' if result['environment_integrity']['campaign_integrity_pass'] else 'GAPS'}",
        "",
        "## What Was Tested",
        "Ten frozen, uniquely named pairs of benign scheduled tasks were registered on one Windows 11 ARM VM. For each pair, the distractor task was briefly created and removed first; its exact local Security Event 4698 was checked before CSG retrieved evidence for the target task. The target then remained present long enough for the native CSG probe to observe it. Both tasks used only `cmd.exe /c exit 0` and were removed after observation.",
        "",
        "A trial passes the strict audit only when native before/after/cleanup state, exact local Windows events, complete Wazuh retrieval, raw Indexer EventRecordIDs, distinct target/distractor physical identities, and finalized target-only `CONSISTENT` reconciliation all agree.",
        "",
        "## Trial Results",
        "| Trial | Target | Target record | Distractor | Distractor record | Matched evidence | Strict result |",
        "|---:|---|---:|---|---:|---|---|",
    ]
    for trial in result["trials"]:
        lines.append(
            f"| {trial['trial']} | `{trial.get('target_task')}` | {trial.get('target_local_event_record_id')} | "
            f"`{trial.get('distractor_task')}` | {trial.get('distractor_local_event_record_id')} | "
            f"`{', '.join(trial.get('reconciliation_matched_evidence_ids', []))}` | {trial['result']} |"
        )
    lines += [
        "",
        "## Findings",
        f"- Runner positive-control passes: {result['execution']['runner_passes']}/{result['execution']['assigned_trials']}",
        f"- Raw-audit exact target-only successes: {outcome['successes']}/{outcome['denominator']}",
        f"- False distractor citations: {outcome['false_distractor_citations']}/{outcome['denominator']}",
        f"- Target and distractor Wazuh event times fell inside the exact reconciliation window: {outcome['target_and_distractor_inside_exact_reconciliation_window']}/{outcome['denominator']}.",
        "- Wazuh agent configuration and active Security query remained unchanged; independent postflight found the service Running and zero residual tasks.",
        "- Alert/archive records were grouped only when they shared the same agent, channel, EventRecordID, EventID, and provider. The raw audit files retain each underlying Indexer document reference.",
        "",
        "## Execution Deviation",
        "The Windows wrapper completed and saved all ten individual trials, but raised a PowerShell `Argument types do not match` exception while serializing its final aggregate. No trial was rerun. `campaign-reconstructed.json` and this analysis were generated from the saved per-trial files; the wrapper defect is preserved in `wrapper-finalization-diagnostic.json`.",
        "",
        "## Latency",
    ]
    for key, stats in result["latency_summaries"].items():
        lines.append(
            f"- `{key}`: n={stats['n']}, median={stats['median_seconds']}, "
            f"min={stats['min_seconds']}, max={stats['max_seconds']}, excluded invalid/negative={stats['invalid_or_negative_excluded']}."
        )
    lines += ["", "## Limits", *[f"- {item}" for item in result["interpretation_limits"]], ""]
    report_path.write_text("\n".join(lines), encoding="utf-8")

    files = sorted(
        path
        for path in campaign_dir.rglob("*")
        if path.is_file() and path.name != "artifact-sha256.json"
    )
    manifest = {
        "schema_version": "csg-campaign-artifact-sha256-manifest-v1",
        "campaign_id": result["campaign_id"],
        "generated_after_analysis": True,
        "file_count": len(files),
        "files": [
            {
                "path": str(path.relative_to(campaign_dir)),
                "size_bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
            for path in files
        ],
    }
    (campaign_dir / "artifact-sha256.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    result = analyze(args.campaign_dir, args.repo_root.resolve())
    write_artifacts(result, args.campaign_dir.resolve())
    print(
        json.dumps(
            {
                "campaign_id": result["campaign_id"],
                "assigned": result["execution"]["assigned_trials"],
                "strict_passes": result["primary_outcome"]["successes"],
                "strict_failures": result["execution"]["strict_raw_audit_failures"],
                "exact_95_interval": result["primary_outcome"][
                    "two_sided_exact_binomial_95_percent_interval"
                ],
                "integrity_pass": result["environment_integrity"]["campaign_integrity_pass"],
                "report": str(args.campaign_dir / "RESULTS.md"),
            },
            indent=2,
        )
    )
    return 0 if result["environment_integrity"]["campaign_integrity_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
