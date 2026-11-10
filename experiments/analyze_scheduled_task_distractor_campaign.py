#!/usr/bin/env python3
"""Audit one frozen Windows same-host scheduled-task distractor campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import datetime, timezone
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


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> dict[str, float] | None:
    if trials == 0:
        return None
    proportion = successes / trials
    denominator = 1 + z * z / trials
    center = (proportion + z * z / (2 * trials)) / denominator
    half_width = z * math.sqrt(
        proportion * (1 - proportion) / trials + z * z / (4 * trials * trials)
    ) / denominator
    return {
        "lower_95": max(0.0, center - half_width),
        "upper_95": min(1.0, center + half_width),
    }


def parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_task_name(value: Any) -> str:
    return str(value or "").strip().lstrip("\\").replace("/", "\\").lower()


def exact_task_event(scenario: dict[str, Any]) -> dict[str, Any] | None:
    events = (scenario.get("event_plane") or {}).get("exact_matches") or []
    return events[0] if len(events) == 1 and isinstance(events[0], dict) else None


def audit_trial(
    run_dir: Path,
    trial_number: int,
    campaign_id: str,
    manifest_entry: dict[str, Any],
) -> dict[str, Any]:
    trial_id = f"trial-{trial_number:02d}"
    trial_path = run_dir / trial_id / "trial.json"
    issues: list[str] = []
    if not trial_path.is_file():
        return {
            "trial_id": trial_id,
            "evaluable": False,
            "result": "INVALID_NOT_EVALUABLE",
            "issues": ["trial.json is missing"],
        }

    trial = read_json(trial_path)
    runner = trial.get("target_runner") or {}
    scenarios = runner.get("scenarios") or []
    scenario = next((item for item in scenarios if item.get("kind") == "scheduled_task"), {})
    target_event = exact_task_event(scenario)
    distractor = trial.get("distractor") or {}
    distractor_event = distractor.get("exact_wazuh_event") or {}
    target_reconciliation = trial.get("target_reconciliation") or {}
    final_reconciliation = target_reconciliation.get("post_ingest_reconciliation") or {}
    ordering = target_reconciliation.get("distractor_availability_ordering") or {}
    checks = trial.get("condition_checks") or {}
    direct_state = (scenario.get("state_plane") or {}).get("direct_windows_verification") or {}
    event_plane = scenario.get("event_plane") or {}
    local_events = (scenario.get("local_source_evidence") or {}).get("exact_events") or []
    local_target = local_events[0] if len(local_events) == 1 else {}
    local_task_name = (local_target.get("event_data") or {}).get("TaskName")
    target_ids = sorted(set(target_reconciliation.get("exact_target_event_ids") or []))
    matched_ids = sorted(set(target_reconciliation.get("matched_evidence_ids") or []))
    probe_invocations = trial.get("probe_invocations") or []

    if trial.get("campaign_id") != f"{campaign_id}-{trial_id}":
        issues.append("trial campaign id differs from manifest")
    if trial.get("trial_id") != trial_id:
        issues.append("trial id differs from its folder/manifest slot")
    if trial.get("status") != "PASS" or manifest_entry.get("status") != "PASS":
        issues.append("controller or campaign manifest did not record PASS")
    if not scenario.get("positive_control", {}).get("passed"):
        issues.append("positive target control did not pass")
    if not (direct_state.get("target_absent_before_action") and direct_state.get("target_present_after_action") and direct_state.get("target_absent_after_cleanup")):
        issues.append("direct Windows before/present/cleanup state proof is incomplete")
    if not event_plane.get("query_completed") or not event_plane.get("query_complete"):
        issues.append("target event query is not recorded complete")
    if not target_event or not local_target:
        issues.append("expected exactly one target Wazuh event and one exact local Security event")
    if local_target and (
        local_target.get("event_id") != 4698
        or not local_target.get("exact_identity_match")
        or normalize_task_name(local_task_name) != normalize_task_name(trial.get("target_task_name"))
    ):
        issues.append("local Security event is not exact Event 4698 for the target")
    if len(target_ids) != 1 or not target_event or target_ids != [target_event.get("event_id")]:
        issues.append("target event identity list is not exactly the one target Wazuh event")
    if not distractor_event.get("event_id"):
        issues.append("exact Wazuh distractor event is absent")
    if target_event and distractor_event:
        target_obj = target_event.get("target") or {}
        distractor_obj = distractor_event.get("target") or {}
        same_host_and_type = (
            target_event.get("host_id") == distractor_event.get("host_id")
            and target_event.get("host_id") == trial.get("host_id")
            and target_event.get("normalized_type") == distractor_event.get("normalized_type")
            and target_event.get("normalized_type") == "scheduled_task_created"
        )
        distinct_object = target_obj.get("key") != distractor_obj.get("key")
        if not same_host_and_type:
            issues.append("target/distractor host or normalized event class differs")
        if not distinct_object:
            issues.append("target and distractor do not have distinct normalized object keys")
        if target_obj.get("key") != scenario.get("expected_object_key"):
            issues.append("target Wazuh object key does not equal expected target key")
    else:
        same_host_and_type = False
        distinct_object = False

    gate = event_plane.get("pre_target_evaluation_gate") or {}
    gate_time = parse_utc(gate.get("distractor_readback_at_utc"))
    query_start = parse_utc(ordering.get("target_wazuh_query_started_at_utc"))
    finalized_at = parse_utc(ordering.get("target_reconciliation_finalized_at_utc"))
    ordered = bool(
        gate.get("verified")
        and gate.get("event_store_readback_complete")
        and gate.get("distractor_event_id") == distractor_event.get("event_id")
        and gate.get("distractor_object_key") == (distractor_event.get("target") or {}).get("key")
        and gate_time
        and query_start
        and finalized_at
        and gate_time <= query_start <= finalized_at
    )
    if not ordered:
        issues.append("distractor event-store readback did not precede target query/finalization")
    if not checks.get("distractor_event_inside_target_padded_window"):
        issues.append("distractor event is not proven inside target's padded observation window")

    overlap = trial.get("overlap_observation") or {}
    overlap_attempts = overlap.get("attempts") or []
    joint_observation = any(
        attempt.get("accepted")
        and attempt.get("category_status") == "healthy"
        and attempt.get("target_present")
        and attempt.get("distractor_present")
        and attempt.get("sampled_before_target_query_started")
        for attempt in overlap_attempts
    )
    # Some controller builds store the timing predicate at the overlap summary level.
    joint_observation = joint_observation or bool(
        overlap.get("target_and_distractor_both_present")
        and overlap.get("sampled_before_target_query_started")
    )
    if not joint_observation:
        issues.append("no fresh healthy direct-probe snapshot proves both objects before target query")

    final_ids = sorted(set(final_reconciliation.get("matched_evidence_ids") or []))
    reconciliation_ok = (
        target_reconciliation.get("status") == "CONSISTENT"
        and target_reconciliation.get("finalized") is True
        and final_reconciliation.get("status") == "CONSISTENT"
        and final_reconciliation.get("finalized") is True
        and target_ids == matched_ids == final_ids
        and bool(target_ids)
        and distractor_event.get("event_id") not in final_ids
        and target_reconciliation.get("cited_only_exact_target_event") is True
    )
    if not reconciliation_ok:
        issues.append("final reconciliation is not finalized CONSISTENT with exactly target evidence only")

    latest_version = final_reconciliation.get("version")
    if not trial.get("cleanup_verified") or not checks.get("cleanup_verified"):
        issues.append("controller cleanup verification failed")
    if trial.get("wazuh_service_after_trial") != "Running" or not checks.get("wazuh_service_running_after_trial"):
        issues.append("Wazuh service was not confirmed running after the trial")
    if not probe_invocations or any(item.get("exit_code") != 0 for item in probe_invocations):
        issues.append("one or more direct probe invocations failed")
    if manifest_entry.get("target_task_name") != trial.get("target_task_name"):
        issues.append("target task name differs between trial and manifest")
    if manifest_entry.get("distractor_task_name") != trial.get("distractor_task_name"):
        issues.append("distractor task name differs between trial and manifest")

    evaluable = bool(target_event and distractor_event and gate_time and query_start and final_reconciliation)
    result = "CORRECT_EXACT_TARGET_ONLY" if evaluable and not issues else (
        "INVALID_NOT_EVALUABLE" if not evaluable else "FAIL"
    )
    if distractor_event.get("event_id") in final_ids:
        result = "FALSE_MATCH_DISTRACTOR_CITED"

    return {
        "trial_id": trial_id,
        "evaluable": evaluable,
        "result": result,
        "issues": issues,
        "target_task_name": trial.get("target_task_name"),
        "target_object_key": (target_event or {}).get("target", {}).get("key"),
        "distractor_task_name": trial.get("distractor_task_name"),
        "distractor_object_key": (distractor_event.get("target") or {}).get("key"),
        "target_event_id": target_ids[0] if len(target_ids) == 1 else None,
        "distractor_event_id": distractor_event.get("event_id"),
        "same_host_and_event_class": same_host_and_type,
        "different_object_identity": distinct_object,
        "local_security_event_exact": bool(local_target.get("exact_identity_match")) if local_target else False,
        "local_security_record_id": local_target.get("record_id") if local_target else None,
        "before_probe_observation_id": (scenario.get("state_plane") or {}).get("before_action_observation", {}).get("observation_id"),
        "after_probe_observation_id": (scenario.get("state_plane") or {}).get("after_action_observation_id"),
        "distractor_readback_preceded_target_query": ordered,
        "distractor_readback_at_utc": ordering.get("distractor_event_store_readback_at_utc"),
        "target_query_started_at_utc": ordering.get("target_wazuh_query_started_at_utc"),
        "target_query_completed_at_utc": ordering.get("target_wazuh_query_completed_at_utc"),
        "target_reconciliation_finalized_at_utc": ordering.get("target_reconciliation_finalized_at_utc"),
        "distractor_precedence_seconds": round((query_start - gate_time).total_seconds(), 3) if query_start and gate_time else None,
        "joint_state_snapshot_before_target_query": joint_observation,
        "target_reconciliation_status": target_reconciliation.get("status"),
        "target_reconciliation_finalized": target_reconciliation.get("finalized"),
        "reconciliation_id": final_reconciliation.get("reconciliation_id"),
        "reconciliation_version": latest_version,
        "delta_id": final_reconciliation.get("delta_id"),
        "finding_id": final_reconciliation.get("finding_id"),
        "matched_evidence_ids": final_ids,
        "distractor_cited": distractor_event.get("event_id") in final_ids,
        "cleanup_verified": bool(trial.get("cleanup_verified")),
        "controller_started_at_utc": trial.get("started_at_utc"),
        "controller_ended_at_utc": trial.get("ended_at_utc"),
        "trial_artifact_sha256": sha256(trial_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path, help="Directory containing campaign-manifest.json and trial-NN/")
    parser.add_argument("--output", type=Path, help="Output JSON path (default: run_dir/analysis.json)")
    args = parser.parse_args()

    run_dir = args.run_dir.resolve()
    manifest_path = run_dir / "campaign-manifest.json"
    if not manifest_path.is_file():
        parser.error(f"campaign manifest not found: {manifest_path}")
    manifest = read_json(manifest_path)
    planned = int(manifest.get("repetitions_planned", 0))
    entries = {str(item.get("trial_id")): item for item in manifest.get("trials", [])}
    trials = [
        audit_trial(
            run_dir,
            number,
            str(manifest.get("campaign_id", "")),
            entries.get(f"trial-{number:02d}", {}),
        )
        for number in range(1, planned + 1)
    ]
    evaluable = [trial for trial in trials if trial["evaluable"]]
    successes = [trial for trial in evaluable if trial["result"] == "CORRECT_EXACT_TARGET_ONLY"]
    false_matches = [trial for trial in trials if trial["result"] == "FALSE_MATCH_DISTRACTOR_CITED"]
    invalid = [trial for trial in trials if not trial["evaluable"]]
    failed = [trial for trial in evaluable if trial["result"] != "CORRECT_EXACT_TARGET_ONLY"]
    postflight_path = run_dir / "postflight-independent.json"
    if not postflight_path.is_file():
        postflight_path = run_dir.parent / "postflight-independent.json"
    postflight = read_json(postflight_path) if postflight_path.is_file() else None

    target_names = [trial.get("target_task_name") for trial in trials if trial.get("target_task_name")]
    distractor_names = [trial.get("distractor_task_name") for trial in trials if trial.get("distractor_task_name")]
    all_event_ids = [
        event_id
        for trial in trials
        for event_id in (trial.get("target_event_id"), trial.get("distractor_event_id"))
        if event_id
    ]
    uniqueness_issues = []
    if len(set(target_names)) != len(target_names):
        uniqueness_issues.append("target task names are not unique across trial slots")
    if len(set(distractor_names)) != len(distractor_names):
        uniqueness_issues.append("distractor task names are not unique across trial slots")
    if len(set(all_event_ids)) != len(all_event_ids):
        uniqueness_issues.append("target/distractor Wazuh event IDs are not globally unique")
    integrity_pass = (
        manifest.get("status") == "ALL_TRIALS_PASS"
        and planned == 10
        and len(trials) == 10
        and not invalid
        and not failed
        and not uniqueness_issues
        and bool(postflight and postflight.get("safe_state_verified"))
    )

    result = {
        "schema_version": "csg-distractor-campaign-audit-v1",
        "campaign_id": manifest.get("campaign_id"),
        "analyzed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "campaign_status": manifest.get("status"),
        "host_id": manifest.get("endpoint"),
        "planned_trials": planned,
        "trial_slots_recorded": len(manifest.get("trials", [])),
        "integrity_pass": integrity_pass,
        "uniqueness_checks": {
            "unique_target_names": len(set(target_names)),
            "target_name_count": len(target_names),
            "unique_distractor_names": len(set(distractor_names)),
            "distractor_name_count": len(distractor_names),
            "unique_wazuh_event_ids": len(set(all_event_ids)),
            "target_and_distractor_event_id_count": len(all_event_ids),
            "issues": uniqueness_issues,
        },
        "intention_to_treat": {
            "pass": sum(trial["result"] == "CORRECT_EXACT_TARGET_ONLY" for trial in trials),
            "fail": len(failed),
            "invalid_not_evaluable": len(invalid),
            "total_slots": planned,
        },
        "evaluable_trial_metrics": {
            "evaluable_n": len(evaluable),
            "correct_exact_target_only": len(successes),
            "correct_exact_target_only_rate": len(successes) / len(evaluable) if evaluable else None,
            "correct_exact_target_only_wilson_95": wilson_interval(len(successes), len(evaluable)),
            "false_distractor_citations": len(false_matches),
            "false_distractor_citation_rate": len(false_matches) / len(evaluable) if evaluable else None,
            "false_distractor_citation_wilson_95": wilson_interval(len(false_matches), len(evaluable)),
        },
        "independent_postflight": postflight,
        "campaign_manifest_sha256": sha256(manifest_path),
        "audit_tool_sha256": sha256(Path(__file__).resolve()),
        "trials": trials,
        "interpretation_limits": [
            "Repeated trials are all from one Windows VM and are not independent-host replications.",
            "The inert task actions test object-specific state/event reconciliation, not malicious-activity detection.",
            "A 10-trial proportion has wide uncertainty; the Wilson interval is descriptive and does not establish deployment-level error rates.",
            "The campaign tests a same-host, same-event-class wrong-object distractor; it does not establish behavior under permanent telemetry loss or other state categories.",
        ],
    }
    output = args.output.resolve() if args.output else run_dir / "analysis.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(output),
        "campaign_status": result["campaign_status"],
        "planned_trials": planned,
        "evaluable_n": len(evaluable),
        "correct_exact_target_only": len(successes),
        "false_distractor_citations": len(false_matches),
        "invalid_not_evaluable": len(invalid),
        "postflight_safe": bool(postflight and postflight.get("safe_state_verified")),
        "integrity_pass": integrity_pass,
    }, indent=2))
    return 0 if integrity_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
