"""Validate and summarize trial artifacts from the Windows registry reconciliation campaign."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def evaluate_trial(record: dict[str, Any], assigned: dict[str, Any]) -> dict[str, Any]:
    condition = str(assigned.get("condition") or record.get("condition") or "unknown")
    target_key = str(record.get("target_object_key") or "").strip().lower()
    target_state = record.get("target_state") or {}
    target = record.get("target") or {}
    provider_events = target.get("wazuh_provider_exact_events") or []
    delta = next(iter(target.get("deltas") or []), {})
    window = delta.get("observation_window") or {}
    tolerance = int(
        (record.get("protocol_parameters") or {}).get("event_time_tolerance_seconds", 0)
    )
    start = _parse_time(window.get("start"))
    end = _parse_time(window.get("end"))
    if start and end:
        start -= timedelta(seconds=tolerance)
        end += timedelta(seconds=tolerance)
    expected_event_ids = {
        str(event.get("event_id"))
        for event in provider_events
        if event.get("event_id")
        and str(event.get("host_id") or "") == str(record.get("host_id") or "")
        and str(event.get("normalized_type") or "") == "registry_value_modified"
        and str((event.get("target") or {}).get("key") or "").strip().lower() == target_key
        and _in_time_window(event.get("event_time"), start, end)
    }
    reconciliation = _latest_reconciliation(target)
    matched_ids = {str(item) for item in (reconciliation or {}).get("matched_evidence_ids", [])}
    history = target.get("reconciliation_history") or []
    revisions = history[0].get("revisions", []) if history else []
    distractor = record.get("bounded_distractor") or {}
    no_change = record.get("no_change_control") or {}
    cleanup = record.get("cleanup") or {}
    service = record.get("wazuh_service") or {}
    service_before = service.get("before") or {}
    service_during = service.get("during") or {}
    service_after = service.get("after") or {}
    action = (record.get("action_journal") or {}).get("target_create") or {}
    action_completed_at = _parse_time(action.get("completed_at"))
    state_observed_at = _parse_time(window.get("end"))
    state_observation_upper_bound = (
        (state_observed_at - action_completed_at).total_seconds()
        if state_observed_at and action_completed_at
        else None
    )
    action_start = _parse_time(action.get("started_at"))
    before_at = _parse_time(service_before.get("captured_at"))
    during_at = _parse_time(service_during.get("captured_at"))
    after_at = _parse_time(service_after.get("captured_at"))
    service_running_during_action = bool(
        service_before.get("status") == "Running"
        and service_after.get("status") == "Running"
        and int(service_before.get("process_id") or 0) > 0
        and int(service_after.get("process_id") or 0) > 0
        and action_start
        and before_at
        and after_at
        and before_at <= action_start <= after_at
        and (service_during.get("status") in {None, "Running"})
    )
    wazuh_stop_verified = bool(
        service_before.get("status") == "Running"
        and int(service_before.get("process_id") or 0) > 0
        and service_during.get("status") == "Stopped"
        and int(service_during.get("process_id") or 0) == 0
        and service_after.get("status") == "Running"
        and int(service_after.get("process_id") or 0) > 0
        and during_at
        and after_at
        and action_start
        and during_at <= action_start <= after_at
        and action.get("exit_code") == 0
    )
    distractor_ids = {str(item) for item in distractor.get("wrong_object_event_ids", []) if item}
    ingested_events = (record.get("source_event_ingestion") or {}).get("database_verified", [])
    distractor_key = str(record.get("distractor_object_key") or "").strip().lower()
    distractor_events = [item for item in ingested_events if item.get("event_id") in distractor_ids]
    distractor_evidence_verified = bool(distractor_events) and all(
        str(item.get("host_id") or "") == str(record.get("host_id") or "")
        and item.get("normalized_type") == "registry_value_modified"
        and str((item.get("target") or {}).get("key") or "").strip().lower() == distractor_key
        and distractor_key != target_key
        and _in_time_window(item.get("event_time"), start, end)
        and bool((item.get("source_reference") or {}).get("document_id"))
        for item in distractor_events
    )

    state_visible = target_state.get("present_after")
    cleanup_verified = (
        cleanup.get("target_absent") is True
        and cleanup.get("distractor_absent") is True
        and cleanup.get("cleanup_probe_succeeded") is True
    )
    if condition == "registry_complete":
        exact_event_present = bool(expected_event_ids)
        correctly_linked = (
            exact_event_present
            and (reconciliation or {}).get("status") == "CONSISTENT"
            and bool(matched_ids & expected_event_ids)
            and matched_ids.issubset(expected_event_ids)
        )
        outcome_pass = (
            state_visible is True
            and correctly_linked
            and service_running_during_action
            and cleanup_verified
        )
    elif condition == "registry_wrong_object":
        distractor_present = distractor.get("wrong_object_event_inside_target_window") is True
        latest_status = (reconciliation or {}).get("status")
        rejected = (
            latest_status == "UNEXPLAINED"
            and distractor.get("finalized_status") == "UNEXPLAINED"
            and not bool(matched_ids & distractor_ids)
        )
        outcome_pass = (
            state_visible is True
            and distractor_present
            and rejected
            and not expected_event_ids
            and wazuh_stop_verified
            and distractor_evidence_verified
            and cleanup_verified
        )
        exact_event_present = bool(expected_event_ids)
        correctly_linked = rejected
    elif condition == "registry_no_change":
        no_target_finding = (
            no_change.get("target_absent_before") is True
            and no_change.get("target_absent_after") is True
            and no_change.get("new_delta_count") == 0
            and no_change.get("new_finding_count") == 0
        )
        outcome_pass = no_target_finding and cleanup_verified
        exact_event_present = bool(expected_event_ids)
        correctly_linked = None
    else:
        exact_event_present = bool(expected_event_ids)
        correctly_linked = None
        outcome_pass = False

    return {
        "trial_id": assigned.get("trial_id") or record.get("trial_id"),
        "condition": condition,
        "started_at": record.get("started_at"),
        "ended_at": record.get("ended_at"),
        "manifest_status": assigned.get("status"),
        "script_trial_pass": record.get("trial_pass"),
        "analysis_pass": bool(outcome_pass),
        "target_object_key": record.get("target_object_key"),
        "target_state_observed": state_visible,
        "action_to_state_observation_upper_bound_seconds": state_observation_upper_bound,
        "exact_target_event_present": exact_event_present,
        "exact_target_event_ids": sorted(expected_event_ids),
        "latest_reconciliation_status": (reconciliation or {}).get("status"),
        "latest_reconciliation_version": (reconciliation or {}).get("version"),
        "matched_evidence_ids": sorted(matched_ids),
        "correct_target_link": correctly_linked,
        "distractor_event_present": distractor.get("wrong_object_event_inside_target_window"),
        "distractor_event_ids": sorted(distractor_ids),
        "distractor_evidence_identity_verified": distractor_evidence_verified,
        "wazuh_service_stop_and_restore_verified": wazuh_stop_verified,
        "wazuh_running_during_target_action": service_running_during_action,
        "wazuh_service_before": service_before.get("status"),
        "wazuh_service_during": service_during.get("status"),
        "wazuh_service_after": service_after.get("status"),
        "target_action_exit_code": action.get("exit_code"),
        "no_change_delta_count": no_change.get("new_delta_count"),
        "no_change_finding_count": no_change.get("new_finding_count"),
        "revision_count": len(revisions),
        "cleanup_verified": cleanup_verified,
        "cleanup_errors": cleanup.get("errors", []),
        "failure_detail": record.get("failure_detail"),
    }


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.astimezone(UTC)


def _in_time_window(value: Any, start: datetime | None, end: datetime | None) -> bool:
    event_time = _parse_time(value)
    return bool(event_time and start and end and start <= event_time <= end)


def _distribution(values: list[float | None]) -> dict[str, Any]:
    valid = sorted(value for value in values if value is not None and value >= 0)
    return {
        "n_valid": len(valid),
        "n_missing_or_invalid": len(values) - len(valid),
        "minimum_seconds": round(valid[0], 3) if valid else None,
        "median_seconds": round(_median(valid), 3) if valid else None,
        "maximum_seconds": round(valid[-1], 3) if valid else None,
        "values_seconds": [round(value, 3) for value in valid],
    }


def _median(values: list[float]) -> float:
    middle = len(values) // 2
    if len(values) % 2:
        return values[middle]
    return (values[middle - 1] + values[middle]) / 2


def summarize_campaign(campaign_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    campaign = _read_json(campaign_path)
    outcomes: list[dict[str, Any]] = []
    missing_artifacts: list[str] = []
    for assigned in campaign.get("schedule", []):
        trial_id = str(assigned.get("trial_id") or "")
        trial_path = campaign_path.parent / trial_id / "run.json"
        if not trial_path.is_file():
            missing_artifacts.append(trial_id)
            continue
        outcomes.append(evaluate_trial(_read_json(trial_path), assigned))

    by_condition: dict[str, Any] = {}
    for condition in ("registry_complete", "registry_wrong_object", "registry_no_change"):
        rows = [row for row in outcomes if row["condition"] == condition]
        assigned_count = sum(
            item.get("condition") == condition for item in campaign.get("schedule", [])
        )
        known_state = [row for row in rows if row["target_state_observed"] is not None]
        cleanup_rows = [row for row in rows if row["cleanup_verified"] is not None]
        if condition == "registry_complete":
            positive = [row for row in rows if row["analysis_pass"]]
            metric = "exact_target_state_and_event_link_pass_rate"
        elif condition == "registry_wrong_object":
            positive = [row for row in rows if row["analysis_pass"]]
            metric = "distractor_rejection_and_state_visibility_pass_rate"
        else:
            positive = [row for row in rows if row["analysis_pass"]]
            metric = "no_change_false_alarm_control_pass_rate"
        state_successes = sum(row["target_state_observed"] is True for row in known_state)
        by_condition[condition] = {
            "assigned": assigned_count,
            "artifacts_found": len(rows),
            "script_passed": sum(row["script_trial_pass"] is True for row in rows),
            "analysis_passed": len(positive),
            "pass_rate": _proportion(len(positive), len(rows)),
            "state_observed": _proportion(state_successes, len(known_state)),
            "cleanup_verified": sum(row["cleanup_verified"] is True for row in cleanup_rows),
            "cleanup_denominator": len(cleanup_rows),
            "primary_metric": metric,
        }

    mutations = [
        row
        for row in outcomes
        if row["condition"] in {"registry_complete", "registry_wrong_object"}
    ]
    observed_mutations = [row for row in mutations if row["target_state_observed"] is not None]
    complete_rows = [row for row in outcomes if row["condition"] == "registry_complete"]
    wrong_rows = [row for row in outcomes if row["condition"] == "registry_wrong_object"]
    no_change_rows = [row for row in outcomes if row["condition"] == "registry_no_change"]
    false_consistent = sum(
        row["latest_reconciliation_status"] == "CONSISTENT" for row in wrong_rows
    )
    false_no_change = sum(
        (row["no_change_delta_count"] or 0) > 0 or (row["no_change_finding_count"] or 0) > 0
        for row in no_change_rows
    )
    summary = {
        "schema_version": "csg-paired-reconciliation-campaign-summary-v1",
        "campaign": {
            "experiment_id": campaign.get("experiment_id"),
            "status": campaign.get("status"),
            "execution_kind": campaign.get("execution_kind"),
            "host_id": campaign.get("host_id"),
            "protocol_sha256": campaign.get("protocol_sha256"),
            "controller_sha256": campaign.get("controller_sha256"),
            "trial_script_sha256": campaign.get("trial_script_sha256"),
            "probe_config_sha256": campaign.get("probe_config_sha256"),
            "random_seed": campaign.get("random_seed"),
            "tolerance_seconds": campaign.get("tolerance_seconds"),
            "event_lookback_seconds": campaign.get("event_lookback_seconds"),
            "created_at": campaign.get("created_at"),
            "completed_at": campaign.get("completed_at"),
        },
        "assigned_trials": len(campaign.get("schedule", [])),
        "artifacts_found": len(outcomes),
        "missing_artifact_trial_ids": missing_artifacts,
        "conditions": by_condition,
        "same_host_timing": {
            "metric": "action completion to current probe observation-window end",
            "interpretation": (
                "Upper bound on observing changed state from Windows endpoint timestamps; "
                "not the exact instant the collector first saw the transition."
            ),
            **_distribution(
                [row["action_to_state_observation_upper_bound_seconds"] for row in complete_rows]
            ),
        },
        "source_verification": {
            "wazuh_running_during_complete_actions": _proportion(
                sum(row["wazuh_running_during_target_action"] is True for row in complete_rows),
                len(complete_rows),
            ),
            "wazuh_stop_and_restore_proven_for_wrong_object_actions": _proportion(
                sum(row["wazuh_service_stop_and_restore_verified"] is True for row in wrong_rows),
                len(wrong_rows),
            ),
            "wrong_object_document_identity_and_window_verified": _proportion(
                sum(row["distractor_evidence_identity_verified"] is True for row in wrong_rows),
                len(wrong_rows),
            ),
        },
        "pooled_endpoint_metrics": {
            "mutation_state_visibility": _proportion(
                sum(row["target_state_observed"] is True for row in observed_mutations),
                len(observed_mutations),
            ),
            "complete_exact_link_pass_rate": _proportion(
                sum(row["analysis_pass"] for row in complete_rows), len(complete_rows)
            ),
            "wrong_object_false_consistent_rate": _proportion(false_consistent, len(wrong_rows)),
            "no_change_false_finding_rate": _proportion(false_no_change, len(no_change_rows)),
        },
        "interpretation_limits": [
            (
                "Wilson intervals describe repeated trials on this one endpoint and do not "
                "estimate between-host variation."
            ),
            "Benign controlled changes do not establish malicious-activity detection accuracy.",
            "A bounded Wazuh pause does not establish permanent event loss.",
            "Derived replay rows must not be counted as additional live action trials.",
        ],
    }
    return summary, outcomes


def _latest_reconciliation(target: dict[str, Any]) -> dict[str, Any] | None:
    history = target.get("reconciliation_history") or []
    if not history:
        return None
    latest = history[0].get("latest")
    if isinstance(latest, dict):
        return latest
    revisions = history[0].get("revisions") or []
    return revisions[-1] if revisions else None


def _proportion(successes: int, denominator: int) -> dict[str, Any]:
    if denominator == 0:
        return {
            "successes": successes,
            "denominator": denominator,
            "estimate": None,
            "wilson_95": None,
        }
    z = 1.959963984540054
    p = successes / denominator
    scale = 1 + z * z / denominator
    center = (p + z * z / (2 * denominator)) / scale
    margin = (
        z * ((p * (1 - p) / denominator + z * z / (4 * denominator * denominator)) ** 0.5) / scale
    )
    return {
        "successes": successes,
        "denominator": denominator,
        "estimate": round(p, 6),
        "wilson_95": [round(max(0.0, center - margin), 6), round(min(1.0, center + margin), 6)],
    }


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def render_results(summary: dict[str, Any], outcomes: list[dict[str, Any]]) -> str:
    campaign = summary["campaign"]
    lines = [
        "# Windows Registry Reconciliation Campaign Results",
        "",
        f"Campaign: `{campaign.get('experiment_id')}`  ",
        f"Execution kind: `{campaign.get('execution_kind')}`  ",
        f"Campaign status: `{campaign.get('status')}`  ",
        f"Host: `{campaign.get('host_id')}`  ",
        f"Protocol SHA-256: `{campaign.get('protocol_sha256')}`",
        "",
        "## Condition Results",
        "",
        (
            "| Condition | Assigned | Artifacts | Script pass | "
            "Evidence-rule pass (95% Wilson) | State observed | Cleanup verified |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for condition, values in summary["conditions"].items():
        lines.append(
            "| `{}` | {} | {} | {} | {} | {} | {}/{} |".format(
                condition,
                values["assigned"],
                values["artifacts_found"],
                values["script_passed"],
                _format_proportion(values["pass_rate"]),
                _format_proportion(values["state_observed"]),
                values["cleanup_verified"],
                values["cleanup_denominator"],
            )
        )
    lines.extend(
        [
            "",
            "## Primary Measures",
            "",
            "| Measure | Result (95% Wilson) |",
            "|---|---:|",
        ]
    )
    metric_labels = {
        "mutation_state_visibility": "Mutation state visibility",
        "complete_exact_link_pass_rate": "Complete-condition exact event link",
        "wrong_object_false_consistent_rate": "Wrong-object false CONSISTENT rate",
        "no_change_false_finding_rate": "No-change false finding rate",
    }
    for key, label in metric_labels.items():
        lines.append(f"| {label} | {_format_proportion(summary['pooled_endpoint_metrics'][key])} |")
    lines.extend(
        [
            "",
            "## Independent Source-State Checks",
            "",
            "| Check | Result (95% Wilson) |",
            "|---|---:|",
        ]
    )
    source_labels = {
        "wazuh_running_during_complete_actions": "WazuhSvc running for complete target actions",
        "wazuh_stop_and_restore_proven_for_wrong_object_actions": (
            "WazuhSvc stopped during wrong-object target actions and restored afterward"
        ),
        "wrong_object_document_identity_and_window_verified": (
            "Wrong-object Wazuh document host/type/object/time verified"
        ),
    }
    for key, label in source_labels.items():
        lines.append(f"| {label} | {_format_proportion(summary['source_verification'][key])} |")
    timing = summary["same_host_timing"]
    lines.extend(
        [
            "",
            "## Same-Host Observation Timing",
            "",
            (
                f"For {timing['n_valid']} complete trials, action completion to the current "
                "probe observation-window end had "
                f"median {timing['median_seconds']:.3f}s, minimum "
                f"{timing['minimum_seconds']:.3f}s, and maximum "
                f"{timing['maximum_seconds']:.3f}s."
            ),
            timing["interpretation"],
            (
                "Wazuh event timestamps are source-event times; they are not used as "
                "ingestion latency."
            ),
        ]
    )
    lines.extend(
        [
            "",
            "## Trial Ledger",
            "",
            (
                "| Trial | Condition | Script | State | Exact target event | "
                "Wazuh source proof | Reconciliation | Cleanup |"
            ),
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for row in outcomes:
        lines.append(
            "| `{}` | `{}` | {} | {} | {} | {} | `{}` | {} |".format(
                row["trial_id"],
                row["condition"],
                "PASS" if row["script_trial_pass"] is True else "FAIL/UNKNOWN",
                _tri_state(row["target_state_observed"]),
                _tri_state(row["exact_target_event_present"]),
                _source_proof(row),
                row["latest_reconciliation_status"] or "N/A",
                "PASS" if row["cleanup_verified"] else "FAIL",
            )
        )
    lines.extend(["", "## Limits", ""])
    lines.extend(f"- {item}" for item in summary["interpretation_limits"])
    if summary["missing_artifact_trial_ids"]:
        lines.extend(["", "## Missing Artifacts", ""])
        lines.extend(f"- `{trial_id}`" for trial_id in summary["missing_artifact_trial_ids"])
    lines.append("")
    return "\n".join(lines)


def _format_proportion(value: dict[str, Any]) -> str:
    if value["estimate"] is None:
        return "N/A"
    low, high = value["wilson_95"]
    return (
        f"{value['successes']}/{value['denominator']} "
        f"({value['estimate']:.3f}; {low:.3f}-{high:.3f})"
    )


def _tri_state(value: Any) -> str:
    if value is True:
        return "YES"
    if value is False:
        return "NO"
    return "UNKNOWN"


def _source_proof(row: dict[str, Any]) -> str:
    if row["condition"] == "registry_complete":
        return "PASS" if row["wazuh_running_during_target_action"] else "FAIL"
    if row["condition"] == "registry_wrong_object":
        return (
            "PASS"
            if row["wazuh_service_stop_and_restore_verified"]
            and row["distractor_evidence_identity_verified"]
            else "FAIL"
        )
    return "N/A"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a Windows registry reconciliation campaign"
    )
    parser.add_argument("campaign_manifest", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    summary, outcomes = summarize_campaign(args.campaign_manifest)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "aggregate.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (args.output_dir / "case-outcomes.jsonl").open("w", encoding="utf-8") as handle:
        for outcome in outcomes:
            handle.write(json.dumps(outcome, sort_keys=True) + "\n")
    (args.output_dir / "RESULTS.md").write_text(render_results(summary, outcomes), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
