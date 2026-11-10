"""Compare event-only, state-only, and reconciled outcomes in a live service campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ACTIVE_CONDITIONS = {
    "complete",
    "delayed_reconciliation",
    "telemetry_delay",
    "capture_drop",
    "same_host_distractor",
}
KNOWN_CONDITIONS = ACTIVE_CONDITIONS | {"no_change"}
EXPECTED_EVENTS = {"ADD": "service_created", "MODIFY": "service_modified"}
PRIMARY_TRANSITIONS = ("ADD", "MODIFY")
WILSON_Z_95 = 1.959963984540054


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def wilson_interval(successes: int, total: int) -> list[float] | None:
    if total <= 0:
        return None
    p = successes / total
    z2 = WILSON_Z_95**2
    denominator = 1 + z2 / total
    center = (p + z2 / (2 * total)) / denominator
    margin = WILSON_Z_95 * math.sqrt(p * (1 - p) / total + z2 / (4 * total**2)) / denominator
    return [max(0.0, center - margin), min(1.0, center + margin)]


def _matches_identity(
    event: dict[str, Any], *, event_type: str, host_id: str, object_key: str, service_name: str
) -> bool:
    return (
        event.get("source") == "wazuh"
        and event.get("host_id") == host_id
        and event.get("normalized_type") == event_type
        and str(event.get("target_key", "")).casefold() == object_key.casefold()
        and str(event.get("service_name", "")).casefold() == service_name.casefold()
    )


def _wazuh_index_class(event: dict[str, Any]) -> str:
    source_reference = event.get("source_reference") or {}
    index_name = str(source_reference.get("index") or "").casefold()
    if index_name.startswith("wazuh-alerts-"):
        return "alert_index"
    if index_name.startswith("wazuh-archives-"):
        return "archive_index"
    return "unclassified_index"


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _exact_events(run: dict[str, Any], event_type: str) -> list[dict[str, Any]]:
    evidence = run.get("verified_exact_wazuh_evidence") or {}
    rows = evidence.get(event_type) or []
    host_id = str(run.get("host_id", ""))
    service_name = str(run.get("service_name", ""))
    object_key = f"service:{service_name.casefold()}"
    started_at = _parse_time(str(run["started_at"]))
    ended_at = _parse_time(str(run["ended_at"]))
    return [
        row
        for row in rows
        if _matches_identity(
            row,
            event_type=event_type,
            host_id=host_id,
            object_key=object_key,
            service_name=service_name,
        )
        and row.get("event_time")
        and started_at <= _parse_time(str(row["event_time"])) <= ended_at
    ]


def _direct_probe_delta(delta: dict[str, Any]) -> bool:
    sources = []
    for side in ("before", "after"):
        record = delta.get(side)
        if record is None:
            continue
        metadata = record.get("metadata") or {}
        sources.append(metadata.get("source") or record.get("source"))
    return bool(sources) and all(source == "direct_probe" for source in sources)


def _trial_analysis(
    *, condition: str, trial_id: str, run: dict[str, Any], validation: dict[str, Any]
) -> dict[str, Any]:
    service_name = str(run.get("service_name", ""))
    host_id = str(run.get("host_id", ""))
    object_key = f"service:{service_name.casefold()}"
    active = condition in ACTIVE_CONDITIONS
    deltas = run.get("target_state_deltas") or []
    findings = run.get("findings") or []
    transition_rows: dict[str, dict[str, Any]] = {}

    for transition_type, event_type in EXPECTED_EVENTS.items():
        expected = active
        target_deltas = [
            delta
            for delta in deltas
            if delta.get("object_key", "").casefold() == object_key
            and delta.get("delta_type") == transition_type
        ]
        native_deltas = [delta for delta in target_deltas if _direct_probe_delta(delta)]
        events = _exact_events(run, event_type)
        alert_events = [event for event in events if _wazuh_index_class(event) == "alert_index"]
        archive_events = [event for event in events if _wazuh_index_class(event) == "archive_index"]
        unclassified_events = [
            event for event in events if _wazuh_index_class(event) == "unclassified_index"
        ]
        matched_findings = [
            finding
            for finding in findings
            if finding.get("object_key", "").casefold() == object_key
            and any(finding.get("delta_id") == delta.get("delta_id") for delta in native_deltas)
        ]
        delta = native_deltas[0] if len(target_deltas) == len(native_deltas) == 1 else None
        finding = None
        if delta:
            same_delta = [
                item for item in matched_findings if item.get("delta_id") == delta.get("delta_id")
            ]
            finding = same_delta[0] if len(same_delta) == 1 else None

        reconciliation = (finding or {}).get("reconciliation") or {}
        status = reconciliation.get("status")
        matched_ids = set(reconciliation.get("matched_evidence_ids") or [])
        event_ids = {str(event.get("event_id")) for event in events if event.get("event_id")}
        event_detected = bool(events)
        alert_detected = bool(alert_events)
        state_detected = len(native_deltas) == len(target_deltas) == 1
        finding_detected = finding is not None
        if expected and not state_detected:
            reconciliation_correct = False
        elif event_detected:
            reconciliation_correct = (
                finding_detected and status == "CONSISTENT" and matched_ids == event_ids
            )
        elif state_detected:
            reconciliation_correct = (
                finding_detected and status == "UNEXPLAINED" and not matched_ids
            )
        else:
            reconciliation_correct = not finding_detected and not matched_ids

        transition_rows[transition_type] = {
            "expected_state_change": expected,
            "state_delta_count": len(target_deltas),
            "direct_probe_delta_count": len(native_deltas),
            "state_source": "direct_probe" if native_deltas else None,
            "state_detected": state_detected,
            "expected_event_type": event_type,
            "exact_wazuh_event_count": len(events),
            "event_detected": event_detected,
            "exact_event_ids": sorted(event_ids),
            "exact_wazuh_alert_count": len(alert_events),
            "exact_wazuh_alert_ids": sorted(
                str(event.get("event_id")) for event in alert_events if event.get("event_id")
            ),
            "exact_wazuh_archive_count": len(archive_events),
            "exact_wazuh_archive_ids": sorted(
                str(event.get("event_id")) for event in archive_events if event.get("event_id")
            ),
            "unclassified_index_event_count": len(unclassified_events),
            "wazuh_alert_detected": alert_detected,
            "wazuh_alert_rule_ids": sorted(
                {
                    str((event.get("attributes") or {}).get("rule_id"))
                    for event in alert_events
                    if (event.get("attributes") or {}).get("rule_id") is not None
                }
            ),
            "wazuh_alert_rule_levels": sorted(
                {
                    int((event.get("attributes") or {}).get("rule_level"))
                    for event in alert_events
                    if str((event.get("attributes") or {}).get("rule_level", "")).isdigit()
                }
            ),
            "target_finding_count": len(matched_findings),
            "csg_finding_detected": finding_detected,
            "reconciliation_status": status,
            "reconciliation_matched_evidence_ids": sorted(matched_ids),
            "reconciliation_decision_correct": reconciliation_correct,
            "delta_id": delta.get("delta_id") if delta else None,
            "finding_id": finding.get("finding_id") if finding else None,
        }

    target_findings = [
        finding
        for finding in findings
        if finding.get("object_key", "").casefold() == object_key
        and finding.get("category") == "service"
    ]
    primary = [transition_rows[item] for item in PRIMARY_TRANSITIONS]
    if active:
        event_pair = all(row["event_detected"] for row in primary)
        alert_pair = all(row["wazuh_alert_detected"] for row in primary)
        state_pair = all(row["state_detected"] for row in primary)
        csg_pair = all(row["csg_finding_detected"] for row in primary)
        reconciliation_pair = all(row["reconciliation_decision_correct"] for row in primary)
    else:
        event_pair = alert_pair = state_pair = csg_pair = reconciliation_pair = False

    wrong_object = None
    if condition == "same_host_distractor":
        proof = run.get("same_host_distractor_proof") or {}
        detail = proof.get("details") or {}
        raw = detail.get("distractor_event") or []
        wrong_object_events = raw if isinstance(raw, list) else [raw]
        wrong_object_events = [
            event
            for event in wrong_object_events
            if event.get("source") == "wazuh"
            and event.get("host_id") == host_id
            and event.get("normalized_type") == "service_created"
            and str(event.get("target_key", "")).casefold() != object_key
            and event.get("event_time")
            and _parse_time(str(run["started_at"]))
            <= _parse_time(str(event["event_time"]))
            <= _parse_time(str(run["ended_at"]))
        ]
        add = transition_rows["ADD"]
        wrong_object = {
            "same_host_wrong_object_event_count": len(wrong_object_events),
            "same_host_wrong_object_event_ids": sorted(
                str(event.get("event_id")) for event in wrong_object_events if event.get("event_id")
            ),
            "target_add_status": add["reconciliation_status"],
            "wrong_object_event_rejected": bool(wrong_object_events)
            and add["reconciliation_status"] == "UNEXPLAINED"
            and not set(add["reconciliation_matched_evidence_ids"]).intersection(
                str(event.get("event_id")) for event in wrong_object_events
            ),
        }

    no_change_false_positive = None
    if condition == "no_change":
        deltas_for_target = [
            delta
            for delta in deltas
            if delta.get("object_key", "").casefold() == object_key
            and delta.get("delta_type") in PRIMARY_TRANSITIONS
        ]
        create_events = _exact_events(run, "service_created")
        modify_events = _exact_events(run, "service_modified")
        create_alerts = [
            event for event in create_events if _wazuh_index_class(event) == "alert_index"
        ]
        modify_alerts = [
            event for event in modify_events if _wazuh_index_class(event) == "alert_index"
        ]
        no_change_false_positive = {
            "state_only": bool(deltas_for_target),
            "event_only": bool(create_events or modify_events),
            "wazuh_alert_only": bool(create_alerts or modify_alerts),
            "csg": bool(target_findings),
        }

    return {
        "trial_id": trial_id,
        "condition": condition,
        "host_id": host_id,
        "target_service": service_name,
        "target_object_key": object_key,
        "protocol_positive_trial": active,
        "validator_passed": bool(validation.get("passed")),
        "transitions": transition_rows,
        "full_workflow": {
            "event_only_detected_both_transitions": event_pair if active else None,
            "wazuh_alert_only_detected_both_transitions": alert_pair if active else None,
            "state_only_detected_both_transitions": state_pair if active else None,
            "csg_emitted_both_target_findings": csg_pair if active else None,
            "csg_reconciliation_correct_for_both": reconciliation_pair if active else None,
        },
        "wrong_object_control": wrong_object,
        "no_change_false_positive": no_change_false_positive,
    }


def analyze_campaign(campaign_dir: Path) -> dict[str, Any]:
    manifest_path = campaign_dir / "campaign-manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"campaign manifest not found: {manifest_path}")
    manifest = _read_json(manifest_path)
    schedule = manifest.get("schedule") or []
    if manifest.get("status") not in {"COMPLETED", "COMPLETED_WITH_FAILURES"}:
        raise ValueError("campaign manifest does not describe a finalized campaign")
    if any(row.get("condition") not in KNOWN_CONDITIONS for row in schedule):
        raise ValueError("campaign contains a condition outside the evaluator's declared scope")
    if any(row.get("status") not in {"COMPLETED", "FAILED"} for row in schedule):
        raise ValueError("campaign schedule contains a pending or running trial")
    completed = [row for row in schedule if row.get("status") == "COMPLETED"]
    failed = [row for row in schedule if row.get("status") == "FAILED"]
    if not completed:
        raise ValueError("campaign has no completed trials")

    trials: list[dict[str, Any]] = []
    input_hashes = {"campaign-manifest.json": _sha256(manifest_path)}
    for entry in failed:
        trial_id = str(entry["trial_id"])
        failure_path = campaign_dir / trial_id / "failure.json"
        if not failure_path.is_file():
            raise FileNotFoundError(f"{trial_id}: failed attempt has no retained failure.json")
        input_hashes[f"{trial_id}/failure.json"] = _sha256(failure_path)
    for entry in completed:
        trial_id = str(entry["trial_id"])
        run_path = campaign_dir / trial_id / "run.json"
        validation_path = campaign_dir / trial_id / "validation.json"
        if not run_path.is_file() or not validation_path.is_file():
            raise FileNotFoundError(f"{trial_id}: run.json or validation.json is missing")
        run = _read_json(run_path)
        validation = _read_json(validation_path)
        input_hashes[f"{trial_id}/run.json"] = _sha256(run_path)
        input_hashes[f"{trial_id}/validation.json"] = _sha256(validation_path)
        if not validation.get("passed"):
            raise ValueError(f"{trial_id}: strict per-run validation did not pass")
        if run.get("run_status") != "COMPLETED":
            raise ValueError(f"{trial_id}: run record is not marked COMPLETED")
        if run.get("telemetry_condition") != entry.get("condition"):
            raise ValueError(f"{trial_id}: manifest/run condition mismatch")
        if (run.get("event_plane_status") or {}).get("event_query_status") != "COMPLETE":
            raise ValueError(f"{trial_id}: central event query was not recorded as complete")
        trials.append(
            _trial_analysis(
                condition=str(entry["condition"]),
                trial_id=trial_id,
                run=run,
                validation=validation,
            )
        )

    conditions = sorted({str(row.get("condition")) for row in schedule})
    condition_summary: dict[str, Any] = {}
    for condition in conditions:
        assigned = [row for row in schedule if row.get("condition") == condition]
        observed = [row for row in trials if row["condition"] == condition]
        is_positive = condition in ACTIVE_CONDITIONS
        condition_summary[condition] = {
            "assigned": len(assigned),
            "completed": sum(row.get("status") == "COMPLETED" for row in assigned),
            "failed": sum(row.get("status") == "FAILED" for row in assigned),
            "state_transition_trials": sum(
                row["full_workflow"]["state_only_detected_both_transitions"] is True
                for row in observed
            )
            if is_positive
            else None,
            "event_only_full_workflow_trials": sum(
                row["full_workflow"]["event_only_detected_both_transitions"] is True
                for row in observed
            )
            if is_positive
            else None,
            "wazuh_alert_only_full_workflow_trials": sum(
                row["full_workflow"]["wazuh_alert_only_detected_both_transitions"] is True
                for row in observed
            )
            if is_positive
            else None,
            "csg_full_workflow_trials": sum(
                row["full_workflow"]["csg_emitted_both_target_findings"] is True for row in observed
            )
            if is_positive
            else None,
            "correct_reconciliation_trials": sum(
                row["full_workflow"]["csg_reconciliation_correct_for_both"] is True
                for row in observed
            )
            if is_positive
            else None,
            "no_change_false_findings": sum(
                bool((row["no_change_false_positive"] or {}).get("csg")) for row in observed
            )
            if condition == "no_change"
            else None,
        }

    positive_trials = [row for row in trials if row["protocol_positive_trial"]]
    n_positive = len(positive_trials)
    workflow_counts = {
        key: sum(row["full_workflow"][key] is True for row in positive_trials)
        for key in (
            "event_only_detected_both_transitions",
            "wazuh_alert_only_detected_both_transitions",
            "state_only_detected_both_transitions",
            "csg_emitted_both_target_findings",
            "csg_reconciliation_correct_for_both",
        )
    }

    transition_summary: dict[str, Any] = {}
    for transition_type in PRIMARY_TRANSITIONS:
        records = [(trial, trial["transitions"][transition_type]) for trial in positive_trials]
        n = len(records)
        state_hits = sum(row["state_detected"] for _, row in records)
        event_hits = sum(row["event_detected"] for _, row in records)
        alert_hits = sum(row["wazuh_alert_detected"] for _, row in records)
        archive_hits = sum(row["exact_wazuh_archive_count"] > 0 for _, row in records)
        finding_hits = sum(row["csg_finding_detected"] for _, row in records)
        correct = sum(row["reconciliation_decision_correct"] for _, row in records)
        consistent = sum(row["reconciliation_status"] == "CONSISTENT" for _, row in records)
        unexplained = sum(row["reconciliation_status"] == "UNEXPLAINED" for _, row in records)
        transition_summary[transition_type] = {
            "expected_transition_count": n,
            "state_only_detected": state_hits,
            "state_only_rate": state_hits / n if n else None,
            "state_only_wilson_95": wilson_interval(state_hits, n),
            "exact_event_only_detected": event_hits,
            "exact_event_only_rate": event_hits / n if n else None,
            "exact_event_only_wilson_95": wilson_interval(event_hits, n),
            "exact_wazuh_alert_only_detected": alert_hits,
            "exact_wazuh_alert_only_rate": alert_hits / n if n else None,
            "exact_wazuh_alert_only_wilson_95": wilson_interval(alert_hits, n),
            "exact_wazuh_archive_only_detected": archive_hits,
            "exact_wazuh_archive_only_rate": archive_hits / n if n else None,
            "exact_wazuh_archive_only_wilson_95": wilson_interval(archive_hits, n),
            "csg_target_findings": finding_hits,
            "reconciliation_consistent": consistent,
            "reconciliation_unexplained": unexplained,
            "csg_correct_reconciliation_decisions": correct,
        }

    no_change_trials = [row for row in trials if row["condition"] == "no_change"]
    distractor_trials = [row for row in trials if row["condition"] == "same_host_distractor"]
    wrong_object_exposures = sum(
        bool((row["wrong_object_control"] or {}).get("same_host_wrong_object_event_count"))
        for row in distractor_trials
    )
    wrong_object_rejections = sum(
        bool((row["wrong_object_control"] or {}).get("wrong_object_event_rejected"))
        for row in distractor_trials
    )
    no_change_false_positives = {
        method: sum(
            bool((row["no_change_false_positive"] or {}).get(method)) for row in no_change_trials
        )
        for method in ("event_only", "wazuh_alert_only", "state_only", "csg")
    }

    return {
        "schema_version": "csg-reconciliation-effectiveness-analysis-v1",
        "analysis_type": "retrospective_descriptive_reanalysis",
        "analysis_plan_status": "exploratory; written after original R2 trial collection",
        "analysis_source": {
            "path": "experiments/reconciliation_effectiveness.py",
            "sha256": _sha256(Path(__file__)),
        },
        "analysis_runtime": {
            "python": platform.python_version(),
            "platform": platform.system(),
            "python_implementation": sys.implementation.name,
        },
        "campaign_id": manifest.get("experiment_id"),
        "campaign_schema_version": manifest.get("schema_version"),
        "campaign_status": manifest.get("status"),
        "assigned_trials": len(schedule),
        "completed_trials": len(completed),
        "failed_trials": len(failed),
        "failed_trial_records": [
            {
                "trial_id": row.get("trial_id"),
                "condition": row.get("condition"),
                "failure_reason": row.get("failure_reason"),
                "failure_artifact_sha256": input_hashes.get(f"{row.get('trial_id')}/failure.json"),
            }
            for row in failed
        ],
        "scope": {
            "host_ids": sorted({row["host_id"] for row in trials}),
            "state_category": "Windows service",
            "trial_unit": "one randomized service target; ADD and MODIFY are paired within trial",
            "positive_label": (
                "the protocol performed a controlled service creation and start-mode modification"
            ),
            "negative_label": "the no-change protocol performed neither target transition",
            "security_label_warning": (
                "positive means a controlled state-changing action, not malicious activity"
            ),
            "primary_transitions": list(PRIMARY_TRANSITIONS),
            "cleanup_REMOVE_excluded": True,
        },
        "baseline_definitions": {
            "event_only": (
                "both expected Wazuh events are present across alert and archive indexes, "
                "with exact host, event type, "
                "target key, and service name"
            ),
            "wazuh_alert_only": (
                "both expected exact Wazuh events are present specifically in wazuh-alerts-*; "
                "this measures native alert-index observability, not malicious-activity "
                "classification"
            ),
            "state_only": (
                "the direct-probe campaign record contains exactly one target ADD and "
                "one target MODIFY delta"
            ),
            "reconciled_csg": (
                "CSG has an exact-target finding for both deltas and marks each "
                "CONSISTENT only with its exact event, otherwise UNEXPLAINED with "
                "no event citation"
            ),
        },
        "workflow_success_counts": {
            key: {
                "successes": count,
                "trials": n_positive,
                "rate": count / n_positive if n_positive else None,
                "wilson_95": wilson_interval(count, n_positive),
            }
            for key, count in workflow_counts.items()
        },
        "transition_level": transition_summary,
        "no_change_control": {
            "completed_trials": len(no_change_trials),
            "false_positive_trials": {
                method: {
                    "count": count,
                    "rate": count / len(no_change_trials) if no_change_trials else None,
                    "wilson_95": wilson_interval(count, len(no_change_trials)),
                }
                for method, count in no_change_false_positives.items()
            },
        },
        "same_host_distractor_control": {
            "completed_trials": len(distractor_trials),
            "trials_with_verified_wrong_object_event": wrong_object_exposures,
            "wrong_object_event_rejected": wrong_object_rejections,
            "rejection_rate_given_exposure": (
                wrong_object_rejections / wrong_object_exposures if wrong_object_exposures else None
            ),
            "wilson_95": wilson_interval(wrong_object_rejections, wrong_object_exposures),
        },
        "condition_summary": condition_summary,
        "input_sha256": dict(sorted(input_hashes.items())),
        "trials": trials,
        "interpretation_limits": [
            (
                "This is a retrospective analysis of the frozen October 2 R2 campaign, "
                "not a preregistered confirmatory analysis."
            ),
            "The positive label is a controlled service-state mutation, not a ground-truth attack.",
            (
                "Event-only outcome means exact event observability, not Wazuh's native "
                "security classification quality; alert-index and archive-index evidence are "
                "reported separately."
            ),
            (
                "All trials are from one Windows 11 ARM64 endpoint; intervals do not "
                "support cross-host or production generalization."
            ),
            (
                "No-change trials test one narrow operation on this endpoint and do not "
                "estimate a general false-positive rate."
            ),
            (
                "The same-host distractor result measures object-association specificity "
                "for service creation only."
            ),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare exact Wazuh event, native CSG state, and reconciled CSG outcomes."
    )
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = analyze_campaign(args.campaign_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    printed_keys = (
        "campaign_id",
        "assigned_trials",
        "completed_trials",
        "failed_trials",
        "workflow_success_counts",
        "transition_level",
        "no_change_control",
        "same_host_distractor_control",
        "condition_summary",
    )
    print(json.dumps({key: result[key] for key in printed_keys}, indent=2))


if __name__ == "__main__":
    main()
