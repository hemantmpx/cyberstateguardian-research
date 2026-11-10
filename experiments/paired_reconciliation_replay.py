"""Run deterministic, parent-linked replay conditions over a live campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from csg.domain.models import (
    EventObservationResult,
    NormalizedEvent,
    StateDelta,
)
from csg.services.reconciliation import ReconciliationEngine, ReconciliationLifecycle


def replay_campaign(campaign_path: Path, output_dir: Path, grace_seconds: int) -> dict[str, Any]:
    campaign = _read_json(campaign_path)
    engine = ReconciliationEngine(
        observation_window_seconds=0,
        event_time_tolerance_seconds=int(campaign["tolerance_seconds"]),
    )
    lifecycle = ReconciliationLifecycle(engine, grace_seconds=grace_seconds)
    cases: list[dict[str, Any]] = []
    source_dir = campaign_path.parent

    for assignment in campaign.get("schedule", []):
        trial_id = str(assignment["trial_id"])
        parent_path = source_dir / trial_id / "run.json"
        parent = _read_json(parent_path)
        parent_hash = _sha256(parent_path)
        delta_payload = next(iter((parent.get("target") or {}).get("deltas") or []), None)

        if assignment.get("condition") == "registry_no_change":
            no_change = parent.get("no_change_control") or {}
            cases.append(
                {
                    "case_id": f"{trial_id}::no_change_original",
                    "parent_trial_id": trial_id,
                    "parent_run_sha256": parent_hash,
                    "case_kind": "original_live_control_summary",
                    "condition": "no_change_control",
                    "state_delta_id": None,
                    "target_object_key": parent.get("target_object_key"),
                    "input_event_ids": [],
                    "matched_evidence_ids": [],
                    "terminal_status": "NOT_APPLICABLE",
                    "native_state_change_observed": not (
                        no_change.get("target_absent_before") is True
                        and no_change.get("target_absent_after") is True
                    ),
                    "exact_target_event_observed": False,
                    "loose_host_type_time_candidate_count": 0,
                    "false_finding": bool(
                        (no_change.get("new_delta_count") or 0)
                        or (no_change.get("new_finding_count") or 0)
                    ),
                    "passed": bool(
                        no_change.get("target_absent_before") is True
                        and no_change.get("target_absent_after") is True
                        and no_change.get("new_delta_count") == 0
                        and no_change.get("new_finding_count") == 0
                        and (parent.get("cleanup") or {}).get("target_absent") is True
                        and (parent.get("cleanup") or {}).get("distractor_absent") is True
                        and (parent.get("cleanup") or {}).get("cleanup_probe_succeeded") is True
                    ),
                    "derived_interventions": [],
                }
            )
            continue

        if delta_payload is None:
            cases.append(_invalid_case(trial_id, parent_hash, "missing_state_delta"))
            continue

        delta = StateDelta.model_validate(delta_payload)
        if assignment.get("condition") == "registry_wrong_object":
            distractor_ids = set(
                (parent.get("bounded_distractor") or {}).get("wrong_object_event_ids") or []
            )
            distractor_payloads = [
                item
                for item in (parent.get("source_event_ingestion") or {}).get(
                    "database_verified", []
                )
                if item.get("event_id") in distractor_ids
            ]
            distractors = [NormalizedEvent.model_validate(item) for item in distractor_payloads]
            result = lifecycle.evaluate(
                delta,
                distractors,
                now=_deadline(engine, delta, grace_seconds) + timedelta(seconds=1),
                event_observation=_observation(distractors, complete=True),
            )
            expected_window = engine.observation_window_for_delta(delta)
            target = parent.get("target") or {}
            service = parent.get("wazuh_service") or {}
            service_before = service.get("before") or {}
            service_during = service.get("during") or {}
            service_after = service.get("after") or {}
            action = (parent.get("action_journal") or {}).get("target_create") or {}
            action_at = _parse_time(action.get("started_at"))
            stopped_at = _parse_time(service_during.get("captured_at"))
            restored_at = _parse_time(service_after.get("captured_at"))
            stopped_and_restored = bool(
                service_before.get("status") == "Running"
                and int(service_before.get("process_id") or 0) > 0
                and service_during.get("status") == "Stopped"
                and int(service_during.get("process_id") or 0) == 0
                and service_after.get("status") == "Running"
                and int(service_after.get("process_id") or 0) > 0
                and action.get("exit_code") == 0
                and action_at
                and stopped_at
                and restored_at
                and stopped_at <= action_at <= restored_at
            )
            wrong_target_verified = bool(distractors) and all(
                (item.target.get("key") or "").casefold() != delta.object_key.casefold()
                and (item.target.get("key") or "").casefold()
                == str(parent.get("distractor_object_key") or "").casefold()
                and item.normalized_type == "registry_value_modified"
                and bool(item.source_reference.get("document_id"))
                for item in distractors
            )
            case = _case(
                trial_id,
                parent_hash,
                "same_host_wrong_object_live",
                delta,
                distractors,
                [result],
                passed=(
                    bool(distractors)
                    and wrong_target_verified
                    and stopped_and_restored
                    and all(item.host_id == delta.host_id for item in distractors)
                    and all(
                        expected_window.start <= item.event_time <= expected_window.end
                        for item in distractors
                    )
                    and not result.matched_evidence_ids
                    and result.status.value == "UNEXPLAINED"
                    and not (target.get("wazuh_provider_exact_events") or [])
                ),
                intervention={"kind": "none", "source": "captured_live_distractor"},
            )
            case.update(
                {
                    "native_state_change_observed": (parent.get("target_state") or {}).get(
                        "present_after"
                    ),
                    "exact_target_event_observed": bool(
                        target.get("wazuh_provider_exact_events") or []
                    ),
                    "loose_host_type_time_candidate_count": sum(
                        event.host_id == delta.host_id
                        and event.normalized_type == "registry_value_modified"
                        and expected_window.start <= event.event_time <= expected_window.end
                        for event in distractors
                    ),
                    "wazuh_service_stop_and_restore_verified": stopped_and_restored,
                    "distractor_evidence_identity_verified": wrong_target_verified,
                    "false_finding": False,
                }
            )
            cases.append(case)
            continue

        event_payloads = (parent.get("target") or {}).get("database_exact_events") or []
        events = [NormalizedEvent.model_validate(item) for item in event_payloads]
        target_events = [
            event
            for event in events
            if event.host_id == delta.host_id
            and event.normalized_type == "registry_value_modified"
            and (event.target.get("key") or "").casefold() == delta.object_key.casefold()
        ]
        observed = _observation(events, complete=True)
        captured_result = lifecycle.evaluate(
            delta,
            events,
            now=delta.observation_window.end + timedelta(seconds=1),
            event_observation=observed,
        )
        case = _case(
            trial_id,
            parent_hash,
            "captured_complete",
            delta,
            events,
            [captured_result],
            passed=(
                bool(target_events)
                and captured_result.status.value == "CONSISTENT"
                and set(captured_result.matched_evidence_ids)
                == {item.event_id for item in target_events}
            ),
            intervention={"kind": "none", "source": "captured_wazuh_database_events"},
        )
        case.update(
            {
                "native_state_change_observed": (parent.get("target_state") or {}).get(
                    "present_after"
                ),
                "exact_target_event_observed": bool(target_events),
                "loose_host_type_time_candidate_count": sum(
                    event.host_id == delta.host_id
                    and event.normalized_type == "registry_value_modified"
                    and engine.observation_window_for_delta(delta).start
                    <= event.event_time
                    <= engine.observation_window_for_delta(delta).end
                    for event in events
                ),
                "false_finding": False,
            }
        )
        cases.append(case)

        missing_result = lifecycle.evaluate(
            delta,
            [],
            now=_deadline(engine, delta, grace_seconds) + timedelta(seconds=1),
            event_observation=_observation([], complete=True),
        )
        cases.append(
            _case(
                trial_id,
                parent_hash,
                "primary_event_removed_healthy_query",
                delta,
                [],
                [missing_result],
                passed=(
                    missing_result.status.value == "UNEXPLAINED"
                    and missing_result.finalized
                    and not missing_result.matched_evidence_ids
                ),
                intervention={
                    "kind": "derived_event_removal",
                    "removed_event_ids": [item.event_id for item in target_events],
                    "collection_health": "AVAILABLE",
                    "query_status": "COMPLETE",
                },
            )
        )

        conflict_events = [_conflict_event(item) for item in target_events]
        conflict_result = lifecycle.evaluate(
            delta,
            conflict_events,
            now=_deadline(engine, delta, grace_seconds) + timedelta(seconds=1),
            event_observation=_observation(conflict_events, complete=True),
        )
        cases.append(
            _case(
                trial_id,
                parent_hash,
                "same_object_wrong_value_conflict",
                delta,
                conflict_events,
                [conflict_result],
                passed=(
                    bool(target_events)
                    and conflict_result.status.value == "UNEXPLAINED"
                    and not conflict_result.matched_evidence_ids
                    and bool(conflict_result.metadata.get("transition_mismatches"))
                    and conflict_result.metadata.get("reconciliation_semantics") == "CONTRADICTED"
                ),
                intervention={
                    "kind": "derived_transition_conflict",
                    "description": (
                        "Kept host, target, type, and source time; changed event value data."
                    ),
                    "source_event_ids": [item.event_id for item in target_events],
                },
            )
        )

        duplicated = [*reversed(events), *(item.model_copy() for item in events)]
        duplicate_result = lifecycle.evaluate(
            delta,
            duplicated,
            now=delta.observation_window.end + timedelta(seconds=1),
            event_observation=_observation(duplicated, complete=True),
        )
        cases.append(
            _case(
                trial_id,
                parent_hash,
                "duplicate_and_reordered_delivery",
                delta,
                duplicated,
                [duplicate_result],
                passed=(
                    duplicate_result.status.value == "CONSISTENT"
                    and set(duplicate_result.matched_evidence_ids)
                    == {item.event_id for item in target_events}
                    and len(duplicate_result.matched_evidence_ids)
                    == len(set(duplicate_result.matched_evidence_ids))
                ),
                intervention={
                    "kind": "derived_retransmission_and_reorder",
                    "input_event_ids": [item.event_id for item in duplicated],
                },
            )
        )

        partial_observation = _observation([], complete=False)
        pending = lifecycle.evaluate(
            delta,
            [],
            now=delta.observation_window.end + timedelta(seconds=1),
            event_observation=partial_observation,
        )
        arrived_in_grace = lifecycle.evaluate(
            delta,
            events,
            now=delta.observation_window.end + timedelta(seconds=min(30, grace_seconds - 1)),
            previous=pending,
            event_observation=observed,
        )
        cases.append(
            _case(
                trial_id,
                parent_hash,
                "simulated_arrival_within_grace",
                delta,
                events,
                [pending, arrived_in_grace],
                passed=(
                    pending.status.value == "PENDING_EVIDENCE"
                    and arrived_in_grace.status.value == "CONSISTENT"
                    and arrived_in_grace.version == 2
                    and arrived_in_grace.supersedes_reconciliation_id == pending.reconciliation_id
                ),
                intervention={
                    "kind": "simulated_receipt_schedule",
                    "receipt_offset_seconds": min(30, grace_seconds - 1),
                    "source_event_time_unchanged": True,
                },
            )
        )

        pending_late = lifecycle.evaluate(
            delta,
            [],
            now=delta.observation_window.end + timedelta(seconds=1),
            event_observation=partial_observation,
        )
        cutoff = lifecycle.evaluate(
            delta,
            [],
            now=_deadline(engine, delta, grace_seconds) + timedelta(seconds=1),
            previous=pending_late,
            event_observation=_observation([], complete=True),
        )
        arrived_after_cutoff = lifecycle.evaluate(
            delta,
            events,
            now=_deadline(engine, delta, grace_seconds) + timedelta(seconds=30),
            previous=cutoff,
            event_observation=observed,
        )
        cases.append(
            _case(
                trial_id,
                parent_hash,
                "simulated_arrival_after_cutoff",
                delta,
                events,
                [pending_late, cutoff, arrived_after_cutoff],
                passed=(
                    pending_late.status.value == "PENDING_EVIDENCE"
                    and cutoff.status.value == "UNEXPLAINED"
                    and cutoff.finalized
                    and arrived_after_cutoff.status.value == "CONSISTENT"
                    and arrived_after_cutoff.version == 3
                    and arrived_after_cutoff.supersedes_reconciliation_id
                    == cutoff.reconciliation_id
                ),
                intervention={
                    "kind": "simulated_receipt_schedule",
                    "receipt_offset_seconds": (campaign["tolerance_seconds"] + grace_seconds + 30),
                    "source_event_time_unchanged": True,
                    "terminal_cutoff_seconds": (campaign["tolerance_seconds"] + grace_seconds),
                },
            )
        )

        unavailable = EventObservationResult(
            events=[],
            query_complete=False,
            endpoint_collection_status="UNAVAILABLE",
            transport_status="AVAILABLE",
            index_status="AVAILABLE",
            coverage_status="UNAVAILABLE",
            metadata={"derived_replay_condition": "endpoint_capture_unavailable"},
        )
        unavailable_result = lifecycle.evaluate(
            delta,
            [],
            now=_deadline(engine, delta, grace_seconds) + timedelta(seconds=1),
            event_observation=unavailable,
        )
        cases.append(
            _case(
                trial_id,
                parent_hash,
                "simulated_endpoint_collection_unavailable",
                delta,
                [],
                [unavailable_result],
                passed=(
                    unavailable_result.status.value == "UNEXPLAINED"
                    and unavailable_result.finalized
                    and unavailable_result.metadata.get("reconciliation_semantics")
                    == "UNCORROBORATED_DEGRADED"
                    and unavailable_result.metadata.get("event_retrieval_complete") is False
                ),
                intervention={
                    "kind": "derived_source_health_condition",
                    "endpoint_collection_status": "UNAVAILABLE",
                    "transport_status": "AVAILABLE",
                    "index_status": "AVAILABLE",
                },
            )
        )

    summary = _summarize(campaign, cases, grace_seconds)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "case-outcomes.jsonl").write_text(
        "".join(json.dumps(case, sort_keys=True) + "\n" for case in cases), encoding="utf-8"
    )
    (output_dir / "aggregate.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "RESULTS.md").write_text(_render_results(summary), encoding="utf-8")
    return summary


def _observation(events: list[NormalizedEvent], *, complete: bool) -> EventObservationResult:
    return EventObservationResult(
        events=events,
        query_complete=complete,
        endpoint_collection_status="AVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE" if complete else "PARTIAL",
        retrieved_count=len(events),
        total_hits=len(events) if complete else None,
        metadata={"derived_replay": True},
    )


def _deadline(engine: ReconciliationEngine, delta: StateDelta, grace_seconds: int):
    return engine.observation_window_for_delta(delta).end + timedelta(seconds=grace_seconds)


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)


def _conflict_event(event: NormalizedEvent) -> NormalizedEvent:
    attributes = dict(event.attributes)
    key = (
        "value"
        if "value" in attributes
        else "new_value"
        if "new_value" in attributes
        else "details"
    )
    attributes[key] = f"{attributes.get(key, '')} [CSG-DERIVED-CONFLICT]"
    return event.model_copy(update={"attributes": attributes})


def _case(
    trial_id: str,
    parent_hash: str,
    condition: str,
    delta: StateDelta,
    events: list[NormalizedEvent],
    revisions: list[Any],
    *,
    passed: bool,
    intervention: dict[str, Any],
) -> dict[str, Any]:
    latest = revisions[-1]
    return {
        "case_id": f"{trial_id}::{condition}",
        "parent_trial_id": trial_id,
        "parent_run_sha256": parent_hash,
        "case_kind": "derived_offline_replay",
        "condition": condition,
        "state_delta_id": delta.delta_id,
        "host_id": delta.host_id,
        "target_object_key": delta.object_key,
        "input_event_ids": [event.event_id for event in events],
        "matched_evidence_ids": latest.matched_evidence_ids,
        "revision_history": [item.model_dump(mode="json") for item in revisions],
        "terminal_status": latest.status.value,
        "terminal_finalized": latest.finalized,
        "transition_mismatches": latest.metadata.get("transition_mismatches", []),
        "reconciliation_semantics": latest.metadata.get("reconciliation_semantics"),
        "passed": passed,
        "derived_interventions": [intervention],
    }


def _invalid_case(trial_id: str, parent_hash: str, reason: str) -> dict[str, Any]:
    return {
        "case_id": f"{trial_id}::invalid",
        "parent_trial_id": trial_id,
        "parent_run_sha256": parent_hash,
        "case_kind": "invalid_original_artifact",
        "condition": "excluded_invalid_parent",
        "passed": False,
        "exclusion_reason": reason,
        "derived_interventions": [],
    }


def _summarize(
    campaign: dict[str, Any], cases: list[dict[str, Any]], grace_seconds: int
) -> dict[str, Any]:
    conditions: dict[str, Any] = {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        grouped[case["condition"]].append(case)
    for name, rows in grouped.items():
        passed = sum(row.get("passed") is True for row in rows)
        conditions[name] = {
            "cases": len(rows),
            "passed": passed,
            "failed": len(rows) - passed,
            "pass_rate": _proportion(passed, len(rows)),
            "terminal_status_counts": dict(
                Counter(str(row.get("terminal_status", "MISSING")) for row in rows)
            ),
            "parent_trial_ids": [row["parent_trial_id"] for row in rows],
        }
    return {
        "schema_version": "csg-paired-reconciliation-replay-v1",
        "campaign_id": campaign.get("experiment_id"),
        "campaign_protocol_sha256": campaign.get("protocol_sha256"),
        "campaign_status": campaign.get("status"),
        "host_id": campaign.get("host_id"),
        "live_original_executions": campaign.get("repetitions_per_condition", 0)
        * len(campaign.get("declared_conditions", [])),
        "derived_replay_rows_are_not_new_live_trials": True,
        "event_time_tolerance_seconds": campaign.get("tolerance_seconds"),
        "reconciliation_grace_seconds": grace_seconds,
        "conditions": conditions,
        "exploratory_live_method_comparison": _live_method_comparison(cases),
        "limitations": [
            (
                "All derived cases reuse evidence from the same live parent executions; replay "
                "rows are not independent action trials."
            ),
            "Receipt schedules are simulated; they do not measure Wazuh transport latency.",
            (
                "Primary-event removal and source-health states are offline interventions, not "
                "observed permanent sensor loss."
            ),
            (
                "Actions are benign registry-value writes and do not measure malicious-activity "
                "detection accuracy."
            ),
            "Repeated trials use one Windows 11 ARM VM and do not estimate between-host variation.",
        ],
    }


def _live_method_comparison(cases: list[dict[str, Any]]) -> dict[str, Any]:
    comparison: dict[str, Any] = {}
    for condition in (
        "captured_complete",
        "same_host_wrong_object_live",
        "no_change_control",
    ):
        rows = [case for case in cases if case["condition"] == condition]
        comparison[condition] = {
            "original_live_executions": len(rows),
            "native_state_changes_observed": sum(
                case.get("native_state_change_observed") is True for case in rows
            ),
            "exact_target_events_observed": sum(
                case.get("exact_target_event_observed") is True for case in rows
            ),
            "loose_host_type_time_candidate_present": sum(
                (case.get("loose_host_type_time_candidate_count") or 0) > 0 for case in rows
            ),
            "full_reconciliation_consistent": sum(
                case.get("terminal_status") == "CONSISTENT" for case in rows
            ),
            "false_findings": sum(case.get("false_finding") is True for case in rows),
        }
    comparison["interpretation"] = [
        (
            "The loose comparator intentionally ignores object identity and transition value; "
            "it is an ablation, not a Wazuh product baseline."
        ),
        "Exact-target event availability is not alert detection or maliciousness.",
        "Native state observation does not by itself attribute a change to telemetry.",
        "These counts are exploratory paired contrasts on one benign Windows endpoint.",
    ]
    return comparison


def _proportion(successes: int, denominator: int) -> dict[str, Any]:
    if denominator == 0:
        return {"successes": successes, "denominator": 0, "estimate": None, "wilson_95": None}
    z = 1.959963984540054
    p = successes / denominator
    scale = 1 + z * z / denominator
    center = (p + z * z / (2 * denominator)) / scale
    margin = z * (p * (1 - p) / denominator + z * z / (4 * denominator**2)) ** 0.5 / scale
    return {
        "successes": successes,
        "denominator": denominator,
        "estimate": round(p, 6),
        "wilson_95": [round(max(0.0, center - margin), 6), round(min(1.0, center + margin), 6)],
    }


def _render_results(summary: dict[str, Any]) -> str:
    lines = [
        "# Paired Reconciliation Replay",
        "",
        f"Campaign: `{summary['campaign_id']}`  ",
        f"Protocol SHA-256: `{summary['campaign_protocol_sha256']}`  ",
        f"Endpoint: `{summary['host_id']}`  ",
        f"Live original actions: {summary['live_original_executions']}  ",
        f"Derived replay rows: {sum(item['cases'] for item in summary['conditions'].values())}",
        "",
        "All rows below are derived from captured parent runs, not additional Windows actions.",
        (
            "Wilson intervals describe these repeated same-endpoint parents and are not "
            "population estimates."
        ),
        "",
        "| Replay condition | Parent cases | Passed | Failed | Statuses | 95% Wilson |",
        "|---|---:|---:|---:|---|---:|",
    ]
    for name, values in summary["conditions"].items():
        interval = values["pass_rate"]["wilson_95"]
        interval_text = "N/A" if interval is None else f"{interval[0]:.3f}-{interval[1]:.3f}"
        statuses = ", ".join(
            f"{key}={value}" for key, value in values["terminal_status_counts"].items()
        )
        lines.append(
            f"| `{name}` | {values['cases']} | {values['passed']} | {values['failed']} | "
            f"{statuses} | {interval_text} |"
        )
    lines.extend(
        [
            "",
            "## Exploratory Live Method Comparison",
            "",
            (
                "| Live condition | n | State changes | Exact target events | "
                "Loose host/type/time candidates | Full CSG `CONSISTENT` | False findings |"
            ),
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for condition in (
        "captured_complete",
        "same_host_wrong_object_live",
        "no_change_control",
    ):
        values = summary["exploratory_live_method_comparison"][condition]
        lines.append(
            f"| `{condition}` | {values['original_live_executions']} | "
            f"{values['native_state_changes_observed']} | "
            f"{values['exact_target_events_observed']} | "
            f"{values['loose_host_type_time_candidate_present']} | "
            f"{values['full_reconciliation_consistent']} | {values['false_findings']} |"
        )
    lines.extend(
        [
            "",
            (
                "The loose row is a deliberately weakened attribution rule, not an evaluation "
                "of Wazuh itself."
            ),
            "Configured Wazuh alert/FIM performance was not measured in this campaign.",
            "",
            "## Limits",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in summary["limitations"])
    return "\n".join(lines) + "\n"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_manifest", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--grace-seconds", type=int, default=60)
    args = parser.parse_args()
    summary = replay_campaign(args.campaign_manifest, args.output_dir, args.grace_seconds)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
