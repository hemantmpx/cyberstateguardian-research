"""Run parent-linked deterministic replay conditions over live scheduled-task trials."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from statistics import NormalDist
from typing import Any

from csg.domain.models import EventObservationResult, NormalizedEvent, StateDelta
from csg.services.reconciliation import ReconciliationEngine, ReconciliationLifecycle


def replay_campaign(
    manifest_path: Path,
    trials_dir: Path,
    output_dir: Path,
    *,
    grace_seconds: int = 60,
) -> dict[str, Any]:
    manifest = _read_json(manifest_path)
    engine = ReconciliationEngine(
        observation_window_seconds=0,
        event_time_tolerance_seconds=int(manifest["settings"]["event_time_tolerance_seconds"]),
    )
    parent_audits: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    invalid_parents: list[dict[str, str]] = []

    for assignment in manifest.get("trials", []):
        trial_id = str(assignment.get("trial_id") or "")
        try:
            parent, delta, target_events, distractor = _load_parent(
                trial_id, assignment, manifest, trials_dir
            )
        except (KeyError, TypeError, ValueError, OSError) as exc:
            invalid_parents.append({"trial_id": trial_id, "reason": str(exc)})
            continue

        outer_path = trials_dir / trial_id / "trial.json"
        inner_path = trials_dir / trial_id / "target-run" / "run.json"
        target_event_ids = sorted(event.event_id for event in target_events)
        parent_audits.append(
            {
                "trial_id": trial_id,
                "outer_trial_sha256": _sha256(outer_path),
                "inner_run_sha256": _sha256(inner_path),
                "target_task_name": parent["outer"]["target_task_name"],
                "distractor_task_name": parent["outer"]["distractor_task_name"],
                "target_object_key": delta.object_key,
                "state_delta": delta.model_dump(mode="json"),
                "target_events": [event.model_dump(mode="json") for event in target_events],
                "distractor_event": distractor.model_dump(mode="json"),
                "live_target_reconciliation": parent["outer"]["target_reconciliation"],
                "pre_target_event_store_readback": parent["outer"]["target_reconciliation"][
                    "distractor_availability_ordering"
                ],
                "target_event_ids": target_event_ids,
                "distractor_event_id": distractor.event_id,
            }
        )
        cases.extend(
            _replay_parent(
                trial_id,
                delta,
                target_events,
                distractor,
                engine,
                grace_seconds,
                parent["outer"]["target_reconciliation"],
            )
        )

    summary = _summarize(
        manifest_path,
        output_dir.parent / "PROTOCOL.md",
        manifest,
        parent_audits,
        cases,
        invalid_parents,
        grace_seconds,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_outputs(output_dir, summary, parent_audits, cases)
    return summary


def _load_parent(
    trial_id: str,
    assignment: dict[str, Any],
    manifest: dict[str, Any],
    trials_dir: Path,
) -> tuple[dict[str, Any], StateDelta, list[NormalizedEvent], NormalizedEvent]:
    if assignment.get("status") != "PASS":
        raise ValueError("assigned parent did not pass the frozen live trial")
    outer_path = trials_dir / trial_id / "trial.json"
    inner_path = trials_dir / trial_id / "target-run" / "run.json"
    outer = _read_json(outer_path)
    inner = _read_json(inner_path)
    if outer.get("status") != "PASS" or outer.get("cleanup_verified") is not True:
        raise ValueError("outer trial status or cleanup gate is not PASS")
    checks = outer.get("condition_checks") or {}
    if len(checks) < 9 or not all(value is True for value in checks.values()):
        raise ValueError("one or more frozen outer trial checks did not pass")
    scenarios = inner.get("scenarios") or []
    if len(scenarios) != 1:
        raise ValueError("expected exactly one archived target scenario")
    scenario = scenarios[0]
    if scenario.get("event_plane", {}).get("query_complete") is not True:
        raise ValueError("target event query was incomplete")
    deltas = [
        StateDelta.model_validate(item)
        for item in scenario.get("deltas", [])
        if item.get("category") == "scheduled_task" and item.get("delta_type") == "ADD"
    ]
    if len(deltas) != 1:
        raise ValueError(f"expected one scheduled_task ADD delta, found {len(deltas)}")
    delta = deltas[0]
    target_events = [
        NormalizedEvent.model_validate(item)
        for item in scenario.get("event_plane", {}).get("exact_matches", [])
        if item.get("normalized_type") == "scheduled_task_created"
        and (item.get("target") or {}).get("key", "").casefold() == delta.object_key.casefold()
    ]
    if not target_events:
        raise ValueError("no exact normalized target Wazuh event is archived")
    outer_rec = outer.get("target_reconciliation") or {}
    exact_ids = _as_ids(outer_rec.get("exact_target_event_ids"))
    matched_ids = _as_ids(outer_rec.get("matched_evidence_ids"))
    if (
        outer_rec.get("status") != "CONSISTENT"
        or outer_rec.get("finalized") is not True
        or not exact_ids
        or set(exact_ids) != set(matched_ids)
        or set(exact_ids) != {item.event_id for item in target_events}
    ):
        raise ValueError("live target reconciliation is not finalized exact-target-only")
    if any(item.host_id != delta.host_id for item in target_events):
        raise ValueError("target Wazuh event host differs from the state delta")
    distractor_data = (outer.get("distractor") or {}).get("exact_wazuh_event") or {}
    distractor = NormalizedEvent.model_validate(distractor_data)
    if (
        distractor.host_id != delta.host_id
        or distractor.normalized_type != "scheduled_task_created"
        or (distractor.target.get("key") or "").casefold() == delta.object_key.casefold()
        or distractor.event_id in exact_ids
    ):
        raise ValueError("distractor is not a distinct same-host, same-class event")
    ordering = outer_rec.get("distractor_availability_ordering") or {}
    readback_at = _parse_time(ordering.get("distractor_event_store_readback_at_utc"))
    query_at = _parse_time(ordering.get("target_wazuh_query_started_at_utc"))
    if (
        not readback_at
        or not query_at
        or readback_at >= query_at
        or ordering.get("store_readback_preceded_target_query_start") is not True
    ):
        raise ValueError("distractor event-store readback did not precede target query start")
    if manifest.get("status") != "COMPLETED":
        raise ValueError("parent campaign is not completed")
    return {"outer": outer, "scenario": scenario}, delta, target_events, distractor


def _replay_parent(
    trial_id: str,
    delta: StateDelta,
    target_events: list[NormalizedEvent],
    distractor: NormalizedEvent,
    engine: ReconciliationEngine,
    grace_seconds: int,
    live_reconciliation: dict[str, Any],
) -> list[dict[str, Any]]:
    lifecycle = ReconciliationLifecycle(engine, grace_seconds=grace_seconds)
    target_ids = sorted(event.event_id for event in target_events)
    events = [*target_events, distractor]
    window = engine.observation_window_for_delta(delta)
    cutoff = window.end + timedelta(seconds=grace_seconds)
    records: list[dict[str, Any]] = []

    complete = lifecycle.evaluate(
        delta,
        events,
        now=cutoff + timedelta(seconds=1),
        event_observation=_observation(events, complete=True),
    )
    loose_candidates = [
        event
        for event in events
        if event.host_id == delta.host_id
        and event.normalized_type == "scheduled_task_created"
        and window.start <= event.event_time <= window.end
    ]
    records.append(
        _case(
            trial_id,
            "complete_with_distractor",
            delta,
            events,
            [complete],
            passed=(
                complete.status.value == "CONSISTENT"
                and complete.finalized
                and set(complete.matched_evidence_ids) == set(target_ids)
            ),
            evidence_ids=target_ids,
            loose_candidate_count=len(loose_candidates),
            state_change_observed=True,
            intervention="unchanged parent events; deterministic engine replay",
        )
    )

    wrong_object_only = [distractor]
    removed = lifecycle.evaluate(
        delta,
        wrong_object_only,
        now=cutoff + timedelta(seconds=1),
        event_observation=_observation(wrong_object_only, complete=True),
    )
    records.append(
        _case(
            trial_id,
            "target_removed_distractor_retained",
            delta,
            wrong_object_only,
            [removed],
            passed=(
                removed.status.value == "UNEXPLAINED"
                and removed.finalized
                and not removed.matched_evidence_ids
                and removed.metadata.get("event_retrieval_complete") is True
            ),
            evidence_ids=[],
            loose_candidate_count=len(
                [
                    event
                    for event in wrong_object_only
                    if event.host_id == delta.host_id
                    and event.normalized_type == "scheduled_task_created"
                    and window.start <= event.event_time <= window.end
                ]
            ),
            state_change_observed=True,
            intervention=(
                "derived removal of target event; retain wrong-object event; query complete/healthy"
            ),
        )
    )

    unavailable_observation = _observation(
        [],
        complete=False,
        endpoint_status="UNAVAILABLE",
        coverage="UNAVAILABLE",
        metadata={
            "source_degradation_interval": {
                "start": window.start.isoformat(),
                "end": window.end.isoformat(),
            },
            "affected_object_keys": [delta.object_key],
        },
    )
    unavailable = lifecycle.evaluate(
        delta,
        [],
        now=cutoff + timedelta(seconds=1),
        event_observation=unavailable_observation,
    )
    records.append(
        _case(
            trial_id,
            "source_unavailable_replay",
            delta,
            [],
            [unavailable],
            passed=(
                unavailable.status.value == "UNEXPLAINED"
                and unavailable.finalized
                and unavailable.metadata.get("source_health_known_degraded") is True
                and not unavailable.matched_evidence_ids
            ),
            evidence_ids=[],
            loose_candidate_count=0,
            state_change_observed=True,
            intervention="derived unavailable endpoint collection; not a live Wazuh outage",
        )
    )

    partial = _observation([], complete=False, coverage="PARTIAL")
    pending = lifecycle.evaluate(
        delta,
        [],
        now=window.end + timedelta(seconds=1),
        event_observation=partial,
    )
    within_grace = lifecycle.evaluate(
        delta,
        target_events,
        now=cutoff - timedelta(seconds=1),
        previous=pending,
        event_observation=_observation(target_events, complete=True),
    )
    records.append(
        _case(
            trial_id,
            "target_arrives_within_grace",
            delta,
            target_events,
            [pending, within_grace],
            passed=(
                pending.status.value == "PENDING_EVIDENCE"
                and within_grace.status.value == "CONSISTENT"
                and within_grace.finalized
                and within_grace.version == 2
                and set(within_grace.matched_evidence_ids) == set(target_ids)
            ),
            evidence_ids=target_ids,
            loose_candidate_count=len(target_events),
            state_change_observed=True,
            intervention=(
                "derived receipt before 60-second grace cutoff; event timestamps unchanged"
            ),
        )
    )

    late_pending = lifecycle.evaluate(
        delta,
        [],
        now=window.end + timedelta(seconds=1),
        event_observation=partial,
    )
    terminal = lifecycle.evaluate(
        delta,
        [],
        now=cutoff + timedelta(seconds=1),
        previous=late_pending,
        event_observation=_observation([], complete=True),
    )
    late_arrival = lifecycle.evaluate(
        delta,
        target_events,
        now=cutoff + timedelta(seconds=30),
        previous=terminal,
        event_observation=_observation(target_events, complete=True),
    )
    records.append(
        _case(
            trial_id,
            "target_arrives_after_cutoff",
            delta,
            target_events,
            [late_pending, terminal, late_arrival],
            passed=(
                late_pending.status.value == "PENDING_EVIDENCE"
                and terminal.status.value == "UNEXPLAINED"
                and terminal.finalized
                and late_arrival.status.value == "CONSISTENT"
                and late_arrival.finalized
                and late_arrival.version == 3
                and late_arrival.supersedes_reconciliation_id == terminal.reconciliation_id
                and set(late_arrival.matched_evidence_ids) == set(target_ids)
            ),
            evidence_ids=target_ids,
            loose_candidate_count=len(target_events),
            state_change_observed=True,
            intervention=(
                "derived target event arrives 30 seconds after terminal cutoff; "
                "source time unchanged"
            ),
        )
    )

    duplicated = [*reversed(events), *(item.model_copy() for item in events)]
    duplicate_result = lifecycle.evaluate(
        delta,
        duplicated,
        now=cutoff + timedelta(seconds=1),
        event_observation=_observation(duplicated, complete=True),
    )
    records.append(
        _case(
            trial_id,
            "duplicate_reordered_delivery",
            delta,
            duplicated,
            [duplicate_result],
            passed=(
                duplicate_result.status.value == "CONSISTENT"
                and duplicate_result.finalized
                and set(duplicate_result.matched_evidence_ids) == set(target_ids)
                and len(duplicate_result.matched_evidence_ids)
                == len(set(duplicate_result.matched_evidence_ids))
            ),
            evidence_ids=target_ids,
            loose_candidate_count=len(loose_candidates),
            state_change_observed=True,
            intervention="duplicate each event object and reverse delivery order; IDs preserved",
        )
    )

    # Keep the original reconciliation linkage visible beside the derived conditions.
    for record in records:
        record["live_parent_reconciliation_id"] = live_reconciliation.get("reconciliation_id")
        record["live_parent_finding_id"] = live_reconciliation.get("finding_id")
        record["live_parent_delta_id"] = live_reconciliation.get("delta_id")
    return records


def _case(
    trial_id: str,
    condition: str,
    delta: StateDelta,
    events: list[NormalizedEvent],
    revisions: list[Any],
    *,
    passed: bool,
    evidence_ids: list[str],
    loose_candidate_count: int,
    state_change_observed: bool,
    intervention: str,
) -> dict[str, Any]:
    latest = revisions[-1]
    return {
        "case_id": f"{trial_id}::{condition}",
        "parent_trial_id": trial_id,
        "case_kind": "derived_offline_replay",
        "condition": condition,
        "parent_delta_id": delta.delta_id,
        "target_object_key": delta.object_key,
        "state_change_observed": state_change_observed,
        "exact_target_event_present_in_transformed_input": any(
            event.event_id in evidence_ids for event in events
        ),
        "input_event_ids": [event.event_id for event in events],
        "loose_same_host_type_time_candidate_count": loose_candidate_count,
        "matched_evidence_ids": latest.matched_evidence_ids,
        "revision_history": [item.model_dump(mode="json") for item in revisions],
        "terminal_status": latest.status.value,
        "terminal_finalized": latest.finalized,
        "source_health_known_degraded": latest.metadata.get("source_health_known_degraded"),
        "event_retrieval_complete": latest.metadata.get("event_retrieval_complete"),
        "reconciliation_semantics": latest.metadata.get("reconciliation_semantics"),
        "transition_mismatches": latest.metadata.get("transition_mismatches", []),
        "passed_derived_invariant": passed,
        "intervention": intervention,
    }


def _summarize(
    manifest_path: Path,
    protocol_path: Path,
    manifest: dict[str, Any],
    parent_audits: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    invalid_parents: list[dict[str, str]],
    grace_seconds: int,
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        grouped[case["condition"]].append(case)
    conditions = {}
    for name, rows in sorted(grouped.items()):
        passed = sum(row["passed_derived_invariant"] for row in rows)
        conditions[name] = {
            "cases": len(rows),
            "passed": passed,
            "failed": len(rows) - passed,
            "pass_rate": round(passed / len(rows), 6) if rows else None,
            "wilson_95_interval": _wilson(passed, len(rows)),
            "terminal_status_counts": dict(Counter(row["terminal_status"] for row in rows)),
        }
    target_removed = [
        row for row in cases if row["condition"] == "target_removed_distractor_retained"
    ]
    target_event_removal_ablation = {
        "parent_trials": len(target_removed),
        "state_add_retained": sum(row["state_change_observed"] for row in target_removed),
        "exact_target_event_absent_from_transformed_input": sum(
            not row["exact_target_event_present_in_transformed_input"] for row in target_removed
        ),
        "wrong_object_same_host_type_time_candidate_retained": sum(
            row["loose_same_host_type_time_candidate_count"] > 0 for row in target_removed
        ),
        "exact_reconciliation_unexplained_without_match": sum(
            row["terminal_status"] == "UNEXPLAINED"
            and not row["matched_evidence_ids"]
            and row["event_retrieval_complete"] is True
            for row in target_removed
        ),
    }
    source_root = Path(__file__).resolve().parents[1]
    reconciliation_source = source_root / "backend/csg/services/reconciliation.py"
    return {
        "schema_version": "csg-paired-task-reconciliation-replay-v1",
        "analysis_kind": "exploratory_parent_linked_counterfactual_replay",
        "campaign_id": manifest.get("campaign_id"),
        "parent_campaign_status": manifest.get("status"),
        "host_id": manifest.get("host_id"),
        "assigned_live_parents": len(manifest.get("trials", [])),
        "eligible_live_parents": len(parent_audits),
        "invalid_live_parents": invalid_parents,
        "derived_replay_rows_are_not_new_live_trials": True,
        "grace_seconds": grace_seconds,
        "event_tolerance_seconds": manifest["settings"]["event_time_tolerance_seconds"],
        "parent_manifest_sha256": _sha256(manifest_path),
        "protocol_sha256": _sha256(protocol_path),
        "replay_script_sha256": _sha256(Path(__file__).resolve()),
        "reconciliation_engine_sha256": _sha256(reconciliation_source),
        "conditions": conditions,
        "target_event_removal_ablation": target_event_removal_ablation,
        "observed_live_parent_counts": {
            "native_state_add_visible": len(parent_audits),
            "exact_target_wazuh_event_in_complete_parent": len(parent_audits),
            "live_exact_target_reconciliation_consistent": len(parent_audits),
            "note": (
                "The target-event-removal and receipt-timing cases are counterfactual replays. "
                "They are not live telemetry-loss observations or Wazuh product baselines."
            ),
        },
        "target_event_removed_counterfactual_parents": len(parent_audits),
        "parent_audits": parent_audits,
        "cases": cases,
        "interpretation_limits": [
            "All transformed cases reuse ten live parent executions from one Windows VM.",
            "Event removal, source unavailability, and receipt delays are simulated inputs.",
            "The loose host/type/time count is an ablation, not a Wazuh product baseline.",
            "The replay invokes the same deterministic implementation being exercised; it is not "
            "an independent correctness oracle.",
            "No malicious behavior, independent host, or population-level reliability is tested.",
        ],
    }


def _write_outputs(
    output_dir: Path,
    summary: dict[str, Any],
    parent_audits: list[dict[str, Any]],
    cases: list[dict[str, Any]],
) -> None:
    (output_dir / "analysis.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "parent-audit.json").write_text(
        json.dumps(parent_audits, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "cases.json").write_text(
        json.dumps(cases, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (output_dir / "cases.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = [
            "parent_trial_id",
            "condition",
            "target_object_key",
            "state_change_observed",
            "exact_target_event_present_in_transformed_input",
            "loose_same_host_type_time_candidate_count",
            "matched_evidence_ids",
            "terminal_status",
            "terminal_finalized",
            "event_retrieval_complete",
            "source_health_known_degraded",
            "passed_derived_invariant",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in cases:
            writer.writerow(
                {
                    **row,
                    "matched_evidence_ids": ";".join(row["matched_evidence_ids"]),
                }
            )
    (output_dir / "RESULTS.md").write_text(_render(summary), encoding="utf-8")


def _render(summary: dict[str, Any]) -> str:
    ablation = summary["target_event_removal_ablation"]
    ablation_text = (
        f"In this target-removal ablation, state ADD remained in "
        f"{ablation['state_add_retained']}/{ablation['parent_trials']}; exact target events "
        f"were absent in "
        f"{ablation['exact_target_event_absent_from_transformed_input']}/"
        f"{ablation['parent_trials']}; loose same-host/type/time candidates remained in "
        f"{ablation['wrong_object_same_host_type_time_candidate_retained']}/"
        f"{ablation['parent_trials']}; exact reconciliation returned `UNEXPLAINED` with no "
        f"match in {ablation['exact_reconciliation_unexplained_without_match']}/"
        f"{ablation['parent_trials']}."
    )
    lines = [
        "# Paired Scheduled-Task Distractor Replay v1",
        "",
        f"Parent campaign: `{summary['campaign_id']}`  ",
        f"Host: `{summary['host_id']}`  ",
        f"Eligible live parents: {summary['eligible_live_parents']}/"
        f"{summary['assigned_live_parents']}  ",
        "**Status: exploratory derived replay, not a new live experiment.**",
        "",
        "## Results",
        "",
        "| Derived condition | Cases | Passed invariant | Wilson 95% | Terminal statuses |",
        "|---|---:|---:|---:|---|",
    ]
    for name, result in summary["conditions"].items():
        statuses = ", ".join(
            f"{key}={value}" for key, value in result["terminal_status_counts"].items()
        )
        interval = result["wilson_95_interval"]
        interval_text = "n/a" if interval is None else f"[{interval[0]:.3f}, {interval[1]:.3f}]"
        lines.append(
            f"| `{name}` | {result['cases']} | {result['passed']}/{result['cases']} | "
            f"{interval_text} | {statuses} |"
        )
    lines.extend(
        [
            "",
            "For `target_removed_distractor_retained`, the archived native state ADD remains "
            "present, "
            "the target event is removed from the derived query input, and the wrong-task event is "
            "retained. A loose same-host/type/time candidate is therefore not sufficient for exact "
            "target attribution. This comparator is an ablation, not a Wazuh product baseline.",
            "",
            ablation_text,
            "",
            "## Interpretation Limits",
            "",
            "These cases replay the deterministic engine over ten real live parent records. "
            "Removal, unavailability, and receipt timing are simulated transformations; "
            "they do not "
            "show that Windows, Sysmon, or Wazuh lost or delayed an event in the original run. "
            "Cases are "
            "paired and dependent within parent trials; the Wilson intervals are descriptive only. "
            "The experiment tests reconciliation mechanics, not malicious-activity detection or "
            "superiority over Wazuh.",
            "",
            "Artifacts: `analysis.json`, `parent-audit.json`, `cases.json`, and `cases.csv`.",
            "",
        ]
    )
    return "\n".join(lines)


def _observation(
    events: list[NormalizedEvent],
    *,
    complete: bool,
    endpoint_status: str = "AVAILABLE",
    coverage: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> EventObservationResult:
    return EventObservationResult(
        events=events,
        query_complete=complete,
        endpoint_collection_status=endpoint_status,
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status=coverage or ("COMPLETE" if complete else "PARTIAL"),
        retrieved_count=len(events),
        total_hits=len(events) if complete else None,
        metadata={"derived_replay": True, **(metadata or {})},
    )


def _as_ids(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    return sorted({str(item) for item in value if item})


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)


def _wilson(successes: int, trials: int) -> list[float] | None:
    if trials == 0:
        return None
    z = NormalDist().inv_cdf(0.975)
    p = successes / trials
    denominator = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * trials)) / trials) / denominator
    return [round(max(0.0, center - margin), 6), round(min(1.0, center + margin), 6)]


def _read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8-sig") as handle:
        return json.load(handle)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_manifest", type=Path)
    parser.add_argument("trials_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--grace-seconds", type=int, default=60)
    args = parser.parse_args()
    if args.grace_seconds < 1:
        parser.error("--grace-seconds must be positive")
    summary = replay_campaign(
        args.campaign_manifest,
        args.trials_dir,
        args.output_dir,
        grace_seconds=args.grace_seconds,
    )
    print(
        f"parents={summary['eligible_live_parents']}/{summary['assigned_live_parents']} "
        f"derived_cases={len(summary['cases'])} "
        f"invalid_parents={len(summary['invalid_live_parents'])}"
    )


if __name__ == "__main__":
    main()
