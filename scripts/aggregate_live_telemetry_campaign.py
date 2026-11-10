"""Build an auditable aggregate for a copied Windows telemetry campaign."""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

Json = dict[str, Any]


def _load(path: Path) -> Json:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _transition_candidates(
    findings: list[Json], transition: str, target_key: str | None
) -> list[Json]:
    expected_type = {
        "ADD": "service_created",
        "MODIFY": "service_modified",
    }[transition]
    candidates: list[Json] = []
    for finding in findings:
        if target_key and (
            finding.get("category") != "service"
            or finding.get("object_key") != target_key
        ):
            continue
        reconciliation = finding.get("reconciliation") or {}
        if reconciliation.get("status") == "NOT_APPLICABLE":
            continue
        evidence_types = {
            item.get("event_type")
            for item in reconciliation.get("match_reasons", [])
            if item.get("event_type")
        }
        evidence_types.update(reconciliation.get("missing_expected_evidence_types") or [])
        if expected_type in evidence_types:
            candidates.append(finding)
    return candidates


def _exact_transition_event_ids(snapshot: Json, transition: str) -> set[str]:
    event_type = {"ADD": "service_created", "MODIFY": "service_modified"}[transition]
    evidence = snapshot.get("verified_exact_wazuh_evidence") or {}
    return {
        str(event.get("event_id"))
        for event in evidence.get(event_type, [])
        if event.get("event_id")
    }


def _status_for_transition(
    findings: list[Json],
    transition: str,
    target_key: str | None = None,
    exact_event_ids: set[str] | None = None,
) -> tuple[str | None, bool]:
    candidates = _transition_candidates(findings, transition, target_key)
    if not candidates:
        return None, False
    exact_event_ids = exact_event_ids or set()
    evidence_linked = [
        finding
        for finding in candidates
        if exact_event_ids.intersection(
            (finding.get("reconciliation") or {}).get("matched_evidence_ids") or []
        )
    ]
    if evidence_linked:
        candidates = evidence_linked
    latest = max(
        candidates,
        key=lambda finding: (
            int((finding.get("reconciliation") or {}).get("version") or 0),
            (finding.get("reconciliation") or {}).get("finalized") is True,
            str(
                (finding.get("reconciliation") or {}).get("finalized_at")
                or (finding.get("reconciliation") or {}).get("created_at")
                or ""
            ),
        ),
    )["reconciliation"]
    return latest.get("status"), latest.get("finalized") is True


def _snapshot_status(snapshot: Json, transition: str, target_key: str) -> str | None:
    status, _ = _status_for_transition(
        snapshot.get("findings", []),
        transition,
        target_key,
        _exact_transition_event_ids(snapshot, transition),
    )
    return status


def _trial(path: Path) -> Json:
    record = _load(path)
    evidence = record.get("verified_exact_wazuh_evidence") or {}
    state = record.get("state_transition") or {}
    proof = record.get("capture_drop_proof") or {}
    delay_proof = record.get("telemetry_delay_proof") or {}
    latency = record.get("latency_measurements") or {}
    validation_path = path.parent / "validation.json"
    validation = _load(validation_path) if validation_path.exists() else {}
    evidence_ids = {
        event.get("event_id")
        for key in ("service_created", "service_modified")
        for event in evidence.get(key, [])
        if event.get("event_id")
    }
    target_key = f"service:{str(record.get('service_name') or '').lower()}"
    transition_statuses = {
        transition: _status_for_transition(
            record.get("findings", []),
            transition,
            target_key,
            _exact_transition_event_ids(record, transition),
        )[0]
        for transition in ("ADD", "MODIFY")
    }
    transition_delta_counts = {}
    for transition in ("ADD", "MODIFY"):
        candidates = _transition_candidates(record.get("findings", []), transition, target_key)
        transition_delta_counts[transition] = len(
            {
                str(
                    (finding.get("reconciliation") or {}).get("delta_id")
                    or finding.get("finding_id")
                )
                for finding in candidates
            }
        )
    target_service_finding_count = sum(
        finding.get("category") == "service" and finding.get("object_key") == target_key
        for finding in record.get("findings", [])
    )
    proof_statuses = proof.get("wazuh_service_proof") or {}
    source_proof_statuses = proof_statuses or delay_proof.get("wazuh_service_proof") or {}
    return {
        "trial_id": record.get("trial_id"),
        "run_id": record.get("run_id"),
        "service_name": record.get("service_name"),
        "condition": record.get("telemetry_condition"),
        "run_status": record.get("run_status"),
        "target_service_finding_count": target_service_finding_count,
        "validation_schema": validation.get("schema_version"),
        "validation_passed": validation.get("passed"),
        "state_observed": bool(
            state.get("before")
            and state.get("after")
            and state.get("before_observation_id")
            and state.get("after_observation_id")
        ),
        "raw_state_observation_ids": {
            key: state.get(key)
            for key in ("before_observation_id", "after_observation_id")
        },
        "raw_state": {key: state.get(key) for key in ("before", "after")},
        "exact_event_counts": {
            "service_created": evidence.get("exact_create_count", 0),
            "service_modified": evidence.get("exact_modify_count", 0),
        },
        "exact_event_ids": sorted(evidence_ids),
        "transition_event_status": (record.get("event_plane_status") or {}).get(
            "transition_event_status", {}
        ),
        "event_plane_status": {
            "event_query_status": (record.get("event_plane_status") or {}).get(
                "event_query_status"
            ),
            "endpoint_collection_status": (record.get("event_plane_status") or {}).get(
                "endpoint_collection_status"
            ),
            "central_index_status": (record.get("event_plane_status") or {}).get(
                "central_index_status",
                (record.get("event_plane_status") or {}).get("indexer_status"),
            ),
        },
        "final_transition_reconciliation": transition_statuses,
        "target_transition_delta_counts": transition_delta_counts,
        "finalized_transitions": {
            transition: _status_for_transition(
                record.get("findings", []),
                transition,
                target_key,
                _exact_transition_event_ids(record, transition),
            )[1]
            for transition in ("ADD", "MODIFY")
        },
        "capture_drop_pre_restore": {
            transition: _snapshot_status(
                proof.get("bounded_observation") or {}, transition, target_key
            )
            for transition in ("ADD", "MODIFY")
        },
        "capture_drop_post_restore": {
            transition: _snapshot_status(
                proof.get("post_restore_recovery") or {}, transition, target_key
            )
            for transition in ("ADD", "MODIFY")
        },
        "source_service_proof": {
            name: (source_proof_statuses.get(name) or {}).get("status")
            for name in (
                "before_stop",
                "during_drop",
                "after_restore",
                "before_pause",
                "during_pause",
                "after_pause",
            )
            if name in source_proof_statuses
        },
        "latency": {
            key: latency.get(key)
            for key in (
                "valid",
                "state_detection_seconds",
                "event_action_to_event_seconds",
                "event_to_query_seconds",
            )
        },
    }


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(float(value) for value in values)
    position = (len(ordered) - 1) * percentile / 100
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _distribution(values: list[float]) -> Json:
    q1 = _percentile(values, 25)
    q3 = _percentile(values, 75)
    count = len(values)
    return {
        "count": count,
        "median": statistics.median(values) if values else None,
        "q1": q1,
        "q3": q3,
        "iqr": q3 - q1 if q1 is not None and q3 is not None else None,
        "p95": _percentile(values, 95),
        "p99": _percentile(values, 99) if count >= 100 else None,
        "p99_note": None if count >= 100 else "not estimated for fewer than 100 observations",
        "min": min(values) if values else None,
        "max": max(values) if values else None,
    }


def _wilson_rate(successes: int, total: int) -> Json:
    if total == 0:
        return {"successes": successes, "total": 0, "rate": None, "ci95": None}
    z = 1.959963984540054
    observed = successes / total
    denominator = 1 + z**2 / total
    center = (observed + z**2 / (2 * total)) / denominator
    margin = (
        z
        * ((observed * (1 - observed) / total + z**2 / (4 * total**2)) ** 0.5)
        / denominator
    )
    return {
        "successes": successes,
        "total": total,
        "rate": observed,
        "ci95": [max(0.0, center - margin), min(1.0, center + margin)],
        "method": "Wilson score interval",
    }


def _condition_summary(condition: str, rows: list[Json]) -> Json:
    final = {
        transition: dict(
            sorted(
                Counter(
                    row["final_transition_reconciliation"].get(transition)
                    for row in rows
                ).items(),
                key=lambda item: str(item[0]),
            )
        )
        for transition in ("ADD", "MODIFY")
    }
    event_presence = {
        event_type: dict(
            sorted(
                Counter(
                    row["transition_event_status"].get(
                        "ADD" if event_type == "service_created" else "MODIFY"
                    )
                    for row in rows
                ).items(),
                key=lambda item: str(item[0]),
            )
        )
        for event_type in ("service_created", "service_modified")
    }
    latencies = {}
    for key in (
        "state_detection_seconds",
        "event_action_to_event_seconds",
        "event_to_query_seconds",
    ):
        latencies[key] = _distribution(
            [
                row["latency"].get(key)
                for row in rows
                if row["latency"].get("valid") is True
                and (key != "state_detection_seconds" or row["state_observed"])
                and isinstance(row["latency"].get(key), (int, float))
            ]
        )
    source_interruption: Json = {
        "service_proof": {
            name: dict(
                Counter(row["source_service_proof"].get(name) for row in rows)
            )
            for name in (
                "before_stop",
                "during_drop",
                "after_restore",
                "before_pause",
                "during_pause",
                "after_pause",
            )
            if any(name in row["source_service_proof"] for row in rows)
        }
    }
    if condition == "capture_drop":
        source_interruption.update(
            {
                "pre_restore_modify_status": dict(
                    Counter(
                        row["capture_drop_pre_restore"].get("MODIFY") for row in rows
                    )
                ),
                "post_restore_modify_status": dict(
                    Counter(
                        row["capture_drop_post_restore"].get("MODIFY") for row in rows
                    )
                ),
            }
        )
    elif condition == "telemetry_delay":
        source_interruption["final_transition_reconciliation"] = {
            transition: dict(
                Counter(
                    row["final_transition_reconciliation"].get(transition)
                    for row in rows
                )
            )
            for transition in ("ADD", "MODIFY")
        }
    return {
        "trial_count": len(rows),
        "validation_passed": sum(row["validation_passed"] is True for row in rows),
        "validation_failed": sum(row["validation_passed"] is False for row in rows),
        "outcome_rates": {
            "validation_passed": _wilson_rate(
                sum(row["validation_passed"] is True for row in rows), len(rows)
            ),
            "state_observed": _wilson_rate(
                sum(row["state_observed"] for row in rows), len(rows)
            ),
            "exact_create_event_once": _wilson_rate(
                sum(row["exact_event_counts"]["service_created"] == 1 for row in rows),
                len(rows),
            ),
            "exact_modify_event_once": _wilson_rate(
                sum(row["exact_event_counts"]["service_modified"] == 1 for row in rows),
                len(rows),
            ),
            "modify_final_consistent": _wilson_rate(
                sum(
                    row["final_transition_reconciliation"].get("MODIFY") == "CONSISTENT"
                    for row in rows
                ),
                len(rows),
            ),
            "no_change_target_false_finding": _wilson_rate(
                sum(row["target_service_finding_count"] > 0 for row in rows),
                len(rows),
            )
            if condition == "no_change"
            else None,
            "capture_drop_bounded_unexplained": _wilson_rate(
                sum(
                    row["capture_drop_pre_restore"].get("MODIFY") == "UNEXPLAINED"
                    for row in rows
                ),
                len(rows),
            )
            if condition == "capture_drop"
            else None,
            "capture_drop_post_restore_consistent": _wilson_rate(
                sum(
                    row["capture_drop_post_restore"].get("MODIFY") == "CONSISTENT"
                    for row in rows
                ),
                len(rows),
            )
            if condition == "capture_drop"
            else None,
        },
        "state_observed": sum(row["state_observed"] for row in rows),
        "raw_before_after_archived": sum(
            bool(row["raw_state"]["before"] and row["raw_state"]["after"])
            for row in rows
        ),
        "exact_event_counts": {
            event_type: dict(
                sorted(
                    Counter(row["exact_event_counts"].get(event_type, 0) for row in rows).items()
                )
            )
            for event_type in ("service_created", "service_modified")
        },
        "transition_event_status": event_presence,
        "final_transition_reconciliation": final,
        "target_transition_delta_counts": {
            transition: dict(
                sorted(
                    Counter(
                        row["target_transition_delta_counts"][transition]
                        for row in rows
                    ).items()
                )
            )
            for transition in ("ADD", "MODIFY")
        },
        "latency": latencies,
        "source_interruption": source_interruption
        if condition in {"capture_drop", "telemetry_delay"}
        else None,
        "trial_rows": rows,
    }


def aggregate(directory: Path) -> Json:
    rows = [_trial(path) for path in sorted(directory.glob("*/run.json"))]
    by_condition: dict[str, list[Json]] = {}
    for row in rows:
        by_condition.setdefault(row["condition"], []).append(row)
    evidence_counts = Counter(event_id for row in rows for event_id in row["exact_event_ids"])
    reused = {event_id: count for event_id, count in evidence_counts.items() if count > 1}
    return {
        "schema_version": "csg-live-telemetry-campaign-aggregate-v2",
        "campaign_manifest": str(directory / "campaign-manifest.json"),
        "statistical_methods": {
            "proportion_intervals": "95% Wilson score intervals",
            "quantiles": "linear interpolation at rank (n - 1) * p",
            "p99_reporting_rule": "reported only with at least 100 observations",
            "scope_caveat": (
                "Trials share one Windows VM and lab deployment; intervals are descriptive "
                "within this controlled setup, not cross-host generalization."
            ),
        },
        "trial_count": len(rows),
        "condition_counts": {key: len(value) for key, value in sorted(by_condition.items())},
        "all_validations_passed": all(row["validation_passed"] is True for row in rows),
        "evidence_identity": {
            "unique_exact_event_ids": len(evidence_counts),
            "reused_exact_event_ids": reused,
            "no_cross_trial_exact_event_reuse": not reused,
        },
        "conditions": {
            condition: _condition_summary(condition, condition_rows)
            for condition, condition_rows in sorted(by_condition.items())
        },
        "interpretation": [
            "Capture-drop trials prove the native state transition remained observable "
            "while the endpoint Wazuh service was stopped.",
            "A post-restore UNEXPLAINED modification means the event was not recovered "
            "in the bounded experiment; it does not by itself prove deletion from every "
            "possible Wazuh buffer.",
            "No-change trials are controls and are validated with the dedicated "
            "no-change validator; raw before/after state is intentionally not applicable.",
            "Exact evidence identity is evaluated per randomized service name and host, "
            "not by event type and time alone.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = aggregate(args.directory)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
