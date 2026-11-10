"""Score the preregistered Windows service reconciliation holdout."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

from scripts.validate_service_drift_result import validate

Json = dict[str, Any]
EVENT_TYPES = {"ADD": "service_created", "MODIFY": "service_modified"}
SOURCE_KINDS = ("wazuh_alert", "wazuh_archive", "unknown")


def _load(path: Path) -> Json:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source_kind(event: Json) -> str:
    metadata = event.get("metadata") or {}
    kind = str(metadata.get("source_kind") or "").lower()
    if kind in SOURCE_KINDS:
        return kind
    index = str((event.get("source_reference") or {}).get("index") or "").lower()
    if "wazuh-alerts" in index:
        return "wazuh_alert"
    if "wazuh-archives" in index:
        return "wazuh_archive"
    return "unknown"


def _event_occurrence_key(event: Json) -> tuple[str, str, str, str, str]:
    attributes = event.get("attributes") or {}
    target = event.get("target") or {}
    return (
        str(event.get("host_id") or ""),
        str(event.get("normalized_type") or ""),
        str(target.get("key") or event.get("target_key") or ""),
        str(event.get("event_time") or ""),
        str(attributes.get("event_code") or ""),
    )


def _evidence_events(snapshot: Json | None, transition: str) -> list[Json]:
    evidence = (snapshot or {}).get("verified_exact_wazuh_evidence") or {}
    return [item for item in evidence.get(EVENT_TYPES[transition], []) if isinstance(item, dict)]


def _target_delta_rows(snapshot: Json | None, service_name: str) -> list[Json]:
    target_key = f"service:{service_name.lower()}"
    return [
        item
        for item in (snapshot or {}).get("target_state_deltas", [])
        if item.get("category") == "service" and item.get("object_key") == target_key
    ]


def _transition_finding(snapshot: Json | None, service_name: str, transition: str) -> Json | None:
    target_key = f"service:{service_name.lower()}"
    expected_type = EVENT_TYPES[transition]
    delta_ids = {
        str(item.get("delta_id"))
        for item in _target_delta_rows(snapshot, service_name)
        if item.get("delta_type") == transition and item.get("delta_id")
    }
    candidates = []
    for finding in (snapshot or {}).get("findings", []):
        if finding.get("category") != "service" or finding.get("object_key") != target_key:
            continue
        reconciliation = finding.get("reconciliation") or {}
        reasons = {
            str(item.get("event_type"))
            for item in reconciliation.get("match_reasons", [])
            if item.get("event_type")
        }
        reasons.update(reconciliation.get("missing_expected_evidence_types") or [])
        if (
            reconciliation.get("delta_id") in delta_ids
            or expected_type in reasons
        ):
            candidates.append(finding)
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda item: (
            int((item.get("reconciliation") or {}).get("version") or 0),
            str((item.get("reconciliation") or {}).get("finalized_at") or ""),
        ),
    )


def _transition_result(snapshot: Json | None, service_name: str, transition: str) -> Json:
    finding = _transition_finding(snapshot, service_name, transition)
    reconciliation = (finding or {}).get("reconciliation") or {}
    events = _evidence_events(snapshot, transition)
    evidence_ids = {str(item.get("event_id")) for item in events if item.get("event_id")}
    cited_ids = {
        str(value) for value in reconciliation.get("matched_evidence_ids", []) if value
    }
    source_counts = Counter(_source_kind(item) for item in events)
    occurrences = {_event_occurrence_key(item) for item in events}
    return {
        "status": reconciliation.get("status"),
        "finalized": reconciliation.get("finalized"),
        "matched_evidence_ids": sorted(cited_ids),
        "exact_evidence_ids": sorted(evidence_ids),
        "cites_exact_target_event": bool(cited_ids & evidence_ids),
        "evidence_record_count": len(events),
        "unique_event_occurrence_count": len(occurrences),
        "source_record_counts": {kind: source_counts.get(kind, 0) for kind in SOURCE_KINDS},
        "source_unique_event_occurrence_counts": {
            kind: len(
                {
                    _event_occurrence_key(item)
                    for item in events
                    if _source_kind(item) == kind
                }
            )
            for kind in SOURCE_KINDS
        },
    }


def _windows_event_ids(record: Json, event_code: int, service_name: str) -> list[str]:
    results = []
    for event in (record.get("windows_source_evidence") or {}).get("events", []):
        message = str(event.get("message") or "").lower()
        values = event.get("event_data") or {}
        value_text = json.dumps(values, sort_keys=True).lower()
        if int(event.get("event_id") or 0) == event_code and (
            service_name.lower() in message or service_name.lower() in value_text
        ):
            results.append(str(event.get("record_id") or event.get("event_id")))
    return results


def _check_map(validation: Json) -> dict[str, Json]:
    return {str(item.get("name")): item for item in validation.get("checks", [])}


def _probe_schedule_isolated(proof: Json) -> bool:
    if proof.get("status") == "not_installed":
        return True
    return all(
        proof.get(key) is expected
        for key, expected in (
            ("enabled_before", True),
            ("enabled_during_trial", False),
            ("enabled_after", True),
        )
    )


def _wilson(successes: int, total: int) -> Json:
    if total == 0:
        return {"successes": 0, "total": 0, "rate": None, "ci95": [None, None]}
    z = 1.959963984540054
    rate = successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    return {
        "successes": successes,
        "total": total,
        "rate": rate,
        "ci95": [max(0.0, center - margin), min(1.0, center + margin)],
    }


def _score_trial(path: Path, run: Json) -> Json:
    validation = validate(run)
    validation_path = path.parent / "validation.json"
    if not validation_path.exists():
        validation_path.write_text(json.dumps(validation, indent=2) + "\n", encoding="utf-8")
    checks = _check_map(validation)
    condition = str(run.get("telemetry_condition") or "unknown")
    service_name = str(run.get("service_name") or "")
    deltas = _target_delta_rows(run, service_name)
    delta_counts = {
        transition: sum(item.get("delta_type") == transition for item in deltas)
        for transition in EVENT_TYPES
    }
    transitions = {
        transition: _transition_result(run, service_name, transition)
        for transition in EVENT_TYPES
    }
    local_events = {
        "service_created_7045_record_ids": _windows_event_ids(run, 7045, service_name),
        "service_modified_7040_record_ids": _windows_event_ids(run, 7040, service_name),
        "query_status": (run.get("windows_source_evidence") or {}).get("query_status"),
    }
    state = run.get("state_transition") or {}
    distractor_proof = run.get("same_host_distractor_proof") or {}
    bounded = distractor_proof.get("bounded_observation") or {}
    bounded_result = _transition_result(bounded, service_name, "ADD")
    distractor_evidence = bounded.get("verified_distractor_wazuh_evidence") or {}
    distractor_events = distractor_evidence.get("service_created") or []
    no_change = state if condition == "no_change" else {}
    task_proof = run.get("probe_scheduled_task") or {}
    task_isolated = _probe_schedule_isolated(task_proof)

    if condition == "complete":
        protocol_pass = all(
            [
                run.get("run_status") == "COMPLETED",
                delta_counts == {"ADD": 1, "MODIFY": 1},
                bool(local_events["service_created_7045_record_ids"]),
                bool(local_events["service_modified_7040_record_ids"]),
                all(
                    transitions[key]["status"] == "CONSISTENT"
                    and transitions[key]["cites_exact_target_event"]
                    for key in EVENT_TYPES
                ),
                state.get("cleanup_present") is False,
                task_isolated,
            ]
        )
    elif condition == "same_host_distractor":
        protocol_pass = (
            checks.get("same_host_distractor_rejection", {}).get("passed") is True
            and task_isolated
        )
    elif condition == "no_change":
        protocol_pass = checks.get("no_change_control", {}).get("passed") is True and task_isolated
    else:
        protocol_pass = False

    return {
        "trial_id": run.get("trial_id"),
        "run_id": run.get("run_id"),
        "condition": condition,
        "service_name": service_name,
        "run_status": run.get("run_status"),
        "protocol_trial_pass": protocol_pass,
        "legacy_validator_pass": validation.get("passed"),
        "legacy_validator_failed_checks": [
            item.get("name")
            for item in validation.get("checks", [])
            if item.get("passed") is False
        ],
        "target_delta_counts": delta_counts,
        "transition_reconciliation": transitions,
        "local_windows_source_events": local_events,
        "probe_schedule_isolation": {"passed": task_isolated, "proof": task_proof},
        "bounded_distractor": {
            "target_add_status": bounded_result["status"],
            "target_add_matched_ids": bounded_result["matched_evidence_ids"],
            "wrong_object_event_count": len(distractor_events),
            "wrong_object_event_ids": [item.get("event_id") for item in distractor_events],
            "source_service_states": {
                key: (distractor_proof.get(key) or {}).get("status")
                for key in (
                    "source_before",
                    "source_during_target_add",
                    "source_after_add_restore",
                )
            },
        }
        if condition == "same_host_distractor"
        else None,
        "no_change_control": {
            "attributes_unchanged": no_change.get("attributes_unchanged"),
            "independent_os_attributes_unchanged": no_change.get(
                "independent_os_attributes_unchanged"
            ),
            "new_delta_count": no_change.get("new_target_delta_count"),
            "new_finding_count": no_change.get("new_target_finding_count"),
        }
        if condition == "no_change"
        else None,
        "timing": run.get("latency_measurements") or {},
        "validation": validation,
    }


def analyze(directory: Path) -> Json:
    manifest_path = directory / "campaign-manifest.json"
    manifest = _load(manifest_path)
    trials = [
        _score_trial(path, _load(path))
        for path in sorted(directory.glob("*/run.json"))
    ]
    condition_names = manifest.get("conditions") or []
    summaries = {}
    for condition in condition_names:
        rows = [item for item in trials if item["condition"] == condition]
        total = sum(
            entry.get("condition") == condition
            for entry in (manifest.get("schedule") or [])
        )
        metrics: dict[str, Json] = {
            "completed_artifact": _wilson(
                sum(item.get("run_status") == "COMPLETED" for item in rows), total
            ),
            "protocol_trial_pass": _wilson(
                sum(item["protocol_trial_pass"] for item in rows), total
            ),
            "probe_schedule_isolated": _wilson(
                sum(item["probe_schedule_isolation"]["passed"] for item in rows), total
            ),
        }
        if condition == "complete":
            for name, predicate in {
                "one_probe_add_and_modify_delta": lambda row: row["target_delta_counts"]
                == {"ADD": 1, "MODIFY": 1},
                "exact_local_7045_and_7040": lambda row: bool(
                    row["local_windows_source_events"]["service_created_7045_record_ids"]
                    and row["local_windows_source_events"]["service_modified_7040_record_ids"]
                ),
                "csg_exact_consistent_add_and_modify": lambda row: all(
                    row["transition_reconciliation"][key]["status"] == "CONSISTENT"
                    and row["transition_reconciliation"][key]["cites_exact_target_event"]
                    for key in EVENT_TYPES
                ),
            }.items():
                metrics[name] = _wilson(sum(predicate(row) for row in rows), total)
            for transition in EVENT_TYPES:
                for source_kind in SOURCE_KINDS:
                    metrics[f"{transition.lower()}_has_{source_kind}_exact_record"] = _wilson(
                        sum(
                            row["transition_reconciliation"][transition]["source_record_counts"][
                                source_kind
                            ]
                            > 0
                            for row in rows
                        ),
                        total,
                    )
        elif condition == "same_host_distractor":
            metrics["bounded_target_add_unexplained_no_citation"] = _wilson(
                sum(
                    row["bounded_distractor"]["target_add_status"] == "UNEXPLAINED"
                    and not row["bounded_distractor"]["target_add_matched_ids"]
                    for row in rows
                ),
                total,
            )
            metrics["wrong_object_event_verified"] = _wilson(
                sum(row["bounded_distractor"]["wrong_object_event_count"] > 0 for row in rows),
                total,
            )
            metrics["distractor_false_consistent"] = _wilson(
                sum(
                    row["bounded_distractor"]["target_add_status"] == "CONSISTENT"
                    for row in rows
                ),
                total,
            )
        elif condition == "no_change":
            metrics["no_change_false_delta_or_finding"] = _wilson(
                sum(
                    (row["no_change_control"]["new_delta_count"] or 0) > 0
                    or (row["no_change_control"]["new_finding_count"] or 0) > 0
                    for row in rows
                ),
                total,
            )
            metrics["os_and_probe_unchanged"] = _wilson(
                sum(
                    row["no_change_control"]["attributes_unchanged"] is True
                    and row["no_change_control"]["independent_os_attributes_unchanged"] is True
                    for row in rows
                ),
                total,
            )
        summaries[condition] = {
            "assigned_trials": total,
            "artifacts_received": len(rows),
            "metrics": metrics,
            "trial_ids": [item["trial_id"] for item in rows],
        }

    protocol_path = directory.parent / "PROTOCOL.md"
    analyzer_path = Path(__file__).resolve()
    return {
        "schema_version": "csg-service-reconciliation-holdout-analysis-v1",
        "campaign_id": manifest.get("experiment_id"),
        "campaign_status": manifest.get("status"),
        "protocol_sha256": (
            hashlib.sha256(protocol_path.read_bytes()).hexdigest()
            if protocol_path.exists()
            else None
        ),
        "analysis_script_sha256": hashlib.sha256(analyzer_path.read_bytes()).hexdigest(),
        "design_limits": [
            "All trials use one Windows VM and one Wazuh deployment.",
            "The 10-second tolerance was chosen using earlier calibration data.",
            "Service configuration mutations are controlled benign actions, not labeled attacks.",
            "Wilson intervals describe this fixed lab campaign and are not population estimates.",
        ],
        "trial_count_with_artifacts": len(trials),
        "conditions": summaries,
        "trials": trials,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.campaign_directory)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "trials"}, indent=2))


if __name__ == "__main__":
    main()
