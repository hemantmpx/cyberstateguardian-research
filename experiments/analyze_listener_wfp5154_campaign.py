"""Independently audit raw artifacts from the frozen WFP listener campaign."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

CONDITIONS = (
    "complete_exact",
    "target_event_absent_with_distractor",
    "no_change_with_distractor",
)


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_frozen_inputs(campaign_dir: Path, freeze: dict[str, Any]) -> list[dict[str, str]]:
    frozen = campaign_dir / "frozen-source"
    paths = {
        "controller_sha256": frozen / "run_listener_wfp5154_campaign.py",
        "windows_runner_sha256": frozen / "run_listener_wfp5154_trial_windows.ps1",
        "analyzer_sha256": frozen / Path(__file__).name,
        "protocol_template_sha256": frozen / "listener-wfp5154-campaign-protocol.md",
        "protocol_sha256": campaign_dir / "PROTOCOL.md",
        "schedule_sha256": campaign_dir / "schedule.json",
    }
    expected = freeze.get("source_hashes") or {}
    actual: dict[str, str] = {}
    missing: list[str] = []
    for name, path in paths.items():
        if not path.is_file():
            missing.append(str(path.relative_to(campaign_dir)))
        else:
            actual[name] = sha256(path)
    if missing:
        raise RuntimeError(f"Frozen inputs missing: {missing}")
    if actual != expected or sha256(Path(__file__).resolve()) != expected.get("analyzer_sha256"):
        raise RuntimeError(f"Frozen input hash mismatch: expected={expected}, actual={actual}")
    return [
        {"path": path.relative_to(campaign_dir).as_posix(), "sha256": actual[name]}
        for name, path in paths.items()
    ]


def event_key(event: dict[str, Any]) -> str | None:
    return (event.get("target") or {}).get("key") or event.get("object_key")


def physical_identity(event: dict[str, Any]) -> dict[str, Any]:
    return (event.get("metadata") or {}).get("windows_event_identity") or {}


def local_matches(runner: dict[str, Any], port: int) -> list[dict[str, Any]]:
    return [
        event
        for event in runner.get("local_5154_events", [])
        if (event.get("fields") or {}).get("SourceAddress") == "127.0.0.1"
        and (event.get("fields") or {}).get("SourcePort") == str(port)
        and (event.get("fields") or {}).get("Protocol") == "6"
    ]


def provider_matches(
    events: list[dict[str, Any]], object_key: str, host_id: str
) -> list[dict[str, Any]]:
    return [
        event
        for event in events
        if event.get("normalized_type") == "listener_created"
        and event_key(event) == object_key
        and event.get("host_id") == host_id
    ]


def exact_physical_links(
    local: list[dict[str, Any]], provider: list[dict[str, Any]], expected_agent_id: str
) -> set[str]:
    local_record_ids = {str(event.get("event_record_id")) for event in local}
    return {
        str(event.get("event_id"))
        for event in provider
        if str(physical_identity(event).get("event_record_id")) in local_record_ids
        and str(physical_identity(event).get("agent_id")) == expected_agent_id
        and physical_identity(event).get("event_code") == "5154"
        and physical_identity(event).get("channel", "").lower() == "security"
        and (event.get("source_reference") or {}).get("document_id")
    }


def object_is_absent(snapshot: dict[str, Any], object_key: str) -> bool:
    return not any(obj.get("object_key") == object_key for obj in snapshot.get("objects", []))


def listener_healthy(snapshot: dict[str, Any]) -> bool:
    statuses = [
        item for item in snapshot.get("category_statuses", []) if item.get("category") == "listener"
    ]
    return bool(statuses) and all(item.get("status") == "healthy" for item in statuses)


def wilson(
    successes: int, total: int, z: float = 1.959963984540054
) -> tuple[float | None, float | None]:
    if total <= 0:
        return None, None
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    radius = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return max(0.0, center - radius), min(1.0, center + radius)


def audit_trial(
    campaign_dir: Path, trial: dict[str, Any], host_id: str, expected_agent_id: str
) -> dict[str, Any]:
    slot_dir = campaign_dir / "slots" / f"slot-{trial['slot']:03d}" / "raw"
    required = {
        "windows": slot_dir / "windows-runner.json",
        "wazuh": slot_dir / "wazuh-observation-final.json",
        "deltas": slot_dir / "csg-target-deltas.json",
        "findings": slot_dir / "csg-target-findings.json",
        "stored_target": slot_dir / "csg-stored-target-events.json",
        "stored_distractor": slot_dir / "csg-stored-distractor-events.json",
        "state_before": slot_dir / "csg-state-before.json",
        "state_after": slot_dir / "csg-state-after.json",
        "ingest": slot_dir / "csg-event-observation-ingest.json",
    }
    missing_files = [name for name, path in required.items() if not path.exists()]
    result: dict[str, Any] = {
        "slot": trial["slot"],
        "block": trial["block"],
        "trial_id": trial["trial_id"],
        "condition": trial["condition"],
        "target_port": trial["target_port"],
        "distractor_port": trial["distractor_port"],
        "evaluable": not missing_files,
        "missing_artifacts": missing_files,
        "gate_failures": [],
    }
    if missing_files:
        result["gate_failures"].append("required_raw_artifact_missing")
        return result

    runner = load(required["windows"])
    observation = load(required["wazuh"])
    deltas = load(required["deltas"])
    findings = load(required["findings"])
    stored_target = load(required["stored_target"])
    stored_distractor = load(required["stored_distractor"])
    before = load(required["state_before"])
    after = load(required["state_after"])
    ingest = load(required["ingest"])
    target_key = f"listener:tcp:127.0.0.1:{trial['target_port']}"
    distractor_key = f"listener:tcp:127.0.0.1:{trial['distractor_port']}"

    local_target = local_matches(runner, trial["target_port"])
    local_distractor = local_matches(runner, trial["distractor_port"])
    events = observation.get("events", [])
    target_key_events = [
        event
        for event in events
        if event.get("normalized_type") == "listener_created" and event_key(event) == target_key
    ]
    distractor_key_events = [
        event
        for event in events
        if event.get("normalized_type") == "listener_created" and event_key(event) == distractor_key
    ]
    wazuh_target = provider_matches(events, target_key, host_id)
    wazuh_distractor = provider_matches(events, distractor_key, host_id)
    target_links = exact_physical_links(local_target, wazuh_target, expected_agent_id)
    distractor_links = exact_physical_links(local_distractor, wazuh_distractor, expected_agent_id)
    target_stored_links = exact_physical_links(local_target, stored_target, expected_agent_id)
    distractor_stored_links = exact_physical_links(
        local_distractor, stored_distractor, expected_agent_id
    )
    target_delta = [
        delta
        for delta in deltas
        if delta.get("object_key") == target_key
        and str(delta.get("delta_type", "")).upper() == "ADD"
    ]
    target_delta_ids = {delta.get("delta_id") for delta in target_delta}
    target_findings = [
        finding for finding in findings if finding.get("delta_id") in target_delta_ids
    ]
    target_finding = next(
        (
            finding
            for finding in target_findings
            if (finding.get("reconciliation") or {}).get("finalized")
        ),
        target_findings[-1] if target_findings else None,
    )
    reconciliation = (target_finding or {}).get("reconciliation") or {}
    matched = set(reconciliation.get("matched_evidence_ids", []))
    condition = trial["condition"]
    expected_local_target = 1 if condition == "complete_exact" else 0
    expected_wazuh_target = expected_local_target

    checks = {
        "runner_assignment_matches_frozen_schedule": runner.get("trial_id") == trial["trial_id"]
        and runner.get("condition") == condition
        and (runner.get("target") or {}).get("port") == trial["target_port"]
        and (runner.get("distractor") or {}).get("port") == trial["distractor_port"],
        "runner_completed_without_error": runner.get("failure") is None,
        "wfp_audit_restored": runner.get("audit_restored_to_baseline") is True,
        "wazuh_service_healthy_after": (runner.get("postflight") or {}).get("wazuh_service")
        == "Running",
        "probe_task_healthy_after": (runner.get("postflight") or {}).get("probe_task") == "Running",
        "target_port_cleaned": (runner.get("postflight") or {}).get("target_port_absent") is True,
        "distractor_port_cleaned": (runner.get("postflight") or {}).get("distractor_port_absent")
        is True,
        "probe_listener_healthy_before": listener_healthy(before),
        "probe_listener_healthy_after": listener_healthy(after),
        "target_absent_before": object_is_absent(before, target_key),
        "target_absent_after": object_is_absent(after, target_key),
        "local_target_event_count_expected": len(local_target) == expected_local_target,
        "local_distractor_event_exactly_once": len(local_distractor) == 1,
        "distractor_event_physical_linked": len(distractor_links) >= 1,
        "wazuh_query_complete": observation.get("query_complete") is True,
        "target_key_events_scoped_to_expected_host": all(
            event.get("host_id") == host_id for event in target_key_events
        ),
        "distractor_key_events_scoped_to_expected_host": all(
            event.get("host_id") == host_id for event in distractor_key_events
        ),
        "wazuh_coverage_complete": observation.get("coverage_status") == "COMPLETE",
        "endpoint_collection_available": observation.get("endpoint_collection_status")
        == "AVAILABLE",
        "transport_available": observation.get("transport_status") == "AVAILABLE",
        "index_available": observation.get("index_status") == "AVAILABLE",
        "csg_ingested_complete_observation": ingest.get("query_complete") is True
        and ingest.get("coverage_status") == "COMPLETE",
        "stored_target_matches_expectation": (
            len(target_stored_links) >= expected_wazuh_target
            if expected_wazuh_target
            else len(stored_target) == 0
        ),
        "stored_distractor_contains_exact_event": len(distractor_stored_links) >= 1,
    }
    if condition == "complete_exact":
        after_object = (target_delta[0].get("after") or {}) if target_delta else {}
        attrs = after_object.get("attributes") or {}
        checks.update(
            {
                "wfp_enabled_for_target": "Filtering Platform Connection"
                in (runner.get("target_audit_policy") or "")
                and "Success" in (runner.get("target_audit_policy") or ""),
                "target_event_physical_linked": len(target_links) >= 1,
                "target_add_exact_identity": bool(target_delta)
                and target_delta[0].get("before") is None
                and attrs.get("local_port") == trial["target_port"]
                and attrs.get("local_address") == "127.0.0.1"
                and attrs.get("protocol") == "tcp",
                "target_finding_finalized_consistent": bool(reconciliation.get("finalized"))
                and reconciliation.get("status") == "CONSISTENT",
                "citations_are_target_only": bool(matched)
                and matched <= target_links
                and not (matched & distractor_links),
            }
        )
    elif condition == "target_event_absent_with_distractor":
        checks.update(
            {
                "wfp_disabled_for_target": "Filtering Platform Connection"
                in (runner.get("target_audit_policy") or "")
                and "No Auditing" in (runner.get("target_audit_policy") or ""),
                "target_absent_from_wazuh": len(wazuh_target) == 0,
                "target_absent_from_csg_event_store": len(stored_target) == 0,
                "target_add_exact_identity": bool(target_delta)
                and target_delta[0].get("before") is None
                and ((target_delta[0].get("after") or {}).get("attributes") or {}).get("local_port")
                == trial["target_port"],
                "target_finding_finalized_unexplained": bool(reconciliation.get("finalized"))
                and reconciliation.get("status") == "UNEXPLAINED",
                "no_wrong_object_citation": not matched,
                "no_wrong_object_in_csg_event_store": len(stored_target) == 0,
            }
        )
    else:
        checks.update(
            {
                "wfp_disabled_after_distractor": "Filtering Platform Connection"
                in (runner.get("target_audit_policy") or "")
                and "No Auditing" in (runner.get("target_audit_policy") or ""),
                "no_target_delta": not any(
                    delta.get("object_key") == target_key for delta in deltas
                ),
                "no_target_finding": not any(
                    finding.get("object_key") == target_key for finding in findings
                ),
                "no_target_wazuh_event": len(wazuh_target) == 0,
                "no_target_csg_event": len(stored_target) == 0,
            }
        )

    result.update(
        {
            "target_object_key": target_key,
            "distractor_object_key": distractor_key,
            "local_target_5154_count": len(local_target),
            "local_distractor_5154_count": len(local_distractor),
            "wazuh_target_event_count": len(wazuh_target),
            "wazuh_distractor_event_count": len(wazuh_distractor),
            "target_event_record_ids_local": sorted(
                {str(event.get("event_record_id")) for event in local_target}
            ),
            "distractor_event_record_ids_local": sorted(
                {str(event.get("event_record_id")) for event in local_distractor}
            ),
            "target_wazuh_ids_physically_linked": sorted(target_links),
            "distractor_wazuh_ids_physically_linked": sorted(distractor_links),
            "target_csg_stored_ids_physically_linked": sorted(target_stored_links),
            "distractor_csg_stored_ids_physically_linked": sorted(distractor_stored_links),
            "target_delta_count": sum(delta.get("object_key") == target_key for delta in deltas),
            "target_finding_count": sum(
                finding.get("object_key") == target_key for finding in findings
            ),
            "target_state_add_count": len(target_delta),
            "target_add_delta_ids": sorted(str(value) for value in target_delta_ids if value),
            "target_reconciliation_status": reconciliation.get("status"),
            "target_reconciliation_finalized": reconciliation.get("finalized"),
            "target_matched_evidence_ids": sorted(str(value) for value in matched),
            "check_results": checks,
        }
    )
    result["gate_failures"] = [name for name, passed in checks.items() if not passed]
    result["all_predeclared_gates_passed"] = not result["gate_failures"]
    return result


def self_test() -> int:
    key = "listener:tcp:127.0.0.1:53001"
    local = [{"event_record_id": "12345"}]
    event = {
        "event_id": "wazuh-exact",
        "host_id": "win11-arm-lab",
        "normalized_type": "listener_created",
        "target": {"key": key},
        "metadata": {
            "windows_event_identity": {
                "agent_id": "001",
                "channel": "security",
                "event_record_id": "12345",
                "event_code": "5154",
            }
        },
        "source_reference": {"document_id": "doc-exact"},
    }
    assert provider_matches([event], key, "win11-arm-lab") == [event]
    assert provider_matches([event], key, "other-host") == []
    assert exact_physical_links(local, [event], "001") == {"wazuh-exact"}
    wrong_record = {
        **event,
        "metadata": {
            "windows_event_identity": {
                **event["metadata"]["windows_event_identity"],
                "event_record_id": "54321",
            }
        },
    }
    wrong_agent = {
        **event,
        "metadata": {
            "windows_event_identity": {
                **event["metadata"]["windows_event_identity"],
                "agent_id": "002",
            }
        },
    }
    assert not exact_physical_links(local, [wrong_record], "001")
    assert not exact_physical_links(local, [wrong_agent], "001")
    print(
        "Analyzer self-test passed: host, agent, EventID, channel, "
        "EventRecordID, and source ID gates."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-dir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.campaign_dir is None:
        parser.error("--campaign-dir is required unless --self-test is selected")
    campaign_dir = args.campaign_dir.resolve()
    freeze = load(campaign_dir / "campaign-freeze.json")
    schedule = load(campaign_dir / "schedule.json")["trials"]
    frozen_inputs = verify_frozen_inputs(campaign_dir, freeze)
    if len(schedule) != freeze.get("assigned_trial_count"):
        raise RuntimeError("Frozen schedule count differs from campaign freeze.")
    scheduled_ports = [
        port for trial in schedule for port in (trial["target_port"], trial["distractor_port"])
    ]
    if len(set(scheduled_ports)) != len(scheduled_ports):
        raise RuntimeError("Frozen schedule reuses a target or distractor port.")
    for block in range(1, freeze["repetitions_per_condition"] + 1):
        conditions = {trial["condition"] for trial in schedule if trial["block"] == block}
        if conditions != set(CONDITIONS):
            raise RuntimeError(f"Frozen block {block} does not contain each condition once.")
    status_path = campaign_dir / "preflight" / "wazuh-status.json"
    if not status_path.is_file():
        raise RuntimeError("Preflight Wazuh status artifact is missing.")
    status = load(status_path)
    endpoint_agent = next(
        (
            agent
            for agent in status.get("agents", [])
            if agent.get("name") == freeze["endpoint_id"] and not agent.get("manager")
        ),
        None,
    )
    if not endpoint_agent or endpoint_agent.get("status") != "active":
        raise RuntimeError("Expected active endpoint agent is absent from frozen preflight status.")
    expected_agent_id = str(endpoint_agent["id"])
    results = [
        audit_trial(campaign_dir, trial, freeze["endpoint_id"], expected_agent_id)
        for trial in schedule
    ]
    completed = [item for item in results if item.get("evaluable")]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in completed:
        grouped[result["condition"]].append(result)
    arm_summary = {}
    for condition in (
        "complete_exact",
        "target_event_absent_with_distractor",
        "no_change_with_distractor",
    ):
        items = grouped.get(condition, [])
        passed = sum(bool(item.get("all_predeclared_gates_passed")) for item in items)
        low, high = wilson(passed, len(items))
        arm_summary[condition] = {
            "assigned": sum(row["condition"] == condition for row in schedule),
            "evaluable": len(items),
            "all_gates_passed": passed,
            "descriptive_wilson_95_interval": [low, high],
            "native_state_adds": sum(item.get("target_state_add_count", 0) > 0 for item in items),
            "exact_target_events_in_wazuh": sum(
                item.get("wazuh_target_event_count", 0) > 0 for item in items
            ),
            "final_consistent": sum(
                item.get("target_reconciliation_status") == "CONSISTENT" for item in items
            ),
            "final_unexplained": sum(
                item.get("target_reconciliation_status") == "UNEXPLAINED" for item in items
            ),
            "wrong_object_cited": sum(
                bool(
                    set(item.get("target_matched_evidence_ids", []))
                    - set(item.get("target_wazuh_ids_physically_linked", []))
                )
                for item in items
            ),
            "false_target_delta_or_finding": sum(
                bool(item.get("target_delta_count")) or bool(item.get("target_finding_count"))
                for item in items
            )
            if condition == "no_change_with_distractor"
            else None,
        }
    all_complete = len(completed) == len(schedule)
    all_gates = all_complete and all(item.get("all_predeclared_gates_passed") for item in completed)
    analysis = {
        "study_id": freeze["study_id"],
        "classification": "prospective_randomized_single_host_mechanism_campaign",
        "frozen_inputs": frozen_inputs,
        "assigned_trials": len(schedule),
        "evaluable_trials": len(completed),
        "all_slots_completed": all_complete,
        "all_predeclared_gates_passed": all_gates,
        "single_host_id": freeze["endpoint_id"],
        "expected_wazuh_agent_id": expected_agent_id,
        "arms": arm_summary,
        "trial_results": results,
        "limits": [
            "One Windows host; trials share one endpoint, not independent hosts.",
            "Benign loopback listeners; no malicious behavior or attack intent was tested.",
            "The target-event-absent arm disables WFP auditing during the target action. "
            "It does not test permanent Wazuh loss or missed delivery of a Windows event.",
            "WFP Success auditing is enabled temporarily, then restored to No Auditing.",
            "Wrong-port distractors test object identity for this listener event class only.",
            "Wilson intervals are descriptive; trials share host, image, sensors, and campaign. "
            "violate an independent-host interpretation.",
            "No product-wide Wazuh superiority, malicious-detection efficacy, or cross-host "
            "generalization claim is supported.",
        ],
    }
    (campaign_dir / "analysis").mkdir(exist_ok=True)
    (campaign_dir / "analysis" / "audit.json").write_text(
        json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (campaign_dir / "analysis" / "trial-results.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        columns = [
            "slot",
            "block",
            "trial_id",
            "condition",
            "target_port",
            "distractor_port",
            "evaluable",
            "all_predeclared_gates_passed",
            "target_delta_count",
            "target_finding_count",
            "target_state_add_count",
            "local_target_5154_count",
            "wazuh_target_event_count",
            "wazuh_distractor_event_count",
            "target_reconciliation_status",
            "target_reconciliation_finalized",
            "target_matched_evidence_ids",
            "gate_failures",
        ]
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for item in results:
            row = {key: item.get(key) for key in columns}
            row["target_matched_evidence_ids"] = ";".join(
                item.get("target_matched_evidence_ids", [])
            )
            row["gate_failures"] = ";".join(item.get("gate_failures", []))
            writer.writerow(row)
    report = [
        "# WFP 5154 Randomized Listener Reconciliation Campaign",
        "",
        f"**Study:** `{freeze['study_id']}`  ",
        f"**Assigned:** {len(schedule)}; **evaluable raw bundles:** {len(completed)}  ",
        f"**Execution complete:** {str(all_complete).lower()}; "
        f"**all predeclared gates pass:** {str(all_gates).lower()}  ",
        f"**Endpoint:** `{freeze['endpoint_id']}` (one Windows VM)  ",
        "**Classification:** single-host benign mechanism evidence; not an attack-efficacy result.",
        "",
        "## Arm outcomes",
        "",
        "| Arm | Assigned | Evaluable | Gates passed | State add | Exact event | "
        "Consistent | Unexplained | Wrong ID |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    labels = {
        "complete_exact": "Complete exact event",
        "target_event_absent_with_distractor": "Target event absent + wrong-port distractor",
        "no_change_with_distractor": "No change + wrong-port distractor",
    }
    for condition in CONDITIONS:
        item = arm_summary[condition]
        report.append(
            f"| {labels[condition]} | {item['assigned']} | {item['evaluable']} | "
            f"{item['all_gates_passed']} | {item['native_state_adds']} | "
            f"{item['exact_target_events_in_wazuh']} | {item['final_consistent']} | "
            f"{item['final_unexplained']} | {item['wrong_object_cited']} |"
        )
    report.extend(
        [
            "",
            "Wilson intervals in `analysis/audit.json` are descriptive only. Trials share one host "
            "and are not independent system observations.",
            "",
            "## Interpretation boundary",
            "",
            "In the absent-event arm, WFP auditing was off while the target listener existed. "
            "A wrong-port Event 5154 was collected during temporary WFP auditing. The arm "
            "tests whether CSG retains the target state and rejects wrong-object evidence under an "
            "endpoint event-coverage gap. It does not test permanent Wazuh loss or missed delivery "
            "for an event Windows emitted. Listeners are benign; this is not malicious-activity "
            "detection or product-wide Wazuh comparison.",
            "",
            "All slots, gate failures, raw Windows/Wazuh records, CSG deltas/findings, and cleanup "
            "proofs are retained under `slots/`. See the protocol, schedule, freeze, audit, and "
            "trial-results CSV.",
        ]
    )
    (campaign_dir / "RESULTS.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    manifest = []
    manifest_path = campaign_dir / "analysis" / "artifact-manifest.json"
    for path in sorted(campaign_dir.rglob("*")):
        if path.is_file() and path.name not in {"SHA256SUMS.txt", "artifact-manifest.json"}:
            manifest.append(
                {
                    "path": path.relative_to(campaign_dir).as_posix(),
                    "sha256": sha256(path),
                    "size_bytes": path.stat().st_size,
                }
            )
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    hashed_files = []
    for path in sorted(campaign_dir.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            hashed_files.append(path)
    (campaign_dir / "SHA256SUMS.txt").write_text(
        "".join(
            f"{sha256(path)}  {path.relative_to(campaign_dir).as_posix()}\n"
            for path in hashed_files
        ),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "assigned": len(schedule),
                "evaluable": len(completed),
                "all_complete": all_complete,
                "all_gates": all_gates,
                "arms": arm_summary,
            },
            indent=2,
        )
    )
    return 0 if all_complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
