"""Independently audit a frozen registry competing-event Windows campaign."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

Z95 = 1.959963984540054


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return data


def norm(value: Any) -> str:
    return str(value or "").strip().lower().replace("\\", "/").replace(":/", "/")


def timestamp(value: Any) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def wilson(successes: int, total: int) -> list[float] | None:
    if total == 0:
        return None
    p = successes / total
    z2 = Z95 * Z95
    denominator = 1 + z2 / total
    center = (p + z2 / (2 * total)) / denominator
    margin = Z95 * math.sqrt(p * (1 - p) / total + z2 / (4 * total * total)) / denominator
    return [max(0.0, center - margin), min(1.0, center + margin)]


def check_row(name: str, passed: bool, **details: Any) -> dict[str, Any]:
    return {"check": name, "status": "PASS" if passed else "FAIL", **details}


def exact_registry_events(events: list[dict[str, Any]], host: str, object_key: str) -> bool:
    return bool(events) and all(
        event.get("host_id") == host
        and event.get("normalized_type") == "registry_value_modified"
        and norm(event.get("target", {}).get("key")) == object_key
        for event in events
    )


def local_wazuh_physical_identity(provider_events: list[dict[str, Any]], local_events: list[dict[str, Any]]) -> bool:
    local_ids = {str(event.get("record_id")) for event in local_events}
    provider_ids = {
        str(event.get("metadata", {}).get("windows_event_identity", {}).get("event_record_id"))
        for event in provider_events
    }
    return bool(local_ids) and local_ids == provider_ids and all(
        event.get("metadata", {}).get("windows_event_identity", {}).get("event_code") == "13"
        and str(event.get("metadata", {}).get("windows_event_identity", {}).get("channel", "")).lower()
        == "microsoft-windows-sysmon/operational"
        for event in provider_events
    )


def audit_competing(run: dict[str, Any], entry: dict[str, Any], tolerance: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    target_key = norm(run.get("target_object_key"))
    distractor_key = norm(run.get("distractor_object_key"))
    target = run.get("target", {})
    source = run.get("source_event_ingestion", {})
    target_provider = target.get("wazuh_provider_exact_events", [])
    distractor_provider = source.get("provider_observation_exact_events", [])
    target_db = target.get("database_exact_events", [])
    distractor_db = source.get("database_verified", [])
    target_local = target.get("sysmon_exact_events", [])
    distractor_local = source.get("local_sysmon_exact_events", [])
    target_ids = {str(item["event_id"]) for item in target_provider if item.get("event_id")}
    distractor_ids = {str(item["event_id"]) for item in distractor_provider if item.get("event_id")}
    delta_rows = [item for item in target.get("deltas", []) if item.get("delta_type") == "ADD"]
    delta = delta_rows[0] if len(delta_rows) == 1 else {}
    after = delta.get("after") or {}
    after_key = norm(after.get("object_key") or after.get("attributes", {}).get("object_key"))

    checks.append(check_row("trial_controller_gate", entry.get("status") == "COMPLETED_PASS"
                            and entry.get("trial_pass") is True and run.get("trial_pass") is True,
                            controller_status=entry.get("status"), trial_pass=run.get("trial_pass")))
    checks.append(check_row("target_native_state_and_one_add", run.get("target_state", {}).get("absent_before") is True
                            and run.get("target_state", {}).get("present_after") is True
                            and len(delta_rows) == 1 and after_key == target_key and delta.get("before") is None,
                            absent_before=run.get("target_state", {}).get("absent_before"),
                            present_after=run.get("target_state", {}).get("present_after"),
                            add_delta_count=len(delta_rows), target_key=target_key, delta_after_key=after_key))
    checks.append(check_row("one_exact_event_per_plane_and_object",
                            len(target_provider) == len(distractor_provider) == 1
                            and len(target_db) == len(distractor_db) == 1
                            and len(target_local) == len(distractor_local) == 1,
                            target_provider=len(target_provider), distractor_provider=len(distractor_provider),
                            target_database=len(target_db), distractor_database=len(distractor_db),
                            target_local=len(target_local), distractor_local=len(distractor_local)))
    provider = source.get("provider_observation", {})
    provider_ok = (provider.get("query_complete") is True and provider.get("coverage_status") == "COMPLETE"
                   and provider.get("endpoint_collection_status") == "AVAILABLE"
                   and provider.get("transport_status") == "AVAILABLE" and provider.get("index_status") == "AVAILABLE")
    checks.append(check_row("complete_healthy_wazuh_query", provider_ok,
                            query_complete=provider.get("query_complete"), coverage=provider.get("coverage_status"),
                            endpoint=provider.get("endpoint_collection_status"), transport=provider.get("transport_status"),
                            index=provider.get("index_status")))
    identity_ok = (bool(target_key) and bool(distractor_key) and target_key != distractor_key
                   and exact_registry_events(target_provider, run.get("host_id"), target_key)
                   and exact_registry_events(distractor_provider, run.get("host_id"), distractor_key))
    checks.append(check_row("exact_same_host_type_distinct_objects", identity_ok,
                            host_id=run.get("host_id"), target_key=target_key, distractor_key=distractor_key))
    physical_ok = (local_wazuh_physical_identity(target_provider, target_local)
                   and local_wazuh_physical_identity(distractor_provider, distractor_local))
    checks.append(check_row("local_sysmon_to_wazuh_physical_event_identity", physical_ok,
                            target_local_record_ids=[event.get("record_id") for event in target_local],
                            target_wazuh_record_ids=[event.get("metadata", {}).get("windows_event_identity", {}).get("event_record_id") for event in target_provider],
                            distractor_local_record_ids=[event.get("record_id") for event in distractor_local],
                            distractor_wazuh_record_ids=[event.get("metadata", {}).get("windows_event_identity", {}).get("event_record_id") for event in distractor_provider]))
    window = delta.get("observation_window") or {}
    try:
        lower = timestamp(window["start"]) - timedelta(seconds=tolerance)
        upper = timestamp(window["end"]) + timedelta(seconds=tolerance)
        distractor_in_window = any(lower <= timestamp(event.get("event_time")) <= upper for event in distractor_provider)
        window_error = None
    except (KeyError, TypeError, ValueError) as exc:
        distractor_in_window = False
        window_error = str(exc)
    checks.append(check_row("distractor_inside_target_window_plus_tolerance", distractor_in_window,
                            window_start=window.get("start"), window_end=window.get("end"),
                            tolerance_seconds=tolerance, error=window_error))
    history = target.get("reconciliation_history", [])
    final = history[-1].get("latest", {}) if history else {}
    matched = {str(item) for item in final.get("matched_evidence_ids", [])}
    checks.append(check_row("finalized_target_consistent", final.get("finalized") is True and final.get("status") == "CONSISTENT",
                            reconciliation_status=final.get("status"), finalized=final.get("finalized")))
    checks.append(check_row("matched_ids_equal_target_only", matched == target_ids and not matched.intersection(distractor_ids),
                            target_event_ids=sorted(target_ids), matched_ids=sorted(matched),
                            distractor_event_ids=sorted(distractor_ids),
                            matched_distractor_ids=sorted(matched.intersection(distractor_ids))))
    cleanup = run.get("cleanup", {})
    task = run.get("scheduled_probe_task", {})
    checks.append(check_row("trial_cleanup_and_task_restoration", cleanup.get("target_absent") is True
                            and cleanup.get("distractor_absent") is True
                            and cleanup.get("cleanup_probe_succeeded") is True
                            and task.get("after", {}).get("enabled") == task.get("before", {}).get("enabled"),
                            target_absent=cleanup.get("target_absent"), distractor_absent=cleanup.get("distractor_absent"),
                            probe_succeeded=cleanup.get("cleanup_probe_succeeded"),
                            task_before=task.get("before"), task_after=task.get("after")))
    post = entry.get("post_trial_health", {})
    checks.append(check_row("controller_posttrial_health_and_config", post.get("passed") is True
                            and post.get("configuration_restored") is True
                            and post.get("wazuh_service") == "Running"
                            and post.get("endpoint_agent_status") == "active"
                            and post.get("sysmon_services_running") is True,
                            posttrial=post))
    summary = {
        "trial_id": run.get("trial_id"), "condition": run.get("condition"),
        "raw_sha256": None, "audit_status": "PASS" if all(c["status"] == "PASS" for c in checks) else "FAIL",
        "target_name": run.get("target_name"), "distractor_name": run.get("distractor_name"),
        "target_delta_id": delta.get("delta_id"),
        "target_local_record_ids": [str(event.get("record_id")) for event in target_local],
        "distractor_local_record_ids": [str(event.get("record_id")) for event in distractor_local],
        "target_event_ids": sorted(target_ids), "distractor_event_ids": sorted(distractor_ids),
        "matched_evidence_ids": sorted(matched), "reconciliation_status": final.get("status"),
        "distractor_in_window": distractor_in_window, "checks": checks,
    }
    return checks, summary


def audit_no_change(run: dict[str, Any], entry: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    target = run.get("target", {})
    state = run.get("no_change_control", {})
    target_key = norm(run.get("target_object_key"))
    local_events = target.get("sysmon_exact_events", [])
    db_events = target.get("database_exact_events", [])
    findings = target.get("findings", [])
    deltas = target.get("deltas", [])
    checks = [
        check_row("trial_controller_gate", entry.get("status") == "COMPLETED_PASS"
                  and entry.get("trial_pass") is True and run.get("trial_pass") is True,
                  controller_status=entry.get("status"), trial_pass=run.get("trial_pass")),
        check_row("no_change_target_absent", run.get("target_state", {}).get("absent_before") is True
                  and run.get("target_state", {}).get("present_after") is False
                  and state.get("target_absent_before") is True and state.get("target_absent_after") is True,
                  target_state=run.get("target_state"), control=state),
        check_row("no_target_delta_or_finding", len(deltas) == 0 and len(findings) == 0
                  and state.get("new_delta_count") == 0 and state.get("new_finding_count") == 0,
                  delta_count=len(deltas), finding_count=len(findings), control=state),
        check_row("no_exact_target_event", not local_events and not db_events
                  and not target.get("wazuh_provider_exact_events", []),
                  local_event_count=len(local_events), database_event_count=len(db_events),
                  provider_event_count=len(target.get("wazuh_provider_exact_events", [])), target_key=target_key),
        check_row("no_change_cleanup_and_posttrial_health", run.get("cleanup", {}).get("target_absent") is True
                  and run.get("cleanup", {}).get("cleanup_probe_succeeded") is True
                  and entry.get("post_trial_health", {}).get("passed") is True
                  and entry.get("post_trial_health", {}).get("configuration_restored") is True,
                  cleanup=run.get("cleanup"), posttrial=entry.get("post_trial_health")),
    ]
    summary = {"trial_id": run.get("trial_id"), "condition": run.get("condition"), "raw_sha256": None,
               "audit_status": "PASS" if all(c["status"] == "PASS" for c in checks) else "FAIL",
               "target_name": run.get("target_name"), "target_key": target_key,
               "target_event_ids": [], "distractor_event_ids": [], "matched_evidence_ids": [],
               "reconciliation_status": None, "distractor_in_window": None, "checks": checks}
    return checks, summary


def audit_campaign(campaign_dir: Path, freeze_path: Path) -> dict[str, Any]:
    manifest_path = campaign_dir / "campaign-manifest.json"
    manifest = read_json(manifest_path)
    freeze = read_json(freeze_path)
    expected_conditions = freeze.get("conditions", {})
    protocol = freeze_path.parent / "PROTOCOL.md"
    frozen = freeze_path.parent / "frozen-sources"
    source_hashes = {
        "trial_runner": sha256(frozen / "run_registry_reconciliation_trial_windows.ps1"),
        "campaign_controller": sha256(frozen / "run_registry_reconciliation_campaign_windows.ps1"),
        "protocol": sha256(protocol),
    }
    source_checks = {key: source_hashes[key] == freeze.get("source_sha256", {}).get(key)
                     for key in source_hashes}
    schedule = manifest.get("schedule", [])
    summaries: list[dict[str, Any]] = []
    counts: dict[str, dict[str, int]] = {}
    expected_total = sum(int(value) for value in expected_conditions.values())
    schedule_valid = (len(schedule) == expected_total
                      and manifest.get("random_seed") == freeze.get("schedule", {}).get("seed")
                      and manifest.get("declared_conditions") == list(expected_conditions))
    for entry in schedule:
        condition = entry.get("condition")
        raw_path = campaign_dir / str(entry.get("trial_id", "")) / "run.json"
        if not raw_path.exists():
            summaries.append({"trial_id": entry.get("trial_id"), "condition": condition,
                              "audit_status": "NOT_RUN", "raw_path": str(raw_path), "checks": []})
            counts.setdefault(str(condition), {"assigned": 0, "completed": 0, "passed": 0, "audited_pass": 0})["assigned"] += 1
            continue
        run = read_json(raw_path)
        if condition == "registry_competing_event":
            checks, summary = audit_competing(run, entry, int(freeze.get("timing", {}).get("event_time_tolerance_seconds", 0)))
        elif condition == "registry_no_change":
            checks, summary = audit_no_change(run, entry)
        else:
            checks = [check_row("declared_condition_supported", False, condition=condition)]
            summary = {"trial_id": run.get("trial_id"), "condition": condition, "audit_status": "FAIL", "checks": checks}
        summary["raw_path"] = str(raw_path)
        summary["raw_sha256"] = sha256(raw_path)
        summaries.append(summary)
        bucket = counts.setdefault(str(condition), {"assigned": 0, "completed": 0, "passed": 0, "audited_pass": 0})
        bucket["assigned"] += 1
        bucket["completed"] += int(entry.get("status", "").startswith("COMPLETED_"))
        bucket["passed"] += int(entry.get("status") == "COMPLETED_PASS")
        bucket["audited_pass"] += int(summary.get("audit_status") == "PASS")

    for condition, expected in expected_conditions.items():
        bucket = counts.setdefault(condition, {"assigned": 0, "completed": 0, "passed": 0, "audited_pass": 0})
        bucket["wilson_95_audited_pass"] = wilson(bucket["audited_pass"], int(expected))
        bucket["expected_n"] = int(expected)
    competing = [item for item in summaries if item.get("condition") == "registry_competing_event"
                 and item.get("audit_status") == "PASS"]

    def flattened(key: str) -> list[str]:
        return [value for trial in competing for value in trial.get(key, []) if value]

    target_names = [str(item.get("target_name")) for item in competing if item.get("target_name")]
    distractor_names = [str(item.get("distractor_name")) for item in competing if item.get("distractor_name")]
    target_event_ids = flattened("target_event_ids")
    distractor_event_ids = flattened("distractor_event_ids")
    target_record_ids = flattened("target_local_record_ids")
    distractor_record_ids = flattened("distractor_local_record_ids")
    delta_ids = [str(item.get("target_delta_id")) for item in competing if item.get("target_delta_id")]
    integrity_checks = [
        check_row("fresh_target_names_not_reused", len(target_names) == len(set(target_names)) == int(expected_conditions.get("registry_competing_event", 0)),
                  assigned_competing_trials=int(expected_conditions.get("registry_competing_event", 0)), unique_target_names=len(set(target_names))),
        check_row("fresh_distractor_names_not_reused", len(distractor_names) == len(set(distractor_names)) == int(expected_conditions.get("registry_competing_event", 0)),
                  assigned_competing_trials=int(expected_conditions.get("registry_competing_event", 0)), unique_distractor_names=len(set(distractor_names))),
        check_row("target_wazuh_event_ids_not_reused", len(target_event_ids) == len(set(target_event_ids)) == int(expected_conditions.get("registry_competing_event", 0)),
                  target_event_ids_unique=len(set(target_event_ids))),
        check_row("distractor_wazuh_event_ids_not_reused", len(distractor_event_ids) == len(set(distractor_event_ids)) == int(expected_conditions.get("registry_competing_event", 0)),
                  distractor_event_ids_unique=len(set(distractor_event_ids))),
        check_row("target_and_distractor_wazuh_ids_disjoint", not set(target_event_ids).intersection(distractor_event_ids),
                  overlap=sorted(set(target_event_ids).intersection(distractor_event_ids))),
        check_row("physical_windows_event_record_ids_not_reused", len(target_record_ids + distractor_record_ids)
                  == len(set(target_record_ids + distractor_record_ids))
                  == 2 * int(expected_conditions.get("registry_competing_event", 0)),
                  distinct_event_record_ids=len(set(target_record_ids + distractor_record_ids))),
        check_row("target_delta_ids_not_reused", len(delta_ids) == len(set(delta_ids)) == int(expected_conditions.get("registry_competing_event", 0)),
                  distinct_target_delta_ids=len(set(delta_ids))),
    ]
    all_trial_pass = len(summaries) == expected_total and all(item.get("audit_status") == "PASS" for item in summaries)
    complete_gate = (manifest.get("status") == "COMPLETED" and manifest.get("postflight", {}).get("postflight_valid") is True)
    status = "PASS" if all(source_checks.values()) and schedule_valid and all_trial_pass and complete_gate \
        and all(item["status"] == "PASS" for item in integrity_checks) else "FAIL_OR_INCOMPLETE"
    return {
        "schema_version": "1.0",
        "audit_created_utc": datetime.now(timezone.utc).isoformat(),
        "campaign_id": manifest.get("experiment_id"),
        "campaign_status": manifest.get("status"),
        "audit_status": status,
        "campaign_manifest_sha256": sha256(manifest_path),
        "freeze_path": str(freeze_path),
        "source_hashes": source_hashes,
        "source_hash_checks": source_checks,
        "schedule_valid": schedule_valid,
        "planned_trials": expected_total,
        "observed_artifacts": sum(item.get("audit_status") != "NOT_RUN" for item in summaries),
        "counts_by_condition": counts,
        "campaign_integrity_checks": integrity_checks,
        "postflight": manifest.get("postflight"),
        "trials": summaries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--freeze-json", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = audit_campaign(args.campaign_dir, args.freeze_json)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "audit.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    fields = ["trial_id", "condition", "audit_status", "target_name", "distractor_name",
              "reconciliation_status", "distractor_in_window", "raw_sha256"]
    with (args.output_dir / "trial-summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(result["trials"])
    brief = {key: result[key] for key in ("audit_status", "campaign_status", "planned_trials", "observed_artifacts", "counts_by_condition", "source_hash_checks")}
    print(json.dumps(brief, indent=2))
    return 0 if result["audit_status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
