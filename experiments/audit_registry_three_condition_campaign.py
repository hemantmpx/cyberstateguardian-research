"""Strictly audit complete-event, EventID-drop, and no-change Windows trials."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from registry_reconciliation_campaign_analysis import event_identity_matches, trial_outcome

Z95 = 1.959963984540054


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def check(name: str, passed: bool, **details: Any) -> dict[str, Any]:
    return {"check": name, "status": "PASS" if passed else "FAIL", **details}


def wilson(successes: int, total: int) -> list[float] | None:
    if not total:
        return None
    p = successes / total
    denominator = 1 + Z95 * Z95 / total
    center = (p + Z95 * Z95 / (2 * total)) / denominator
    margin = Z95 * math.sqrt(p * (1 - p) / total + Z95 * Z95 / (4 * total * total)) / denominator
    return [max(0.0, center - margin), min(1.0, center + margin)]


def expected_conditions(freeze: dict[str, Any]) -> dict[str, int]:
    if isinstance(freeze.get("conditions"), dict):
        return {str(key): int(value) for key, value in freeze["conditions"].items()}
    design = freeze.get("design", {})
    repetitions = int(design.get("repetitions_per_condition", 0))
    return {str(condition): repetitions for condition in design.get("conditions", [])}


def seed(freeze: dict[str, Any]) -> int | None:
    return freeze.get("schedule", {}).get("seed", freeze.get("design", {}).get("random_seed"))


def frozen_sources(run_dir: Path, freeze: dict[str, Any]) -> dict[str, str]:
    if isinstance(freeze.get("source_sha256"), dict):
        return {str(key): str(value) for key, value in freeze["source_sha256"].items() if key in {"trial_runner", "campaign_controller", "protocol"}}
    return {str(key): str(value.get("sha256")) for key, value in freeze.get("sources", {}).items() if key in {"trial_runner", "campaign_controller", "protocol"}}


def audit_trial(run: dict[str, Any], entry: dict[str, Any], postflight: dict[str, Any]) -> dict[str, Any]:
    condition = str(entry.get("condition"))
    target = run.get("target", {})
    source = run.get("source_event_ingestion", {})
    target_key = str(run.get("target_object_key") or "")
    host_id = str(run.get("host_id") or "")
    local = target.get("sysmon_exact_events") or []
    provider = [event for event in target.get("wazuh_provider_exact_events") or []
                if event_identity_matches(event, target_key, host_id)]
    database = [event for event in target.get("database_exact_events") or []
                if event_identity_matches(event, target_key, host_id)]
    matched = {str(value) for value in run.get("_audit_reconciliation", {}).get("reconciliation_matched_evidence_ids", [])}
    result = run.get("_audit_outcome", {})
    provider_query = result.get("provider_query", {})
    source_absence_verified = result.get("absence_evidence_query_healthy") is True
    deltas = [delta for delta in target.get("deltas", []) if delta.get("delta_type") == "ADD"
              and str(delta.get("object_key", "")).casefold() == target_key.casefold()]
    findings = [finding for finding in target.get("findings", [])
                if str(finding.get("object_key", "")).casefold() == target_key.casefold()]
    final_rows = [row.get("latest", {}) for row in target.get("reconciliation_history", []) if row.get("latest")]
    final = max(final_rows, key=lambda item: (int(item.get("version") or 0), str(item.get("created_at") or "")), default={})
    exact_provider_ids = {str(event.get("event_id")) for event in provider if event.get("event_id")}
    local_record_ids = {str(event.get("record_id")) for event in local if event.get("record_id")}
    physical_ids = {str((event.get("metadata") or {}).get("windows_event_identity", {}).get("event_record_id")) for event in provider}
    physical_ok = bool(local_record_ids) and local_record_ids == physical_ids and all(
        str((event.get("metadata") or {}).get("windows_event_identity", {}).get("event_code")) == "13"
        and str((event.get("metadata") or {}).get("windows_event_identity", {}).get("channel", "")).casefold()
        == "microsoft-windows-sysmon/operational" for event in provider
    )
    state = run.get("target_state", {})
    cleanup = run.get("cleanup", {})
    cleanup_ok = (cleanup.get("target_absent") is True and cleanup.get("cleanup_probe_succeeded") is True
                  and not cleanup.get("errors")
                  and run.get("scheduled_probe_task", {}).get("after", {}).get("enabled")
                  == run.get("scheduled_probe_task", {}).get("before", {}).get("enabled"))
    common = [
        check("controller_and_trial_pass", entry.get("status") == "COMPLETED_PASS" and entry.get("trial_pass") is True and run.get("trial_pass") is True),
        check("protocol_adherent", run.get("protocol_adherent") is True),
        check("posttrial_health_and_config_restored", postflight.get("passed") is True and postflight.get("configuration_restored") is True
              and postflight.get("wazuh_service") == "Running" and postflight.get("endpoint_agent_status") == "active"
              and postflight.get("sysmon_services_running") is True),
        check("cleanup_and_probe_schedule_restored", cleanup_ok),
    ]

    if condition == "registry_complete":
        provider_ids = exact_provider_ids
        checks = common + [
            check("native_state_transition_and_one_exact_add", state.get("absent_before") is True and state.get("present_after") is True
                  and len(deltas) == 1 and deltas[0].get("before") is None),
            check("one_exact_event_per_evidence_plane", len(local) == len(provider) == len(database) == 1),
            check("complete_healthy_provider_query", provider_query.get("query_complete") is True
                  and provider_query.get("coverage_status") == "COMPLETE"
                  and provider_query.get("endpoint_collection_status") == "AVAILABLE"
                  and provider_query.get("transport_status") == "AVAILABLE"
                  and provider_query.get("index_status") == "AVAILABLE"),
            check("exact_host_type_and_target_object", bool(target_key) and all(event_identity_matches(event, target_key, host_id) for event in provider)),
            check("local_sysmon_and_wazuh_physical_identity", physical_ok,
                  local_record_ids=sorted(local_record_ids), wazuh_record_ids=sorted(physical_ids)),
            check("final_consistent_matches_target_ids_only", final.get("finalized") is True and final.get("status") == "CONSISTENT"
                  and matched == provider_ids and bool(provider_ids), matched_ids=sorted(matched), target_event_ids=sorted(provider_ids)),
        ]
    elif condition == "registry_eventid_drop":
        filter_proof = run.get("target_event_filter", {})
        restoration = filter_proof.get("restoration", {})
        query = source.get("provider_observation", {})
        checks = common + [
            check("native_state_transition_and_one_exact_add", state.get("absent_before") is True and state.get("present_after") is True
                  and len(deltas) == 1 and deltas[0].get("before") is None),
            check("local_sysmon_retains_target_event", len(local) == 1 and bool(local_record_ids)),
            check("healthy_complete_query_proves_exact_event_absent", source_absence_verified and len(provider) == 0
                  and len(database) == 0 and query.get("events") is not None),
            check("eventid_filter_was_applied_and_exactly_restored", filter_proof.get("filter_scope") == "all_event_id_13"
                  and filter_proof.get("status") == "RESTORED_AND_HEALTHY"
                  and filter_proof.get("effective_config_sha256") != filter_proof.get("original_config_sha256")
                  and restoration.get("restored_config_sha256") == filter_proof.get("original_config_sha256")
                  and restoration.get("backup_removed_after_verification") is True),
            check("collector_stayed_available_and_service_running", filter_proof.get("collector_stability", {}).get("active") is True
                  and (run.get("wazuh_service", {}).get("during") or {}).get("status") == "Running"
                  and (run.get("wazuh_service", {}).get("after") or {}).get("status") == "Running"),
            check("final_unexplained_has_no_citations", final.get("finalized") is True and final.get("status") == "UNEXPLAINED"
                  and not matched and not provider, matched_ids=sorted(matched)),
        ]
    elif condition == "registry_no_change":
        quiet = run.get("no_change_control", {})
        checks = common + [
            check("target_absent_and_no_state_delta_or_finding", quiet.get("target_absent_before") is True
                  and quiet.get("target_absent_after") is True and quiet.get("new_delta_count") == 0
                  and quiet.get("new_finding_count") == 0 and not target.get("deltas") and not target.get("findings")),
            check("no_exact_target_events", not local and not provider and not database),
        ]
    else:
        checks = common + [check("condition_is_supported", False, condition=condition)]

    return {
        "trial_id": run.get("trial_id"),
        "condition": condition,
        "audit_status": "PASS" if all(item["status"] == "PASS" for item in checks) else "FAIL",
        "target_name": run.get("target_name"),
        "target_delta_id": deltas[0].get("delta_id") if len(deltas) == 1 else None,
        "target_local_record_ids": sorted(local_record_ids),
        "target_event_ids": sorted(exact_provider_ids),
        "matched_evidence_ids": sorted(matched),
        "reconciliation_status": final.get("status"),
        "target_state_seen": state.get("absent_before") is True and state.get("present_after") is True,
        "provider_query": provider_query,
        "cleanup_pass": cleanup_ok,
        "checks": checks,
    }


def audit(campaign_dir: Path, freeze_path: Path, protocol_path: Path) -> dict[str, Any]:
    freeze = read_json(freeze_path)
    manifest_path = campaign_dir / "campaign-manifest.json"
    manifest = read_json(manifest_path)
    run_dir = campaign_dir.parent
    expected = expected_conditions(freeze)
    frozen = frozen_sources(run_dir, freeze)
    files = {
        "trial_runner": run_dir / "frozen-sources" / "run_registry_reconciliation_trial_windows.ps1",
        "campaign_controller": run_dir / "frozen-sources" / "run_registry_reconciliation_campaign_windows.ps1",
        "protocol": protocol_path,
    }
    source_checks = {key: key in frozen and path.is_file() and sha256(path) == frozen[key] for key, path in files.items()}
    analysis_paths = {
        "analysis_auditor": Path(__file__).resolve(),
        "analysis_engine": Path(__file__).with_name("registry_reconciliation_campaign_analysis.py").resolve(),
    }
    for key, expected_hash in freeze.get("analysis_source_sha256", {}).items():
        local_path = analysis_paths.get(key)
        frozen_copy = run_dir / "analysis" / "source" / (local_path.name if local_path else "")
        source_checks[key] = bool(local_path and local_path.is_file() and sha256(local_path) == expected_hash
                                  and frozen_copy.is_file() and sha256(frozen_copy) == expected_hash)
    source_checks["manifest_matches_frozen_sources"] = (
        manifest.get("trial_script_sha256") == frozen.get("trial_runner")
        and manifest.get("controller_sha256") == frozen.get("campaign_controller")
        and manifest.get("protocol_sha256") == frozen.get("protocol")
    )

    outcomes = []
    seen: set[str] = set()
    for entry in manifest.get("schedule", []):
        trial_id = str(entry.get("trial_id"))
        if trial_id in seen:
            raise ValueError(f"Duplicate trial ID: {trial_id}")
        seen.add(trial_id)
        raw_path = campaign_dir / trial_id / "run.json"
        if not raw_path.is_file():
            outcomes.append({"trial_id": trial_id, "condition": entry.get("condition"), "audit_status": "NOT_RUN", "raw_path": str(raw_path)})
            continue
        run = read_json(raw_path)
        derived = trial_outcome(trial_id, entry, run, entry.get("post_trial_health") or {})
        run["_audit_outcome"] = derived
        run["_audit_reconciliation"] = derived
        outcome = audit_trial(run, entry, entry.get("post_trial_health") or {})
        outcome["raw_sha256"] = sha256(raw_path)
        outcome["schedule_status"] = entry.get("status")
        outcomes.append(outcome)

    counts = {}
    for condition, n in expected.items():
        rows = [row for row in outcomes if row.get("condition") == condition]
        counts[condition] = {
            "assigned_expected": n,
            "observed_artifacts": sum(row.get("audit_status") != "NOT_RUN" for row in rows),
            "audited_pass": sum(row.get("audit_status") == "PASS" for row in rows),
            "wilson_95": wilson(sum(row.get("audit_status") == "PASS" for row in rows), n),
        }
    mutations = [row for row in outcomes if row.get("condition") in {"registry_complete", "registry_eventid_drop"}
                 and row.get("audit_status") == "PASS"]
    target_names = [str(row.get("target_name")) for row in mutations if row.get("target_name")]
    delta_ids = [str(row.get("target_delta_id")) for row in mutations if row.get("target_delta_id")]
    local_ids = [value for row in mutations for value in row.get("target_local_record_ids", [])]
    target_event_ids = [value for row in outcomes if row.get("condition") == "registry_complete" for value in row.get("target_event_ids", [])]
    integrity = [
        check("mutation_target_names_unique", len(target_names) == len(set(target_names)) == sum(expected.get(c, 0) for c in ("registry_complete", "registry_eventid_drop")), unique=len(set(target_names))),
        check("mutation_delta_ids_unique", len(delta_ids) == len(set(delta_ids)) == sum(expected.get(c, 0) for c in ("registry_complete", "registry_eventid_drop")), unique=len(set(delta_ids))),
        check("local_sysmon_eventrecordids_unique", len(local_ids) == len(set(local_ids)) == sum(expected.get(c, 0) for c in ("registry_complete", "registry_eventid_drop")), unique=len(set(local_ids))),
        check("complete_condition_wazuh_event_ids_unique", len(target_event_ids) == len(set(target_event_ids)) == expected.get("registry_complete", 0), unique=len(set(target_event_ids))),
    ]
    expected_total = sum(expected.values())
    schedule_counts = {condition: sum(entry.get("condition") == condition for entry in manifest.get("schedule", [])) for condition in expected}
    schedule_valid = schedule_counts == expected and manifest.get("random_seed") == seed(freeze)
    all_trials_pass = len(outcomes) == expected_total and all(row.get("audit_status") == "PASS" for row in outcomes)
    postflight = manifest.get("postflight", {})
    complete_gate = manifest.get("status") == "COMPLETED" and postflight.get("postflight_valid") is True
    status = "PASS" if all(source_checks.values()) and schedule_valid and all_trials_pass and complete_gate and all(item["status"] == "PASS" for item in integrity) else "FAIL_OR_INCOMPLETE"
    return {
        "schema_version": "csg-registry-three-condition-independent-audit-v1",
        "audit_created_utc": datetime.now(timezone.utc).isoformat(),
        "campaign_id": manifest.get("experiment_id"),
        "campaign_status": manifest.get("status"),
        "audit_status": status,
        "campaign_manifest_sha256": sha256(manifest_path),
        "freeze_sha256": sha256(freeze_path),
        "source_hash_checks": source_checks,
        "schedule_valid": schedule_valid,
        "schedule_counts": schedule_counts,
        "expected_conditions": expected,
        "planned_trials": expected_total,
        "observed_artifacts": sum(row.get("audit_status") != "NOT_RUN" for row in outcomes),
        "counts_by_condition": counts,
        "campaign_integrity_checks": integrity,
        "postflight": postflight,
        "trials": outcomes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--freeze-json", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.campaign_dir, args.freeze_json, args.protocol)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "audit.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    fields = ["trial_id", "condition", "audit_status", "target_name", "target_delta_id", "target_event_ids",
              "target_local_record_ids", "matched_evidence_ids", "reconciliation_status", "raw_sha256"]
    with (args.output_dir / "trial-summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in result["trials"]:
            writer.writerow({key: json.dumps(row.get(key)) if isinstance(row.get(key), list) else row.get(key) for key in fields})
    print(json.dumps({key: result[key] for key in ("audit_status", "planned_trials", "observed_artifacts", "counts_by_condition", "source_hash_checks", "schedule_valid")}, indent=2))
    return 0 if result["audit_status"] == "PASS" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
