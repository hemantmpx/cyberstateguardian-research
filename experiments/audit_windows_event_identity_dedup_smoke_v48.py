"""Audit the v48 live smoke trial and its independent CSG event-store readback."""

# Report prose intentionally uses long readable lines.
# ruff: noqa: E501

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    args = parser.parse_args()
    run_dir = args.run_directory.resolve()
    execution = run_dir / "executions/campaign-01"
    summary = read_json(execution / "campaign-summary.json")
    run = read_json(execution / "trial-01/windows-raw/run.json")
    scenario = next(
        item for item in run["scenarios"] if item.get("scenario_id") == "scheduled-task-persistence"
    )
    readback = read_json(run_dir / "postflight/csg-event-store-readback.json")
    freeze = read_json(run_dir / "source-freeze.json")
    controller_trial = summary["trials"][0]
    target_name = scenario["object_name"]
    exact_matches = scenario["event_plane"]["exact_matches"]
    local_events = scenario["local_source_evidence"]["exact_events"]
    local_event = local_events[0]
    local_identity = {
        "agent_id": "001",
        "channel": "security",
        "event_record_id": str(local_event["record_id"]),
        "event_code": "4698",
        "provider_name": "microsoft-windows-security-auditing",
    }
    matching_readback = [
        event
        for event in readback
        if event.get("event_id") == exact_matches[0].get("event_id")
        and event.get("target", {}).get("key") == scenario["expected_object_key"]
    ]
    stored_event = matching_readback[0] if len(matching_readback) == 1 else {}
    identity = stored_event.get("metadata", {}).get("windows_event_identity", {})
    additional_refs = stored_event.get("metadata", {}).get("additional_source_references", [])
    source_refs = [stored_event.get("source_reference", {}), *additional_refs]
    indexes = sorted({str(ref.get("index", "")) for ref in source_refs if ref.get("index")})
    histories = scenario.get("csg_reconciliation", {}).get("history") or []
    if isinstance(histories, dict):
        histories = [histories]
    finalized = [entry for entry in histories if entry.get("finalized") is True]
    final = max(finalized, key=lambda entry: entry.get("version", 0), default={})
    matched_ids = final.get("matched_evidence_ids", [])
    if isinstance(matched_ids, str):
        matched_ids = [matched_ids]
    postflight = read_json(execution / "trial-01/postflight.json")
    expected_config_hash = freeze["preflight"]["agent_config_sha256"].lower()
    checks = {
        "campaign_controller_passed": summary.get("campaign_status") == "ALL_ASSIGNED_TRIALS_PASSED"
        and summary.get("passed_trial_count") == 1
        and controller_trial.get("positive_control_passed") is True,
        "strict_runner_positive_control_passed": run.get("status")
        == "ALL_REQUIRED_POSITIVE_CONTROLS_PASSED"
        and scenario.get("positive_control", {}).get("passed") is True,
        "probe_absent_present_absent": scenario.get("state_plane", {}).get(
            "target_absent_before_action"
        )
        is True
        and bool(scenario.get("state_plane", {}).get("after_action_observed"))
        and scenario.get("state_plane", {}).get("cleanup_removed_from_probe") is True,
        "exact_local_event_4698": len(local_events) == 1
        and local_event.get("event_id") == 4698
        and local_event.get("exact_identity_match") is True
        and local_event.get("event_data", {}).get("TaskName", "").strip("\\").casefold()
        == target_name.casefold(),
        "one_canonical_csg_event_for_physical_identity": len(exact_matches) == 1
        and len(matching_readback) == 1
        and identity == local_identity,
        "alert_and_archive_sources_preserved_as_aliases": any(
            str(ref.get("index", "")).startswith("wazuh-alerts-") for ref in source_refs
        )
        and any(str(ref.get("index", "")).startswith("wazuh-archives-") for ref in source_refs)
        and len({(ref.get("index"), ref.get("document_id")) for ref in source_refs}) == 2,
        "finalized_consistent_citing_one_canonical_id": final.get("status") == "CONSISTENT"
        and final.get("finalized") is True
        and matched_ids == [exact_matches[0].get("event_id")],
        "postflight_cleanup_and_config_restored": postflight.get("target_absent") is True
        and not postflight.get("residual_csgapt_tasks")
        and postflight.get("agent_config_sha256", "").lower() == expected_config_hash
        and postflight.get("wazuh_service_state") == "Running"
        and postflight.get("endpoint_agent_status") == "active",
    }
    frozen_records = {
        "protocol": freeze["protocol"],
        "schedule": freeze["schedule"],
        **freeze["source_files"],
        "windows_preflight": {
            "path": freeze["preflight"]["windows"],
            "sha256": freeze["preflight"]["windows_sha256"],
        },
        "active_wazuh_query": {
            "path": freeze["preflight"]["active_wazuh_query"],
            "sha256": freeze["preflight"]["active_wazuh_query_sha256"],
        },
    }
    frozen_hashes: dict[str, str | None] = {}
    freeze_hash_checks: dict[str, bool] = {}
    for name, record in frozen_records.items():
        path = (run_dir / record["path"]).resolve()
        actual = sha256(path) if path.is_file() else None
        frozen_hashes[name] = actual
        freeze_hash_checks[name] = actual == record["sha256"]
    checks["all_frozen_input_hashes_match"] = all(freeze_hash_checks.values())
    audit = {
        "schema_version": "csg-windows-event-identity-dedup-smoke-audit-v1",
        "experiment_id": freeze["experiment_id"],
        "classification": "ONE_TRIAL_BENIGN_ENGINEERING_SMOKE",
        "target_task_name": target_name,
        "local_event_record_id": local_event.get("record_id"),
        "windows_event_identity": identity,
        "canonical_csg_event_id": stored_event.get("event_id"),
        "wazuh_source_references": source_refs,
        "wazuh_source_indexes": indexes,
        "final_reconciliation_status": final.get("status"),
        "final_reconciliation_version": final.get("version"),
        "final_reconciliation_matched_ids": matched_ids,
        "checks": checks,
        "source_freeze_hash_checks": freeze_hash_checks,
        "passed": all(checks.values()),
        "frozen_artifact_sha256": frozen_hashes,
        "derived_audit_script_sha256": sha256(Path(__file__)),
        "interpretation": (
            "The active Wazuh provider collapsed the alert/archive hits into one canonical CSG event "
            "and preserved both source references. The reconciler finalized CONSISTENT using one ID. "
            "Because only one canonical row reached the engine, this live smoke does not exercise its "
            "database-alias-group branch; that branch is covered by focused unit tests."
        ),
    }
    out = run_dir / "postflight/identity-dedup-audit.json"
    out.write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    manifest_path = run_dir / "artifact-sha256.json"
    manifest = {
        "schema_version": "csg-artifact-sha256-v1",
        "experiment_id": freeze["experiment_id"],
        "files": {
            str(path.relative_to(run_dir)): sha256(path)
            for path in sorted(run_dir.rglob("*"))
            if path.is_file() and path != manifest_path
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": audit["passed"], "checks": checks, "audit": str(out)}, indent=2))


if __name__ == "__main__":
    main()
