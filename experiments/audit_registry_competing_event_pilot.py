"""Independently audit a frozen same-host registry distractor pilot artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize(value: Any) -> str:
    return str(value or "").strip().lower().replace("\\", "/").replace(":/", "/")


def parse_time(value: Any) -> datetime:
    text = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def audit(run_path: Path, freeze_path: Path, postflight_path: Path) -> dict[str, Any]:
    run = read_json(run_path)
    freeze = read_json(freeze_path)
    postflight = read_json(postflight_path)
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, **details: Any) -> None:
        checks.append({"check": name, "status": "PASS" if passed else "FAIL", **details})

    frozen_sources = freeze_path.parent / "frozen-sources"
    frozen_runner = frozen_sources / "run_registry_reconciliation_trial_windows.ps1"
    protocol = freeze_path.parent / "PROTOCOL.md"
    expected_hashes = freeze.get("source_sha256", {})
    actual_hashes = {
        "trial_runner": sha256(frozen_runner) if frozen_runner.is_file() else None,
        "protocol": sha256(protocol) if protocol.is_file() else None,
    }
    check(
        "frozen_sources_match_pre_execution_hashes",
        all(actual_hashes[key] == expected_hashes.get(key) for key in actual_hashes),
        expected=expected_hashes,
        actual=actual_hashes,
    )
    check("expected_condition_and_trial", run.get("condition") == "registry_competing_event"
          and run.get("trial_id") == "registry_competing_event-v77-001",
          condition=run.get("condition"), trial_id=run.get("trial_id"))
    check("runner_protocol_gate_passed", run.get("trial_pass") is True
          and run.get("protocol_adherent") is True,
          trial_pass=run.get("trial_pass"), protocol_adherent=run.get("protocol_adherent"))

    target_key = normalize(run.get("target_object_key"))
    distractor_key = normalize(run.get("distractor_object_key"))
    deltas = run.get("target", {}).get("deltas", [])
    target_deltas = [delta for delta in deltas if delta.get("delta_type") == "ADD"]
    delta = target_deltas[0] if len(target_deltas) == 1 else {}
    after = delta.get("after") or {}
    after_key = normalize(after.get("object_key") or after.get("attributes", {}).get("object_key"))
    check("one_exact_target_add_delta", len(target_deltas) == 1
          and after_key == target_key and delta.get("before") is None,
          target_delta_count=len(target_deltas), target_key=target_key, delta_after_key=after_key,
          before=delta.get("before"))
    check("native_probe_observed_target_absent_then_present",
          run.get("target_state", {}).get("absent_before") is True
          and run.get("target_state", {}).get("present_after") is True
          and after.get("metadata", {}).get("source") == "direct_probe",
          absent_before=run.get("target_state", {}).get("absent_before"),
          present_after=run.get("target_state", {}).get("present_after"),
          delta_source=after.get("metadata", {}).get("source"))

    target_events = run.get("target", {}).get("wazuh_provider_exact_events", [])
    distractor_events = run.get("source_event_ingestion", {}).get("provider_observation_exact_events", [])
    target_db_events = run.get("target", {}).get("database_exact_events", [])
    distractor_db_events = run.get("source_event_ingestion", {}).get("database_verified", [])
    target_local = run.get("target", {}).get("sysmon_exact_events", [])
    distractor_local = run.get("source_event_ingestion", {}).get("local_sysmon_exact_events", [])
    target_ids = {str(event.get("event_id")) for event in target_events if event.get("event_id")}
    distractor_ids = {str(event.get("event_id")) for event in distractor_events if event.get("event_id")}
    check("both_physical_events_present_in_wazuh_and_csg",
          bool(target_ids) and bool(distractor_ids) and bool(target_db_events)
          and bool(distractor_db_events) and bool(target_local) and bool(distractor_local),
          target_provider_ids=sorted(target_ids), distractor_provider_ids=sorted(distractor_ids),
          target_database_count=len(target_db_events), distractor_database_count=len(distractor_db_events),
          target_local_record_ids=[event.get("record_id") for event in target_local],
          distractor_local_record_ids=[event.get("record_id") for event in distractor_local])

    check("one_exact_event_per_object_per_evidence_plane",
          len(target_events) == len(distractor_events) == 1
          and len(target_db_events) == len(distractor_db_events) == 1
          and len(target_local) == len(distractor_local) == 1,
          target_provider=len(target_events), distractor_provider=len(distractor_events),
          target_database=len(target_db_events), distractor_database=len(distractor_db_events),
          target_local=len(target_local), distractor_local=len(distractor_local))

    provider = run.get("source_event_ingestion", {}).get("provider_observation", {})
    health_ok = (provider.get("query_complete") is True
                 and provider.get("coverage_status") == "COMPLETE"
                 and provider.get("endpoint_collection_status") == "AVAILABLE"
                 and provider.get("transport_status") == "AVAILABLE"
                 and provider.get("index_status") == "AVAILABLE")
    check("provider_query_complete_and_healthy", health_ok,
          query_complete=provider.get("query_complete"),
          coverage_status=provider.get("coverage_status"),
          endpoint_collection_status=provider.get("endpoint_collection_status"),
          transport_status=provider.get("transport_status"), index_status=provider.get("index_status"))

    def exact_event_identity(events: list[dict[str, Any]], expected_key: str) -> bool:
        return bool(events) and all(
            event.get("host_id") == run.get("host_id")
            and event.get("normalized_type") == "registry_value_modified"
            and normalize(event.get("target", {}).get("key")) == expected_key
            for event in events
        )

    check("target_and_distractor_identities_are_distinct_same_host_same_class",
          bool(target_key) and bool(distractor_key) and target_key != distractor_key
          and exact_event_identity(target_events, target_key)
          and exact_event_identity(distractor_events, distractor_key),
          target_key=target_key, distractor_key=distractor_key,
          target_events_exact=exact_event_identity(target_events, target_key),
          distractor_events_exact=exact_event_identity(distractor_events, distractor_key))

    def physical_event_ids_match(provider_events: list[dict[str, Any]], local_events: list[dict[str, Any]]) -> bool:
        local_ids = {str(event.get("record_id")) for event in local_events}
        windows_ids = {
            str(event.get("metadata", {}).get("windows_event_identity", {}).get("event_record_id"))
            for event in provider_events
        }
        return bool(local_ids) and local_ids == windows_ids and all(
            event.get("metadata", {}).get("windows_event_identity", {}).get("event_code") == "13"
            and str(event.get("metadata", {}).get("windows_event_identity", {}).get("channel", "")).lower()
            == "microsoft-windows-sysmon/operational"
            for event in provider_events
        )

    check("wazuh_physical_event_records_match_local_sysmon_records",
          physical_event_ids_match(target_events, target_local)
          and physical_event_ids_match(distractor_events, distractor_local),
          target_local_record_ids=sorted(str(item.get("record_id")) for item in target_local),
          target_wazuh_record_ids=sorted(str(item.get("metadata", {}).get("windows_event_identity", {}).get("event_record_id")) for item in target_events),
          distractor_local_record_ids=sorted(str(item.get("record_id")) for item in distractor_local),
          distractor_wazuh_record_ids=sorted(str(item.get("metadata", {}).get("windows_event_identity", {}).get("event_record_id")) for item in distractor_events))

    window = delta.get("observation_window") or {}
    tolerance = int(freeze.get("frozen_parameters", {}).get("same_host_object_event_window_tolerance_seconds", 0))
    in_window = False
    window_error = None
    try:
        start = parse_time(window["start"]) - timedelta(seconds=tolerance)
        end = parse_time(window["end"]) + timedelta(seconds=tolerance)
        in_window = any(start <= parse_time(event.get("event_time")) <= end for event in distractor_events)
    except (KeyError, TypeError, ValueError) as exc:
        window_error = str(exc)
    check("distractor_event_inside_target_delta_window", in_window,
          window_start=window.get("start"), window_end=window.get("end"),
          tolerance_seconds=tolerance, error=window_error)

    history = run.get("target", {}).get("reconciliation_history", [])
    final = history[-1].get("latest", {}) if history else {}
    matched_ids = {str(item) for item in final.get("matched_evidence_ids", [])}
    check("finalized_consistent_reconciliation", final.get("finalized") is True
          and final.get("status") == "CONSISTENT",
          reconciliation_status=final.get("status"), finalized=final.get("finalized"))
    check("only_target_event_id_matched", matched_ids == target_ids and not (matched_ids & distractor_ids),
          target_event_ids=sorted(target_ids), matched_evidence_ids=sorted(matched_ids),
          distractor_event_ids=sorted(distractor_ids), matched_distractor_ids=sorted(matched_ids & distractor_ids))

    cleanup = run.get("cleanup", {})
    task = run.get("scheduled_probe_task", {})
    wazuh = run.get("wazuh_service", {})
    check("cleanup_and_probe_task_restoration", cleanup.get("target_absent") is True
          and cleanup.get("distractor_absent") is True
          and cleanup.get("cleanup_probe_succeeded") is True
          and task.get("after", {}).get("enabled") == task.get("before", {}).get("enabled"),
          cleanup=cleanup, task_before=task.get("before"), task_after=task.get("after"))
    before_service = wazuh.get("before", {})
    after_service = wazuh.get("after", {})
    check("wazuh_service_stayed_running_without_restart",
          before_service.get("status") == after_service.get("status") == "Running"
          and before_service.get("process_id") == after_service.get("process_id"),
          before=before_service, after=after_service)
    expected_config = freeze.get("baseline_wazuh_agent_config_sha256_expected")
    check("independent_postflight_services_config_and_probe_task",
          postflight.get("wazuh_service", {}).get("status") == "Running"
          and postflight.get("sysmon_service", {}).get("status") == "Running"
          and postflight.get("baseline_config_matches") is True
          and postflight.get("agent_config_sha256") == expected_config
          and postflight.get("probe_task_enabled") is True,
          captured_at_utc=postflight.get("captured_at_utc"),
          wazuh_service=postflight.get("wazuh_service"),
          sysmon_service=postflight.get("sysmon_service"),
          agent_config_sha256=postflight.get("agent_config_sha256"),
          expected_agent_config_sha256=expected_config,
          probe_task_enabled=postflight.get("probe_task_enabled"))
    check("independent_postflight_trial_values_absent",
          postflight.get("target_registry_value_present") is False
          and postflight.get("distractor_registry_value_present") is False,
          target_present=postflight.get("target_registry_value_present"),
          distractor_present=postflight.get("distractor_registry_value_present"))

    failed = [item["check"] for item in checks if item["status"] != "PASS"]
    return {
        "schema_version": "1.0",
        "audit_created_utc": datetime.now(timezone.utc).isoformat(),
        "study_id": freeze.get("study_id"),
        "trial_id": run.get("trial_id"),
        "raw_run_path": str(run_path),
        "raw_run_sha256": sha256(run_path),
        "freeze_path": str(freeze_path),
        "postflight_path": str(postflight_path),
        "postflight_sha256": sha256(postflight_path),
        "audit_status": "PASS" if not failed else "FAIL",
        "checks_passed": len(checks) - len(failed),
        "checks_total": len(checks),
        "failed_checks": failed,
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-json", required=True, type=Path)
    parser.add_argument("--freeze-json", required=True, type=Path)
    parser.add_argument("--postflight-json", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = audit(args.run_json, args.freeze_json, args.postflight_json)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("audit_status", "checks_passed", "checks_total", "failed_checks", "raw_run_sha256")}, indent=2))
    return 0 if result["audit_status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
