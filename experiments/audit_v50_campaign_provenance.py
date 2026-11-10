from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode
from urllib.request import urlopen


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def source_key(reference: dict[str, Any]) -> str:
    return "{}|{}".format(
        str(reference.get("index", "")).casefold(),
        str(reference.get("document_id", "")).casefold(),
    )


def query_events(
    api_base: str,
    host_id: str,
    event_time: datetime,
    object_key: str,
    object_name: str,
) -> list[dict[str, Any]]:
    params = urlencode(
        {
            "start": (event_time - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
            "end": (event_time + timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
            "normalized_type": "scheduled_task_created",
            "source": "wazuh",
            "object_key": object_key,
            "object_name": object_name,
            "limit": "500",
        }
    )
    url = f"{api_base.rstrip('/')}/api/hosts/{quote(host_id, safe='')}/events?{params}"
    with urlopen(url, timeout=30) as response:
        return json.load(response)


def audit_no_action(trial_dir: Path) -> dict[str, Any]:
    result = read_json(trial_dir / "windows-raw" / trial_dir.name / "result.json")
    execution = read_json(trial_dir / "execution-record.json")
    safety = read_json(trial_dir / "post-launch-safety-check.json")
    query = read_json(trial_dir / "baseline-query-after-abort.json")
    checks = {
        "controller_aborted_before_task_action": result.get("active_query_gate", {}).get(
            "status"
        )
        == "ABORTED_BEFORE_TASK_ACTION_APPROVAL_TIMEOUT",
        "no_target_or_distractor_created": result.get("target_task_name") is None
        and result.get("distractor_task_name") is None
        and result.get("residual_study_tasks") == []
        and safety.get("study_task_names") == [],
        "original_agent_config_restored": result.get("restoration", {}).get("hash_restored")
        is True
        and safety.get("agent_config_sha256")
        == result.get("restoration", {}).get("original_config_sha256"),
        "wazuh_query_and_endpoint_health_restored": query.get("matches_expected_query") is True
        and safety.get("probe_state") == "Ready"
        and safety.get("probe_enabled") is True
        and {item["name"]: item["state"] for item in safety.get("services", [])}
        == {"WazuhSvc": "Running", "Sysmon64a": "Running"},
        "driver_failure_captured_without_promoting_trial": execution.get("active_query_approved")
        is False
        and execution.get("assessment", {}).get("strict_trial_pass") is False,
    }
    return {
        "trial_id": trial_dir.name,
        "evidence_class": "PRE_ACTION_ABORT_SAFETY_AUDIT_NOT_A_BEHAVIOR_TRIAL",
        "checks": checks,
        "passed": all(checks.values()),
        "strict_trial_pass": False,
    }


def audit_behavior_trial(trial_dir: Path, api_base: str) -> dict[str, Any]:
    trial_id = trial_dir.name
    raw_controller_path = trial_dir / "windows-raw" / trial_id / "result.json"
    controller = read_json(raw_controller_path)
    execution = read_json(trial_dir / "execution-record.json")
    distractor = controller["distractor_event"]
    local_event = distractor["local_windows_event"]
    event_time = datetime.fromisoformat(local_event["event_time_utc"].replace("Z", "+00:00"))
    rows = query_events(
        api_base,
        controller["host_id"],
        event_time,
        distractor["object_key"],
        distractor["task_name"],
    )
    postrun = trial_dir / "postrun"
    postrun.mkdir(parents=True, exist_ok=True)
    raw_path = postrun / "csg-event-store-raw-readback.json"
    raw_path.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = controller["distractor_event_store_readback_validation"]
    provider_keys = {
        str(value).casefold() for value in validation["provider_source_reference_keys"]
    }
    controller_readback_keys = {
        str(value).casefold() for value in validation["readback_source_reference_keys"]
    }
    actual_references: list[dict[str, Any]] = []
    for row in rows:
        if row.get("source_reference"):
            actual_references.append(row["source_reference"])
        actual_references.extend(row.get("metadata", {}).get("additional_source_references", []))
    actual_keys = {source_key(reference) for reference in actual_references}
    identity = (
        rows[0].get("metadata", {}).get("windows_event_identity", {}) if len(rows) == 1 else {}
    )
    final = controller.get("final_target_reconciliation", {})
    checks = {
        "live_active_query_gate_was_approved": execution.get("active_query_approved") is True,
        "target_state_sequence_observed": controller.get("direct_probe_state_sequence_passed")
        is True,
        "target_event_absent_during_filtered_collection": controller.get(
            "target_absent_from_csg_event_store_during_filter"
        )
        is True
        and controller.get("exact_wazuh_target_event_count_during_filter") == 0,
        "filtered_source_query_complete_and_healthy": controller.get(
            "query_complete_during_filter"
        )
        is True
        and controller.get("query_coverage_and_source_availability_during_filter") is True,
        "local_distractor_is_exact_windows_event_4698": str(local_event.get("event_id"))
        == "4698"
        and local_event.get("exact_identity_match") is True,
        "one_canonical_distractor_record_in_csg_store": len(rows) == 1,
        "csg_host_type_and_object_are_exact": len(rows) == 1
        and rows[0].get("host_id") == controller.get("host_id")
        and rows[0].get("normalized_type") == "scheduled_task_created"
        and rows[0].get("target", {}).get("key", "").casefold()
        == str(distractor["object_key"]).casefold(),
        "physical_windows_event_identity_matches_local_record": len(rows) == 1
        and str(identity.get("event_record_id")) == str(local_event.get("record_id"))
        and str(identity.get("event_code")) == str(local_event.get("event_id"))
        and str(identity.get("provider_name", "")).casefold()
        == str(local_event.get("provider", "")).casefold(),
        "all_alert_and_archive_source_refs_retained_in_store": provider_keys == actual_keys
        and len(provider_keys) == 2,
        "controller_projection_arrays_match_even_though_boolean_gate_failed": provider_keys
        == controller_readback_keys
        and validation.get("readback_references_match_provider_alert_and_archive_references")
        is False,
        "distractor_is_same_host_type_wrong_object_and_in_window": controller.get(
            "distractor_same_host_same_type_different_object"
        )
        is True
        and controller.get("distractor_inside_final_reconciliation_window") is True,
        "target_finalized_unexplained_without_citations": final.get("status") == "UNEXPLAINED"
        and final.get("finalized") is True
        and final.get("matched_evidence_ids") == [],
        "cleanup_and_config_restore_passed": controller.get("cleanup_verified") is True
        and controller.get("restored_hash_matches_original") is True,
    }
    result = {
        "schema_version": "csg-v50-supplemental-provenance-audit-v1",
        "audited_at_utc": datetime.now(UTC).isoformat(),
        "trial_id": trial_id,
        "evidence_class": "SUPPLEMENTAL_READ_ONLY_AUDIT_NOT_FROZEN_CONTROLLER_SCORING",
        "controller_trial_status": controller.get("status"),
        "controller_trial_is_promoted": False,
        "raw_readback_sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        "physical_windows_event_identity": {
            "event_record_id": local_event.get("record_id"),
            "event_code": local_event.get("event_id"),
            "provider": local_event.get("provider"),
            "task_name": local_event.get("task_name"),
        },
        "canonical_event_ids": [row.get("event_id") for row in rows],
        "provider_source_reference_keys": sorted(provider_keys),
        "controller_readback_source_reference_keys": sorted(controller_readback_keys),
        "csg_api_store_source_reference_keys": sorted(actual_keys),
        "canonical_rows": len(rows),
        "unique_source_references": len(actual_keys),
        "checks": checks,
        "passed": all(checks.values()),
        "interpretation": (
            "This read-only query confirms the provider's alert/archive references and exact "
            "physical event identity are retained in CSG. It does not promote the frozen v15 "
            "controller result; the controller boolean remains false because its cardinality "
            "predicate compares two alias references with one canonical row."
        ),
    }
    (postrun / "provenance-audit.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--api-base", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    root = args.campaign_dir.resolve()
    summary = read_json(root / "campaign-summary.json")
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for attempt in summary["attempts"]:
        trial_dir = root / attempt["trial_id"]
        try:
            if attempt["trial_id"] == "trial-01":
                result = audit_no_action(trial_dir)
                out = trial_dir / "postrun" / "provenance-audit.json"
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(
                    json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
            else:
                result = audit_behavior_trial(trial_dir, args.api_base)
            results.append(result)
        except (KeyError, OSError, ValueError, TimeoutError) as exc:
            errors.append(
                {"trial_id": attempt["trial_id"], "error": f"{type(exc).__name__}: {exc}"}
            )

    behavior = [item for item in results if item.get("canonical_rows") is not None]
    no_action = next((item for item in results if item["trial_id"] == "trial-01"), None)
    aggregate = {
        "schema_version": "csg-v50-campaign-provenance-audit-v1",
        "audited_at_utc": datetime.now(UTC).isoformat(),
        "campaign_id": summary["experiment_id"],
        "evidence_class": "SUPPLEMENTAL_READ_ONLY_AUDIT_NOT_FROZEN_CONTROLLER_SCORING",
        "assigned_trials": summary["assigned_count"],
        "pre_action_failure_count": 1,
        "behavior_trials_audited": len(behavior),
        "supplemental_behavior_audits_passed": sum(bool(item["passed"]) for item in behavior),
        "supplemental_behavior_audits_failed": sum(not item["passed"] for item in behavior),
        "pre_action_safety_audit_passed": bool(no_action and no_action["passed"]),
        "controller_strict_pass_count": summary["strict_pass_count"],
        "audit_errors": errors,
        "trials": [
            {
                "trial_id": item["trial_id"],
                "evidence_class": item["evidence_class"],
                "passed": item["passed"],
                "checks_passed": sum(item["checks"].values()),
                "checks_total": len(item["checks"]),
                "event_id": item.get("canonical_event_ids", [None])[0],
            }
            for item in results
        ],
        "strict_dispositions_unchanged": True,
        "generalization_note": "All behavior trials are repeated measures on one Windows endpoint.",
    }
    output = root / "postrun" / "campaign-provenance-audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(aggregate, indent=2, sort_keys=True))
    return 0 if not errors and all(item["passed"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
