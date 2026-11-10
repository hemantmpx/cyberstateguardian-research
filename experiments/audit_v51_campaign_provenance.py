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


def strict_gate_failures(controller: dict[str, Any]) -> list[str]:
    reconciliation = controller.get("final_target_reconciliation") or {}
    event_plane = (reconciliation.get("metadata") or {}).get("event_plane") or {}
    expected = {
        "capture_gates_passed": controller.get("capture_gates_passed") is True,
        "paired_wrong_object_trial_passed": controller.get("paired_wrong_object_trial_passed")
        is True,
        "direct_probe_state_sequence_passed": controller.get(
            "direct_probe_state_sequence_passed"
        )
        is True,
        "target_absent_from_csg_event_store_during_filter": controller.get(
            "target_absent_from_csg_event_store_during_filter"
        )
        is True,
        "query_complete_during_filter": controller.get("query_complete_during_filter") is True,
        "distractor_inside_final_reconciliation_window": controller.get(
            "distractor_inside_final_reconciliation_window"
        )
        is True,
        "final_status_unexplained": reconciliation.get("status") == "UNEXPLAINED",
        "finalized": reconciliation.get("finalized") is True,
        "no_matched_evidence_ids": reconciliation.get("matched_evidence_ids") == [],
        "event_plane_query_complete": event_plane.get("query_complete") is True,
        "event_plane_coverage_complete": event_plane.get("coverage_status") == "COMPLETE",
        "endpoint_collection_available": event_plane.get("endpoint_collection_status")
        == "AVAILABLE",
        "event_transport_available": event_plane.get("transport_status") == "AVAILABLE",
        "event_index_available": event_plane.get("index_status") == "AVAILABLE",
    }
    return [name for name, passed in expected.items() if not passed]


def audit_trial(trial_dir: Path, api_base: str, strict_status: bool) -> dict[str, Any]:
    trial_id = trial_dir.name
    controller = read_json(trial_dir / "windows-raw" / trial_id / "result.json")
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
    references: list[dict[str, Any]] = []
    for row in rows:
        if row.get("source_reference"):
            references.append(row["source_reference"])
        references.extend(row.get("metadata", {}).get("additional_source_references", []))
    store_keys = {source_key(reference) for reference in references}
    identities = [
        row.get("metadata", {}).get("windows_event_identity", {}) for row in rows
    ]
    identity_keys = {
        tuple(
            str(value or "").casefold()
            for value in (
                item.get("agent_id"),
                item.get("channel"),
                item.get("event_record_id"),
                item.get("event_code"),
                item.get("provider_name"),
            )
        )
        for item in identities
    }
    reconciliation = controller.get("final_target_reconciliation", {})
    alias_groups = reconciliation.get("metadata", {}).get(
        "deduplicated_windows_event_aliases", []
    )
    row_ids = {str(row.get("event_id", "")) for row in rows}
    alias_group_matches = any(
        {
            str(alias.get("canonical_event_id", "")),
            *[str(value) for value in alias.get("alias_event_ids", [])],
        }
        == row_ids
        for alias in alias_groups
    )
    target_name = str(controller.get("target_task_name", ""))
    target_key = f"scheduled_task:\\{target_name}".casefold() if target_name else ""
    distractor_key = str(distractor.get("object_key", "")).casefold()
    active_query = (
        controller.get("active_query_gate", {}).get("approval", {}).get("active_query", "")
    )
    post_restore_queries = controller.get("post_restore_provider_queries", [])
    checks = {
        "active_query_approval_recorded": execution.get("active_query_approved") is True,
        "approved_filter_excludes_windows_event_4698": controller.get(
            "active_query_gate", {}
        ).get("approval", {}).get("matches_expected_query")
        is True
        and "system/eventid != 4698" in str(active_query).casefold(),
        "target_state_transition_observed": controller.get(
            "direct_probe_state_sequence_passed"
        )
        is True,
        "target_event_absent_during_filter": controller.get(
            "target_absent_from_csg_event_store_during_filter"
        )
        is True
        and controller.get("exact_wazuh_target_event_count_during_filter") == 0,
        "filtered_query_completed_with_available_sources": controller.get(
            "query_complete_during_filter"
        )
        is True
        and controller.get("query_coverage_and_source_availability_during_filter") is True,
        "local_distractor_is_exact_security_event_4698": str(local_event.get("event_id"))
        == "4698"
        and local_event.get("exact_identity_match") is True,
        "one_physical_distractor_identity_read_back": bool(rows)
        and len(identity_keys) == 1
        and next(iter(identity_keys))[2] == str(local_event.get("record_id")).casefold()
        and next(iter(identity_keys))[3] == str(local_event.get("event_id")).casefold()
        and next(iter(identity_keys))[4] == str(local_event.get("provider", "")).casefold(),
        "all_readback_rows_have_exact_host_type_and_object": bool(rows)
        and all(
            row.get("host_id") == controller.get("host_id")
            and row.get("normalized_type") == "scheduled_task_created"
            and str(row.get("target", {}).get("key", "")).casefold() == distractor_key
            for row in rows
        ),
        "reconciliation_canonicalizes_multiple_source_rows": len(rows) == 1
        or (len(rows) > 1 and alias_group_matches),
        "provider_and_controller_reference_sets_agree": provider_keys == controller_readback_keys,
        "all_provider_references_persisted_in_csg": bool(provider_keys)
        and provider_keys == store_keys
        and len(store_keys) == 2,
        "distractor_is_same_host_type_wrong_object_inside_window": controller.get(
            "distractor_same_host_same_type_different_object"
        )
        is True
        and controller.get("distractor_inside_final_reconciliation_window") is True
        and bool(target_key)
        and distractor_key != target_key,
        "final_target_is_unexplained_without_citations": reconciliation.get("status")
        == "UNEXPLAINED"
        and reconciliation.get("finalized") is True
        and reconciliation.get("matched_evidence_ids") == [],
        "target_event_still_absent_after_filter_restored": controller.get(
            "target_event_absent_after_restore"
        )
        is True
        and controller.get("target_wazuh_event_ids_after_restore") == [],
        "six_postrestore_queries_complete_healthy_and_target_absent": len(
            post_restore_queries
        )
        == 6
        and all(
            query.get("query_complete") is True
            and query.get("coverage_status") == "COMPLETE"
            and query.get("endpoint_collection_status") == "AVAILABLE"
            and query.get("transport_status") == "AVAILABLE"
            and query.get("index_status") == "AVAILABLE"
            and query.get("request_error") is None
            and query.get("exact_target_event_count") == 0
            for query in post_restore_queries
        ),
        "cleanup_and_original_config_restored": controller.get("cleanup_verified") is True
        and controller.get("restored_hash_matches_original") is True,
    }
    result = {
        "schema_version": "csg-v51-supplemental-provenance-audit-v3",
        "audited_at_utc": datetime.now(UTC).isoformat(),
        "trial_id": trial_id,
        "evidence_class": "READ_ONLY_POSTRUN_AUDIT_NOT_CONTROLLER_SCORING",
        "controller_strict_trial_pass": strict_status,
        "controller_strict_trial_promoted": False,
        "controller_strict_gate_failures": strict_gate_failures(controller),
        "raw_readback_sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        "physical_windows_event_identity": {
            "event_record_id": local_event.get("record_id"),
            "event_code": local_event.get("event_id"),
            "provider": local_event.get("provider"),
            "task_name": local_event.get("task_name"),
        },
        "target_object_key": target_key,
        "canonical_event_ids": [row.get("event_id") for row in rows],
        "provider_source_reference_keys": sorted(provider_keys),
        "csg_store_source_reference_keys": sorted(store_keys),
        "raw_event_rows": len(rows),
        "logical_physical_event_count": len(identity_keys),
        "reconciliation_alias_groups": alias_groups,
        "postrestore_query_count": len(post_restore_queries),
        "postrestore_exact_target_counts": [
            query.get("exact_target_event_count") for query in post_restore_queries
        ],
        "unique_source_references": len(store_keys),
        "checks": checks,
        "passed": all(checks.values()),
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
    audit_results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for attempt in summary["attempts"]:
        trial_dir = root / attempt["trial_id"]
        try:
            audit_results.append(
                audit_trial(
                    trial_dir,
                    args.api_base,
                    attempt["assessment"].get("strict_trial_pass") is True,
                )
            )
        except (KeyError, OSError, ValueError, TimeoutError) as exc:
            errors.append(
                {"trial_id": attempt["trial_id"], "error": f"{type(exc).__name__}: {exc}"}
            )

    aggregate = {
        "schema_version": "csg-v51-campaign-provenance-audit-v3",
        "audited_at_utc": datetime.now(UTC).isoformat(),
        "campaign_id": summary["experiment_id"],
        "evidence_class": "READ_ONLY_POSTRUN_AUDIT_NOT_CONTROLLER_SCORING",
        "assigned_trials": summary["assigned_count"],
        "accounted_trials": len(summary["attempts"]),
        "controller_strict_pass_count": summary["strict_pass_count"],
        "supplemental_audits_passed": sum(item["passed"] for item in audit_results),
        "supplemental_audits_failed": sum(not item["passed"] for item in audit_results),
        "audit_errors": errors,
        "strict_dispositions_unchanged": True,
        "trials": [
            {
                "trial_id": item["trial_id"],
                "controller_strict_trial_pass": item["controller_strict_trial_pass"],
                "strict_gate_failures": item["controller_strict_gate_failures"],
                "supplemental_audit_passed": item["passed"],
                "checks_passed": sum(item["checks"].values()),
                "checks_total": len(item["checks"]),
                "event_ids": item["canonical_event_ids"],
                "physical_event_count": item["logical_physical_event_count"],
                "raw_event_rows": item["raw_event_rows"],
            }
            for item in audit_results
        ],
        "interpretation": (
            "The API readback independently audits exact wrong-object event provenance. "
            "It does not alter frozen controller outcomes or turn a failed strict trial "
            "into a pass."
        ),
    }
    output = root / "postrun" / "campaign-provenance-audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(aggregate, indent=2, sort_keys=True))
    return (
        0
        if not errors
        and len(audit_results) == summary["assigned_count"]
        and all(item["passed"] for item in audit_results)
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
