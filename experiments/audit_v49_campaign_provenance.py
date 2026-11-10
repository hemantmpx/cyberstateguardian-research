from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import urlopen


def source_key(reference: dict[str, Any]) -> str:
    index = str(reference.get("index", "")).casefold()
    document_id = str(reference.get("document_id", "")).casefold()
    return f"{index}|{document_id}"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def query_csg_events(
    api_base: str, host_id: str, event_time: datetime, object_key: str, object_name: str
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


def audit_trial(trial_dir: Path, api_base: str) -> dict[str, Any]:
    trial_id = trial_dir.name
    raw_path = trial_dir / "windows-raw" / trial_id / "result.json"
    controller = read_json(raw_path)
    host_id = str(controller["host_id"])
    distractor = controller["distractor_event"]
    local_event = distractor["local_windows_event"]
    event_time = datetime.fromisoformat(local_event["event_time_utc"].replace("Z", "+00:00"))
    rows = query_csg_events(
        api_base,
        host_id,
        event_time,
        str(distractor["object_key"]),
        str(distractor["task_name"]),
    )

    postrun_dir = trial_dir / "postrun"
    postrun_dir.mkdir(parents=True, exist_ok=True)
    readback_path = postrun_dir / "csg-event-store-raw-readback.json"
    readback_path.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = controller["distractor_event_store_readback_validation"]
    provider_keys = {str(key).casefold() for key in validation["provider_source_reference_keys"]}
    refs: list[dict[str, Any]] = []
    for row in rows:
        if row.get("source_reference"):
            refs.append(row["source_reference"])
        refs.extend(row.get("metadata", {}).get("additional_source_references", []))
    store_keys = {source_key(reference) for reference in refs}
    event_identity = (
        rows[0].get("metadata", {}).get("windows_event_identity", {}) if len(rows) == 1 else {}
    )
    final_reconciliation = controller.get("final_target_reconciliation", {})
    checks = {
        "original_controller_remains_incomplete": controller.get("status")
        == "INCOMPLETE_OR_INVALID",
        "target_state_sequence_observed": controller.get(
            "direct_probe_state_sequence_passed"
        )
        is True,
        "target_absent_from_event_store_during_filter": controller.get(
            "target_absent_from_csg_event_store_during_filter"
        ) is True,
        "filtered_event_query_completed": controller.get("query_complete_during_filter") is True,
        "local_distractor_was_exact_event_4698": str(local_event.get("event_id")) == "4698"
        and local_event.get("exact_identity_match") is True,
        "one_canonical_distractor_event_in_csg_store": len(rows) == 1,
        "host_type_and_exact_object_match": len(rows) == 1
        and rows[0].get("host_id") == host_id
        and rows[0].get("normalized_type") == "scheduled_task_created"
        and rows[0].get("target", {}).get("key", "").casefold()
        == str(distractor["object_key"]).casefold(),
        "physical_windows_event_identity_matches_local_event": len(rows) == 1
        and str(event_identity.get("event_record_id")) == str(local_event.get("record_id"))
        and str(event_identity.get("event_code")) == str(local_event.get("event_id"))
        and str(event_identity.get("provider_name", "")).casefold()
        == str(local_event.get("provider", "")).casefold(),
        "provider_alert_and_archive_refs_preserved_in_csg_store": bool(provider_keys)
        and store_keys == provider_keys
        and len(store_keys) == 2,
        "distractor_inside_target_window_and_wrong_object": controller.get(
            "distractor_inside_final_reconciliation_window"
        ) is True
        and controller.get("distractor_same_host_same_type_different_object") is True,
        "target_finalized_unexplained_without_citations": final_reconciliation.get("status")
        == "UNEXPLAINED"
        and final_reconciliation.get("matched_evidence_ids") == [],
        "cleanup_and_configuration_restore_verified": controller.get("cleanup_verified") is True
        and controller.get("restored_hash_matches_original") is True,
    }
    result = {
        "schema_version": "csg-v49-supplemental-provenance-audit-v1",
        "audited_at_utc": datetime.now(UTC).isoformat(),
        "trial_id": trial_id,
        "evidence_class": "POSTRUN_READ_ONLY_CORROBORATION_NOT_A_CONTROLLER_PASS",
        "controller_trial_status": controller.get("status"),
        "controller_trial_is_promoted": False,
        "raw_readback_sha256": hashlib.sha256(readback_path.read_bytes()).hexdigest(),
        "local_event_identity": {
            "event_code": local_event.get("event_id"),
            "event_record_id": local_event.get("record_id"),
            "provider": local_event.get("provider"),
            "task_name": local_event.get("task_name"),
        },
        "canonical_csg_event_ids": [row.get("event_id") for row in rows],
        "provider_source_reference_keys": sorted(provider_keys),
        "csg_store_source_reference_keys": sorted(store_keys),
        "frozen_v14_projection_reported_refs_match": validation.get(
            "readback_references_match_provider_alert_and_archive_references"
        ),
        "checks": checks,
        "passed": all(checks.values()),
        "interpretation": (
            "Supplemental API readback checks whether the CSG store retained the provider's "
            "alert/archive aliases and exact physical Windows event identity. It does not "
            "change the frozen controller disposition or convert this trial into a strict pass."
        ),
    }
    audit_path = postrun_dir / "provenance-audit.json"
    audit_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--api-base", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    campaign_dir = args.campaign_dir.resolve()
    summary = read_json(campaign_dir / "campaign-summary.json")
    attempted = {
        item["trial_id"]
        for item in summary["attempts"]
        if item.get("assessment", {}).get("result_present") is True
    }
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for trial_id in sorted(attempted):
        try:
            results.append(audit_trial(campaign_dir / trial_id, args.api_base))
        except (HTTPError, URLError, KeyError, OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append({"trial_id": trial_id, "error": f"{type(exc).__name__}: {exc}"})

    aggregate = {
        "schema_version": "csg-v49-campaign-provenance-audit-v1",
        "audited_at_utc": datetime.now(UTC).isoformat(),
        "campaign_id": summary["experiment_id"],
        "evidence_class": "SUPPLEMENTAL_READ_ONLY_AUDIT_NOT_FROZEN_CONTROLLER_SCORING",
        "assigned_trials": summary["assigned_count"],
        "attempted_trials_with_result": len(attempted),
        "controller_strict_passes": summary["strict_pass_count"],
        "supplemental_audits_passed": sum(bool(item["passed"]) for item in results),
        "supplemental_audits_failed": sum(not item["passed"] for item in results),
        "audit_errors": errors,
        "trials": [
            {
                "trial_id": item["trial_id"],
                "passed": item["passed"],
                "controller_trial_status": item["controller_trial_status"],
                "checks_passed": sum(item["checks"].values()),
                "checks_total": len(item["checks"]),
                "event_id": item["canonical_csg_event_ids"][0]
                if item["canonical_csg_event_ids"]
                else None,
            }
            for item in results
        ],
        "strict_trial_disposition_unchanged": True,
        "notes": [
            "The first assignment had a pre-mutation launch/transfer failure and has no result "
            "to audit.",
            "Supplemental event-store readback is not used to retroactively promote a v49 trial.",
            "All trials are repeated measures on one Windows endpoint, not independent hosts.",
        ],
    }
    output = campaign_dir / "postrun" / "campaign-provenance-audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(aggregate, indent=2, sort_keys=True))
    return 0 if not errors and all(item["passed"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
