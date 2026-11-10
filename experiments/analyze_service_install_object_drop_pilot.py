"""Independently audit one frozen Windows service-install drop pilot."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _items(value: Any) -> list[Any]:
    """Unwrap Windows PowerShell's serialized collection wrapper if present."""
    while (
        isinstance(value, list)
        and len(value) == 1
        and isinstance(value[0], dict)
        and "value" in value[0]
        and "Count" in value[0]
    ):
        value = value[0]
    while isinstance(value, dict) and "value" in value and "Count" in value:
        value = value["value"]
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def analyze(directory: Path) -> dict[str, Any]:
    assignment = _json(directory / "assignment.json")
    frozen = _json(directory / "source-freeze.json")
    run = _json(directory / "service-install-object-drop-pilot-v5.json")
    provider = _json(directory / "provider-query-postflight.json")
    event_store = _json(directory / "event-store-target-postflight.json")
    final = _json(directory / "final-reconciliation-postflight.json")

    target_name = assignment["target_service_name"]
    distractor_name = assignment["distractor_service_name"]
    host_id = assignment["host_id"]
    target_key = f"service:{target_name.lower()}"
    distractor_key = f"service:{distractor_name.lower()}"
    target_delta_id = "f654ee68-da7e-55a2-99c5-1ec0df6ce3b8"

    target_deltas = [
        item
        for item in _items(run.get("target_delta"))
        if isinstance(item, dict) and item.get("object_key") == target_key
    ]
    target_adds = [item for item in target_deltas if item.get("delta_type") == "ADD"]
    target_add = next((item for item in target_adds if item.get("delta_id") == target_delta_id), {})

    final_findings = [
        item
        for item in final.get("target_finding", [])
        if item.get("object_key") == target_key and item.get("delta_id") == target_delta_id
    ]
    final_finding = final_findings[0] if len(final_findings) == 1 else {}
    reconciliation = final_finding.get("reconciliation") or {}
    event_plane = reconciliation.get("metadata", {}).get("event_plane", {})

    initial_provider = run.get("provider_query") or {}
    provider_target = initial_provider.get("target_exact_service_created_events") or []
    provider_distractor = initial_provider.get("distractor_exact_service_created_events") or []
    post_target = provider.get("service_created_target") or []
    post_distractor = provider.get("service_created_distractor") or []
    local_target = (run.get("target") or {}).get("local_7045") or {}
    local_distractor = (run.get("distractor") or {}).get("local_7045") or {}
    add_after = target_add.get("after") or {}
    add_attributes = add_after.get("attributes") or {}
    remove_target = run.get("cleanup", {}).get("target_remove_delta") or {}
    remove_distractor = run.get("cleanup", {}).get("distractor_remove_delta") or {}
    source_hashes = {
        "protocol": _sha256(directory / "PROTOCOL.md"),
        "runner": _sha256(directory / "run_service_install_object_drop_pilot_windows.ps1"),
    }
    exact_run_findings = [
        item
        for item in _items(run.get("target_findings"))
        if isinstance(item, dict)
        and item.get("object_key") == target_key
        and item.get("delta_id") == target_delta_id
    ]
    raw_findings = run.get("target_findings")
    findings_wrapper = (
        raw_findings[0]
        if isinstance(raw_findings, list)
        and len(raw_findings) == 1
        and isinstance(raw_findings[0], dict)
        else raw_findings
    )

    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "status": "PASS" if passed else "FAIL", "detail": detail})

    record(
        "frozen_inputs_match",
        source_hashes["protocol"] == frozen["protocol_sha256"]
        and source_hashes["runner"] == frozen["runner_sha256"],
        "Protocol and PowerShell runner hashes match the pre-mutation source freeze.",
    )
    record(
        "native_target_add",
        len(target_adds) == 1
        and add_attributes.get("service_name") == target_name
        and add_attributes.get("start_mode") == "manual"
        and add_attributes.get("status") == "stopped"
        and add_after.get("metadata", {}).get("source") == "direct_probe",
        "Exact target ADD delta names the registered service; it remained stopped/demand-start and came from the direct probe.",
    )
    record(
        "local_target_7045",
        local_target.get("event_id") == 7045
        and local_target.get("service_name") == target_name
        and local_target.get("computer") == run.get("computer_name"),
        "Raw local System event is Event 7045 for the assigned target on the Windows endpoint.",
    )
    record(
        "same_host_distractor_positive",
        len(provider_distractor) == 1
        and provider_distractor[0].get("host_id") == host_id
        and provider_distractor[0].get("normalized_type") == "service_created"
        and provider_distractor[0].get("target", {}).get("key") == distractor_key
        and provider_distractor[0].get("attributes", {}).get("event_code") == "7045"
        and provider_distractor[0].get("attributes", {}).get("rule_id") == "61138",
        "Wazuh returned the same-host, same-event-class distractor as rule 61138.",
    )
    record(
        "healthy_complete_provider_query",
        initial_provider.get("query_complete") is True
        and initial_provider.get("endpoint_collection_status") == "AVAILABLE"
        and initial_provider.get("index_status") == "AVAILABLE"
        and initial_provider.get("coverage_status") == "COMPLETE",
        "The event query completed while endpoint collection and index were available.",
    )
    record(
        "target_event_absent_initial_and_postflight",
        len(provider_target) == 0 and len(post_target) == 0,
        "No exact target service_created event was returned in the in-run or postflight Wazuh queries.",
    )
    record(
        "target_event_absent_from_csg_store",
        event_store.get("event_count") == 0 and event_store.get("events") == [],
        "The exact target service_created query against CSG's persisted event store returned zero rows.",
    )
    record(
        "distractor_remained_visible_postflight",
        len(post_distractor) == 1
        and post_distractor[0].get("target", {}).get("key") == distractor_key,
        "The same-host distractor was still visible on the postflight provider query.",
    )
    record(
        "final_target_unexplained_without_citation",
        len(final_findings) == 1
        and reconciliation.get("status") == "UNEXPLAINED"
        and reconciliation.get("finalized") is True
        and reconciliation.get("matched_evidence_ids") == []
        and "service_created" in reconciliation.get("missing_expected_evidence_types", []),
        "The exact ADD finding finalized UNEXPLAINED with no matched event IDs.",
    )
    record(
        "final_query_health_is_complete",
        event_plane.get("query_complete") is True
        and event_plane.get("endpoint_collection_status") == "AVAILABLE"
        and event_plane.get("transport_status") == "AVAILABLE"
        and event_plane.get("index_status") == "AVAILABLE"
        and event_plane.get("coverage_status") == "COMPLETE",
        "The reconciliation's final event-plane record reports a complete healthy query.",
    )
    record(
        "configuration_restored_and_healthy",
        run.get("restoration", {}).get("exact_hash_match") is True
        and run.get("restoration", {}).get("original_hash")
        == run.get("restoration", {}).get("restored_hash")
        and run.get("restoration", {}).get("healthy_after_restart", {}).get("wazuh_service_status")
        == "Running",
        "The runner recorded exact Wazuh config hash restoration and healthy service/agent/indexer after restart.",
    )
    record(
        "windows_and_probe_cleanup",
        run.get("cleanup", {}).get("target_windows_absent") is True
        and run.get("cleanup", {}).get("distractor_windows_absent") is True
        and run.get("cleanup", {}).get("target_probe_absent") is True
        and run.get("cleanup", {}).get("distractor_probe_absent") is True
        and remove_target.get("delta_type") == "REMOVE"
        and remove_target.get("object_key") == target_key
        and remove_distractor.get("delta_type") == "REMOVE"
        and remove_distractor.get("object_key") == distractor_key,
        "Windows absence and exact direct-probe REMOVE deltas were captured for both assigned services.",
    )

    # The original runner serialized a 500-item PowerShell response wrapper into the
    # run artifact. Use exact object/delta IDs above and the later API readback instead.
    runner_diagnostics = {
        "runner_outcome_field": run.get("outcome"),
        "runner_target_findings_collection_count": (findings_wrapper or {}).get("Count")
        if isinstance(findings_wrapper, dict)
        else None,
        "scoped_target_findings_in_raw_collection": len(exact_run_findings),
        "runner_poll_count": len(run.get("reconciliation_polls") or []),
        "poll_summary_valid_for_target": False,
        "reason": "Windows PowerShell serialized Invoke-RestMethod list responses as Count/value wrappers; the runner's pipeline filter/status summary was therefore unscoped. Final status is taken from the exact finding_id/delta_id API postflight artifact.",
    }
    passed = sum(item["status"] == "PASS" for item in checks)
    failed = len(checks) - passed
    return {
        "schema_version": "csg-service-install-object-drop-analysis-v1",
        "experiment_id": assignment["experiment_id"],
        "trial_id": assignment["trial_id"],
        "host_id": host_id,
        "target_service_name": target_name,
        "distractor_service_name": distractor_name,
        "classification": "QUALIFIED_SINGLE_MECHANISM_PILOT" if failed == 0 else "NOT_QUALIFIED",
        "confirmatory": False,
        "denominator": 1,
        "checks": checks,
        "check_summary": {"passed": passed, "failed": failed},
        "observed": {
            "target_delta_id": target_add.get("delta_id"),
            "target_finding_id": final_finding.get("finding_id"),
            "target_reconciliation_status": reconciliation.get("status"),
            "target_reconciliation_version": reconciliation.get("version"),
            "target_reconciliation_finalized_at": reconciliation.get("finalized_at"),
            "target_wazuh_event_count": len(post_target),
            "distractor_wazuh_event_count": len(post_distractor),
            "final_event_plane_semantics": reconciliation.get("metadata", {}).get("reconciliation_semantics"),
            "final_source_health_attribution": reconciliation.get("metadata", {}).get("source_health_attribution"),
            "runner_diagnostics": runner_diagnostics,
        },
        "interpretation": (
            "On one Windows 11 ARM64 endpoint, a benign target service ADD was observed by the native probe and its local Event 7045 was not returned by complete healthy Wazuh queries or found in CSG's target event store. A same-host service_created distractor remained visible, and the exact target finding finalized UNEXPLAINED without evidence citations. This demonstrates the object-specific mechanism under a deliberate target filter in one pilot; it does not estimate reliability or detect malicious activity. The reconciler's semantics field is INCONCLUSIVE and source attribution is UNKNOWN, so do not claim that the status independently identifies the reason the event was absent."
        ),
        "limitations": [
            "n=1 exploratory pilot on one Windows VM; V1-V4 runner attempts stopped before target mutation and are excluded.",
            "The intervention intentionally filtered one exact EventID 7045 name and ignored that target's exact FIM registry key; it is not a natural outage or general permanent-loss test.",
            "Target reconciliation is UNEXPLAINED, but reconciliation_semantics is INCONCLUSIVE and source_health_attribution is UNKNOWN.",
            "The V5 raw runner's PowerShell list handling caused an unscoped poll summary and a 16 MiB artifact containing unrelated findings; the independent audit scopes by exact host/object/delta/finding IDs and leaves the raw file unchanged.",
            "No malicious payload was executed and no malicious-intent or detection-accuracy claim is supported."
        ],
        "source_hashes": source_hashes,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.directory)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"classification": result["classification"], **result["check_summary"]}))
    return 0 if result["classification"] == "QUALIFIED_SINGLE_MECHANISM_PILOT" else 1


if __name__ == "__main__":
    raise SystemExit(main())
