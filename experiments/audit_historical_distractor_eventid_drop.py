from __future__ import annotations

import argparse
import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def scheduled_task_scenario(run: dict[str, Any], label: str) -> dict[str, Any]:
    scenarios = [item for item in run.get("scenarios", []) if item.get("kind") == "scheduled_task"]
    if len(scenarios) != 1:
        raise ValueError(f"{label} must contain exactly one scheduled_task scenario")
    return scenarios[0]


def normalize_task_name(value: Any) -> str:
    return str(value or "").strip().lstrip("\\/").replace("/", "\\").casefold()


def event_references(event: dict[str, Any]) -> set[tuple[str, str]]:
    references = set()
    metadata = event.get("metadata") or {}
    all_references = [
        event.get("source_reference"),
        *(metadata.get("additional_source_references") or []),
    ]
    for reference in all_references:
        if isinstance(reference, dict) and reference.get("index") and reference.get("document_id"):
            references.add((str(reference["index"]), str(reference["document_id"])))
    return references


def physical_identity_group(
    audit: dict[str, Any], task_name: str
) -> tuple[list[dict[str, Any]], tuple[str, ...], set[str], set[tuple[str, str]]]:
    matching_groups = []
    for group in audit.get("stable_identity_groups", []):
        docs = [
            item
            for item in group.get("documents", [])
            if normalize_task_name(item.get("raw_task_name")) == normalize_task_name(task_name)
        ]
        if docs:
            matching_groups.append((group, docs))
    if len(matching_groups) != 1:
        raise ValueError("Raw Indexer audit must identify exactly one physical task-creation event")
    group, docs = matching_groups[0]
    identity = tuple(str(part) for part in group.get("identity", []))
    if not identity or any(not item.get("document_found") for item in docs):
        raise ValueError(
            "Physical event identity is incomplete or a referenced Indexer document is absent"
        )
    aliases = {str(item["event_id"]) for item in docs if item.get("event_id")}
    references = {
        (str(item["index"]), str(item["document_id"]))
        for item in docs
        if item.get("index") and item.get("document_id")
    }
    if not aliases or not references:
        raise ValueError("Raw physical-event group has no Wazuh event/document references")
    return docs, identity, aliases, references


def is_exact_task_event(
    event: dict[str, Any], *, host_id: str, object_key: str
) -> bool:
    return (
        event.get("host_id") == host_id
        and event.get("source") == "wazuh"
        and event.get("normalized_type") == "scheduled_task_created"
        and str(event.get("target", {}).get("key", "")).casefold() == object_key.casefold()
    )


def represents_physical_event(
    event: dict[str, Any], *, aliases: set[str], references: set[tuple[str, str]]
) -> bool:
    return event.get("event_id") in aliases or bool(event_references(event) & references)


async def query_events(
    client: httpx.AsyncClient,
    *,
    api_base: str,
    host_id: str,
    start: str,
    end: str,
    provider: bool,
) -> dict[str, Any] | list[dict[str, Any]]:
    route = (
        f"/api/hosts/{quote(host_id, safe='')}/provider-event-observation"
        if provider
        else f"/api/hosts/{quote(host_id, safe='')}/events"
    )
    response = await client.get(
        f"{api_base.rstrip('/')}{route}",
        params={
            "start": start,
            "end": end,
            "normalized_type": "scheduled_task_created",
            "source": "wazuh",
            "limit": 5000,
        },
    )
    response.raise_for_status()
    payload = response.json()
    if provider and not isinstance(payload, dict):
        raise ValueError("Provider observation endpoint returned an unexpected payload")
    if not provider and not isinstance(payload, list):
        raise ValueError("CSG event-store endpoint returned an unexpected payload")
    return payload


async def capture_window(
    *, api_base: str, host_id: str, start: str, end: str, timeout: float
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        provider = await query_events(
            client,
            api_base=api_base,
            host_id=host_id,
            start=start,
            end=end,
            provider=True,
        )
        store = await query_events(
            client,
            api_base=api_base,
            host_id=host_id,
            start=start,
            end=end,
            provider=False,
        )
    assert isinstance(provider, dict) and isinstance(store, list)
    return provider, store


async def run_pretarget(args: argparse.Namespace) -> dict[str, Any]:
    run = load_json(args.distractor_run)
    scenario = scheduled_task_scenario(run, "distractor run")
    name = scenario["object_name"]
    key = scenario["expected_object_key"]
    identity_audit = load_json(args.distractor_identity_audit)
    docs, identity, aliases, references = physical_identity_group(identity_audit, name)
    event_matches = [
        event
        for event in scenario.get("event_plane", {}).get("exact_matches", [])
        if is_exact_task_event(event, host_id=args.host_id, object_key=key)
        and represents_physical_event(event, aliases=aliases, references=references)
    ]
    if not event_matches:
        raise ValueError(
            "Runner output has no exact Wazuh event matching the raw physical identity"
        )

    retrieval = scenario.get("event_retrieval", {})
    start = retrieval.get("query_start")
    end = retrieval.get("query_end")
    if not start or not end:
        raise ValueError("Distractor run has no bounded provider query window")
    provider, store = await capture_window(
        api_base=args.api_base,
        host_id=args.host_id,
        start=start,
        end=end,
        timeout=args.timeout,
    )
    provider_events = [
        event
        for event in provider.get("events", [])
        if is_exact_task_event(event, host_id=args.host_id, object_key=key)
        and represents_physical_event(event, aliases=aliases, references=references)
    ]
    store_events = [
        event
        for event in store
        if is_exact_task_event(event, host_id=args.host_id, object_key=key)
        and represents_physical_event(event, aliases=aliases, references=references)
    ]
    local_events = [
        event
        for event in scenario.get("local_source_evidence", {}).get("exact_events", [])
        if event.get("event_id") == 4698
        and normalize_task_name(event.get("event_data", {}).get("TaskName"))
        == normalize_task_name(name)
    ]
    local_record_ids = {str(event.get("record_id")) for event in local_events}
    raw_record_ids = {str(document.get("event_record_id")) for document in docs}
    checks = {
        "native_probe_observed_and_cleaned_task": bool(
            scenario.get("state_plane", {}).get("target_absent_before_action")
            and scenario.get("state_plane", {}).get("after_action_observed")
            and scenario.get("state_plane", {}).get("cleanup_removed_from_probe")
            and scenario.get("action", {}).get("cleanup_completed")
        ),
        "one_physical_event_in_raw_indexer_audit": len(
            {tuple(item.get("stable_windows_event_identity", [])) for item in docs}
        )
        == 1,
        "physical_identity_matches_local_eventrecordid": bool(local_record_ids & raw_record_ids),
        "same_physical_event_in_provider_query": bool(provider_events),
        "same_physical_event_in_csg_event_store": bool(store_events),
        "provider_query_complete_and_available": bool(
            provider.get("query_complete") is True
            and provider.get("coverage_status") == "COMPLETE"
            and provider.get("endpoint_collection_status") == "AVAILABLE"
            and provider.get("transport_status") == "AVAILABLE"
            and provider.get("index_status") == "AVAILABLE"
        ),
    }
    output = {
        "schema_version": "csg-historical-distractor-pretarget-verification-v1",
        "verified_at_utc": datetime.now(UTC).isoformat(),
        "campaign_id": "scheduled-task-historical-distractor-eventid-drop-v26",
        "host_id": args.host_id,
        "task_name": name,
        "object_key": key,
        "physical_windows_event_identity": list(identity),
        "physical_event_record_id": (
            next(iter(raw_record_ids)) if len(raw_record_ids) == 1 else None
        ),
        "wazuh_document_alias_event_ids": sorted(aliases),
        "wazuh_source_references": [
            {"index": index, "document_id": document_id}
            for index, document_id in sorted(references)
        ],
        "query_window": {"start": start, "end": end},
        "provider_observation": provider,
        "csg_event_store_query": store,
        "checks": checks,
        "all_checks_passed": all(checks.values()),
        "runner_positive_control_status": scenario.get("positive_control", {}).get("passed"),
        "runner_status_note": (
            "The runner's exact-event-ID set predicate may reject alert/archive aliases; "
            "uses raw Windows physical identity and still requires exact task identity."
        ),
    }
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


async def run_final(args: argparse.Namespace) -> dict[str, Any]:
    distractor_run = load_json(args.distractor_run)
    distractor = scheduled_task_scenario(distractor_run, "distractor run")
    distractor_name = distractor["object_name"]
    distractor_key = distractor["expected_object_key"]
    identity_audit = load_json(args.distractor_identity_audit)
    docs, identity, aliases, references = physical_identity_group(identity_audit, distractor_name)

    target_run = load_json(args.target_run)
    target = scheduled_task_scenario(target_run, "target run")
    target_name = target["object_name"]
    target_key = target["expected_object_key"]
    diagnostic = load_json(args.diagnostic_result)
    final_reconciliation = diagnostic.get("final_target_reconciliation") or {}
    observation_window = final_reconciliation.get("observation_window") or {}
    start = observation_window.get("start")
    end = observation_window.get("end")
    if not start or not end:
        raise ValueError("Final reconciliation has no bounded observation window")
    start_time = datetime.fromisoformat(start.replace("Z", "+00:00"))
    end_time = datetime.fromisoformat(end.replace("Z", "+00:00"))
    if end_time <= start_time or (end_time - start_time).total_seconds() > 1800:
        raise ValueError(
            "Reconciliation query window is invalid or exceeds the API's 30-minute limit"
        )

    provider, store = await capture_window(
        api_base=args.api_base,
        host_id=args.host_id,
        start=start,
        end=end,
        timeout=args.timeout,
    )
    provider_events = provider.get("events", [])
    distractor_provider = [
        event
        for event in provider_events
        if is_exact_task_event(event, host_id=args.host_id, object_key=distractor_key)
        and represents_physical_event(event, aliases=aliases, references=references)
    ]
    distractor_store = [
        event
        for event in store
        if is_exact_task_event(event, host_id=args.host_id, object_key=distractor_key)
        and represents_physical_event(event, aliases=aliases, references=references)
    ]
    target_provider = [
        event
        for event in provider_events
        if is_exact_task_event(event, host_id=args.host_id, object_key=target_key)
    ]
    target_store = [
        event
        for event in store
        if is_exact_task_event(event, host_id=args.host_id, object_key=target_key)
    ]
    distractor_time = datetime.fromisoformat(
        docs[0]["event_timestamp"].replace("Z", "+00:00")
    )
    distractor_in_window = start_time <= distractor_time <= end_time
    matched_ids = final_reconciliation.get("matched_evidence_ids", [])
    raw_local = target.get("local_source_evidence", {})
    local_target_events = [
        item
        for item in raw_local.get("exact_events", [])
        if item.get("event_id") == 4698
        and item.get("exact_identity_match") is True
        and normalize_task_name(item.get("event_data", {}).get("TaskName"))
        == normalize_task_name(target_name)
    ]
    retrieval = target.get("event_retrieval", {})
    history = diagnostic.get("target_reconciliation_history", [])
    original_hash = diagnostic.get("original_agent_config_sha256")
    restored_hash = diagnostic.get("restored_agent_config_sha256")
    source_health = diagnostic.get("source_health_after_restore") or {}

    checks = {
        "target_local_event_4698_exact": len(local_target_events) == 1,
        "probe_observed_target_state": bool(
            target.get("state_plane", {}).get("after_action_observed")
            and target.get("state_plane", {}).get("target_absent_before_action")
            and target.get("state_plane", {}).get("cleanup_removed_from_probe")
        ),
        "target_provider_query_complete": bool(retrieval.get("query_complete")),
        "target_event_absent_from_provider_query": (
            diagnostic.get("exact_wazuh_target_event_count_during_filter") == 0
            and len(target_provider) == 0
        ),
        "target_absent_from_csg_event_store": (
            diagnostic.get("target_absent_from_csg_event_store_during_filter") is True
            and len(target_store) == 0
        ),
        "distractor_in_reconciliation_window": distractor_in_window,
        "same_physical_distractor_present_in_provider": bool(distractor_provider),
        "same_physical_distractor_present_in_csg_store": bool(distractor_store),
        "query_complete_and_available": bool(
            provider.get("query_complete") is True
            and provider.get("coverage_status") == "COMPLETE"
            and provider.get("endpoint_collection_status") == "AVAILABLE"
            and provider.get("transport_status") == "AVAILABLE"
            and provider.get("index_status") == "AVAILABLE"
        ),
        "finalized_unexplained_without_citations": bool(
            final_reconciliation.get("status") == "UNEXPLAINED"
            and final_reconciliation.get("finalized") is True
            and not matched_ids
        ),
        "distractor_not_cited": not bool(set(matched_ids) & aliases),
        "baseline_agent_config_restored": bool(
            original_hash and original_hash == restored_hash
        ),
        "agent_active_after_restore": source_health.get("endpoint_agent_status") == "active",
        "target_and_distractor_names_distinct": target_name.casefold()
        != distractor_name.casefold(),
        "reconciliation_history_has_finalized_unexplained": any(
            item.get("status") == "UNEXPLAINED" and item.get("finalized") is True
            for item in history
        ),
    }
    output = {
        "schema_version": "csg-historical-distractor-capture-drop-audit-v1",
        "audited_at_utc": datetime.now(UTC).isoformat(),
        "campaign_id": "scheduled-task-historical-distractor-eventid-drop-v26",
        "host_id": args.host_id,
        "target": {"task_name": target_name, "object_key": target_key},
        "distractor": {
            "task_name": distractor_name,
            "object_key": distractor_key,
            "physical_windows_event_identity": list(identity),
            "physical_event_record_id": docs[0]["event_record_id"],
            "wazuh_document_alias_event_ids": sorted(aliases),
            "event_time": docs[0]["event_timestamp"],
            "inside_final_reconciliation_window": distractor_in_window,
        },
        "reconciliation_window": {"start": start, "end": end},
        "provider_observation": provider,
        "csg_event_store_query": store,
        "final_reconciliation": final_reconciliation,
        "checks": checks,
        "all_checks_passed": all(checks.values()),
        "interpretation_limit": (
            "One benign, single-host mechanism trial. A complete bounded query and absent target "
            "event do not establish permanent loss under every future recovery path or improved "
            "malicious-activity detection."
        ),
    }
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify physical Wazuh/Windows identity for a preloaded task distractor and "
            "audit its use during a later capture-drop trial."
        )
    )
    parser.add_argument("--phase", choices=("pretarget", "final"), required=True)
    parser.add_argument("--distractor-run", type=Path, required=True)
    parser.add_argument("--distractor-identity-audit", type=Path, required=True)
    parser.add_argument("--target-run", type=Path)
    parser.add_argument("--diagnostic-result", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--api-base", default="http://localhost:8000")
    parser.add_argument("--host-id", default="win11-arm-lab")
    parser.add_argument("--timeout", type=float, default=60.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.phase == "pretarget":
        result = asyncio.run(run_pretarget(args))
    else:
        if not args.target_run or not args.diagnostic_result:
            raise SystemExit("--target-run and --diagnostic-result are required for final audit")
        result = asyncio.run(run_final(args))
    print(
        json.dumps(
            {"all_checks_passed": result["all_checks_passed"], "checks": result["checks"]},
            indent=2,
        )
    )
    return 0 if result["all_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
