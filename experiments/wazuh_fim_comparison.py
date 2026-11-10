from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from csg.config import Settings
from csg.providers.wazuh import WazuhClient, WazuhConfig, _host_match_clauses

Json = dict[str, Any]


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


def _canonical_registry_path(value: str | None) -> str:
    path = (value or "").strip().replace("/", "\\")
    while "\\\\" in path:
        path = path.replace("\\\\", "\\")
    path = path.removeprefix("registry:")
    lowered = path.casefold()
    if lowered.startswith("hku\\") or lowered.startswith("hku:"):
        path = "HKEY_USERS\\" + path[4:].lstrip("\\:")
    elif lowered.startswith("hkey_users\\"):
        path = "HKEY_USERS\\" + path[len("hkey_users\\") :]
    return path.rstrip("\\").casefold()


def _trial_files(campaign_dir: Path) -> list[tuple[Path, Json]]:
    trials: list[tuple[Path, Json]] = []
    for path in sorted(campaign_dir.rglob("run.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        if record.get("schema_version") == "csg-registry-reconciliation-trial-v1":
            trials.append((path, record))
    return trials


async def _fetch_fim_documents(
    client: WazuhClient,
    host_id: str,
    start: datetime,
    end: datetime,
    index_pattern: str,
) -> tuple[list[Json], Json]:
    hits: list[Json] = []
    search_after: list[Any] | None = None
    total: int | None = None
    pages = 0
    complete = False
    while pages < 100:
        body: Json = {
            "size": 1000,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": _iso(start), "lte": _iso(end)}}},
                        {"exists": {"field": "syscheck.path"}},
                    ],
                    "should": _host_match_clauses(host_id),
                    "minimum_should_match": 1,
                }
            },
            "sort": [
                {"@timestamp": {"order": "asc", "unmapped_type": "date"}},
                {"_id": "asc"},
            ],
        }
        if search_after is not None:
            body["search_after"] = search_after
        payload = await client.indexer_search(index_pattern, body)
        page = payload.get("hits", {}).get("hits", [])
        if not isinstance(page, list):
            page = []
        pages += 1
        if total is None:
            total_field = payload.get("hits", {}).get("total")
            total = int(total_field.get("value")) if isinstance(total_field, dict) else None
        hits.extend(hit for hit in page if isinstance(hit, dict))
        if not page or len(page) < 1000:
            complete = True
            break
        values = page[-1].get("sort")
        if not isinstance(values, list) or not values:
            complete = total is not None and total <= len(hits)
            break
        search_after = values
    if pages >= 100 and not complete:
        complete = total is not None and total <= len(hits)
    return hits, {
        "complete": complete,
        "pages": pages,
        "returned_documents": len(hits),
        "reported_total": total,
        "index_pattern": index_pattern,
    }


async def _fetch_sysmon_registry_documents(
    client: WazuhClient,
    host_id: str,
    start: datetime,
    end: datetime,
    index_pattern: str,
) -> tuple[list[Json], Json]:
    hits: list[Json] = []
    search_after: list[Any] | None = None
    total: int | None = None
    pages = 0
    complete = False
    while pages < 100:
        body: Json = {
            "size": 1000,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": _iso(start), "lte": _iso(end)}}},
                        {
                            "bool": {
                                "should": [
                                    {"term": {"data.win.system.eventID": "13"}},
                                    {"term": {"data.win.system.eventId": "13"}},
                                    {"term": {"data.win.system.eventID": 13}},
                                    {"term": {"win.system.eventID": "13"}},
                                    {"term": {"win.system.eventID": 13}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {
                                        "wildcard": {
                                            "data.win.eventdata.TargetObject.keyword": (
                                                "*CSGConfRun*"
                                            )
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "data.win.eventdata.TargetObject": "*CSGConfRun*"
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "data.win.eventdata.targetObject.keyword": (
                                                "*CSGConfRun*"
                                            )
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "data.win.eventdata.targetObject": "*CSGConfRun*"
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "win.eventdata.TargetObject.keyword": "*CSGConfRun*"
                                        }
                                    },
                                    {"wildcard": {"win.eventdata.TargetObject": "*CSGConfRun*"}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                    ],
                    "should": _host_match_clauses(host_id),
                    "minimum_should_match": 1,
                }
            },
            "sort": [
                {"@timestamp": {"order": "asc", "unmapped_type": "date"}},
                {"_id": "asc"},
            ],
        }
        if search_after is not None:
            body["search_after"] = search_after
        payload = await client.indexer_search(index_pattern, body)
        page = payload.get("hits", {}).get("hits", [])
        if not isinstance(page, list):
            page = []
        pages += 1
        if total is None:
            total_field = payload.get("hits", {}).get("total")
            total = int(total_field.get("value")) if isinstance(total_field, dict) else None
        hits.extend(hit for hit in page if isinstance(hit, dict))
        if not page or len(page) < 1000:
            complete = True
            break
        values = page[-1].get("sort")
        if not isinstance(values, list) or not values:
            complete = total is not None and total <= len(hits)
            break
        search_after = values
    if pages >= 100 and not complete:
        complete = total is not None and total <= len(hits)
    return hits, {
        "complete": complete,
        "pages": pages,
        "returned_documents": len(hits),
        "reported_total": total,
        "index_pattern": index_pattern,
    }


def _alert_projection(hit: Json) -> Json:
    source = hit.get("_source") or {}
    syscheck = source.get("syscheck") or {}
    agent = source.get("agent") or {}
    rule = source.get("rule") or {}
    return {
        "document_id": hit.get("_id"),
        "index": hit.get("_index"),
        "timestamp": source.get("@timestamp"),
        "agent_id": agent.get("id"),
        "agent_name": agent.get("name"),
        "syscheck_path": syscheck.get("path"),
        "syscheck_event": syscheck.get("event"),
        "syscheck_value_name": syscheck.get("value_name"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
    }


def _sysmon_registry_projection(hit: Json) -> Json:
    source = hit.get("_source") or {}
    data = source.get("data") or {}
    win = data.get("win") or source.get("win") or {}
    event_data = win.get("eventdata") or source.get("eventdata") or {}
    system = win.get("system") or {}
    agent = source.get("agent") or {}
    rule = source.get("rule") or {}
    return {
        "document_id": hit.get("_id"),
        "index": hit.get("_index"),
        "timestamp": source.get("@timestamp"),
        "agent_id": agent.get("id"),
        "agent_name": agent.get("name"),
        "event_code": system.get("eventID") or system.get("eventId"),
        "provider_name": system.get("providerName"),
        "event_record_id": system.get("eventRecordID") or system.get("eventRecordId"),
        "target_object": event_data.get("TargetObject") or event_data.get("targetObject"),
        "event_type": event_data.get("EventType") or event_data.get("eventType"),
        "rule_id": rule.get("id"),
    }


def _unique_observation_count(alerts: list[Json]) -> int:
    unique = {
        (
            str(item.get("agent_name", "")).casefold(),
            _canonical_registry_path(item.get("syscheck_path")),
            str(item.get("syscheck_value_name", "")).casefold(),
            str(item.get("syscheck_event", "")).casefold(),
            str(item.get("timestamp", "")),
        )
        for item in alerts
    }
    return len(unique)


def _trial_analysis(
    record: Json,
    alerts: list[Json],
    sysmon_events: list[Json],
    query_end: datetime,
) -> Json:
    target_name = str(record.get("target_name") or "")
    distractor_name = str(record.get("distractor_name") or "")

    def object_path(object_key: str) -> str:
        key = _canonical_registry_path(object_key.split(":", 1)[-1])
        return key.rsplit("\\", 1)[0] if "\\" in key else ""

    target_key = object_path(str(record.get("target_object_key") or ""))
    distractor_key = object_path(str(record.get("distractor_object_key") or ""))
    target_full_key = _canonical_registry_path(
        str(record.get("target_object_key") or "").split(":", 1)[-1]
    )
    distractor_full_key = _canonical_registry_path(
        str(record.get("distractor_object_key") or "").split(":", 1)[-1]
    )
    action = (record.get("action_journal") or {}).get("target_create") or {}
    target_start = _parse_time(action.get("started_at"))
    target_completed = _parse_time(action.get("completed_at"))
    decision = _parse_time((record.get("target") or {}).get("decision_at"))
    cleanup = record.get("cleanup") or {}
    cleanup_start = _parse_time(cleanup.get("started_at"))
    cleanup_end = _parse_time(cleanup.get("completed_at"))
    service_down = _parse_time(
        ((record.get("wazuh_service") or {}).get("during") or {}).get("captured_at")
    )

    def exact(name: str, key: str) -> list[Json]:
        if not name or not key:
            return []
        return [
            item
            for item in alerts
            if str(item.get("syscheck_value_name") or "").casefold() == name.casefold()
            and _canonical_registry_path(item.get("syscheck_path")) == key
        ]

    target_alerts = exact(target_name, target_key)
    distractor_alerts = exact(distractor_name, distractor_key)
    target_added_alerts = [
        item
        for item in target_alerts
        if str(item.get("syscheck_event") or "").casefold() == "added"
    ]
    distractor_added_alerts = [
        item
        for item in distractor_alerts
        if str(item.get("syscheck_event") or "").casefold() == "added"
    ]
    target_deleted_after_cleanup = [
        item
        for item in target_alerts
        if str(item.get("syscheck_event") or "").casefold() == "deleted"
        and (timestamp := _parse_time(item.get("timestamp"))) is not None
        and cleanup_end is not None
        and timestamp >= cleanup_end
    ]
    same_name_wrong_path = [
        item
        for item in alerts
        if target_name
        and str(item.get("syscheck_value_name") or "").casefold() == target_name.casefold()
        and _canonical_registry_path(item.get("syscheck_path")) != target_key
    ]

    def at_or_before(items: list[Json], boundary: datetime | None) -> list[Json]:
        return [
            item
            for item in items
            if (timestamp := _parse_time(item.get("timestamp"))) is not None
            and boundary is not None
            and timestamp <= boundary
        ]

    target_by_decision = at_or_before(target_added_alerts, decision)
    target_after_decision = (
        [item for item in target_added_alerts if item not in target_by_decision]
        if decision
        else None
    )
    target_during_action = [
        item
        for item in target_added_alerts
        if (timestamp := _parse_time(item.get("timestamp"))) is not None
        and target_start is not None
        and timestamp >= target_start
        and (cleanup_start is None or timestamp <= cleanup_start)
    ]
    distractor_after_stop = [
        item
        for item in distractor_alerts
        if (timestamp := _parse_time(item.get("timestamp"))) is not None
        and service_down is not None
        and timestamp >= service_down
    ]
    latency: list[float] = []
    if target_completed:
        unique_timestamps = {
            timestamp
            for item in target_during_action
            if (timestamp := _parse_time(item.get("timestamp"))) is not None
        }
        latency = [
            round((timestamp - target_completed).total_seconds(), 6)
            for timestamp in sorted(unique_timestamps)
        ]

    def exact_sysmon_events(object_key: str) -> list[Json]:
        if not object_key:
            return []
        return [
            item
            for item in sysmon_events
            if _canonical_registry_path(item.get("target_object")) == object_key
            and str(item.get("event_code") or "") == "13"
        ]

    target_sysmon_events = exact_sysmon_events(target_full_key)
    distractor_sysmon_events = exact_sysmon_events(distractor_full_key)
    target_sysmon_during_trial = [
        item
        for item in target_sysmon_events
        if (timestamp := _parse_time(item.get("timestamp"))) is not None
        and target_start is not None
        and timestamp >= target_start
        and (cleanup_end is None or timestamp <= cleanup_end)
    ]
    target_sysmon_by_decision = at_or_before(target_sysmon_during_trial, decision)

    observations = record.get("observations") or {}
    state_after = observations.get("after") or {}
    registry_after = ((state_after.get("categories") or {}).get("registry") or {}).get(
        "items"
    ) or []
    registry_after_category = (state_after.get("categories") or {}).get("registry") or {}
    exact_probe_state = any(
        str(item.get("name", "")).casefold() == target_name.casefold()
        and _canonical_registry_path(item.get("path")) == target_key
        for item in registry_after
    )
    target = record.get("target") or {}
    reconciliation = [
        (entry.get("latest") or {}).get("status")
        for entry in target.get("reconciliation_history") or []
        if isinstance(entry, dict)
    ]
    matched_evidence_ids = sorted(
        {
            str(evidence_id)
            for entry in target.get("reconciliation_history") or []
            if isinstance(entry, dict)
            for evidence_id in ((entry.get("latest") or {}).get("matched_evidence_ids") or [])
        }
    )
    archived_target_docs_by_id = {
        str(event.get("document_id")): event
        for event in target_sysmon_during_trial
        if event.get("document_id")
    }
    matched_wazuh_events = []
    for event in target.get("wazuh_provider_exact_events") or []:
        if event.get("event_id") not in matched_evidence_ids:
            continue
        source_reference = event.get("source_reference") or {}
        archive_record = archived_target_docs_by_id.get(str(source_reference.get("document_id")))
        event_target_object = (event.get("target") or {}).get("target_object")
        matched_wazuh_events.append(
            {
                "event_id": event.get("event_id"),
                "host_id": event.get("host_id"),
                "event_time": event.get("event_time"),
                "normalized_type": event.get("normalized_type"),
                "target_object": event_target_object,
                "source_reference": source_reference,
                "archive_document_exact_target_match": bool(
                    archive_record
                    and str(event.get("host_id", "")).casefold()
                    == str(record.get("host_id", "")).casefold()
                    and _canonical_registry_path(event_target_object) == target_full_key
                    and _canonical_registry_path(archive_record.get("target_object"))
                    == target_full_key
                    and str(archive_record.get("event_code")) == "13"
                ),
            }
        )
    exact_archive_link_valid = (
        bool(matched_evidence_ids)
        and len(matched_wazuh_events) == len(matched_evidence_ids)
        and all(event["archive_document_exact_target_match"] for event in matched_wazuh_events)
        if matched_evidence_ids
        else None
    )
    state_observed_at = _parse_time(registry_after_category.get("observed_at"))
    state_delay = (
        round((state_observed_at - target_completed).total_seconds(), 6)
        if state_observed_at and target_completed
        else None
    )
    failure = (record.get("failure_detail") or {}).get("message")
    return {
        "trial_id": record.get("trial_id"),
        "condition": record.get("condition"),
        "run_artifact_found": True,
        "trial_status": "PASS" if record.get("trial_pass") else "FAIL_OR_UNRECORDED",
        "failure_reason": failure,
        "target_value_name": target_name,
        "target_registry_object_key": record.get("target_object_key"),
        "target_mutation_performed": bool(action),
        "distractor_event_precondition_verified": bool(
            (record.get("source_event_ingestion") or {}).get("database_verified")
        ),
        "action_at": _iso(target_start),
        "action_completed_at": _iso(target_completed),
        "bounded_decision_at": _iso(decision),
        "cleanup_started_at": _iso(cleanup_start),
        "cleanup_completed_at": _iso(cleanup_end),
        "csg_state_present_after": exact_probe_state,
        "csg_state_observed_at": _iso(state_observed_at),
        "csg_state_observation_delay_seconds": state_delay,
        "csg_delta_count": len(target.get("deltas") or []),
        "csg_finding_count": len(target.get("findings") or []),
        "local_sysmon_exact_event_count": len(target.get("sysmon_exact_events") or []),
        "wazuh_provider_exact_event_count": len(target.get("wazuh_provider_exact_events") or []),
        "database_exact_event_count": len(target.get("database_exact_events") or []),
        "ingested_distractor_event_count": len(
            (record.get("source_event_ingestion") or {}).get("database_verified") or []
        ),
        "csg_reconciliation_statuses": reconciliation,
        "csg_matched_evidence_ids": matched_evidence_ids,
        "csg_matched_wazuh_events": matched_wazuh_events,
        "csg_exact_target_archive_link_valid": exact_archive_link_valid,
        "bounded_distractor_matched_evidence_ids": (record.get("bounded_distractor") or {}).get(
            "matched_ids"
        )
        or [],
        "exact_target_fim_documents": target_alerts,
        "exact_target_sysmon_index_documents": target_sysmon_events,
        "exact_target_sysmon_index_trial_documents": target_sysmon_during_trial,
        "exact_target_sysmon_index_at_decision": bool(target_sysmon_by_decision)
        if decision
        else None,
        "exact_target_sysmon_index_after_decision": [
            item for item in target_sysmon_during_trial if item not in target_sysmon_by_decision
        ]
        if decision
        else None,
        "exact_distractor_sysmon_index_documents": distractor_sysmon_events,
        "exact_target_fim_unique_observations": _unique_observation_count(target_alerts),
        "exact_target_fim_added_documents": target_added_alerts,
        "exact_target_fim_added_unique_observations": _unique_observation_count(
            target_added_alerts
        ),
        "exact_target_fim_deleted_after_cleanup_documents": target_deleted_after_cleanup,
        "exact_target_fim_event_types": sorted(
            {str(item.get("syscheck_event") or "unknown") for item in target_alerts}
        ),
        "exact_target_fim_at_decision": bool(target_by_decision) if decision else None,
        "exact_target_fim_during_action_to_cleanup": bool(target_during_action),
        "exact_target_fim_after_decision": target_after_decision,
        "same_name_wrong_path_documents": same_name_wrong_path,
        "distractor_value_name": distractor_name or None,
        "exact_distractor_fim_documents": distractor_alerts,
        "exact_distractor_fim_unique_observations": _unique_observation_count(distractor_alerts),
        "exact_distractor_fim_added_documents": distractor_added_alerts,
        "exact_distractor_fim_added_unique_observations": _unique_observation_count(
            distractor_added_alerts
        ),
        "distractor_fim_at_or_after_wazuh_stop": bool(distractor_after_stop),
        "action_completion_to_first_fim_alert_seconds": latency[0] if latency else None,
        "all_action_completion_to_fim_alert_offsets_seconds": latency,
        "wazuh_stop_proof": (record.get("wazuh_service") or {}).get("during"),
        "cleanup_verified": bool(
            cleanup.get("cleanup_probe_succeeded") and cleanup.get("target_absent")
        ),
        "fim_query_window_end": _iso(query_end),
    }


def _summarize(trials: list[Json]) -> Json:
    def wilson(successes: int, count: int) -> Json:
        if count == 0:
            return {"successes": successes, "trials": 0, "rate": None, "ci95": None}
        z = 1.96
        p = successes / count
        denominator = 1 + z**2 / count
        center = (p + z**2 / (2 * count)) / denominator
        margin = z * math.sqrt(p * (1 - p) / count + z**2 / (4 * count**2)) / denominator
        return {
            "successes": successes,
            "trials": count,
            "rate": round(p, 4),
            "ci95": [round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4)],
        }

    def latency_summary(values: list[float | int | None]) -> Json:
        observed_values = sorted(float(value) for value in values if value is not None)
        if not observed_values:
            return {
                "observations": 0,
                "median_seconds": None,
                "min_seconds": None,
                "max_seconds": None,
            }
        return {
            "observations": len(observed_values),
            "median_seconds": round(statistics.median(observed_values), 6),
            "min_seconds": round(observed_values[0], 6),
            "max_seconds": round(observed_values[-1], 6),
        }

    grouped: dict[str, list[Json]] = defaultdict(list)
    for trial in trials:
        grouped[str(trial.get("condition") or "unknown")].append(trial)
    summary: dict[str, Json] = {}
    for condition, rows in sorted(grouped.items()):
        observed = [row for row in rows if row["run_artifact_found"]]
        mutated = [row for row in observed if row["target_mutation_performed"]]
        decided = [row for row in observed if row["bounded_decision_at"] is not None]
        wrong_object_rejections = sum(
            "UNEXPLAINED" in row["csg_reconciliation_statuses"]
            and not row["csg_matched_evidence_ids"]
            for row in mutated
        )
        no_change_rows = [row for row in observed if row["condition"] == "registry_no_change"]
        exact_sysmon_target_trials = [
            row for row in mutated if row["exact_target_sysmon_index_trial_documents"]
        ]
        exact_sysmon_target_by_decision = [
            row for row in decided if row["exact_target_sysmon_index_at_decision"] is True
        ]
        linked_decisions = [
            row for row in decided if row["csg_exact_target_archive_link_valid"] is not None
        ]
        csg_consistent_decisions = sum(
            "CONSISTENT" in row["csg_reconciliation_statuses"] for row in decided
        )
        distractor_archived = sum(
            bool(row["exact_distractor_sysmon_index_documents"]) for row in observed
        )
        summary[condition] = {
            "assigned_trials": len(rows),
            "runner_passes": sum(row["trial_status"] == "PASS" for row in rows),
            "runner_failures": sum(row["trial_status"] == "FAIL_OR_UNRECORDED" for row in rows),
            "failure_reason_counts": dict(
                Counter(row["failure_reason"] for row in rows if row.get("failure_reason"))
            ),
            "missing_run_artifacts": sum(not row["run_artifact_found"] for row in rows),
            "target_mutations_executed": len(mutated),
            "distractor_event_precondition_verified": sum(
                row["distractor_event_precondition_verified"] for row in observed
            ),
            "trials_with_completed_decision": len(decided),
            "cleanup_verified": sum(row["cleanup_verified"] for row in rows),
            "csg_state_present": sum(row["csg_state_present_after"] for row in rows),
            "exact_target_fim_at_decision": sum(
                row["exact_target_fim_at_decision"] is True for row in rows
            ),
            "exact_target_fim_during_action_to_cleanup": sum(
                row["exact_target_fim_during_action_to_cleanup"] for row in rows
            ),
            "trials_with_exact_distractor_fim": sum(
                row["exact_distractor_fim_unique_observations"] > 0 for row in rows
            ),
            "trials_with_exact_distractor_fim_added": sum(
                row["exact_distractor_fim_added_unique_observations"] > 0 for row in rows
            ),
            "trials_with_any_csg_reconciliation_consistent": sum(
                "CONSISTENT" in row["csg_reconciliation_statuses"] for row in rows
            ),
            "trials_with_any_csg_reconciliation_unexplained": sum(
                "UNEXPLAINED" in row["csg_reconciliation_statuses"] for row in rows
            ),
            "exact_target_fim_document_count": sum(
                len(row["exact_target_fim_documents"]) for row in rows
            ),
            "exact_target_fim_unique_observation_count": sum(
                row["exact_target_fim_unique_observations"] for row in rows
            ),
            "exact_target_fim_added_document_count": sum(
                len(row["exact_target_fim_added_documents"]) for row in rows
            ),
            "exact_target_fim_added_unique_observation_count": sum(
                row["exact_target_fim_added_unique_observations"] for row in rows
            ),
            "target_fim_deletion_alerts_after_cleanup": sum(
                len(row["exact_target_fim_deleted_after_cleanup_documents"]) for row in rows
            ),
            "trials_with_local_sysmon_exact_event": sum(
                row["local_sysmon_exact_event_count"] > 0 for row in observed
            ),
            "trials_with_wazuh_provider_exact_event": sum(
                row["wazuh_provider_exact_event_count"] > 0 for row in observed
            ),
            "trials_with_csg_exact_target_archive_link": sum(
                row["csg_exact_target_archive_link_valid"] is True for row in decided
            ),
            "trials_with_exact_target_sysmon_index_event": sum(
                bool(row["exact_target_sysmon_index_trial_documents"]) for row in observed
            ),
            "trials_with_exact_target_sysmon_index_event_by_decision": sum(
                row["exact_target_sysmon_index_at_decision"] is True for row in decided
            ),
            "trials_with_exact_sysmon_distractor_by_full_object": distractor_archived,
            "trials_with_exact_distractor_sysmon_index_event": sum(
                bool(row["exact_distractor_sysmon_index_documents"]) for row in observed
            ),
            "trials_with_database_exact_event": sum(
                row["database_exact_event_count"] > 0 for row in observed
            ),
            "latency_seconds_by_trial": {
                "csg_state_observation_after_action": latency_summary(
                    [row["csg_state_observation_delay_seconds"] for row in mutated]
                ),
                "first_exact_fim_alert_after_action": latency_summary(
                    [row["action_completion_to_first_fim_alert_seconds"] for row in mutated]
                ),
            },
            "descriptive_within_host_rates_wilson_95": {
                "csg_state_observed": wilson(
                    sum(row["csg_state_present_after"] for row in mutated), len(mutated)
                ),
                "exact_target_fim_by_decision": wilson(
                    sum(row["exact_target_fim_at_decision"] is True for row in decided),
                    len(decided),
                ),
                "exact_target_fim_during_action_to_cleanup": wilson(
                    sum(row["exact_target_fim_during_action_to_cleanup"] for row in mutated),
                    len(mutated),
                ),
                "exact_target_sysmon_archive_event": wilson(
                    len(exact_sysmon_target_trials), len(mutated)
                ),
                "exact_target_sysmon_archive_event_by_decision": wilson(
                    len(exact_sysmon_target_by_decision), len(decided)
                ),
                "csg_exact_target_archive_link": wilson(
                    sum(
                        row["csg_exact_target_archive_link_valid"] is True
                        for row in linked_decisions
                    ),
                    len(linked_decisions),
                ),
                "csg_consistent_among_completed_decisions": wilson(
                    csg_consistent_decisions, len(decided)
                ),
                "exact_sysmon_distractor_archived": wilson(distractor_archived, len(observed))
                if condition == "registry_wrong_object"
                else None,
                "csg_wrong_object_rejected": wilson(wrong_object_rejections, len(mutated))
                if condition == "registry_wrong_object"
                else None,
                "no_change_csg_false_finding": wilson(
                    sum(row["csg_finding_count"] > 0 for row in no_change_rows),
                    len(no_change_rows),
                )
                if condition == "registry_no_change"
                else None,
            },
        }
    return summary


def _resource_summary(path: Path) -> Json:
    if not path.exists():
        return {"available": False, "sample_count": 0}
    samples: list[Json] = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            samples.append(item)
    cpu_samples = [
        (item.get("sampled_at"), float(item["process_cpu_seconds"]))
        for item in samples
        if item.get("process_cpu_seconds") is not None
    ]
    cpu_delta = None
    elapsed = None
    if cpu_samples and len({item.get("wazuh_service_pid") for item in samples}) == 1:
        first_time = _parse_time(cpu_samples[0][0])
        last_time = _parse_time(cpu_samples[-1][0])
        elapsed = (last_time - first_time).total_seconds() if first_time and last_time else None
        if elapsed and elapsed > 0:
            cpu_delta = cpu_samples[-1][1] - cpu_samples[0][1]

    def numeric_range(key: str) -> Json:
        values = [float(item[key]) for item in samples if item.get(key) is not None]
        if not values:
            return {"samples": 0, "median": None, "min": None, "max": None}
        return {
            "samples": len(values),
            "median": round(statistics.median(values), 2),
            "min": round(min(values), 2),
            "max": round(max(values), 2),
        }

    return {
        "available": bool(samples),
        "sample_count": len(samples),
        "service_pids": sorted({item.get("wazuh_service_pid") for item in samples}),
        "service_states": dict(
            (state, sum(item.get("wazuh_service_state") == state for item in samples))
            for state in sorted({str(item.get("wazuh_service_state")) for item in samples})
        ),
        "process_cpu_cumulative_delta_seconds": round(cpu_delta, 3)
        if cpu_delta is not None
        else None,
        "elapsed_seconds": round(elapsed, 3) if elapsed is not None else None,
        "average_percent_of_one_core": round(cpu_delta / elapsed * 100, 3)
        if cpu_delta is not None and elapsed
        else None,
        "process_working_set_bytes": numeric_range("process_working_set_bytes"),
        "process_private_bytes": numeric_range("process_private_bytes"),
        "available_physical_memory_bytes": numeric_range("available_physical_memory_bytes"),
        "interpretation": (
            "Descriptive during-run process/system samples only; no pre-campaign "
            "baseline, so not a causal overhead estimate."
        ),
    }


def _write_markdown(path: Path, evidence: Json) -> None:
    resources = evidence["resource_observation"]
    working_set = resources["process_working_set_bytes"]["median"]
    available_memory = resources["available_physical_memory_bytes"]["min"]
    working_set_mib = round(working_set / 1_048_576, 2) if working_set else None
    available_memory_mib = round(available_memory / 1_048_576, 2) if available_memory else None
    rows = [
        "# Wazuh FIM and CSG Matched Registry Results",
        "",
        f"- Campaign: {evidence['campaign_directory']}",
        (
            f"- Wazuh FIM query complete: **{evidence['query']['complete']}** "
            f"({evidence['query']['returned_documents']} FIM documents scanned)"
        ),
        (
            f"- Wazuh Sysmon Event ID 13 query complete: "
            f"**{evidence['sysmon_event_query']['complete']}** "
            f"({evidence['sysmon_event_query']['returned_documents']} archived events scanned; "
            "queried independently from the alert/FIM index)."
        ),
        f"- Query window: {evidence['query']['start']} to {evidence['query']['end']}",
        (
            f"- Campaign runner status: {evidence.get('campaign_status')}; "
            f"assigned schedule: {evidence['assigned_schedule_count']}; "
            f"raw trial artifacts: {evidence['run_artifact_count']}."
        ),
        (
            "- Unit: one randomized registry-value trial on one Windows 11 VM; "
            "trials are repeated measures on the same host."
        ),
        (
            "- FIM alert timestamps are scanner/alert timestamps, not exact "
            "registry mutation timestamps."
        ),
        "- Raw registry value contents are deliberately excluded from this export.",
        (
            f"- Wazuh resource samples: {resources['sample_count']}; service states "
            f"{resources['service_states']}; median observed working set {working_set_mib} MiB; "
            f"lowest observed available memory {available_memory_mib} MiB. CPU delta is "
            "unavailable because the service was restarted/stopped and had multiple PIDs; "
            "descriptive only, with no pre-run baseline."
        ),
        (
            "- Restore audit: initial controller status "
            f"{evidence['controller_manifest'].get('status')}; "
            "later verification config-hash-match="
            f"{evidence['post_restore_verification'].get('config_hash_matches_original')}, "
            f"WazuhSvc={evidence['post_restore_verification'].get('wazuh_service_state')}, "
            f"agent={evidence['post_restore_verification'].get('wazuh_agent_status')}."
        ),
        (
            "- Wilson intervals are descriptive within-host uncertainty; "
            "repeated trials are not independent host replications."
        ),
        "",
        "## Condition Summary",
        "",
        (
            "| Condition | Assigned | Mutations | CSG state | Exact target archive | "
            "Exact distractor archive | CSG outcomes (consistent / unexplained) | "
            "FIM target added by cleanup | Runner pass | Cleanup |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for condition, values in evidence["summary"].items():
        rows.append(
            "| {condition} | {assigned_trials} | {target_mutations_executed} | "
            "{csg_state_present} | {trials_with_exact_target_sysmon_index_event} | "
            "{trials_with_exact_distractor_sysmon_index_event} | "
            "{trials_with_any_csg_reconciliation_consistent} / "
            "{trials_with_any_csg_reconciliation_unexplained} | "
            "{exact_target_fim_during_action_to_cleanup} | "
            "{runner_passes} | {cleanup_verified} |".format(condition=condition, **values)
        )
    rows.extend(
        [
            "",
            "## Interpretation Guardrails",
            "",
            (
                "- This is a configured same-host comparison, not a comparison "
                "against every Wazuh detection capability."
            ),
            (
                "- registry_wrong_object is a bounded WazuhSvc collection "
                "interruption, not permanent telemetry loss."
            ),
            (
                "- A FIM alert is exact only when both normalized registry path "
                "and value name match the trial object."
            ),
            (
                "- A Sysmon event is exact only when Event ID 13 and the complete "
                "normalized TargetObject (key plus value name) match the trial. "
                "Raw archive presence is not equivalent to an alert or to CSG having "
                "ingested that event."
            ),
            (
                "- Multiple rule documents for the same agent, path, value name, "
                "event, and timestamp are retained by document ID but counted "
                "as one unique observation."
            ),
            (
                "- The three conditions use inert values that were never executed; "
                "results do not establish malicious-activity detection."
            ),
            (
                "- A missing decision timestamp is not counted as a FIM miss; "
                "decision-conditioned rates use only trials that reached a decision."
            ),
            "",
            "## Trial-Level FIM Evidence",
            "",
            (
                "| Trial | Condition | Target added docs | Target deleted after cleanup | "
                "Added alert by decision | Distractor added docs | Cleanup verified |"
            ),
            "|---|---|---:|---:|---|---:|---|",
        ]
    )
    for trial in evidence["trials"]:
        rows.append(
            f"| {trial['trial_id']} | {trial['condition']} | "
            f"{len(trial['exact_target_fim_added_documents'])} | "
            f"{len(trial['exact_target_fim_deleted_after_cleanup_documents'])} | "
            f"{trial['exact_target_fim_at_decision']} | "
            f"{len(trial['exact_distractor_fim_added_documents'])} | "
            f"{trial['cleanup_verified']} |"
        )
    rows.extend(
        [
            "",
            "## Exact Sysmon Archive Event IDs",
            "",
            (
                "Rows below require Event ID 13 and an exact, case-insensitive full `TargetObject` "
                "match. Both the Wazuh archive document ID and Windows EventRecordID are retained."
            ),
            "",
            "| Trial | Role | Archive document ID | EventRecordID | Timestamp | "
            "Exact TargetObject |",
            "|---|---|---|---:|---|---|",
        ]
    )
    for trial in evidence["trials"]:
        for role, field in (
            ("target", "exact_target_sysmon_index_trial_documents"),
            ("distractor", "exact_distractor_sysmon_index_documents"),
        ):
            for event in trial[field]:
                rows.append(
                    f"| {trial['trial_id']} | {role} | {event['document_id']} | "
                    f"{event['event_record_id']} | {event['timestamp']} | "
                    f"`{event['target_object']}` |"
                )
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_artifact_manifest(output_dir: Path) -> Path:
    repo_root = Path(__file__).resolve().parents[1]
    manifest_path = output_dir / "artifact-manifest.json"
    artifacts = [
        {
            "path": str(path.relative_to(output_dir)),
            "bytes": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for path in sorted(output_dir.rglob("*"))
        if path.is_file() and path != manifest_path
    ]
    source_inputs = [
        repo_root / "experiments/wazuh_fim_comparison.py",
        repo_root / "scripts/run_wazuh_fim_comparison_windows.ps1",
        repo_root / "scripts/run_registry_reconciliation_campaign_windows.ps1",
        repo_root / "scripts/run_registry_reconciliation_trial_windows.ps1",
        repo_root / "tests/test_wazuh_fim_comparison.py",
        repo_root / "backend/csg/config.py",
        repo_root / "backend/csg/providers/wazuh.py",
        output_dir / "PROTOCOL.md",
    ]
    manifest = {
        "schema_version": "csg-research-run-artifact-hashes-v1",
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "run_directory": str(output_dir),
        "self_hash_note": "This manifest intentionally does not hash itself.",
        "artifacts": artifacts,
        "source_inputs": [
            {
                "path": str(path.relative_to(repo_root)),
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
            for path in source_inputs
            if path.is_file()
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest_path


def _restore_verification(controller: Json, separate_check: Json) -> Json:
    if separate_check:
        return separate_check
    checks = controller.get("restore_health_checks") or []
    latest = checks[-1] if checks else {}
    service = controller.get("service_after_restore") or {}
    if not controller and not checks and not service:
        return {}
    return {
        "verification_source": "fim-campaign-manifest.json post-restore polling",
        "config_hash_matches_original": controller.get("restored_original_config"),
        "original_agent_config_sha256": controller.get("original_agent_config_sha256"),
        "temporary_agent_config_sha256": controller.get("temporary_agent_config_sha256"),
        "wazuh_service_state": service.get("state"),
        "wazuh_service_pid": service.get("pid"),
        "wazuh_agent_status": latest.get("agent_status"),
        "initial_wazuh_agent_status": controller.get("initial_restore_agent_status"),
        "agent_active_after_restore": controller.get("agent_active_after_restore"),
        "health_check_count": len(checks),
        "health_checks": checks,
    }


async def _run(args: argparse.Namespace) -> Json:
    campaign_dir = args.campaign_dir.resolve()
    paths_and_records = _trial_files(campaign_dir)
    manifest_path = campaign_dir / "campaign-manifest.json"
    campaign_manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8-sig")) if manifest_path.exists() else {}
    )
    controller_path = campaign_dir.parent / "fim-campaign-manifest.json"
    restore_check_path = campaign_dir.parent / "post-restore-verification.json"
    controller_manifest = (
        json.loads(controller_path.read_text(encoding="utf-8-sig"))
        if controller_path.exists()
        else {}
    )
    restore_check = (
        json.loads(restore_check_path.read_text(encoding="utf-8-sig"))
        if restore_check_path.exists()
        else {}
    )
    restore_check = _restore_verification(controller_manifest, restore_check)
    schedule = campaign_manifest.get("schedule") or []
    if not paths_and_records and not schedule:
        raise SystemExit(f"No registry trial run.json files found beneath {campaign_dir}")
    times = [
        value
        for _, record in paths_and_records
        for value in (_parse_time(record.get("started_at")), _parse_time(record.get("ended_at")))
        if value
    ]
    times.extend(
        value
        for value in (
            _parse_time(campaign_manifest.get("created_at")),
            _parse_time(campaign_manifest.get("completed_at")),
        )
        if value
    )
    start = min(times) - timedelta(minutes=args.lookback_minutes)
    end = max(times) + timedelta(minutes=args.recovery_minutes)
    settings = Settings()
    config = WazuhConfig.from_settings(settings)
    all_names = {
        name.casefold()
        for _, record in paths_and_records
        for name in (record.get("target_name"), record.get("distractor_name"))
        if name
    }
    async with WazuhClient(config) as client:
        hits, query_status = await _fetch_fim_documents(
            client, args.host_id, start, end, args.index_pattern or config.alert_index_pattern
        )
        sysmon_hits, sysmon_query_status = await _fetch_sysmon_registry_documents(
            client,
            args.host_id,
            start,
            end,
            args.archive_index_pattern,
        )
    projected = [_alert_projection(hit) for hit in hits]
    relevant = [
        item
        for item in projected
        if str(item.get("syscheck_value_name") or "").casefold() in all_names
    ]
    query_status["relevant_name_documents"] = len(relevant)
    query_status["query_semantics"] = (
        "host + time range + syscheck.path exists; exact trial matching performed locally"
    )
    sysmon_projected = [_sysmon_registry_projection(hit) for hit in sysmon_hits]
    sysmon_projected = [
        item
        for item in sysmon_projected
        if item.get("target_object")
        and any(name in str(item["target_object"]).casefold() for name in all_names)
    ]
    sysmon_query_status["relevant_target_object_documents"] = len(sysmon_projected)
    sysmon_query_status["query_semantics"] = (
        "host + time range + Sysmon Event ID 13 + randomized CSGConfRun name; "
        "full target-object identity matched locally"
    )
    query_end = end
    records_by_id = {str(record.get("trial_id")): record for _, record in paths_and_records}
    trials: list[Json] = []
    if schedule:
        for scheduled in schedule:
            trial_id = str(scheduled.get("trial_id"))
            record = records_by_id.get(trial_id)
            if record is None:
                trials.append(
                    {
                        "trial_id": trial_id,
                        "condition": scheduled.get("condition"),
                        "run_artifact_found": False,
                        "trial_status": "MISSING_ARTIFACT",
                        "campaign_runner_status": scheduled.get("status"),
                        "campaign_failure_reason": scheduled.get("failure_reason"),
                        "target_value_name": None,
                        "target_registry_object_key": None,
                        "failure_reason": scheduled.get("failure_reason"),
                        "target_mutation_performed": False,
                        "distractor_event_precondition_verified": False,
                        "action_at": None,
                        "action_completed_at": None,
                        "bounded_decision_at": None,
                        "cleanup_started_at": None,
                        "cleanup_completed_at": None,
                        "csg_state_present_after": False,
                        "csg_state_observed_at": None,
                        "csg_state_observation_delay_seconds": None,
                        "csg_delta_count": 0,
                        "csg_finding_count": 0,
                        "local_sysmon_exact_event_count": 0,
                        "exact_target_sysmon_index_documents": [],
                        "exact_target_sysmon_index_trial_documents": [],
                        "exact_target_sysmon_index_at_decision": None,
                        "exact_target_sysmon_index_after_decision": None,
                        "exact_distractor_sysmon_index_documents": [],
                        "wazuh_provider_exact_event_count": 0,
                        "database_exact_event_count": 0,
                        "ingested_distractor_event_count": 0,
                        "csg_reconciliation_statuses": [],
                        "exact_target_fim_documents": [],
                        "csg_matched_evidence_ids": [],
                        "csg_matched_wazuh_events": [],
                        "csg_exact_target_archive_link_valid": None,
                        "bounded_distractor_matched_evidence_ids": [],
                        "exact_target_fim_unique_observations": 0,
                        "exact_target_fim_added_documents": [],
                        "exact_target_fim_added_unique_observations": 0,
                        "exact_target_fim_deleted_after_cleanup_documents": [],
                        "exact_target_fim_event_types": [],
                        "exact_target_fim_at_decision": None,
                        "exact_target_fim_during_action_to_cleanup": False,
                        "exact_target_fim_after_decision": [],
                        "action_completion_to_first_fim_alert_seconds": None,
                        "all_action_completion_to_fim_alert_offsets_seconds": [],
                        "same_name_wrong_path_documents": [],
                        "distractor_value_name": None,
                        "exact_distractor_fim_documents": [],
                        "exact_distractor_fim_unique_observations": 0,
                        "exact_distractor_fim_added_documents": [],
                        "exact_distractor_fim_added_unique_observations": 0,
                        "distractor_fim_at_or_after_wazuh_stop": False,
                        "wazuh_stop_proof": None,
                        "cleanup_verified": False,
                    }
                )
                continue
            trial = _trial_analysis(record, relevant, sysmon_projected, query_end)
            trial["campaign_runner_status"] = scheduled.get("status")
            trial["campaign_failure_reason"] = scheduled.get("failure_reason")
            trials.append(trial)
    else:
        trials = [
            _trial_analysis(record, relevant, sysmon_projected, query_end)
            for _, record in paths_and_records
        ]
    return {
        "schema_version": "csg-wazuh-fim-csg-comparison-results-v1",
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "campaign_directory": str(campaign_dir),
        "host_id": args.host_id,
        "query": {**query_status, "start": _iso(start), "end": _iso(end)},
        "sysmon_event_query": {
            **sysmon_query_status,
            "start": _iso(start),
            "end": _iso(end),
        },
        "trial_count": len(trials),
        "run_artifact_count": len(paths_and_records),
        "assigned_schedule_count": len(schedule) if schedule else len(paths_and_records),
        "campaign_status": campaign_manifest.get("status"),
        "resource_observation": _resource_summary(campaign_dir.parent / "resource-samples.jsonl"),
        "controller_manifest": controller_manifest,
        "post_restore_verification": restore_check,
        "trials": trials,
        "summary": _summarize(trials),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Join exact Wazuh Registry FIM alerts to CSG Windows trials."
    )
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--host-id", default="win11-arm-lab")
    parser.add_argument("--index-pattern", default=None)
    parser.add_argument("--archive-index-pattern", default="wazuh-archives-*")
    parser.add_argument("--lookback-minutes", type=int, default=5)
    parser.add_argument("--recovery-minutes", type=int, default=10)
    args = parser.parse_args()
    output_dir = (args.output_dir or args.campaign_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    result = asyncio.run(_run(args))
    json_path = output_dir / "fim-evidence-and-analysis.json"
    markdown_path = output_dir / "fim-results-summary.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_markdown(markdown_path, result)
    hash_manifest = _write_artifact_manifest(output_dir)
    print(f"Analyzed {result['trial_count']} trials")
    print(f"Wazuh query complete={result['query']['complete']}")
    print(f"Wazuh archive query complete={result['sysmon_event_query']['complete']}")
    print(f"Evidence: {json_path}")
    print(f"Summary: {markdown_path}")
    print(f"Artifact hashes: {hash_manifest}")


if __name__ == "__main__":
    main()
