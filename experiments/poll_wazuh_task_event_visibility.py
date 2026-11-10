"""Poll CSG's live Wazuh event provider and bracket task-event first visibility."""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import urlopen


def iso_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def canonical_task_name(event: dict[str, Any]) -> str:
    attributes = event.get("attributes") or {}
    target = event.get("target") or {}
    return str(attributes.get("task_name") or target.get("task_name") or "").strip("\\").lower()


def save_checkpoint(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def query_provider(
    base_url: str, host_id: str, start: str, end: str, timeout: float
) -> dict[str, Any]:
    query = urlencode({"start": start, "end": end})
    url = f"{base_url.rstrip('/')}/api/hosts/{host_id}/provider-event-observation?{query}"
    started = iso_now()
    try:
        with urlopen(url, timeout=timeout) as response:
            result = json.loads(response.read())
        return {
            "request_started_at_utc": started,
            "response_completed_at_utc": iso_now(),
            "http_status": 200,
            "query_complete": result.get("query_complete") is True,
            "endpoint_collection_status": result.get("endpoint_collection_status"),
            "transport_status": result.get("transport_status"),
            "index_status": result.get("index_status"),
            "coverage_status": result.get("coverage_status"),
            "retrieved_count": result.get("retrieved_count"),
            "total_hits": result.get("total_hits"),
            "retrieval_pages": result.get("retrieval_pages"),
            "events": result.get("events") or [],
            "error": None,
        }
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        return {
            "request_started_at_utc": started,
            "response_completed_at_utc": iso_now(),
            "http_status": getattr(exc, "code", None),
            "query_complete": False,
            "endpoint_collection_status": None,
            "transport_status": None,
            "index_status": None,
            "coverage_status": None,
            "retrieved_count": None,
            "total_hits": None,
            "retrieval_pages": None,
            "events": [],
            "error": str(exc),
        }


def compact_event(event: dict[str, Any]) -> dict[str, Any]:
    attributes = event.get("attributes") or {}
    target = event.get("target") or {}
    source_reference = event.get("source_reference") or {}
    return {
        "event_id": event.get("event_id"),
        "event_time_utc": event.get("event_time"),
        "host_id": event.get("host_id"),
        "source": event.get("source"),
        "normalized_type": event.get("normalized_type"),
        "object_key": target.get("key"),
        "task_name": attributes.get("task_name") or target.get("task_name"),
        "event_code": attributes.get("event_code"),
        "rule_id": attributes.get("rule_id"),
        "source_reference": source_reference,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--host-id", default="win11-arm-lab")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--required-events", type=int, default=5)
    parser.add_argument("--poll-interval-seconds", type=float, default=2.0)
    parser.add_argument("--max-seconds", type=int, default=900)
    parser.add_argument("--request-timeout-seconds", type=float, default=45.0)
    args = parser.parse_args()
    if args.required_events < 1 or args.poll_interval_seconds <= 0 or args.max_seconds < 1:
        parser.error("event count, poll interval, and maximum duration must be positive")

    started_at = iso_now()
    query_start = (datetime.now(UTC) - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    result: dict[str, Any] = {
        "schema_version": "csg-wazuh-event-visibility-poll-v1",
        "started_at_utc": started_at,
        "finished_at_utc": None,
        "host_id": args.host_id,
        "api_base": args.api,
        "event_filter": {
            "host_id": args.host_id,
            "normalized_type": "scheduled_task_created",
            "task_name_prefix": "csgapttask",
            "event_time_not_before_utc": started_at,
        },
        "poll_interval_seconds": args.poll_interval_seconds,
        "polls": [],
        "events": {},
        "status": "RUNNING",
    }
    deadline = time.monotonic() + args.max_seconds
    previous_complete_poll: dict[str, Any] | None = None
    baseline_ids: set[str] = set()
    baseline_initialized = False
    poll_number = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    save_checkpoint(args.output, result)

    while time.monotonic() < deadline:
        poll_number += 1
        poll_end = iso_now()
        query = query_provider(
            args.api,
            args.host_id,
            query_start,
            poll_end,
            args.request_timeout_seconds,
        )
        timestamp_cutoff = parse_time(started_at)
        task_events = []
        for event in query.pop("events"):
            task_name = canonical_task_name(event)
            event_time = parse_time(event.get("event_time"))
            if (
                event.get("host_id") == args.host_id
                and event.get("normalized_type") == "scheduled_task_created"
                and task_name.startswith("csgapttask")
                and event_time is not None
                and timestamp_cutoff is not None
                and event_time >= timestamp_cutoff - timedelta(seconds=60)
            ):
                task_events.append(compact_event(event))
        query["poll_number"] = poll_number
        query["matching_task_event_count"] = len(task_events)
        query["matching_task_event_ids"] = [event.get("event_id") for event in task_events]
        result["polls"].append(query)

        if query["query_complete"]:
            current_ids = {str(event["event_id"]) for event in task_events if event.get("event_id")}
            if not baseline_initialized:
                baseline_ids = current_ids
                result["baseline_task_event_ids"] = sorted(baseline_ids)
                result["baseline_poll_number"] = poll_number
                baseline_initialized = True
            for event in task_events:
                event_id = str(event.get("event_id") or "")
                if not event_id or event_id in baseline_ids:
                    continue
                task_key = str(event.get("task_name") or event.get("object_key") or event_id)
                if task_key not in result["events"]:
                    result["events"][task_key] = {
                        **event,
                        "first_seen_query": {
                            "poll_number": poll_number,
                            "request_started_at_utc": query["request_started_at_utc"],
                            "response_completed_at_utc": query["response_completed_at_utc"],
                        },
                        "previous_complete_absence_query": (
                            {
                                "poll_number": previous_complete_poll["poll_number"],
                                "request_started_at_utc": previous_complete_poll[
                                    "request_started_at_utc"
                                ],
                                "response_completed_at_utc": previous_complete_poll[
                                    "response_completed_at_utc"
                                ],
                                "matching_task_event_ids": previous_complete_poll[
                                    "matching_task_event_ids"
                                ],
                            }
                            if previous_complete_poll
                            else None
                        ),
                    }
            previous_complete_poll = query

        result["finished_at_utc"] = iso_now()
        result["events_detected"] = len(result["events"])
        if result["events_detected"] >= args.required_events:
            result["status"] = "REQUIRED_EVENT_COUNT_OBSERVED"
            save_checkpoint(args.output, result)
            break
        save_checkpoint(args.output, result)
        time.sleep(args.poll_interval_seconds)
    else:
        result["status"] = "TIMEOUT_BEFORE_REQUIRED_EVENT_COUNT"
        result["finished_at_utc"] = iso_now()
        result["events_detected"] = len(result["events"])
        save_checkpoint(args.output, result)

    print(
        f"{result['status']}: {result.get('events_detected', 0)} new task events "
        f"across {len(result['polls'])} provider queries"
    )
    for task_name, event in result["events"].items():
        print(
            f"{task_name}: {event['event_id']} first_seen="
            f"{event['first_seen_query']['response_completed_at_utc']}"
        )


if __name__ == "__main__":
    main()
