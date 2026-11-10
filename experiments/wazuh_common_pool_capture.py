"""Poll CSG's Wazuh provider for a target-unfiltered, auditable event window."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamps must include a UTC offset")
    return parsed.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _canonical_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _write_checkpoint(path: Path, capture: dict[str, Any]) -> None:
    payload = dict(capture)
    payload["payload_sha256"] = _canonical_hash(capture)
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        json.dump(payload, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        temporary = Path(stream.name)
    temporary.replace(path)


def _query_url(api_url: str, host_id: str, window_start: datetime, window_end: datetime) -> str:
    query = urlencode({"start": _iso(window_start), "end": _iso(window_end)})
    host = quote(host_id, safe="")
    return f"{api_url.rstrip('/')}/api/hosts/{host}/provider-event-observation?{query}"


def _fetch_observation(url: str, timeout_seconds: float) -> dict[str, Any]:
    request = Request(url, headers={"Accept": "application/json"})
    with urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read())


def _record_poll(
    capture: dict[str, Any],
    response: dict[str, Any] | None,
    *,
    request_started_at: datetime,
    response_received_at: datetime,
    error: str | None = None,
) -> None:
    retrieval = ((response or {}).get("metadata") or {}).get("retrieval") or {}
    query_completed_at = retrieval.get("query_completed_at") or _iso(response_received_at)
    query_complete = bool((response or {}).get("query_complete", False)) and error is None
    events = (response or {}).get("events") or []
    seen_ids: set[str] = set()
    prior_complete_queries = [
        poll["query_completed_at"] for poll in capture["polls"] if poll["query_complete"]
    ]
    for event in events:
        event_id = event.get("event_id")
        if not event_id:
            continue
        seen_ids.add(event_id)
        if event_id not in capture["events"]:
            capture["events"][event_id] = {
                "event": event,
                "first_observed_at": query_completed_at,
                "first_seen_lower_bound": prior_complete_queries[-1]
                if prior_complete_queries
                else None,
                "first_seen_upper_bound": query_completed_at,
                "first_seen_query_complete": query_complete,
            }

    capture["polls"].append(
        {
            "poll_number": len(capture["polls"]) + 1,
            "request_started_at": _iso(request_started_at),
            "response_received_at": _iso(response_received_at),
            "query_completed_at": query_completed_at,
            "query_complete": query_complete,
            "endpoint_collection_status": (response or {}).get(
                "endpoint_collection_status", "UNKNOWN"
            ),
            "transport_status": (response or {}).get("transport_status", "UNKNOWN"),
            "index_status": (response or {}).get("index_status", "UNKNOWN"),
            "coverage_status": (response or {}).get("coverage_status", "UNKNOWN"),
            "retrieved_count": (response or {}).get("retrieved_count", 0),
            "event_ids": sorted(seen_ids),
            "retrieval_metadata": retrieval,
            "error": error,
        }
    )
    capture["last_poll_at"] = _iso(response_received_at)
    capture["last_query_complete"] = query_complete
    capture["unique_event_count"] = len(capture["events"])


def capture_window(
    *,
    api_url: str,
    host_id: str,
    window_start: datetime,
    window_end: datetime,
    capture_until: datetime,
    poll_interval_seconds: float,
    timeout_seconds: float,
    output_path: Path,
    overwrite: bool = False,
) -> dict[str, Any]:
    for name, value in (
        ("window_start", window_start),
        ("window_end", window_end),
        ("capture_until", capture_until),
    ):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{name} must be timezone-aware")
    window_start = window_start.astimezone(UTC)
    window_end = window_end.astimezone(UTC)
    capture_until = capture_until.astimezone(UTC)
    if window_end <= window_start:
        raise ValueError("window_end must be later than window_start")
    if (window_end - window_start).total_seconds() > 1800:
        raise ValueError("CSG provider event queries are limited to 30 minutes")
    if poll_interval_seconds <= 0 or timeout_seconds <= 0:
        raise ValueError("poll interval and request timeout must be positive")
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing capture: {output_path}")

    capture: dict[str, Any] = {
        "schema_version": "csg-wazuh-common-pool-capture-v1",
        "capture_status": "RUNNING",
        "host_id": host_id,
        "api_url": api_url.rstrip("/"),
        "window_start": _iso(window_start),
        "window_end": _iso(window_end),
        "capture_until": _iso(capture_until),
        "poll_interval_seconds": poll_interval_seconds,
        "events": {},
        "polls": [],
    }
    _write_checkpoint(output_path, capture)
    url = _query_url(api_url, host_id, window_start, window_end)

    try:
        while True:
            started = datetime.now(UTC)
            response = None
            error = None
            try:
                response = _fetch_observation(url, timeout_seconds)
            except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
                error = f"{type(exc).__name__}: {exc}"
            received = datetime.now(UTC)
            _record_poll(
                capture,
                response,
                request_started_at=started,
                response_received_at=received,
                error=error,
            )
            _write_checkpoint(output_path, capture)
            remaining = (capture_until - datetime.now(UTC)).total_seconds()
            if remaining <= 0:
                break
            time.sleep(min(poll_interval_seconds, remaining))
        capture["capture_status"] = (
            "COMPLETE" if all(poll["query_complete"] for poll in capture["polls"])
            else "COMPLETE_WITH_QUERY_ERRORS"
        )
    except KeyboardInterrupt:
        capture["capture_status"] = "INTERRUPTED"
    _write_checkpoint(output_path, capture)
    return capture


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Poll and archive the complete Wazuh event pool for one host/time window."
    )
    parser.add_argument("--api-url", required=True, help="CSG base URL, e.g. http://127.0.0.1:8000")
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--window-start", required=True, type=_parse_time)
    parser.add_argument("--window-end", required=True, type=_parse_time)
    parser.add_argument("--capture-until", required=True, type=_parse_time)
    parser.add_argument("--poll-interval-seconds", type=float, default=5)
    parser.add_argument("--timeout-seconds", type=float, default=20)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    capture = capture_window(
        api_url=args.api_url,
        host_id=args.host_id,
        window_start=args.window_start,
        window_end=args.window_end,
        capture_until=args.capture_until,
        poll_interval_seconds=args.poll_interval_seconds,
        timeout_seconds=args.timeout_seconds,
        output_path=args.output,
        overwrite=args.overwrite,
    )
    print(
        json.dumps(
            {
                "capture_status": capture["capture_status"],
                "poll_count": len(capture["polls"]),
                "unique_event_count": capture["unique_event_count"],
                "output": str(args.output),
                "payload_sha256": _canonical_hash(capture),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
