"""Post-hoc, read-only timing replay for provider-event campaign windows."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import urlopen


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp must include a timezone: {value}")
    return parsed.astimezone(UTC)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _target_event_ids(reconciliation: dict[str, Any]) -> list[str]:
    value = reconciliation.get("matched_evidence_ids", [])
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return []


def _source_summary(retrieval: dict[str, Any]) -> dict[str, Any]:
    sources = retrieval.get("sources", {})
    if not isinstance(sources, dict):
        return {}
    fields = (
        "status",
        "complete",
        "duration_seconds",
        "pages",
        "returned_hits",
        "total_hits",
        "error",
    )
    return {
        name: {field: source.get(field) for field in fields if field in source}
        for name, source in sources.items()
        if isinstance(source, dict)
    }


def _replay_one(
    *,
    api_base: str,
    host_id: str,
    trial_id: str,
    original_trial_status: str,
    action: dict[str, Any],
    expected_event_ids: list[str],
    timeout_seconds: float,
) -> dict[str, Any]:
    start = _timestamp(action["started_at"]) - timedelta(minutes=2)
    end = _timestamp(action["ended_at"]) + timedelta(minutes=2)
    query = urlencode({"start": start.isoformat(), "end": end.isoformat()})
    url = (
        f"{api_base.rstrip('/')}/api/hosts/{quote(host_id, safe='')}"
        f"/provider-event-observation?{query}"
    )
    observed_at = datetime.now(UTC).isoformat()
    timer = time.perf_counter()
    try:
        with urlopen(url, timeout=timeout_seconds) as response:
            status = response.status
            body = response.read()
        payload = json.loads(body)
        events = payload.get("events", [])
        event_ids = {
            str(event.get("event_id"))
            for event in events
            if isinstance(event, dict) and event.get("event_id")
        }
        metadata = payload.get("metadata", {})
        retrieval = metadata.get("retrieval", {}) if isinstance(metadata, dict) else {}
        if not isinstance(retrieval, dict):
            retrieval = {}
        found = sorted(event_ids.intersection(expected_event_ids))
        return {
            "trial_id": trial_id,
            "original_trial_status": original_trial_status,
            "query_window": {"start": start.isoformat(), "end": end.isoformat()},
            "observed_at_utc": observed_at,
            "http_status": status,
            "client_elapsed_seconds": round(time.perf_counter() - timer, 6),
            "response_bytes": len(body),
            "query_complete": payload.get("query_complete"),
            "event_count": len(events),
            "server_retrieval": {
                "query_started_at": retrieval.get("query_started_at"),
                "query_completed_at": retrieval.get("query_completed_at"),
                "duration_seconds": retrieval.get("duration_seconds"),
                "endpoint_status_duration_seconds": retrieval.get(
                    "endpoint_status_duration_seconds"
                ),
                "sources": _source_summary(retrieval),
            },
            "expected_target_event_ids": expected_event_ids,
            "target_event_ids_retrievable_now": found,
            "all_expected_target_ids_retrievable_now": bool(expected_event_ids)
            and len(found) == len(expected_event_ids),
        }
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return {
            "trial_id": trial_id,
            "original_trial_status": original_trial_status,
            "query_window": {"start": start.isoformat(), "end": end.isoformat()},
            "observed_at_utc": observed_at,
            "http_status": getattr(exc, "code", None),
            "client_elapsed_seconds": round(time.perf_counter() - timer, 6),
            "query_complete": False,
            "error": f"{type(exc).__name__}: {exc}",
            "expected_target_event_ids": expected_event_ids,
            "target_event_ids_retrievable_now": [],
            "all_expected_target_ids_retrievable_now": False,
        }


def run_replay(
    raw_dir: Path,
    *,
    api_base: str,
    timeout_seconds: float = 120,
) -> dict[str, Any]:
    manifest_path = raw_dir / "campaign-manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8-sig"))
    host_id = str(manifest["host_id"])
    results = []
    for assignment in manifest["trials"]:
        trial_id = str(assignment["trial_id"])
        run_files = sorted(
            (raw_dir / "trials" / trial_id / "target-run" / "trials").glob("*.json")
        )
        if len(run_files) != 1:
            results.append(
                {
                    "trial_id": trial_id,
                    "original_trial_status": assignment.get("status", "UNKNOWN"),
                    "query_complete": False,
                    "error": f"expected one nested trial artifact, found {len(run_files)}",
                    "target_event_ids_retrievable_now": [],
                    "all_expected_target_ids_retrievable_now": False,
                }
            )
            continue
        trial = _read_json(run_files[0])
        results.append(
            _replay_one(
                api_base=api_base,
                host_id=host_id,
                trial_id=trial_id,
                original_trial_status=str(assignment.get("status", "UNKNOWN")),
                action=trial["action"],
                expected_event_ids=_target_event_ids(trial.get("csg_reconciliation", {})),
                timeout_seconds=timeout_seconds,
            )
        )
    complete = sum(item.get("query_complete") is True for item in results)
    retrievable = sum(
        item.get("all_expected_target_ids_retrievable_now") is True for item in results
    )
    by_original_status = {}
    for status in sorted({str(item.get("original_trial_status", "UNKNOWN")) for item in results}):
        cohort = [item for item in results if item.get("original_trial_status") == status]
        durations = [
            float(item["client_elapsed_seconds"])
            for item in cohort
            if item.get("client_elapsed_seconds") is not None
        ]
        by_original_status[status] = {
            "assigned_windows": len(cohort),
            "queries_complete_now": sum(item.get("query_complete") is True for item in cohort),
            "target_ids_retrievable_now": sum(
                item.get("all_expected_target_ids_retrievable_now") is True for item in cohort
            ),
            "client_elapsed_seconds": {
                "n": len(durations),
                "median": statistics.median(durations) if durations else None,
                "minimum": min(durations) if durations else None,
                "maximum": max(durations) if durations else None,
            },
        }
    return {
        "schema_version": "csg-provider-query-replay-diagnostic-v1",
        "campaign_id": manifest["campaign_id"],
        "study_status": "POSTHOC_READ_ONLY_DIAGNOSTIC_NOT_FORMAL_TRIALS",
        "host_id": host_id,
        "api_base": api_base.rstrip("/"),
        "input_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "run_at_utc": datetime.now(UTC).isoformat(),
        "timeout_seconds": timeout_seconds,
        "raw_event_payloads_retained": False,
        "summary": {
            "assigned_windows": len(results),
            "queries_complete_now": complete,
            "original_target_ids_retrievable_now": retrievable,
            "by_original_trial_status": by_original_status,
            "interpretation": (
                "Post-hoc availability and query-time diagnostic only. It cannot establish what "
                "the index returned or how long retrieval took during the original live trial."
            ),
        },
        "trials": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw_dir", type=Path, help="Campaign raw/ directory")
    parser.add_argument("--api-base", required=True, help="CSG API base URL")
    parser.add_argument("--timeout-seconds", type=float, default=120)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = run_replay(
        args.raw_dir,
        api_base=args.api_base,
        timeout_seconds=args.timeout_seconds,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    summary = result["summary"]
    print(
        f"Replayed {summary['assigned_windows']} windows read-only; "
        f"complete_now={summary['queries_complete_now']}; "
        f"target_IDs_retrievable_now={summary['original_target_ids_retrievable_now']}"
    )


if __name__ == "__main__":
    main()
