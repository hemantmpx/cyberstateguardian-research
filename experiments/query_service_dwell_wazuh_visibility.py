#!/usr/bin/env python3
"""Post-hoc, exact-object Wazuh query for each service-dwell trial."""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

BEFORE_SECONDS = 30
AFTER_SECONDS = 60


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8-sig") as handle:
        return json.load(handle)


def as_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(UTC)


def action_bounds(run: dict[str, Any]) -> tuple[datetime, datetime]:
    actions = run.get("action_timeline", [])
    if run.get("condition") == "dwell":
        first = next(item for item in actions if item.get("action") == "manual_to_auto")
        last = next(item for item in actions if item.get("action") == "auto_to_manual")
        return as_utc(first["invoked_at_utc"]), as_utc(last["completed_at_utc"])
    stable = next(item for item in actions if item.get("action") == "stable_no_change_interval")
    return as_utc(stable["start_utc"]), as_utc(stable["planned_end_utc"])


def query_observation(
    api_base: str, host_id: str, start: datetime, end: datetime
) -> dict[str, Any]:
    query = urllib.parse.urlencode({"start": start.isoformat(), "end": end.isoformat()})
    host_path = urllib.parse.quote(host_id, safe="")
    url = f"{api_base.rstrip('/')}/hosts/{host_path}/provider-event-observation?{query}"
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.loads(response.read().decode("utf-8"))


def exact_service_events(
    observation: dict[str, Any], service_name: str, object_key: str
) -> list[dict[str, Any]]:
    exact: list[dict[str, Any]] = []
    for event in observation.get("events", []):
        target = event.get("target") or {}
        attributes = event.get("attributes") or {}
        event_name = str(attributes.get("service_name") or target.get("service_name") or "")
        name_consistent = not event_name or event_name.casefold() == service_name.casefold()
        if (
            event.get("normalized_type") == "service_modified"
            and target.get("key") == object_key
            and name_consistent
        ):
            exact.append(event)
    return exact


def run_queries(campaign_dir: Path, api_base: str, limit: int | None = None) -> dict[str, Any]:
    manifest = load_json(campaign_dir / "campaign-manifest.json")
    trials = [load_json(path) for path in sorted(campaign_dir.glob("trial-*/run.json"))]
    if limit is not None:
        trials = trials[:limit]
    output_dir = campaign_dir / "analysis" / "wazuh-visibility-posthoc"
    output_dir.mkdir(parents=True, exist_ok=True)

    exact_owner: dict[str, set[str]] = defaultdict(set)
    outcome_counts: dict[str, Counter[str]] = defaultdict(Counter)
    system_log_counts: Counter[str] = Counter()
    reconciliation_overlap = Counter()
    summaries: list[dict[str, Any]] = []

    for run in trials:
        service_name = run["target"]["service_name"]
        object_key = run["target"]["object_key"]
        start, end = action_bounds(run)
        query_start = start - timedelta(seconds=BEFORE_SECONDS)
        query_end = end + timedelta(seconds=AFTER_SECONDS)
        trial_result: dict[str, Any] = {
            "campaign_id": manifest.get("campaign_id"),
            "trial_id": run.get("trial_id"),
            "condition": run.get("condition"),
            "planned_dwell_seconds": run.get("planned_dwell_seconds"),
            "service_name": service_name,
            "object_key": object_key,
            "action_window": {"start": start.isoformat(), "end": end.isoformat()},
            "provider_query_window": {
                "start": query_start.isoformat(),
                "end": query_end.isoformat(),
            },
            "posthoc_query": True,
            "query_status": "ERROR",
            "error": None,
            "retrieval": {},
            "exact_target_events": [],
            "same_name_nonexact_candidates": [],
            "reconciliation_evidence_ids": [],
            "query_evidence_id_overlap_with_reconciliation": [],
        }
        try:
            observation = query_observation(api_base, run["host_id"], query_start, query_end)
            exact = exact_service_events(observation, service_name, object_key)
            named_candidates = [
                event
                for event in observation.get("events", [])
                if event.get("normalized_type") == "service_modified"
                and str((event.get("attributes") or {}).get("service_name", "")).casefold()
                == service_name.casefold()
                and (event.get("target") or {}).get("key") != object_key
            ]
            reconciliation_ids = sorted(
                {
                    str(evidence_id)
                    for attempt in run.get("reconciliation_attempts", [])
                    for evidence_id in (attempt.get("matched_evidence_ids") or [])
                }
            )
            exact_ids = sorted(
                {str(event.get("event_id")) for event in exact if event.get("event_id")}
            )
            overlap = sorted(set(exact_ids) & set(reconciliation_ids))
            retrieval_fields = {
                "query_complete": observation.get("query_complete"),
                "endpoint_collection_status": observation.get("endpoint_collection_status"),
                "transport_status": observation.get("transport_status"),
                "index_status": observation.get("index_status"),
                "coverage_status": observation.get("coverage_status"),
                "retrieval_pages": observation.get("retrieval_pages"),
                "retrieved_count": observation.get("retrieved_count"),
                "total_hits": observation.get("total_hits"),
                "metadata": observation.get("metadata", {}),
                "normalized_event_count": len(observation.get("events", [])),
            }
            trial_result.update(
                {
                    "query_status": "COMPLETE"
                    if observation.get("query_complete")
                    else "INCOMPLETE",
                    "retrieval": retrieval_fields,
                    "exact_target_events": exact,
                    "same_name_nonexact_candidates": named_candidates,
                    "reconciliation_evidence_ids": reconciliation_ids,
                    "query_evidence_id_overlap_with_reconciliation": overlap,
                }
            )
            for event_id in exact_ids:
                exact_owner[event_id].add(service_name)
            reconciliation_overlap["matched"] += len(overlap)
            reconciliation_overlap["reconciliation_ids"] += len(reconciliation_ids)
        except (
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
            KeyError,
            StopIteration,
        ) as exc:
            trial_result["error"] = f"{type(exc).__name__}: {exc}"

        outcome_counts[str(run.get("condition"))][trial_result["query_status"]] += 1
        outcome_counts[str(run.get("condition"))][
            f"exact_events_{len(trial_result['exact_target_events'])}"
        ] += 1
        system_log_counts[str(run.get("condition"))] += len(run.get("windows_system_7040", []))
        (output_dir / f"{run['trial_id']}.json").write_text(
            json.dumps(trial_result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        summaries.append(
            {
                "trial_id": run.get("trial_id"),
                "condition": run.get("condition"),
                "planned_dwell_seconds": run.get("planned_dwell_seconds"),
                "query_status": trial_result["query_status"],
                "exact_event_count": len(trial_result["exact_target_events"]),
                "windows_system_7040_count": len(run.get("windows_system_7040", [])),
                "query_evidence_id_overlap_count": len(
                    trial_result["query_evidence_id_overlap_with_reconciliation"]
                ),
            }
        )

    duplicate_ids = {
        event_id: sorted(owners) for event_id, owners in exact_owner.items() if len(owners) > 1
    }
    report = {
        "schema_version": "1.0",
        "campaign_id": manifest.get("campaign_id"),
        "query_performed_at_utc": datetime.now(UTC).isoformat(),
        "api_base": api_base,
        "method": (
            "Post-hoc provider-event-observation query per trial; 30s pre-window and "
            "60s post-window; exact service_modified target key required."
        ),
        "scope_note": (
            "Supplementary exploratory visibility analysis; not part of the frozen primary "
            "endpoint or a permanent-loss experiment."
        ),
        "trials_queried": len(trials),
        "query_status_counts_by_condition": {
            key: dict(sorted(value.items())) for key, value in sorted(outcome_counts.items())
        },
        "windows_system_7040_counts_by_condition": dict(sorted(system_log_counts.items())),
        "unique_exact_wazuh_event_ids": len(exact_owner),
        "duplicate_exact_wazuh_event_ids_across_services": duplicate_ids,
        "reconciliation_event_id_overlap": dict(reconciliation_overlap),
        "trials": summaries,
    }
    (output_dir / "summary.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument(
        "--api-base", default=os.environ.get("CSG_API_BASE_URL", "http://127.0.0.1:8000/api")
    )
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    report = run_queries(args.campaign_dir, args.api_base, args.limit)
    print(
        json.dumps(
            {key: value for key, value in report.items() if key != "trials"},
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
