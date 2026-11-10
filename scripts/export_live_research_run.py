from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx


def export_live_run(
    api_base: str,
    host_id: str,
    *,
    lookback_hours: int = 24,
) -> dict[str, Any]:
    base = api_base.rstrip("/")
    now = datetime.now(UTC)
    start = now - timedelta(hours=lookback_hours)
    with httpx.Client(timeout=30) as client:
        host = _get(client, f"{base}/api/hosts/{host_id}")
        state = _get(client, f"{base}/api/hosts/{host_id}/state/latest")
        deltas = _get(client, f"{base}/api/hosts/{host_id}/deltas?limit=500")
        events = _get(
            client,
            f"{base}/api/hosts/{host_id}/events?"
            + urlencode({"start": start.isoformat(), "end": now.isoformat()}),
        )
        findings = _get(client, f"{base}/api/findings?host_id={host_id}&limit=500")
        incidents = _get(client, f"{base}/api/incidents?host_id={host_id}&limit=500")
        wazuh_status = _get(client, f"{base}/api/wazuh/status")
        reconciliation_histories = {
            finding["finding_id"]: _get(
                client,
                f"{base}/api/findings/{finding['finding_id']}/reconciliations",
            )
            for finding in findings
        }
        assignments = {
            incident["incident_id"]: _get(
                client,
                f"{base}/api/incidents/{incident['incident_id']}/assignments",
            )
            for incident in incidents
        }

    return {
        "schema_version": "csg-live-research-export-v1",
        "exported_at": now.isoformat(),
        "host_id": host_id,
        "collection_window": {"start": start.isoformat(), "end": now.isoformat()},
        "research_configuration": {
            "authoritative_state_plane": state.get("source") if state else None,
            "expected_authoritative_state_plane": "direct_probe",
            "event_sources": sorted({event.get("source", "unknown") for event in events}),
            "planes_independent": bool(
                state
                and state.get("source") == "direct_probe"
                and any(event.get("source") == "wazuh" for event in events)
            ),
        },
        "host": host,
        "latest_state": state,
        "deltas": deltas,
        "events": events,
        "findings": findings,
        "reconciliation_histories": reconciliation_histories,
        "incidents": incidents,
        "incident_assignments": assignments,
        "wazuh_status": wazuh_status,
        "interpretation_warning": (
            "This export is an experimental record. Controlled scenario results do not establish "
            "real-world detection accuracy."
        ),
    }


def _get(client: httpx.Client, url: str) -> Any:
    response = client.get(url)
    response.raise_for_status()
    return response.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="Export a live CSG research evidence bundle")
    parser.add_argument("host_id")
    parser.add_argument("--api-base", default="http://localhost:8000")
    parser.add_argument("--lookback-hours", type=int, default=24)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("experiments/results/live-research-export.json"),
    )
    args = parser.parse_args()
    payload = export_live_run(
        args.api_base,
        args.host_id,
        lookback_hours=args.lookback_hours,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"wrote live research export to {args.output}")


if __name__ == "__main__":
    main()
