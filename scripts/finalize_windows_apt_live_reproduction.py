"""Attach post-window reconciliation versions to a completed live run."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

Json = dict[str, Any]


def get_json(url: str) -> Any:
    request = Request(url, headers={"Accept": "application/json"})
    with urlopen(request, timeout=30) as response:  # noqa: S310 - controlled local API
        return json.loads(response.read().decode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--api-base", required=True)
    parser.add_argument("--host-id", required=True)
    args = parser.parse_args()

    payload: Json = json.loads(args.artifact.read_text(encoding="utf-8-sig"))
    findings = get_json(
        f"{args.api_base.rstrip('/')}/api/findings?host_id={args.host_id}&limit=500"
    )
    by_id = {str(finding.get("finding_id")): finding for finding in findings}
    captured_at = datetime.now(UTC).isoformat()
    for scenario in payload.get("scenarios", []):
        raw_findings = scenario.get("findings") or []
        candidates = [
            by_id[finding["finding_id"]]
            for finding in raw_findings
            if finding.get("finding_id") in by_id
        ]
        if not candidates:
            continue
        # The last finding in the runner record is the ADD/MODIFY action finding;
        # the first is the cleanup REMOVE and is intentionally NOT_APPLICABLE.
        action_finding = candidates[-1]
        finding_id = action_finding["finding_id"]
        histories = get_json(
            f"{args.api_base.rstrip('/')}/api/findings/{finding_id}/reconciliations"
        )
        scenario["post_campaign_finalization"] = {
            "captured_at": captured_at,
            "source": "CSG reconciliation API after observation window closed",
            "finding_id": finding_id,
            "finding": action_finding,
            "reconciliation_history": histories,
        }
    payload["post_campaign_finalization"] = {
        "captured_at": captured_at,
        "source": "CSG reconciliation API after observation windows and grace period",
        "status": "captured",
    }
    args.artifact.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"attached post-window reconciliation records to {args.artifact}")


if __name__ == "__main__":
    main()
