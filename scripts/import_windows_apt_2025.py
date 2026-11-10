"""Hash and stream-import the published Windows-APT archive into a summary artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from experiments.datasets.windows_apt_2025.loader import iter_dataset, load_scenario_manifest


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def summarize(archive: Path) -> dict[str, object]:
    counts: Counter[str] = Counter()
    agents: set[str] = set()
    first: datetime | None = None
    last: datetime | None = None
    total = 0
    for event in iter_dataset(archive):
        total += 1
        counts[event.normalized_type] += 1
        agents.add(str(event.metadata.get("raw_record", {}).get("_source.agent.name") or "unknown"))
        first = event.event_time if first is None or event.event_time < first else first
        last = event.event_time if last is None or event.event_time > last else last
    return {
        "dataset": "Windows-APT 2025",
        "dataset_id": "b8fmtzvpy8",
        "revision": 3,
        "archive": str(archive),
        "sha256": sha256_file(archive),
        "event_count": total,
        "event_type_counts": dict(sorted(counts.items())),
        "agent_count": len(agents),
        "agents": sorted(agents),
        "event_time_range": {
            "first": first.isoformat() if first else None,
            "last": last.isoformat() if last else None,
        },
        "scenario_count": len(load_scenario_manifest(archive)),
        "independent_state_evidence": False,
        "limitations": [
            "The archive supplies Wazuh/Sysmon event telemetry, not independent persistent state.",
            "Scenario-level event-to-label joins require the publisher manifest and validation "
            "files.",
            "This import summary is descriptive; it is not a CSG detection accuracy result.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = summarize(args.archive)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
