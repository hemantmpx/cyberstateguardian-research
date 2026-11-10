from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from csg.domain.enums import DeltaType
from csg.domain.models import NormalizedEvent, StateDelta
from csg.services.reconciliation import ReconciliationEngine


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def replay_campaign(campaign_dir: Path, event_time_tolerance_seconds: int = 5) -> dict[str, Any]:
    run_files = sorted((campaign_dir / "windows/raw").glob("scheduled-task-positive-*/run.json"))
    if not run_files:
        raise ValueError(f"No scheduled-task run artifacts found under {campaign_dir}")

    engine = ReconciliationEngine(event_time_tolerance_seconds=event_time_tolerance_seconds)
    trials: list[dict[str, Any]] = []
    for run_path in run_files:
        payload = json.loads(run_path.read_text(encoding="utf-8-sig"))
        scenarios = payload.get("scenarios") or []
        if len(scenarios) != 1:
            raise ValueError(f"{run_path} must contain exactly one scenario")
        scenario = scenarios[0]
        add_deltas = [
            StateDelta.model_validate(item)
            for item in scenario.get("deltas", [])
            if item.get("delta_type") == DeltaType.ADD.value
        ]
        if len(add_deltas) != 1:
            raise ValueError(f"{run_path} must contain exactly one ADD delta")
        delta = add_deltas[0]
        events = [
            NormalizedEvent.model_validate(item)
            for item in scenario.get("event_plane", {}).get("exact_matches", [])
        ]
        if not events:
            raise ValueError(f"{run_path} has no exact Wazuh event to replay")
        result = engine.reconcile_delta(delta, events)
        findings = scenario.get("findings", [])
        finding = next((item for item in findings if item.get("delta_id") == delta.delta_id), {})
        captured = finding.get("reconciliation") or {}
        replay_ids = set(result.matched_evidence_ids)
        exact_ids = {event.event_id for event in events}
        trials.append(
            {
                "trial_id": run_path.parent.name,
                "target_object_key": delta.object_key,
                "captured_finding_status_at_export": captured.get("status"),
                "captured_finalized_at_export": captured.get("finalized"),
                "captured_event_ids": sorted(exact_ids),
                "replay_status": result.status.value,
                "replay_matched_evidence_ids": result.matched_evidence_ids,
                "replay_links_only_trial_events": replay_ids.issubset(exact_ids),
                "run_artifact_sha256": _sha256(run_path),
            }
        )

    return {
        "schema_version": "csg-scheduled-task-identity-fix-replay-v1",
        "campaign_id": "csg-current-version-family-positive-controls-20261010-v2",
        "analysis_kind": "offline deterministic re-evaluation of captured state/event pairs",
        "not_a_new_live_trial": True,
        "event_time_tolerance_seconds": event_time_tolerance_seconds,
        "source_hashes": {
            "backend/csg/state/normalize.py": _sha256(Path("backend/csg/state/normalize.py")),
            "backend/csg/services/reconciliation.py": _sha256(
                Path("backend/csg/services/reconciliation.py")
            ),
        },
        "trial_count": len(trials),
        "consistent_trials": sum(item["replay_status"] == "CONSISTENT" for item in trials),
        "trials": trials,
        "interpretation": (
            "This replay tests the corrected identity matcher against the original per-trial "
            "state and Wazuh event records. It does not rewrite the as-run finding or turn the "
            "original campaign into a post-fix live experiment."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--event-time-tolerance-seconds", type=int, default=5)
    args = parser.parse_args()

    report = replay_campaign(args.campaign_dir, args.event_time_tolerance_seconds)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        f"Replayed {report['trial_count']} captured task transitions: "
        f"{report['consistent_trials']} CONSISTENT"
    )
    return 0 if report["consistent_trials"] == report["trial_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
