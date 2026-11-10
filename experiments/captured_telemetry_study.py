"""Replay independent captured state under explicitly labeled offline event masks."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from csg.domain.models import NormalizedEvent, StateSnapshot
from csg.services.reconciliation import ReconciliationEngine
from csg.state.diff import DeltaEngine


def replay_capture(
    bundle: dict,
    *,
    before_id: str,
    after_id: str,
    object_key: str,
    key_event_ids: set[str],
    window_seconds: int = 900,
) -> dict:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    snapshots = {
        row["snapshot_id"]: StateSnapshot.model_validate(row) for row in bundle["snapshots"]
    }
    before, after = snapshots[before_id], snapshots[after_id]
    if before.source != "direct_probe" or after.source != "direct_probe":
        raise ValueError("independent-state replay requires native direct_probe snapshots")
    if after.built_at <= before.built_at:
        raise ValueError("snapshot times must increase")
    deltas = [
        delta for delta in DeltaEngine().diff(before, after) if delta.object_key == object_key
    ]
    if not deltas:
        raise ValueError("selected target has no observable delta")
    engine = ReconciliationEngine(window_seconds)
    window = engine.observation_window_for_delta(deltas[0])
    events = [NormalizedEvent.model_validate(row) for row in bundle["events"]]
    events = [
        event
        for event in events
        if event.host_id == after.host_id and window.start <= event.event_time <= window.end
    ]
    if any(event.synthetic or event.source != "wazuh" for event in events):
        raise ValueError("captured replay requires nonsynthetic Wazuh events")
    relevant_ids = {event.event_id for event in events if event.target.get("key") == object_key}
    if not key_event_ids or not key_event_ids <= relevant_ids:
        raise ValueError("key event IDs must identify captured events for this target and window")
    conditions = {
        "complete": events,
        "noncritical_removed": [event for event in events if event.event_id in key_event_ids],
        "key_events_removed": [event for event in events if event.event_id not in key_event_ids],
        "heavily_degraded": [],
        "source_unavailable": [],
        # Unlike source_unavailable, this is a final-window capture-drop mask: no late
        # recovery is admitted into the result, so the state delta must remain unexplained.
        "capture_drop": [],
    }
    return {
        "schema_version": "csg-captured-telemetry-study-v1",
        "execution_kind": "offline_masking_of_supplied_capture",
        "input_sha256": hashlib.sha256(json.dumps(bundle, sort_keys=True).encode()).hexdigest(),
        "before_snapshot_id": before_id,
        "after_snapshot_id": after_id,
        "target": object_key,
        "key_event_ids": sorted(key_event_ids),
        "window": window.model_dump(mode="json"),
        "conditions": {
            name: {
                "event_source_available": name != "source_unavailable",
                "retained_event_ids": [event.event_id for event in retained],
                "removed_event_ids": sorted(
                    {e.event_id for e in events} - {e.event_id for e in retained}
                ),
                "deltas": [delta.model_dump(mode="json") for delta in deltas],
                "reconciliations": [
                    engine.reconcile_delta(delta, retained).model_dump(mode="json")
                    for delta in deltas
                ],
            }
            for name, retained in conditions.items()
        },
        "capture_drop_definition": (
            "Events are permanently excluded from the bounded replay result; later recovery is "
            "not admitted. This is the offline analogue of the live capture_drop drill."
        ),
        "warning": "Offline final-window reconciliation, not a live outage or timing study. "
        "Source labels alone do not authenticate capture provenance. Archive original evidence.",
    }


def main():
    parser = argparse.ArgumentParser(
        description="Replay captured native state with five event masks"
    )
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--before-id", required=True)
    parser.add_argument("--after-id", required=True)
    parser.add_argument("--object-key", required=True)
    parser.add_argument("--key-event-id", required=True, action="append")
    parser.add_argument("--window-seconds", type=int, default=900)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = replay_capture(
        json.loads(args.bundle.read_text()),
        before_id=args.before_id,
        after_id=args.after_id,
        object_key=args.object_key,
        key_event_ids=set(args.key_event_id),
        window_seconds=args.window_seconds,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
