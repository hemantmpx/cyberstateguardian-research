"""Counterfactually replay a captured task transition with its wrong-object event retained."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from csg.domain.models import EventObservationResult, NormalizedEvent, StateDelta
from csg.services.reconciliation import ReconciliationEngine, ReconciliationLifecycle


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def replay(input_path: Path, output_dir: Path, grace_seconds: int) -> dict[str, Any]:
    trial = json.loads(input_path.read_text(encoding="utf-8-sig"))
    additions = [
        StateDelta.model_validate(item)
        for item in trial.get("deltas", [])
        if item.get("category") == "scheduled_task" and item.get("delta_type") == "ADD"
    ]
    if len(additions) != 1:
        raise ValueError(f"Expected one scheduled-task ADD delta; found {len(additions)}")
    delta = additions[0]
    target_events = [
        NormalizedEvent.model_validate(item)
        for item in trial.get("event_plane", {}).get("exact_matches", [])
        if item.get("normalized_type") == "scheduled_task_created"
        and (item.get("target") or {}).get("key", "").casefold()
        == delta.object_key.casefold()
        and item.get("host_id") == delta.host_id
    ]
    distractor_events = [
        NormalizedEvent.model_validate(item)
        for item in (trial.get("distractor_evidence") or {}).get("provider_events", [])
        if item.get("normalized_type") == "scheduled_task_created"
        and item.get("host_id") == delta.host_id
        and (item.get("target") or {}).get("key", "").casefold()
        != delta.object_key.casefold()
    ]
    if len(target_events) != 1 or len(distractor_events) != 1:
        raise ValueError(
            "Expected one exact target event and one distinct same-host distractor event"
        )
    target = target_events[0]
    distractor = distractor_events[0]
    target_label = "".join(
        character.lower() if character.isalnum() else "-"
        for character in str(trial.get("object_name") or target.event_id)
    ).strip("-")
    engine = ReconciliationEngine(observation_window_seconds=0, event_time_tolerance_seconds=20)
    lifecycle = ReconciliationLifecycle(engine, grace_seconds=grace_seconds)
    window = engine.observation_window_for_delta(delta)
    both_in_window = all(
        window.start <= item.event_time <= window.end for item in (target, distractor)
    )
    if not both_in_window:
        raise ValueError("Target and distractor must both be inside the derived transition window")

    observation_both = EventObservationResult(
        events=[target, distractor],
        query_complete=True,
        endpoint_collection_status="AVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        retrieved_count=2,
        total_hits=2,
        metadata={"derived_replay": True, "intervention": "none"},
    )
    live_equivalent = lifecycle.evaluate(
        delta,
        [target, distractor],
        now=window.end + timedelta(seconds=grace_seconds + 1),
        event_observation=observation_both,
    )

    observation_distractor = EventObservationResult(
        events=[distractor],
        query_complete=True,
        endpoint_collection_status="AVAILABLE",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        retrieved_count=1,
        total_hits=1,
        metadata={
            "derived_replay": True,
            "intervention": "remove exact target event; retain captured wrong-object event",
            "primary_evidence_modified": False,
        },
    )
    target_dropped = lifecycle.evaluate(
        delta,
        [distractor],
        now=window.end + timedelta(seconds=grace_seconds + 1),
        event_observation=observation_distractor,
    )
    naive_candidate = (
        distractor.host_id == delta.host_id
        and distractor.normalized_type == "scheduled_task_created"
        and window.start <= distractor.event_time <= window.end
    )

    checks = {
        "captured_target_and_distractor_are_distinct": (
            (target.target.get("key") or "").casefold()
            != (distractor.target.get("key") or "").casefold()
        ),
        "both_captured_events_inside_transition_window": both_in_window,
        "complete_replay_matches_exact_target_only": (
            live_equivalent.status.value == "CONSISTENT"
            and set(live_equivalent.matched_evidence_ids) == {target.event_id}
        ),
        "target_drop_replay_is_complete_and_healthy": (
            target_dropped.metadata.get("event_retrieval_complete") is True
            and not target_dropped.metadata.get("source_health_known_degraded")
        ),
        "wrong_object_only_finalizes_unexplained": (
            target_dropped.status.value == "UNEXPLAINED" and target_dropped.finalized
        ),
        "wrong_object_id_not_matched": not target_dropped.matched_evidence_ids,
        "naive_type_time_baseline_would_false_explain": naive_candidate,
    }

    result = {
        "schema_version": "csg-target-drop-wrong-object-counterfactual-v1",
        "replay_id": f"{target_label}-target-event-drop-distractor-retained",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "evidence_class": "counterfactual_replay_of_live_capture_not_a_live_endpoint_trial",
        "input": {
            "path": str(input_path),
            "sha256": _sha256(input_path),
            "scenario_id": trial.get("scenario_id"),
            "target_object_name": trial.get("object_name"),
            "target_object_key": delta.object_key,
            "target_delta_id": delta.delta_id,
            "target_event_id": target.event_id,
            "distractor_object_key": distractor.target.get("key"),
            "distractor_event_id": distractor.event_id,
            "host_id": delta.host_id,
            "event_type": distractor.normalized_type,
        },
        "analysis_script": {
            "path": "experiments/replay_target_event_drop_with_distractor.py",
            "sha256": _sha256(Path(__file__).resolve()),
        },
        "method": {
            "engine": "backend.csg.services.reconciliation.ReconciliationEngine",
            "engine_observation_window_seconds": 0,
            "event_time_tolerance_seconds": 20,
            "lifecycle_grace_seconds": grace_seconds,
            "target_event_removed_only_in_replay_copy": True,
            "distractor_event_preserved_unchanged": True,
            "source_observation_marked_complete_and_healthy": True,
            "original_live_artifacts_modified": False,
            "evaluation_time_utc": (window.end + timedelta(seconds=grace_seconds + 1)).isoformat(),
        },
        "transition_window": {"start": window.start.isoformat(), "end": window.end.isoformat()},
        "event_times": {
            "target_utc": target.event_time.isoformat(),
            "distractor_utc": distractor.event_time.isoformat(),
        },
        "conditions": {
            "captured_complete_target_plus_distractor": {
                "status": live_equivalent.status.value,
                "finalized": live_equivalent.finalized,
                "matched_evidence_ids": live_equivalent.matched_evidence_ids,
                "expected_target_event_id": target.event_id,
                "distractor_event_id": distractor.event_id,
            },
            "counterfactual_target_removed_distractor_retained": {
                "available_event_ids": [distractor.event_id],
                "query_complete": True,
                "source_status": "AVAILABLE",
                "status": target_dropped.status.value,
                "finalized": target_dropped.finalized,
                "matched_evidence_ids": target_dropped.matched_evidence_ids,
                "missing_expected_evidence_types": target_dropped.missing_expected_evidence_types,
                "metadata": target_dropped.metadata,
            },
            "naive_same_host_type_time_only_baseline": {
                "candidate_event_ids": [distractor.event_id] if naive_candidate else [],
                "would_label_target_explained": naive_candidate,
                "object_identity_checked": False,
            },
        },
        "checks": checks,
        "all_checks_passed": all(checks.values()),
        "permitted_interpretation": (
            "In a deterministic counterfactual replay of one live Windows transition, retaining "
            "only the exact same-host/same-type wrong-object event produced a finalized "
            "UNEXPLAINED CSG result despite complete/healthy query metadata; a type-and-time-only "
            "baseline would have called that distractor explanatory. This tests reconciliation "
            "logic on one captured example, not live Wazuh loss or detection effectiveness."
        ),
        "limitations": [
            "The target event was removed in an offline replay; it was present in the live run.",
            "Single captured transition and one endpoint; not a reliability estimate.",
            "Complete/healthy source status is a replay assumption, not observed health "
            "after a real drop.",
            "No attack or malicious behavior was executed.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "counterfactual-replay.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Archived live trial JSON")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--grace-seconds", type=int, default=60)
    args = parser.parse_args()
    result = replay(args.input, args.output_dir, args.grace_seconds)
    print(
        json.dumps(
            {"all_checks_passed": result["all_checks_passed"], "checks": result["checks"]},
            indent=2,
        )
    )
    return 0 if result["all_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
