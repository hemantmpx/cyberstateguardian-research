from __future__ import annotations

import json
from pathlib import Path

import pytest
from experiments.replay_target_event_drop_with_distractor import replay
from experiments.run_v25_counterfactual_replay_campaign import canonicalize_replay_input

ROOT = Path(__file__).resolve().parents[1]
PARENT_RAW = (
    ROOT
    / "experiments/results/runs/20261013/"
    "scheduled-task-same-window-complete-distractor-campaign-v25/windows/raw/"
    "research-campaign-20261013-scheduled-task-same-window-complete-distractor-v25"
)


@pytest.mark.parametrize(
    ("trial_number", "target_alias_count", "distractor_alias_count"),
    [(1, 1, 1), (5, 2, 1)],
)
def test_replay_canonicalizes_aliases_and_removes_target_physical_event(
    tmp_path: Path,
    trial_number: int,
    target_alias_count: int,
    distractor_alias_count: int,
) -> None:
    input_path = (
        PARENT_RAW
        / f"trial-{trial_number:02d}/trials/trial-01-scheduled-task-persistence.json"
    )

    original = input_path.read_bytes()
    scenario = json.loads(original)
    target_delta = next(
        delta
        for delta in scenario["deltas"]
        if delta["category"] == "scheduled_task" and delta["delta_type"] == "ADD"
    )
    target_key = target_delta["object_key"].casefold()
    target_ids = sorted(
        event["event_id"]
        for event in scenario["event_plane"]["exact_matches"]
        if (event.get("target") or {}).get("key", "").casefold() == target_key
    )
    distractor_ids = sorted(
        event["event_id"]
        for event in scenario["distractor_evidence"]["provider_events"]
        if (event.get("target") or {}).get("key", "").casefold() != target_key
    )
    canonical_path = tmp_path / f"trial-{trial_number:02d}" / "canonical.json"
    target_id, distractor_id = canonicalize_replay_input(
        input_path, canonical_path, target_ids, distractor_ids
    )
    canonical = json.loads(canonical_path.read_text())
    assert len(canonical["event_plane"]["exact_matches"]) == 1
    assert len(canonical["distractor_evidence"]["provider_events"]) == 1
    assert input_path.read_bytes() == original

    result = replay(
        canonical_path,
        tmp_path / f"trial-{trial_number:02d}" / "replay",
        grace_seconds=60,
    )

    complete = result["conditions"]["captured_complete_target_plus_distractor"]
    dropped = result["conditions"]["counterfactual_target_removed_distractor_retained"]
    assert len(target_ids) == target_alias_count
    assert len(distractor_ids) == distractor_alias_count
    assert complete["matched_evidence_ids"] == [target_id]
    assert target_id not in distractor_ids and distractor_id not in target_ids
    assert dropped["available_event_ids"] == [distractor_id]
    assert dropped["status"] == "UNEXPLAINED"
    assert dropped["finalized"] is True
    assert dropped["matched_evidence_ids"] == []
    assert result["checks"]["naive_type_time_baseline_would_false_explain"] is True
    assert result["all_checks_passed"] is True
