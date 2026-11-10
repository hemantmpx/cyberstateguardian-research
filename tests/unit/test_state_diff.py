from __future__ import annotations

from datetime import UTC, datetime

import pytest
from tests.conftest import ROOT, load_json

from csg.domain.models import StateSnapshot
from csg.state.diff import DeltaEngine


def _snapshot(name: str) -> StateSnapshot:
    return StateSnapshot.model_validate(load_json(ROOT / "experiments/fixtures/state" / name))


def test_delta_engine_detects_add_modify_and_no_change() -> None:
    engine = DeltaEngine()
    baseline = _snapshot("baseline.json")
    new_service = _snapshot("new_service.json")
    modified = _snapshot("modified_service.json")

    assert engine.diff(baseline, baseline) == []
    add_deltas = engine.diff(baseline, new_service)
    assert [(delta.category, delta.delta_type.value, delta.object_key) for delta in add_deltas] == [
        ("service", "ADD", "service:systemupdate"),
    ]
    modify_deltas = engine.diff(baseline, modified)
    assert [
        (delta.category, delta.delta_type.value, delta.object_key) for delta in modify_deltas
    ] == [
        ("service", "MODIFY", "service:eventlog"),
    ]


def test_collector_failure_does_not_create_mass_removals() -> None:
    deltas = DeltaEngine().diff(
        _snapshot("baseline.json"), _snapshot("service_collector_error.json")
    )
    assert deltas == []


def test_partial_category_does_not_claim_absence() -> None:
    baseline = _snapshot("baseline.json")
    added = _snapshot("new_service.json")
    partial = baseline.model_copy(
        update={
            "category_statuses": [
                status.model_copy(update={"status": "partial"})
                for status in baseline.category_statuses
            ]
        }
    )
    assert DeltaEngine().diff(partial, added) == []
    # Missing objects in an incomplete collection cannot prove removal either.
    assert DeltaEngine().diff(added, partial) == []


def test_cross_source_snapshot_comparison_is_rejected() -> None:
    baseline = _snapshot("baseline.json")
    with pytest.raises(ValueError, match="different state sources"):
        DeltaEngine().diff(baseline, baseline.model_copy(update={"source": "other"}))


def test_delta_window_uses_category_sample_times_not_snapshot_envelopes() -> None:
    baseline = _snapshot("baseline.json")
    changed = _snapshot("new_service.json")
    previous_sample = datetime(2026, 9, 13, 20, 10, tzinfo=UTC)
    current_sample = datetime(2026, 9, 13, 20, 11, tzinfo=UTC)
    previous = baseline.model_copy(
        update={
            "built_at": datetime(2026, 9, 13, 20, 12, tzinfo=UTC),
            "category_statuses": [
                status.model_copy(update={"observed_at": previous_sample})
                for status in baseline.category_statuses
            ],
        }
    )
    current = changed.model_copy(
        update={
            "built_at": datetime(2026, 9, 13, 20, 16, tzinfo=UTC),
            "category_statuses": [
                status.model_copy(update={"observed_at": current_sample})
                for status in changed.category_statuses
            ],
        }
    )

    delta = DeltaEngine().diff(previous, current)[0]

    assert delta.observation_window.start == previous_sample
    assert delta.observation_window.end == current_sample
