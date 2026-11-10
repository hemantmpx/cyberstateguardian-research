from datetime import UTC, datetime, timedelta

from experiments.paired_task_reconciliation_replay import _replay_parent

from csg.domain.models import NormalizedEvent, StateDelta, StateObject, TimeWindow
from csg.services.reconciliation import ReconciliationEngine


def test_task_replay_preserves_exact_identity_and_lifecycle_revisions():
    start = datetime(2026, 1, 1, tzinfo=UTC)
    target_key = "scheduled_task:\\target-task"
    distractor_key = "scheduled_task:\\different-task"
    delta = StateDelta(
        delta_id="delta-target",
        host_id="windows-lab",
        category="scheduled_task",
        object_key=target_key,
        delta_type="ADD",
        after=StateObject(
            category="scheduled_task",
            object_key=target_key,
            attributes={"task_name": "\\Target-Task"},
            source_timestamp=start + timedelta(seconds=2),
        ),
        observation_window=TimeWindow(
            start=start,
            end=start + timedelta(seconds=5),
        ),
    )
    target = NormalizedEvent(
        event_id="event-target",
        host_id="windows-lab",
        event_time=start + timedelta(seconds=3),
        normalized_type="scheduled_task_created",
        target={"key": target_key},
        source="test",
    )
    distractor = NormalizedEvent(
        event_id="event-distractor",
        host_id="windows-lab",
        event_time=start + timedelta(seconds=4),
        normalized_type="scheduled_task_created",
        target={"key": distractor_key},
        source="test",
    )
    engine = ReconciliationEngine(
        observation_window_seconds=0,
        event_time_tolerance_seconds=20,
    )

    cases = _replay_parent(
        "trial-1",
        delta,
        [target],
        distractor,
        engine,
        60,
        {"reconciliation_id": "live-rec", "finding_id": "live-finding", "delta_id": delta.delta_id},
    )
    by_condition = {case["condition"]: case for case in cases}

    assert len(cases) == 6
    assert all(case["passed_derived_invariant"] for case in cases)
    removed = by_condition["target_removed_distractor_retained"]
    assert removed["terminal_status"] == "UNEXPLAINED"
    assert removed["matched_evidence_ids"] == []
    assert removed["loose_same_host_type_time_candidate_count"] == 1
    unavailable = by_condition["source_unavailable_replay"]
    assert unavailable["source_health_known_degraded"] is True
    late = by_condition["target_arrives_after_cutoff"]["revision_history"]
    assert [revision["status"] for revision in late] == [
        "PENDING_EVIDENCE",
        "UNEXPLAINED",
        "CONSISTENT",
    ]
    assert late[-1]["version"] == 3
