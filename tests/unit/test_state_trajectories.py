from __future__ import annotations

from datetime import UTC, datetime, timedelta

from csg.domain.enums import TrajectoryType, TransitionRelation
from csg.domain.models import (
    CategoryStatus,
    StateObject,
    StateSnapshot,
    StateTransitionRecord,
)
from csg.services.trajectories import StateTrajectoryBuilder

START = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
HOST = "trajectory-test-host"
KEY = "service:sample"


def snapshot(at: datetime, attributes: dict | None, snapshot_id: str) -> StateSnapshot:
    objects = (
        [StateObject(category="service", object_key=KEY, attributes=attributes)]
        if attributes is not None
        else []
    )
    return StateSnapshot(
        snapshot_id=snapshot_id,
        host_id=HOST,
        built_at=at,
        source="direct_probe",
        category_statuses=[
            CategoryStatus(category="service", status="healthy", source="direct_probe")
        ],
        objects=objects,
    )


def transition(
    transition_id: str,
    at: datetime,
    old: dict | None,
    new: dict | None,
    transition_type: str = "MODIFY",
) -> StateTransitionRecord:
    return StateTransitionRecord(
        transition_id=transition_id,
        host_id=HOST,
        category="service",
        object_key=KEY,
        transition_type=transition_type,
        observed_at=at,
        capture_method="test_adapter",
        collector_health="HEALTHY",
        old_state=old,
        new_state=new,
    )


def build(before, after, transitions, **kwargs):
    results = StateTrajectoryBuilder().build_interval(
        before,
        after,
        transitions,
        coverage_by_category={"service": "HEALTHY"},
        **kwargs,
    )
    assert len(results) == 1
    return results[0]


def test_reverted_state_transitions_are_preserved_without_a_snapshot_delta() -> None:
    baseline = {"start_mode": "manual", "binary_path": "c:/sample.exe"}
    automatic = {"start_mode": "auto", "binary_path": "c:/sample.exe"}
    result = build(
        snapshot(START, baseline, "before"),
        snapshot(START + timedelta(minutes=30), baseline, "after"),
        [
            transition("t1", START + timedelta(minutes=6), baseline, automatic),
            transition("t2", START + timedelta(minutes=11), automatic, baseline),
        ],
    )

    assert result.snapshot_delta is None
    assert result.trajectory_type == TrajectoryType.REVERTED
    assert [item.transition_id for item in result.transitions] == ["t1", "t2"]
    assert {link.relation for link in result.transition_links} == {
        TransitionRelation.REVERTED_BEFORE_SNAPSHOT
    }


def test_mismatched_intermediate_states_are_not_misreported_as_reverted() -> None:
    manual = {"start_mode": "manual", "binary_path": "c:/sample.exe"}
    automatic = {"start_mode": "auto", "binary_path": "c:/sample.exe"}
    disabled = {"start_mode": "disabled", "binary_path": "c:/sample.exe"}
    result = build(
        snapshot(START, manual, "before"),
        snapshot(START + timedelta(minutes=1), manual, "after"),
        [
            transition("first", START + timedelta(seconds=10), manual, automatic),
            transition("broken-link", START + timedelta(seconds=20), disabled, manual),
        ],
    )
    assert result.trajectory_type == TrajectoryType.INCONSISTENT
    assert "chain" in result.coverage_gaps[0]


def test_runtime_service_transition_is_not_mislabeled_reverted() -> None:
    stopped = {"start_mode": "manual", "status": "stopped", "binary_path": "c:/sample.exe"}
    running = {"start_mode": "manual", "status": "running", "binary_path": "c:/sample.exe"}
    result = build(
        snapshot(START, stopped, "before"),
        snapshot(START + timedelta(seconds=15), running, "after"),
        [
            transition(
                "runtime",
                START + timedelta(seconds=7),
                stopped,
                running,
                "SERVICE_RUNTIME_STATUS_CHANGED",
            )
        ],
    )
    assert result.snapshot_delta is None
    assert result.trajectory_type == TrajectoryType.NON_PERSISTENT_TRANSITION
    assert result.transition_links[0].relation == TransitionRelation.NON_PERSISTENT_TRANSITION


def test_durable_and_multistep_durable_transitions_link_to_normal_delta() -> None:
    manual = {"start_mode": "manual", "binary_path": "c:/sample.exe"}
    automatic = {"start_mode": "auto", "binary_path": "c:/sample.exe"}
    disabled = {"start_mode": "disabled", "binary_path": "c:/sample.exe"}
    before = snapshot(START, manual, "before")
    after = snapshot(START + timedelta(minutes=1), automatic, "after")

    one = build(
        before,
        after,
        [transition("one", START + timedelta(seconds=10), manual, automatic)],
    )
    assert one.trajectory_type == TrajectoryType.DURABLE
    assert one.snapshot_delta is not None
    assert one.transition_links[0].relation == TransitionRelation.REPRESENTED_BY_DELTA

    final = snapshot(START + timedelta(minutes=2), disabled, "final")
    multi = build(
        before,
        final,
        [
            transition("m1", START + timedelta(seconds=10), manual, automatic),
            transition("m2", START + timedelta(seconds=20), automatic, disabled),
        ],
    )
    assert multi.trajectory_type == TrajectoryType.MULTI_STEP_DURABLE
    assert all(
        link.relation == TransitionRelation.PART_OF_MULTISTEP_DELTA
        for link in multi.transition_links
    )


def test_transient_object_and_snapshot_only_coverage_gap_are_distinct() -> None:
    created = {"start_mode": "auto", "binary_path": "c:/temporary.exe"}
    transient = build(
        snapshot(START, None, "before"),
        snapshot(START + timedelta(minutes=1), None, "after"),
        [
            transition("create", START + timedelta(seconds=10), None, created, "CREATE"),
            transition("remove", START + timedelta(seconds=20), created, None, "REMOVE"),
        ],
    )
    assert transient.trajectory_type == TrajectoryType.TRANSIENT_OBJECT
    assert transient.snapshot_delta is None

    manual = {"start_mode": "manual", "binary_path": "c:/sample.exe"}
    automatic = {"start_mode": "auto", "binary_path": "c:/sample.exe"}
    gap = build(
        snapshot(START, manual, "before"),
        snapshot(START + timedelta(minutes=1), automatic, "after"),
        [],
    )
    assert gap.trajectory_type == TrajectoryType.TRANSITION_CAPTURE_GAP
    assert gap.snapshot_delta is not None
    assert gap.coverage_gaps


def test_stable_requires_healthy_coverage_and_interval_filters_records() -> None:
    manual = {"start_mode": "manual", "binary_path": "c:/sample.exe"}
    before = snapshot(START, manual, "before")
    after = snapshot(START + timedelta(minutes=1), manual, "after")
    result = build(before, after, [], include_stable=True)
    assert result.trajectory_type == TrajectoryType.STABLE

    unobserved = StateTrajectoryBuilder().build_interval(
        before,
        after,
        [],
        coverage_by_category={"service": "OFFLINE"},
        include_stable=True,
    )[0]
    assert unobserved.trajectory_type == TrajectoryType.UNOBSERVED_INTERVAL

    outside = transition("outside", START - timedelta(seconds=1), manual, {"start_mode": "auto"})
    assert (
        build(before, after, [outside], include_stable=True).trajectory_type
        == TrajectoryType.STABLE
    )


def test_builder_rejects_cross_host_or_reversed_snapshot_intervals() -> None:
    baseline = snapshot(START, {"start_mode": "manual"}, "before")
    with_other_host = snapshot(
        START + timedelta(minutes=1), {"start_mode": "manual"}, "after"
    ).model_copy(update={"host_id": "other-host"})
    builder = StateTrajectoryBuilder()
    try:
        builder.build_interval(baseline, with_other_host, [])
    except ValueError as exc:
        assert "same host" in str(exc)
    else:
        raise AssertionError("cross-host trajectories must be rejected")

    reversed_snapshot = snapshot(START - timedelta(seconds=1), {"start_mode": "manual"}, "old")
    try:
        builder.build_interval(baseline, reversed_snapshot, [])
    except ValueError as exc:
        assert "ordered" in str(exc)
    else:
        raise AssertionError("reversed intervals must be rejected")
