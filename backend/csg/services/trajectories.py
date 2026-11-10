from __future__ import annotations

from collections import defaultdict
from uuid import NAMESPACE_URL, uuid5

from csg.domain.enums import TrajectoryType, TransitionRelation
from csg.domain.models import (
    MonitorHealthStatus,
    StateDelta,
    StateSnapshot,
    StateTrajectory,
    StateTransitionRecord,
    TimeWindow,
    TrajectoryTransitionLink,
)
from csg.state.diff import DeltaEngine
from csg.state.normalize import normalize_attributes


class StateTrajectoryBuilder:
    """Derive object histories without changing snapshots, deltas, or captured records."""

    def __init__(self) -> None:
        self.delta_engine = DeltaEngine()

    def build_interval(
        self,
        before: StateSnapshot,
        after: StateSnapshot,
        transitions: list[StateTransitionRecord],
        *,
        coverage_by_category: dict[str, MonitorHealthStatus] | None = None,
        category: str | None = None,
        object_key: str | None = None,
        include_stable: bool = False,
    ) -> list[StateTrajectory]:
        if before.host_id != after.host_id:
            raise ValueError("trajectory snapshots must belong to the same host")
        if before.source != after.source:
            raise ValueError("trajectory snapshots must use the same state source")
        if after.built_at < before.built_at:
            raise ValueError("trajectory snapshot interval must be ordered")

        interval = TimeWindow(start=before.built_at, end=after.built_at)
        interval_transitions = [
            item
            for item in transitions
            if item.host_id == before.host_id and interval.start <= item.observed_at <= interval.end
        ]
        by_object: dict[tuple[str, str], list[StateTransitionRecord]] = defaultdict(list)
        for item in interval_transitions:
            by_object[(item.category, item.object_key)].append(item)

        deltas = {
            (delta.category, delta.object_key): delta
            for delta in self.delta_engine.diff(before, after)
        }
        before_objects = {(obj.category, obj.object_key): obj for obj in before.objects}
        after_objects = {(obj.category, obj.object_key): obj for obj in after.objects}
        keys = set(before_objects) | set(after_objects) | set(by_object)
        if category is not None:
            keys = {key for key in keys if key[0] == category}
        if object_key is not None:
            keys = {key for key in keys if key[1] == object_key}

        coverage_by_category = coverage_by_category or {}
        trajectories: list[StateTrajectory] = []
        for object_category, stable_key in sorted(keys):
            boundary_before = before_objects.get((object_category, stable_key))
            boundary_after = after_objects.get((object_category, stable_key))
            records = sorted(
                by_object.get((object_category, stable_key), []),
                key=lambda item: (
                    item.observed_at,
                    item.sequence_number if item.sequence_number is not None else -1,
                    item.transition_id,
                ),
            )
            delta = deltas.get((object_category, stable_key))
            coverage = coverage_by_category.get(object_category, "UNKNOWN")
            kind, gaps = self._classify(
                object_category, boundary_before, boundary_after, records, delta, coverage
            )
            if kind in {TrajectoryType.STABLE, TrajectoryType.UNOBSERVED_INTERVAL} and not (
                include_stable or object_key is not None
            ):
                continue
            relation = self._relation(delta, boundary_before, boundary_after, records, kind)
            links = [
                TrajectoryTransitionLink(transition_id=item.transition_id, relation=relation)
                for item in records
            ]
            identity = "|".join(
                (before.host_id, before.snapshot_id, after.snapshot_id, object_category, stable_key)
            )
            trajectories.append(
                StateTrajectory(
                    trajectory_id=str(uuid5(NAMESPACE_URL, f"csg-trajectory:{identity}")),
                    host_id=before.host_id,
                    category=object_category,
                    object_key=stable_key,
                    snapshot_before_id=before.snapshot_id,
                    snapshot_after_id=after.snapshot_id,
                    interval=interval,
                    state_before=boundary_before,
                    state_after=boundary_after,
                    snapshot_delta=delta,
                    transitions=records,
                    transition_links=links,
                    trajectory_type=kind,
                    coverage_status=coverage,
                    coverage_gaps=gaps,
                )
            )
        return trajectories

    @classmethod
    def _classify(
        cls,
        category: str,
        before,
        after,
        transitions: list[StateTransitionRecord],
        delta: StateDelta | None,
        coverage: MonitorHealthStatus,
    ) -> tuple[TrajectoryType, list[str]]:
        if transitions:
            if before is None and after is None:
                if (
                    cls._is_create(transitions[0].transition_type)
                    and cls._is_remove(transitions[-1].transition_type)
                    and cls._chain_matches(category, before, after, transitions)
                ):
                    return TrajectoryType.TRANSIENT_OBJECT, []
                return TrajectoryType.INCONSISTENT, [
                    "object absent at both snapshots without a boundary-consistent "
                    "create/remove chain"
                ]

            if not cls._chain_matches(category, before, after, transitions):
                return TrajectoryType.INCONSISTENT, [
                    "captured transition chain does not match ordered snapshot boundaries"
                ]
            if delta:
                return (
                    TrajectoryType.DURABLE
                    if len(transitions) == 1
                    else TrajectoryType.MULTI_STEP_DURABLE,
                    [],
                )

            if cls._full_state_matches(
                before.attributes if before else None,
                after.attributes if after else None,
                category,
            ) and any(
                not cls._full_state_matches(item.old_state, item.new_state, category)
                for item in transitions
            ):
                return TrajectoryType.REVERTED, []
            return TrajectoryType.NON_PERSISTENT_TRANSITION, []

        if delta:
            return TrajectoryType.TRANSITION_CAPTURE_GAP, [
                f"snapshot delta {delta.delta_id} has no transition record",
                f"monitor coverage was {coverage}",
            ]
        if coverage == "HEALTHY":
            return TrajectoryType.STABLE, []
        return TrajectoryType.UNOBSERVED_INTERVAL, [
            f"no transition record was observed and monitor coverage was {coverage}"
        ]

    @classmethod
    def _full_state_matches(cls, first: dict | None, second: dict | None, category: str) -> bool:
        if first is None or second is None:
            return first is second
        return normalize_attributes(category, first) == normalize_attributes(category, second)

    @classmethod
    def _chain_matches(cls, category, before, after, transitions) -> bool:
        if not transitions:
            return True
        boundary_before = before.attributes if before else None
        boundary_after = after.attributes if after else None
        if not cls._full_state_matches(transitions[0].old_state, boundary_before, category):
            return False
        for first, second in zip(transitions, transitions[1:], strict=False):
            if not cls._full_state_matches(first.new_state, second.old_state, category):
                return False
        return cls._full_state_matches(transitions[-1].new_state, boundary_after, category)

    @staticmethod
    def _is_create(value: str) -> bool:
        return value in {
            "CREATE",
            "CREATED",
            "SERVICE_CREATED",
            "TASK_CREATED",
            "PROCESS_START",
            "OPEN",
        }

    @staticmethod
    def _is_remove(value: str) -> bool:
        return value in {
            "REMOVE",
            "REMOVED",
            "SERVICE_DELETED",
            "TASK_DELETED",
            "PROCESS_EXIT",
            "CLOSE",
        }

    @staticmethod
    def _relation(
        delta: StateDelta | None,
        before,
        after,
        transitions: list[StateTransitionRecord],
        kind: TrajectoryType,
    ) -> TransitionRelation:
        if kind == TrajectoryType.TRANSIENT_OBJECT:
            return TransitionRelation.TRANSIENT_BETWEEN_SNAPSHOTS
        if delta and len(transitions) > 1:
            return TransitionRelation.PART_OF_MULTISTEP_DELTA
        if delta:
            return TransitionRelation.REPRESENTED_BY_DELTA
        if kind == TrajectoryType.NON_PERSISTENT_TRANSITION:
            return TransitionRelation.NON_PERSISTENT_TRANSITION
        if transitions:
            return TransitionRelation.REVERTED_BEFORE_SNAPSHOT
        return TransitionRelation.NOT_OBSERVED_BY_TRANSITION_MONITOR
