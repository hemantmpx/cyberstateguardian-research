from __future__ import annotations

import json
from hashlib import sha256
from uuid import NAMESPACE_URL, uuid5

from csg.domain.enums import DeltaType
from csg.domain.models import StateDelta, StateObject, StateSnapshot, TimeWindow
from csg.state.normalize import comparable_attributes


class DeltaEngine:
    def diff(self, previous: StateSnapshot, current: StateSnapshot) -> list[StateDelta]:
        if previous.host_id != current.host_id:
            raise ValueError("cannot compare snapshots from different hosts")
        if previous.source != current.source:
            raise ValueError("cannot compare snapshots from different state sources")

        previous_by_category = self._objects_by_category(previous.objects)
        current_by_category = self._objects_by_category(current.objects)
        categories = sorted(set(previous_by_category) | set(current_by_category))
        deltas: list[StateDelta] = []

        for category in categories:
            previous_status = previous.status_for(category)
            current_status = current.status_for(category)
            if not previous_status or not current_status:
                continue
            if not previous_status.usable or not current_status.usable:
                continue

            before_objects = previous_by_category.get(category, {})
            after_objects = current_by_category.get(category, {})
            all_keys = sorted(set(before_objects) | set(after_objects))

            for object_key in all_keys:
                before = before_objects.get(object_key)
                after = after_objects.get(object_key)
                delta_type: DeltaType | None = None
                if before is None and after is not None:
                    if previous_status.status == "healthy":
                        delta_type = DeltaType.ADD
                elif before is not None and after is None:
                    if current_status.status == "healthy":
                        delta_type = DeltaType.REMOVE
                elif before and after and self._changed(before, after):
                    delta_type = DeltaType.MODIFY

                if delta_type is None:
                    continue

                transition = {
                    "version": 1,
                    "previous_snapshot_id": previous.snapshot_id,
                    "host_id": current.host_id,
                    "category": category,
                    "object_key": object_key,
                    "delta_type": delta_type.value,
                    "before": comparable_attributes(before.attributes, category)
                    if before
                    else None,
                    "after": comparable_attributes(after.attributes, category)
                    if after
                    else None,
                    "scope": {
                        key: current.metadata[key]
                        for key in ("experiment_id", "trial_id")
                        if current.metadata.get(key)
                    },
                }
                transition_key = json.dumps(
                    transition,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                )

                deltas.append(
                    StateDelta(
                        delta_id=str(uuid5(NAMESPACE_URL, f"csg-state-delta:{transition_key}")),
                        host_id=current.host_id,
                        category=category,
                        object_key=object_key,
                        delta_type=delta_type,
                        before=before,
                        after=after,
                        source_quality={
                            "previous": previous_status.model_dump(mode="json"),
                            "current": current_status.model_dump(mode="json"),
                        },
                        observation_window=TimeWindow(
                            start=previous_status.observed_at,
                            end=current_status.observed_at,
                        ),
                        created_at=current.built_at,
                        metadata={
                            "transition_key_version": 1,
                            "previous_snapshot_id": previous.snapshot_id,
                            "current_snapshot_id": current.snapshot_id,
                            "transition_key_sha256": sha256(
                                transition_key.encode("utf-8")
                            ).hexdigest(),
                            **{
                                key: current.metadata[key]
                                for key in ("experiment_id", "trial_id")
                                if current.metadata.get(key)
                            },
                        },
                    ),
                )
        return sorted(
            deltas, key=lambda delta: (delta.category, delta.object_key, delta.delta_type.value)
        )

    @staticmethod
    def _objects_by_category(objects: list[StateObject]) -> dict[str, dict[str, StateObject]]:
        grouped: dict[str, dict[str, StateObject]] = {}
        for obj in objects:
            grouped.setdefault(obj.category, {})[obj.object_key] = obj
        return grouped

    @staticmethod
    def _changed(before: StateObject, after: StateObject) -> bool:
        return comparable_attributes(before.attributes, before.category) != comparable_attributes(
            after.attributes, after.category
        )
