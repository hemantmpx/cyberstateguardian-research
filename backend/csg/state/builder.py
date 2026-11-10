from __future__ import annotations

from csg.domain.models import (
    CategoryStatus,
    CollectorObservation,
    ProbeObservation,
    StateObject,
    StateSnapshot,
)
from csg.state.normalize import normalize_attributes, stable_object_key


class StateBuilder:
    def build_from_probe_observation(self, observation: ProbeObservation) -> StateSnapshot:
        scope = {
            key: observation.metadata[key]
            for key in ("experiment_id", "trial_id")
            if observation.metadata.get(key)
        }
        statuses: list[CategoryStatus] = []
        objects: list[StateObject] = []
        for category, collector in sorted(observation.categories.items()):
            collector = (
                collector
                if isinstance(collector, CollectorObservation)
                else CollectorObservation.model_validate(collector)
            )
            statuses.append(
                CategoryStatus(
                    category=category,
                    status=collector.status,
                    source=observation.source,
                    observed_at=collector.observed_at,
                    message=collector.message,
                ),
            )
            if collector.status not in {"healthy", "partial"}:
                continue
            for item in collector.items:
                attributes = normalize_attributes(category, item)
                objects.append(
                    StateObject(
                        category=category,
                        object_key=stable_object_key(category, attributes),
                        attributes=attributes,
                        source_timestamp=collector.observed_at,
                        metadata={
                            "observation_id": observation.observation_id,
                            "source": observation.source,
                            **scope,
                        },
                    ),
                )
        return StateSnapshot(
            host_id=observation.host_id,
            built_at=max(
                observation.observed_at,
                *(status.observed_at for status in statuses),
            ),
            source=observation.source,
            category_statuses=statuses,
            objects=sorted(objects, key=lambda item: (item.category, item.object_key)),
            metadata={"observation_id": observation.observation_id, **scope},
        )

    @staticmethod
    def retain_newer_category_observations(
        previous: StateSnapshot,
        current: StateSnapshot,
    ) -> StateSnapshot:
        """Prevent a late, slow collector result from rolling a category backward."""
        previous_statuses = {status.category: status for status in previous.category_statuses}
        current_statuses = {status.category: status for status in current.category_statuses}
        previous_objects: dict[str, list[StateObject]] = {}
        current_objects: dict[str, list[StateObject]] = {}
        for state_object in previous.objects:
            previous_objects.setdefault(state_object.category, []).append(state_object)
        for state_object in current.objects:
            current_objects.setdefault(state_object.category, []).append(state_object)

        statuses = []
        objects = []
        retained_categories = []
        for category in sorted(set(previous_statuses) | set(current_statuses)):
            old_status = previous_statuses.get(category)
            new_status = current_statuses.get(category)
            if old_status and (
                new_status is None or new_status.observed_at <= old_status.observed_at
            ):
                statuses.append(old_status)
                objects.extend(previous_objects.get(category, []))
                retained_categories.append(category)
            elif new_status:
                statuses.append(new_status)
                objects.extend(current_objects.get(category, []))

        return current.model_copy(
            update={
                "built_at": max(
                    current.built_at,
                    *(status.observed_at for status in statuses),
                ),
                "category_statuses": statuses,
                "objects": sorted(objects, key=lambda item: (item.category, item.object_key)),
                "metadata": {
                    **current.metadata,
                    "stale_category_observations_retained": retained_categories,
                },
            }
        )
