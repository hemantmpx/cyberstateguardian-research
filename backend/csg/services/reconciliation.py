from __future__ import annotations

from datetime import datetime, timedelta

from csg.domain.enums import DeltaType, ReconciliationStatus
from csg.domain.models import (
    EventObservationResult,
    NormalizedEvent,
    ReconciliationResult,
    StateDelta,
    TimeWindow,
    TransientObservation,
    ensure_utc,
)
from csg.state.normalize import (
    normalize_registry_key,
    normalize_service_status,
    normalize_string,
    stable_listener_key,
    stable_privileged_group_key,
    stable_scheduled_task_key,
)


def source_health_attribution_for_window(
    window: TimeWindow,
    object_key: str,
    observation: EventObservationResult | None,
) -> str:
    """Return health proven for this object's observation window, not merely at query time."""
    if observation is None:
        return "UNKNOWN"

    metadata = observation.metadata
    affected = metadata.get("affected_object_keys")
    if (
        isinstance(affected, list)
        and affected
        and object_key.casefold() not in {str(key).casefold() for key in affected}
    ):
        return "UNKNOWN"

    outage = metadata.get("source_degradation_interval")
    if isinstance(outage, dict):
        try:
            outage_start = ensure_utc(
                datetime.fromisoformat(str(outage["start"]).replace("Z", "+00:00"))
            )
            outage_end = ensure_utc(
                datetime.fromisoformat(str(outage["end"]).replace("Z", "+00:00"))
            )
        except (KeyError, TypeError, ValueError):
            return "UNKNOWN"
        if outage_start <= window.end and outage_end >= window.start:
            return "DEGRADED"

    checked_at = metadata.get("source_health_checked_at")
    if not checked_at:
        return "UNKNOWN"
    try:
        health_time = ensure_utc(datetime.fromisoformat(str(checked_at).replace("Z", "+00:00")))
    except ValueError:
        return "UNKNOWN"
    if not window.start <= health_time <= window.end:
        return "UNKNOWN"

    statuses = (
        observation.endpoint_collection_status,
        observation.transport_status,
        observation.index_status,
    )
    if any(status in {"DEGRADED", "UNAVAILABLE"} for status in statuses):
        return "DEGRADED"
    if all(status == "AVAILABLE" for status in statuses):
        return "AVAILABLE"
    return "UNKNOWN"


class ReconciliationEngine:
    def __init__(
        self,
        observation_window_seconds: int = 900,
        event_time_tolerance_seconds: int = 5,
    ) -> None:
        # The legacy window is retained for compatibility with callers and old records. New
        # deltas use their actual snapshot interval plus this measured clock/receipt tolerance.
        self.observation_window_seconds = observation_window_seconds
        self.event_time_tolerance_seconds = event_time_tolerance_seconds

    def observation_window_for_delta(self, delta: StateDelta) -> TimeWindow:
        tolerance = timedelta(seconds=self.event_time_tolerance_seconds)
        return TimeWindow(
            start=delta.observation_window.start - tolerance,
            end=delta.observation_window.end + tolerance,
        )

    def reconcile_delta(
        self,
        delta: StateDelta,
        events: list[NormalizedEvent],
        event_observation: EventObservationResult | None = None,
    ) -> ReconciliationResult:
        if delta.delta_type == DeltaType.REMOVE:
            return ReconciliationResult(
                host_id=delta.host_id,
                delta_id=delta.delta_id,
                status=ReconciliationStatus.NOT_APPLICABLE,
                observation_window=self.observation_window_for_delta(delta),
                match_reasons=[],
                missing_expected_evidence_types=[],
                confidence=1.0,
                metadata={"reason": "remove deltas do not require creation evidence"},
            )

        expected_primary, accepted_related = self._expected_event_types(delta)
        if not expected_primary:
            return ReconciliationResult(
                host_id=delta.host_id,
                delta_id=delta.delta_id,
                status=ReconciliationStatus.NOT_APPLICABLE,
                observation_window=self.observation_window_for_delta(delta),
                confidence=1.0,
            )

        transition_mismatches: list[dict[str, str]] = []
        events_by_id: dict[str, NormalizedEvent] = {}
        duplicate_event_ids: set[str] = set()
        conflicting_event_ids: set[str] = set()
        for event in events:
            previous = events_by_id.get(event.event_id)
            if previous is None and event.event_id not in conflicting_event_ids:
                events_by_id[event.event_id] = event
            elif previous is not None:
                duplicate_event_ids.add(event.event_id)
                if not self._same_evidence_identity(previous, event):
                    conflicting_event_ids.add(event.event_id)
                    events_by_id.pop(event.event_id, None)

        events_by_windows_identity: dict[tuple[str, ...], list[NormalizedEvent]] = {}
        events_without_windows_identity: list[NormalizedEvent] = []
        for event in events_by_id.values():
            identity = self._windows_event_identity_key(event)
            if identity is None:
                events_without_windows_identity.append(event)
            else:
                events_by_windows_identity.setdefault(identity, []).append(event)

        canonical_events = list(events_without_windows_identity)
        windows_event_aliases: list[dict[str, object]] = []
        conflicting_windows_event_identity_ids: set[str] = set()
        for group in events_by_windows_identity.values():
            ordered_group = sorted(group, key=self._windows_event_preference)
            primary = ordered_group[0]
            if any(
                not self._same_windows_event_payload(primary, candidate)
                for candidate in ordered_group[1:]
            ):
                conflicting_windows_event_identity_ids.update(
                    item.event_id for item in ordered_group
                )
                continue

            canonical_events.append(primary)
            aliases = ordered_group[1:]
            if aliases:
                windows_event_aliases.append(
                    {
                        "canonical_event_id": primary.event_id,
                        "alias_event_ids": [item.event_id for item in aliases],
                        "source_references": [
                            {
                                "event_id": item.event_id,
                                **item.source_reference,
                            }
                            for item in ordered_group
                        ],
                    }
                )

        matches = sorted(
            [
                event
                for event in canonical_events
                if event.normalized_type in {*expected_primary, *accepted_related}
                and self._event_matches_delta(event, delta, transition_mismatches)
            ],
            key=lambda item: (item.event_time, item.event_id),
        )
        primary_matches = [event for event in matches if event.normalized_type in expected_primary]
        related_matches = [event for event in matches if event.normalized_type in accepted_related]

        match_reasons = [
            {
                "event_id": event.event_id,
                "event_type": event.normalized_type,
                "reason": self._reason_for(event, delta),
            }
            for event in sorted(matches, key=lambda item: (item.event_time, item.event_id))
        ]
        missing = [
            event_type
            for event_type in expected_primary
            if event_type not in {event.normalized_type for event in primary_matches}
        ]

        if primary_matches:
            status = ReconciliationStatus.CONSISTENT
            confidence = 0.95
        elif related_matches:
            status = ReconciliationStatus.PARTIALLY_EXPLAINED
            confidence = 0.65
        else:
            status = ReconciliationStatus.UNEXPLAINED
            confidence = 0.35

        metadata = {
            "rule": "deterministic_event_state_reconciliation",
            "delta_id": delta.delta_id,
            "transition_aware": True,
            "transition_mismatches": transition_mismatches,
            "event_time_tolerance_seconds": self.event_time_tolerance_seconds,
            "duplicate_event_ids": sorted(duplicate_event_ids - conflicting_event_ids),
            "conflicting_event_identity_ids": sorted(conflicting_event_ids),
            "deduplicated_windows_event_aliases": windows_event_aliases,
            "conflicting_windows_event_identity_ids": sorted(
                conflicting_windows_event_identity_ids
            ),
        }
        if event_observation is not None:
            metadata["event_plane"] = event_observation.model_dump(mode="json", exclude={"events"})
        return ReconciliationResult(
            host_id=delta.host_id,
            delta_id=delta.delta_id,
            status=status,
            matched_evidence_ids=[event.event_id for event in matches],
            match_reasons=match_reasons,
            missing_expected_evidence_types=missing,
            observation_window=self.observation_window_for_delta(delta),
            confidence=confidence,
            metadata=metadata,
        )

    def derive_event_only_transients(
        self,
        events: list[NormalizedEvent],
        deltas: list[StateDelta],
    ) -> list[TransientObservation]:
        delta_event_ids: set[str] = set()
        for delta in deltas:
            result = self.reconcile_delta(delta, events)
            delta_event_ids.update(result.matched_evidence_ids)

        transients: list[TransientObservation] = []
        for event in events:
            if event.event_id in delta_event_ids:
                continue
            if event.normalized_type not in {"process_start", "network_activity"}:
                continue
            transients.append(
                TransientObservation(
                    host_id=event.host_id,
                    event_id=event.event_id,
                    event_time=event.event_time,
                    normalized_type=event.normalized_type,
                    actor=event.actor,
                    target=event.target,
                    attributes=event.attributes,
                    reason="event appeared in telemetry but produced no persistent state delta",
                    metadata={
                        "source": event.source,
                        "scenario_id": event.scenario_id,
                        "synthetic": event.synthetic,
                    },
                ),
            )
        return transients

    @staticmethod
    def _expected_event_types(delta: StateDelta) -> tuple[list[str], list[str]]:
        if delta.category == "service" and delta.delta_type == DeltaType.ADD:
            return ["service_created"], ["process_start"]
        if delta.category == "service" and delta.delta_type == DeltaType.MODIFY:
            return ["service_modified"], ["process_start"]
        if delta.category == "listener" and delta.delta_type == DeltaType.ADD:
            # A connection to destination port 443 does not prove a local bind on 443.
            return ["listener_created"], ["network_activity", "process_start"]
        if delta.category == "privileged_group":
            return ["privileged_group_member_added"], ["process_start"]
        if delta.category == "scheduled_task":
            if delta.delta_type == DeltaType.MODIFY:
                return ["scheduled_task_modified"], ["process_start"]
            return ["scheduled_task_created"], ["process_start"]
        if delta.category == "registry":
            return ["registry_value_modified"], ["process_start"]
        if delta.category == "process" and delta.delta_type == DeltaType.ADD:
            return ["process_start"], []
        return [], []

    def event_matches_delta(
        self,
        event: NormalizedEvent,
        delta: StateDelta,
        transition_mismatches: list[dict[str, str]] | None = None,
    ) -> bool:
        """Shared strict matcher for snapshot deltas and independent transitions."""
        return self._event_matches_delta(event, delta, transition_mismatches)

    def _event_matches_delta(
        self,
        event: NormalizedEvent,
        delta: StateDelta,
        transition_mismatches: list[dict[str, str]] | None = None,
    ) -> bool:
        if event.host_id != delta.host_id:
            return False
        window = self.observation_window_for_delta(delta)
        if not window.start <= event.event_time <= window.end:
            return False
        target_key = normalize_string(event.target.get("key")).lower()
        identity_matches = (
            self._category_match(event, delta)
            if delta.category == "privileged_group"
            else target_key == delta.object_key or self._category_match(event, delta)
        )
        if not identity_matches:
            return False
        if self._transition_matches(event, delta):
            return True
        if transition_mismatches is not None:
            transition_mismatches.append(
                {
                    "event_id": event.event_id,
                    "event_type": event.normalized_type,
                    "reason": "same object and operation type but incompatible transition",
                }
            )
        return False

    @staticmethod
    def _transition_matches(event: NormalizedEvent, delta: StateDelta) -> bool:
        if delta.category == "registry":
            after = delta.after.attributes if delta.after else {}
            if "value" not in after:
                return True

            operation = normalize_string(event.attributes.get("event_type")).casefold()
            if operation and operation not in {"setvalue", "createkey"}:
                return False

            observed_value = next(
                (
                    event.attributes[key]
                    for key in ("value", "new_value", "details")
                    if key in event.attributes and event.attributes[key] is not None
                ),
                None,
            )
            expected = ReconciliationEngine._normalize_registry_data(after["value"])
            observed = ReconciliationEngine._normalize_registry_data(observed_value)
            return expected is not None and observed is not None and expected == observed

        if delta.category != "service" or delta.delta_type != DeltaType.MODIFY:
            return True

        before_mode = ReconciliationEngine._normalize_start_mode(
            (delta.before.attributes if delta.before else {}).get("start_mode")
        )
        after_mode = ReconciliationEngine._normalize_start_mode(
            (delta.after.attributes if delta.after else {}).get("start_mode")
        )
        if before_mode == after_mode:
            return True

        event_old_mode = ReconciliationEngine._normalize_start_mode(
            event.attributes.get("old_start_mode")
        )
        event_new_mode = ReconciliationEngine._normalize_start_mode(
            event.attributes.get("new_start_mode")
        )
        return bool(
            before_mode
            and after_mode
            and event_old_mode
            and event_new_mode
            and event_old_mode == before_mode
            and event_new_mode == after_mode
        )

    @staticmethod
    def _normalize_start_mode(value: object) -> str:
        normalized = normalize_service_status(value).removesuffix("_start")
        # Windows Event 7040 calls Manual startup type "demand start", while
        # the native service probe reports the same state as "Manual".
        aliases = {
            "demand": "manual",
            "manual": "manual",
            "automatic": "auto",
            "auto": "auto",
        }
        return aliases.get(normalized, normalized)

    @staticmethod
    def _normalize_registry_data(value: object) -> str | None:
        if value is None:
            return None
        normalized = normalize_string(value).strip()
        while "\\\\" in normalized:
            normalized = normalized.replace("\\\\", "\\")
        return normalized

    @staticmethod
    def _same_evidence_identity(left: NormalizedEvent, right: NormalizedEvent) -> bool:
        return (
            left.host_id == right.host_id
            and left.event_time == right.event_time
            and left.normalized_type == right.normalized_type
            and left.actor == right.actor
            and left.target == right.target
            and left.attributes == right.attributes
            and left.source_reference == right.source_reference
        )

    @staticmethod
    def _windows_event_identity_key(event: NormalizedEvent) -> tuple[str, ...] | None:
        identity = event.metadata.get("windows_event_identity")
        if not isinstance(identity, dict):
            return None
        values = (
            identity.get("agent_id"),
            identity.get("channel"),
            identity.get("event_record_id"),
            identity.get("event_code"),
            identity.get("provider_name", ""),
        )
        if not all(str(value or "").strip() for value in values[:4]):
            return None
        return (event.host_id, *(str(value or "").strip().casefold() for value in values))

    @staticmethod
    def _windows_event_preference(event: NormalizedEvent) -> tuple[int, str]:
        index = str(event.source_reference.get("index", "")).casefold()
        source_rank = 0 if index.startswith("wazuh-alerts-") else 1
        return source_rank, event.event_id

    @staticmethod
    def _same_windows_event_payload(left: NormalizedEvent, right: NormalizedEvent) -> bool:
        left_key = normalize_string(left.target.get("key")).casefold()
        right_key = normalize_string(right.target.get("key")).casefold()
        return (
            left.host_id == right.host_id
            and left.event_time == right.event_time
            and left.normalized_type == right.normalized_type
            and left_key == right_key
        )

    @staticmethod
    def _category_match(event: NormalizedEvent, delta: StateDelta) -> bool:
        object_key = delta.object_key
        if delta.category == "service":
            # A Windows display name is not a stable object identity. Only the
            # normalized internal service name or exact target key may explain a
            # persistent service delta.
            delta_name = ReconciliationEngine._service_name(delta)
            event_name = normalize_string(event.attributes.get("service_name")).lower()
            return bool(delta_name and event_name and event_name == delta_name)

        if delta.category == "listener":
            event_address = event.attributes.get("local_address") or event.target.get(
                "local_address"
            )
            event_port = event.attributes.get("local_port") or event.target.get("local_port")
            event_protocol = event.attributes.get("protocol") or event.target.get("protocol")
            if not event_address or not event_port or not event_protocol:
                return False
            return (
                stable_listener_key(
                    {
                        "protocol": event_protocol,
                        "local_address": event_address,
                        "local_port": event_port,
                    }
                )
                == object_key.casefold()
            )

        if delta.category == "privileged_group":
            group = normalize_string(
                event.attributes.get("group") or event.target.get("group")
            ).lower()
            if not group:
                return False

            state_attributes = next(
                (
                    state.attributes
                    for state in (delta.after, delta.before)
                    if state and state.attributes.get("group") and state.attributes.get("member")
                ),
                {},
            )
            state_key = stable_privileged_group_key(state_attributes)
            if state_key != object_key.casefold():
                return False

            state_group = normalize_string(state_attributes.get("group")).lower()
            if group != state_group:
                return False

            state_sid = normalize_string(state_attributes.get("sid")).casefold()
            event_sid = normalize_string(
                event.attributes.get("member_sid") or event.target.get("member_sid")
            ).casefold()
            member = normalize_string(event.attributes.get("member") or event.target.get("member"))
            if member and member != "-":
                event_key = stable_privileged_group_key({"group": group, "member": member})
                return event_key == object_key.casefold() and not (
                    event_sid and state_sid and event_sid != state_sid
                )

            return bool(event_sid and state_sid and event_sid == state_sid)

        if delta.category == "scheduled_task":
            task_name = event.attributes.get("task_name") or event.target.get("task_name")
            event_key = stable_scheduled_task_key({"task_name": task_name})
            return bool(task_name and object_key == event_key)

        if delta.category == "registry":
            target = event.attributes.get("target_object") or event.target.get("key")
            return bool(target) and normalize_registry_key(target) == normalize_registry_key(
                object_key
            )

        return False

    @staticmethod
    def _service_name(delta: StateDelta) -> str:
        for state_object in (delta.after, delta.before):
            if state_object is None:
                continue
            value = normalize_string(state_object.attributes.get("service_name")).lower()
            if value:
                return value
        return normalize_string(delta.object_key.removeprefix("service:")).lower()

    @staticmethod
    def _reason_for(event: NormalizedEvent, delta: StateDelta) -> str:
        return (
            f"{event.normalized_type} matched {delta.category} "
            f"{delta.delta_type.value} for {delta.object_key}"
        )


class ReconciliationLifecycle:
    """Turns a point-in-time match into an auditable, latency-aware decision."""

    def __init__(
        self,
        engine: ReconciliationEngine,
        grace_seconds: int = 60,
    ) -> None:
        self.engine = engine
        self.grace_seconds = grace_seconds

    def evaluate(
        self,
        delta: StateDelta,
        events: list[NormalizedEvent],
        *,
        now: datetime,
        previous: ReconciliationResult | None = None,
        finding_id: str | None = None,
        evidence_complete: bool | None = None,
        event_observation: EventObservationResult | None = None,
    ) -> ReconciliationResult:
        base = self.engine.reconcile_delta(delta, events, event_observation)
        deadline = base.observation_window.end + timedelta(seconds=self.grace_seconds)
        retrieval_complete = (
            event_observation.query_complete and event_observation.coverage_status == "COMPLETE"
            if event_observation is not None
            else evidence_complete
            if evidence_complete is not None
            else False
        )
        health_attribution = source_health_attribution_for_window(
            base.observation_window,
            delta.object_key,
            event_observation,
        )
        health_attribution_source = "current_observation"
        prior_health_evidence: dict | None = None
        if health_attribution == "UNKNOWN" and previous is not None:
            prior_record = previous.metadata.get("event_plane_last_observation")
            prior_health_evidence = (
                prior_record.get("observation") if isinstance(prior_record, dict) else None
            )
            if not isinstance(prior_health_evidence, dict):
                prior_health_evidence = previous.metadata.get(
                    "source_health_attribution_observation"
                )
            if isinstance(prior_health_evidence, dict):
                try:
                    prior_observation = EventObservationResult.model_validate(prior_health_evidence)
                except (TypeError, ValueError):
                    prior_observation = None
                if prior_observation is not None:
                    prior_attribution = source_health_attribution_for_window(
                        base.observation_window,
                        delta.object_key,
                        prior_observation,
                    )
                    if prior_attribution != "UNKNOWN":
                        health_attribution = prior_attribution
                        health_attribution_source = "prior_in_window_observation"

        current_health_attribution = source_health_attribution_for_window(
            base.observation_window,
            delta.object_key,
            event_observation,
        )
        current_source_degradation = current_health_attribution == "DEGRADED"
        health_observed_outside_window = (
            event_observation is not None
            and health_attribution == "UNKNOWN"
            and any(
                status in {"DEGRADED", "UNAVAILABLE"}
                for status in (
                    event_observation.endpoint_collection_status,
                    event_observation.transport_status,
                    event_observation.index_status,
                )
            )
            and health_attribution == "UNKNOWN"
        )
        correction = (
            event_observation.metadata.get("source_health_correction")
            if event_observation is not None
            else None
        )
        valid_correction = (
            isinstance(correction, dict)
            and bool(correction.get("reason"))
            and bool(correction.get("evidence_reference"))
            and not current_source_degradation
        )
        known_source_degradation = current_source_degradation or bool(
            previous
            and previous.metadata.get("source_health_known_degraded")
            and not valid_correction
        )
        positive_match = base.status in {
            ReconciliationStatus.CONSISTENT,
            ReconciliationStatus.NOT_APPLICABLE,
        }
        can_finalize = positive_match or retrieval_complete or known_source_degradation
        final = can_finalize and (positive_match or now >= deadline)
        status = base.status if final else ReconciliationStatus.PENDING_EVIDENCE
        transition_mismatches = base.metadata.get("transition_mismatches", [])
        if base.status == ReconciliationStatus.CONSISTENT:
            semantics = "CORROBORATED"
        elif transition_mismatches:
            semantics = "CONTRADICTED"
        elif known_source_degradation:
            semantics = "UNCORROBORATED_DEGRADED"
        elif health_observed_outside_window:
            semantics = "INCONCLUSIVE"
        elif retrieval_complete and health_attribution == "AVAILABLE":
            semantics = "UNCORROBORATED_HEALTHY"
        else:
            semantics = "INCONCLUSIVE"
        metadata = {
            **base.metadata,
            "provisional_status": base.status.value if not final else None,
            "evidence_deadline": deadline.isoformat(),
            "lifecycle_rule": "observation_window_plus_grace",
            "event_retrieval_complete": retrieval_complete,
            "reconciliation_semantics": semantics,
            "source_health_known_degraded": known_source_degradation,
            "source_health_attribution": health_attribution,
            "source_health_attribution_source": health_attribution_source,
        }
        if health_attribution_source == "prior_in_window_observation" and prior_health_evidence:
            metadata["source_health_attribution_observation"] = prior_health_evidence
        elif health_attribution != "UNKNOWN" and event_observation is not None:
            metadata["source_health_attribution_observation"] = event_observation.model_dump(
                mode="json", exclude={"events"}
            )
        if previous and previous.metadata.get("source_health_known_degraded"):
            metadata["source_health_evidence"] = previous.metadata.get(
                "source_health_evidence", previous.metadata.get("event_plane")
            )
        if event_observation is not None:
            observation_evidence = event_observation.model_dump(mode="json", exclude={"events"})
            metadata["event_plane_last_observation"] = {
                "observation": observation_evidence,
                "observation_current_for_revision": True,
                "source_reconciliation_id": base.reconciliation_id,
                "source_reconciliation_version": base.version,
            }
            if (
                previous
                and previous.metadata.get("source_health_known_degraded")
                and not (current_source_degradation or valid_correction)
            ):
                metadata["source_health_last_observation"] = observation_evidence
            elif current_source_degradation:
                metadata["source_health_evidence"] = observation_evidence
            else:
                metadata["source_health_observation"] = observation_evidence
        elif previous is not None:
            prior_observation = previous.metadata.get("event_plane_last_observation")
            if isinstance(prior_observation, dict) and isinstance(
                prior_observation.get("observation"), dict
            ):
                observation_evidence = prior_observation["observation"]
            else:
                observation_evidence = (
                    previous.metadata.get("event_plane")
                    or previous.metadata.get("source_health_observation")
                    or previous.metadata.get("source_health_evidence")
                )
            if isinstance(observation_evidence, dict):
                metadata["event_plane_last_observation"] = {
                    "observation": observation_evidence,
                    "observation_current_for_revision": False,
                    "source_reconciliation_id": previous.reconciliation_id,
                    "source_reconciliation_version": previous.version,
                }
        if valid_correction:
            metadata["source_health_correction"] = correction
        for scope_key in ("experiment_id", "trial_id"):
            if scope_value := delta.metadata.get(scope_key):
                metadata[scope_key] = scope_value
        return base.model_copy(
            update={
                "status": status,
                "finding_id": finding_id,
                "version": previous.version + 1 if previous else 1,
                "finalized": final,
                "finalized_at": now if final else None,
                "supersedes_reconciliation_id": (previous.reconciliation_id if previous else None),
                "created_at": now,
                "metadata": metadata,
            }
        )
