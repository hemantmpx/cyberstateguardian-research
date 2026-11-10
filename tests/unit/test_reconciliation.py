from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tests.conftest import ROOT, load_json

from csg.domain.enums import DeltaType, ReconciliationStatus
from csg.domain.models import NormalizedEvent, StateDelta, StateObject, StateSnapshot, TimeWindow
from csg.services.reconciliation import ReconciliationEngine
from csg.state.diff import DeltaEngine
from csg.state.normalize import stable_listener_key, stable_scheduled_task_key


def _snapshot(name: str) -> StateSnapshot:
    return StateSnapshot.model_validate(load_json(ROOT / "experiments/fixtures/state" / name))


def _events(name: str) -> list[NormalizedEvent]:
    payload = load_json(ROOT / "experiments/fixtures/events" / name)
    return [NormalizedEvent.model_validate(row) for row in payload["events"]]


def test_reconciliation_distinguishes_consistent_partial_and_unexplained() -> None:
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("new_service.json"))[0]
    engine = ReconciliationEngine()

    consistent = engine.reconcile_delta(delta, _events("svc-create-consistent.json"))
    partial = engine.reconcile_delta(delta, _events("svc-create-partial.json"))
    unexplained = engine.reconcile_delta(delta, _events("svc-create-unexplained.json"))

    assert consistent.status == ReconciliationStatus.CONSISTENT
    assert consistent.matched_evidence_ids == ["evt-service-001"]
    assert partial.status == ReconciliationStatus.PARTIALLY_EXPLAINED
    assert partial.missing_expected_evidence_types == ["service_created"]
    assert unexplained.status == ReconciliationStatus.UNEXPLAINED


def test_event_only_transient_does_not_create_fake_delta() -> None:
    deltas = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("baseline.json"))
    transients = ReconciliationEngine().derive_event_only_transients(
        _events("short-lived-process.json"),
        deltas,
    )
    assert deltas == []
    assert len(transients) == 1
    assert transients[0].event_id == "evt-process-ephemeral-001"


def test_service_runtime_status_change_is_not_configuration_drift() -> None:
    baseline = _snapshot("baseline.json")
    current = baseline.model_copy(
        update={
            "built_at": baseline.built_at.replace(minute=15),
            "objects": [
                obj.model_copy(
                    update={
                        "attributes": {
                            **obj.attributes,
                            "status": "stopped",
                        }
                    }
                )
                if obj.object_key == "service:eventlog"
                else obj
                for obj in baseline.objects
            ],
        }
    )

    assert not [
        delta for delta in DeltaEngine().diff(baseline, current) if delta.category == "service"
    ]


def test_unrelated_service_event_does_not_explain_delta() -> None:
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("new_service.json"))[0]
    event = _events("svc-create-consistent.json")[0].model_copy(
        update={
            "target": {"key": "service:unrelated"},
            "attributes": {"service_name": "Unrelated"},
        }
    )
    result = ReconciliationEngine().reconcile_delta(delta, [event])
    assert result.status == ReconciliationStatus.UNEXPLAINED
    assert result.matched_evidence_ids == []


def test_same_host_same_time_wrong_service_does_not_explain_delta() -> None:
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("new_service.json"))[0]
    distractor = _events("svc-create-consistent.json")[0].model_copy(
        update={
            "event_id": "evt-same-host-same-time-other-service",
            "target": {"key": "service:csgresearchdistractor"},
            "attributes": {"service_name": "CSGResearchDistractor"},
        }
    )

    result = ReconciliationEngine().reconcile_delta(delta, [distractor])

    assert distractor.host_id == delta.host_id
    assert result.status == ReconciliationStatus.UNEXPLAINED
    assert result.matched_evidence_ids == []


def _scheduled_task_delta(task_name: str = r"\CSG\Research") -> StateDelta:
    observed_at = datetime(2026, 10, 3, 22, 13, tzinfo=UTC)
    object_key = stable_scheduled_task_key({"task_name": task_name})
    return StateDelta(
        host_id="win11-arm-lab",
        category="scheduled_task",
        object_key=object_key,
        delta_type=DeltaType.ADD,
        after=StateObject(
            category="scheduled_task",
            object_key=object_key,
            attributes={"task_name": task_name},
        ),
        observation_window=TimeWindow(start=observed_at, end=observed_at.replace(second=20)),
    )


def test_scheduled_task_event_with_repeated_separators_matches_exact_state_identity() -> None:
    delta = _scheduled_task_delta()
    event = NormalizedEvent(
        event_id="wazuh-scheduled-task-exact",
        host_id=delta.host_id,
        event_time=delta.observation_window.start.replace(second=12),
        normalized_type="scheduled_task_created",
        target={"key": r"scheduled_task:\\CSG\Research"},
        attributes={"task_name": r"\\CSG\Research"},
        source="wazuh",
    )

    result = ReconciliationEngine().reconcile_delta(delta, [event])

    assert delta.object_key == r"scheduled_task:\csg\research"
    assert stable_scheduled_task_key({"task_name": r"\\CSG\Research"}) == delta.object_key
    assert result.status == ReconciliationStatus.CONSISTENT
    assert result.matched_evidence_ids == [event.event_id]


def test_scheduled_task_event_time_bound_covers_measured_pre_observation_lag() -> None:
    delta = _scheduled_task_delta()
    event = NormalizedEvent(
        event_id="wazuh-scheduled-task-observed-before-probe",
        host_id=delta.host_id,
        event_time=delta.observation_window.start.replace(second=0) - timedelta(seconds=14),
        normalized_type="scheduled_task_created",
        target={"key": r"scheduled_task:\\CSG\Research"},
        attributes={"task_name": r"\\CSG\Research"},
        source="wazuh",
    )

    calibrated = ReconciliationEngine(event_time_tolerance_seconds=20).reconcile_delta(
        delta, [event]
    )
    legacy = ReconciliationEngine(event_time_tolerance_seconds=5).reconcile_delta(delta, [event])

    assert calibrated.status == ReconciliationStatus.CONSISTENT
    assert calibrated.matched_evidence_ids == [event.event_id]
    assert legacy.status == ReconciliationStatus.UNEXPLAINED
    assert legacy.matched_evidence_ids == []


def test_scheduled_task_normalization_does_not_match_wrong_task() -> None:
    delta = _scheduled_task_delta()
    distractor = NormalizedEvent(
        event_id="wazuh-scheduled-task-distractor",
        host_id=delta.host_id,
        event_time=delta.observation_window.start.replace(second=12),
        normalized_type="scheduled_task_created",
        target={"key": r"scheduled_task:\\CSG\Other"},
        attributes={"task_name": r"\\CSG\Other"},
        source="wazuh",
    )

    result = ReconciliationEngine().reconcile_delta(delta, [distractor])

    assert result.status == ReconciliationStatus.UNEXPLAINED
    assert result.matched_evidence_ids == []


def _privileged_group_delta(
    *, member: str = "win-host/csgresearchuser", sid: str = "S-1-5-21-1-2-3-1002"
) -> StateDelta:
    observed_at = datetime(2026, 10, 16, 17, 16, 9, tzinfo=UTC)
    object_key = f"privileged_group:administrators:{member}"
    return StateDelta(
        host_id="win11-arm-lab",
        category="privileged_group",
        object_key=object_key,
        delta_type=DeltaType.ADD,
        after=StateObject(
            category="privileged_group",
            object_key=object_key,
            attributes={"group": "Administrators", "member": member, "sid": sid},
        ),
        observation_window=TimeWindow(
            start=observed_at - timedelta(seconds=5),
            end=observed_at + timedelta(seconds=5),
        ),
    )


def _privileged_group_event(**overrides) -> NormalizedEvent:
    values = {
        "event_id": "wazuh-group-event-exact-sid",
        "host_id": "win11-arm-lab",
        "event_time": datetime(2026, 10, 16, 17, 16, 7, tzinfo=UTC),
        "normalized_type": "privileged_group_member_added",
        "target": {
            "group": "Administrators",
            "member_sid": "S-1-5-21-1-2-3-1002",
        },
        "attributes": {
            "event_code": "4732",
            "group": "Administrators",
            "member_sid": "S-1-5-21-1-2-3-1002",
        },
        "source": "wazuh",
    }
    values.update(overrides)
    return NormalizedEvent(**values)


def test_privileged_group_event_matches_exact_group_and_member_sid() -> None:
    delta = _privileged_group_delta()
    event = _privileged_group_event()

    result = ReconciliationEngine().reconcile_delta(delta, [event])

    assert result.status == ReconciliationStatus.CONSISTENT
    assert result.matched_evidence_ids == [event.event_id]


def test_privileged_group_event_with_wrong_member_sid_does_not_match() -> None:
    delta = _privileged_group_delta()
    distractor = _privileged_group_event(
        event_id="wazuh-group-event-wrong-sid",
        target={"group": "Administrators", "member_sid": "S-1-5-21-1-2-3-9999"},
        attributes={
            "event_code": "4732",
            "group": "Administrators",
            "member_sid": "S-1-5-21-1-2-3-9999",
        },
    )

    result = ReconciliationEngine().reconcile_delta(delta, [distractor])

    assert result.status == ReconciliationStatus.UNEXPLAINED
    assert result.matched_evidence_ids == []


def test_privileged_group_event_with_wrong_group_does_not_match_even_with_exact_sid() -> None:
    delta = _privileged_group_delta()
    distractor = _privileged_group_event(
        event_id="wazuh-group-event-wrong-group",
        target={"group": "Remote Desktop Users", "member_sid": "S-1-5-21-1-2-3-1002"},
        attributes={
            "event_code": "4732",
            "group": "Remote Desktop Users",
            "member_sid": "S-1-5-21-1-2-3-1002",
        },
    )

    result = ReconciliationEngine().reconcile_delta(delta, [distractor])

    assert result.status == ReconciliationStatus.UNEXPLAINED
    assert result.matched_evidence_ids == []


def test_privileged_group_member_name_is_exactly_matched_and_sid_must_not_conflict() -> None:
    delta = _privileged_group_delta()
    event = _privileged_group_event(
        target={
            "key": delta.object_key,
            "group": "Administrators",
            "member": "WIN-HOST\\CSGResearchUser",
            "member_sid": "S-1-5-21-1-2-3-1002",
        },
        attributes={
            "group": "Administrators",
            "member": "WIN-HOST\\CSGResearchUser",
            "member_sid": "S-1-5-21-1-2-3-1002",
        },
    )

    assert ReconciliationEngine().event_matches_delta(event, delta)
    assert not ReconciliationEngine().event_matches_delta(
        event.model_copy(
            update={"attributes": {**event.attributes, "member_sid": "S-1-5-21-1-2-3-9999"}}
        ),
        delta,
    )


def _listener_delta(address: str = "127.0.0.1", port: int = 47474) -> StateDelta:
    observed_at = datetime(2026, 10, 3, 22, 13, tzinfo=UTC)
    attributes = {"protocol": "tcp", "local_address": address, "local_port": port}
    object_key = stable_listener_key(attributes)
    return StateDelta(
        host_id="win11-arm-lab",
        category="listener",
        delta_type=DeltaType.ADD,
        object_key=object_key,
        after=StateObject(
            category="listener",
            object_key=object_key,
            attributes=attributes,
        ),
        observation_window=TimeWindow(
            start=observed_at,
            end=observed_at + timedelta(seconds=20),
        ),
    )


def _listener_event(attributes: dict[str, object]) -> NormalizedEvent:
    observed_at = datetime(2026, 10, 3, 22, 13, 12, tzinfo=UTC)
    target = (
        {"key": stable_listener_key(attributes)}
        if all(attributes.get(key) for key in ("protocol", "local_address", "local_port"))
        else {}
    )
    return NormalizedEvent(
        event_id="wazuh-listener-network-event",
        host_id="win11-arm-lab",
        event_time=observed_at,
        normalized_type="network_activity",
        target=target,
        attributes=attributes,
        source="wazuh",
    )


def test_listener_event_requires_exact_protocol_address_and_port() -> None:
    delta = _listener_delta()
    engine = ReconciliationEngine()
    exact = _listener_event({"protocol": "TCP", "local_address": "127.0.0.1", "local_port": 47474})
    same_port_wrong_address = _listener_event(
        {"protocol": "tcp", "local_address": "0.0.0.0", "local_port": 47474}
    )
    missing_address = _listener_event({"protocol": "tcp", "local_port": 47474})

    assert engine.event_matches_delta(exact, delta)
    assert not engine.event_matches_delta(same_port_wrong_address, delta)
    assert not engine.event_matches_delta(missing_address, delta)


def test_wfp_listener_permitted_event_reconciles_exact_listener_endpoint() -> None:
    delta = _listener_delta(port=49389)
    event = NormalizedEvent(
        event_id="wazuh-wfp-5154-178250",
        host_id="win11-arm-lab",
        event_time=datetime(2026, 10, 3, 22, 13, 12, tzinfo=UTC),
        normalized_type="listener_created",
        target={"key": delta.object_key},
        attributes={
            "event_code": "5154",
            "protocol": "tcp",
            "local_address": "127.0.0.1",
            "local_port": 49389,
        },
        source="wazuh",
    )

    result = ReconciliationEngine().reconcile_delta(delta, [event])

    assert result.status == ReconciliationStatus.CONSISTENT
    assert result.matched_evidence_ids == ["wazuh-wfp-5154-178250"]


def _registry_delta() -> StateDelta:
    observation_time = datetime(2026, 10, 3, 22, 13, tzinfo=UTC)
    key = (
        "registry:hku/s-1-5-21-100-200-300-1001/software/microsoft/windows/"
        "currentversion/run/csgaptrun1234567890"
    )
    return StateDelta(
        host_id="win11-arm-lab",
        category="registry",
        object_key=key,
        delta_type=DeltaType.ADD,
        after=StateObject(
            category="registry",
            object_key=key,
            attributes={"name": "CSGAPTRun1234567890", "state_type": "autorun"},
        ),
        observation_window=TimeWindow(
            start=observation_time,
            end=observation_time.replace(second=20),
        ),
    )


def test_exact_sysmon_registry_target_explains_probe_delta() -> None:
    delta = _registry_delta()
    event = NormalizedEvent(
        event_id="wazuh-exact-registry-event",
        host_id=delta.host_id,
        event_time=datetime(2026, 10, 3, 22, 13, 12, tzinfo=UTC),
        normalized_type="registry_value_modified",
        target={"key": delta.object_key},
        attributes={
            "target_object": (
                r"HKU\\S-1-5-21-100-200-300-1001\\Software\\Microsoft\\Windows"
                r"\\CurrentVersion\\Run\\CSGAPTRun1234567890"
            )
        },
        source="wazuh",
        metadata={"source_kind": "wazuh_archive"},
    )

    result = ReconciliationEngine().reconcile_delta(delta, [event])

    assert result.status == ReconciliationStatus.CONSISTENT
    assert result.matched_evidence_ids == [event.event_id]


def test_registry_value_must_match_observed_after_state() -> None:
    delta = _registry_delta()
    delta = delta.model_copy(
        update={
            "after": delta.after.model_copy(
                update={
                    "attributes": {
                        **delta.after.attributes,
                        "value": r"C:\Windows\System32\cmd.exe /c exit 0",
                    }
                }
            )
        }
    )
    event = NormalizedEvent(
        event_id="wazuh-conflicting-registry-value",
        host_id=delta.host_id,
        event_time=delta.observation_window.start,
        normalized_type="registry_value_modified",
        target={"key": delta.object_key},
        attributes={
            "event_type": "SetValue",
            "details": r"C:\\Windows\\System32\\cmd.exe /c exit 1",
        },
        source="wazuh",
    )

    compatible_event = event.model_copy(
        update={
            "attributes": {
                **event.attributes,
                "details": r"C:\\Windows\\System32\\cmd.exe /c exit 0",
            }
        }
    )
    compatible = ReconciliationEngine().reconcile_delta(delta, [compatible_event])
    result = ReconciliationEngine().reconcile_delta(delta, [event])

    assert compatible.status == ReconciliationStatus.CONSISTENT
    assert compatible.matched_evidence_ids == [event.event_id]
    assert result.status == ReconciliationStatus.UNEXPLAINED
    assert result.matched_evidence_ids == []
    assert result.metadata["transition_mismatches"][0]["event_id"] == event.event_id


def test_duplicate_stable_event_id_is_not_counted_twice_or_order_dependent() -> None:
    delta = _registry_delta()
    event = NormalizedEvent(
        event_id="wazuh-duplicate-registry-event",
        host_id=delta.host_id,
        event_time=delta.observation_window.start,
        normalized_type="registry_value_modified",
        target={"key": delta.object_key},
        source="wazuh",
    )

    first = ReconciliationEngine().reconcile_delta(delta, [event, event.model_copy()])
    reordered = ReconciliationEngine().reconcile_delta(delta, [event.model_copy(), event])

    assert first.matched_evidence_ids == [event.event_id]
    assert reordered.matched_evidence_ids == [event.event_id]
    assert first.metadata["duplicate_event_ids"] == [event.event_id]
    assert reordered.metadata["duplicate_event_ids"] == [event.event_id]


def test_alert_archive_aliases_for_one_windows_record_match_once_and_keep_provenance() -> None:
    delta = _scheduled_task_delta(r"\CSGAPTTaske572105078")
    identity = {
        "agent_id": "001",
        "channel": "security",
        "event_record_id": "158739",
        "event_code": "4698",
        "provider_name": "microsoft-windows-security-auditing",
    }
    alert = NormalizedEvent(
        event_id="wazuh-alert-record-158739",
        host_id=delta.host_id,
        event_time=delta.observation_window.start,
        normalized_type="scheduled_task_created",
        target={"key": delta.object_key},
        attributes={"task_name": r"\CSGAPTTaske572105078"},
        source="wazuh",
        source_reference={"index": "wazuh-alerts-4.x-test", "document_id": "alert-1"},
        metadata={"windows_event_identity": identity},
    )
    archive = alert.model_copy(
        update={
            "event_id": "wazuh-archive-record-158739",
            "source_reference": {"index": "wazuh-archives-4.x-test", "document_id": "archive-1"},
        }
    )

    result = ReconciliationEngine().reconcile_delta(delta, [archive, alert])

    assert result.status == ReconciliationStatus.CONSISTENT
    assert result.matched_evidence_ids == [alert.event_id]
    assert result.metadata["deduplicated_windows_event_aliases"] == [
        {
            "canonical_event_id": alert.event_id,
            "alias_event_ids": [archive.event_id],
            "source_references": [
                {"event_id": alert.event_id, **alert.source_reference},
                {"event_id": archive.event_id, **archive.source_reference},
            ],
        }
    ]


def test_conflicting_targets_with_same_windows_identity_are_not_reconciled() -> None:
    delta = _scheduled_task_delta(r"\CSGAPTTaske572105078")
    identity = {
        "agent_id": "001",
        "channel": "security",
        "event_record_id": "158739",
        "event_code": "4698",
        "provider_name": "microsoft-windows-security-auditing",
    }
    exact = NormalizedEvent(
        event_id="wazuh-alert-record-158739",
        host_id=delta.host_id,
        event_time=delta.observation_window.start,
        normalized_type="scheduled_task_created",
        target={"key": delta.object_key},
        source="wazuh",
        metadata={"windows_event_identity": identity},
    )
    conflicting = exact.model_copy(
        update={
            "event_id": "wazuh-archive-record-158739",
            "target": {"key": "scheduled_task:other"},
        }
    )

    result = ReconciliationEngine().reconcile_delta(delta, [exact, conflicting])

    assert result.status == ReconciliationStatus.UNEXPLAINED
    assert result.matched_evidence_ids == []
    assert result.metadata["conflicting_windows_event_identity_ids"] == sorted(
        [exact.event_id, conflicting.event_id]
    )


def test_conflicting_payloads_with_same_event_id_are_excluded() -> None:
    delta = _registry_delta()
    event = NormalizedEvent(
        event_id="wazuh-colliding-registry-event-id",
        host_id=delta.host_id,
        event_time=delta.observation_window.start,
        normalized_type="registry_value_modified",
        target={"key": delta.object_key},
        source="wazuh",
    )
    conflict = event.model_copy(update={"target": {"key": "registry:other-value"}})

    result = ReconciliationEngine().reconcile_delta(delta, [event, conflict])

    assert result.status == ReconciliationStatus.UNEXPLAINED
    assert result.matched_evidence_ids == []
    assert result.metadata["conflicting_event_identity_ids"] == [event.event_id]


def test_same_host_same_time_same_type_wrong_registry_target_is_distractor() -> None:
    delta = _registry_delta()
    event = NormalizedEvent(
        event_id="wazuh-other-registry-event",
        host_id=delta.host_id,
        event_time=datetime(2026, 10, 3, 22, 13, 12, tzinfo=UTC),
        normalized_type="registry_value_modified",
        target={"key": delta.object_key.removesuffix("csgaptrun1234567890") + "another-run-value"},
        attributes={
            "target_object": (
                r"HKU\S-1-5-21-100-200-300-1001\Software\Microsoft\Windows"
                r"\CurrentVersion\Run\AnotherRunValue"
            )
        },
        source="wazuh",
    )

    result = ReconciliationEngine().reconcile_delta(delta, [event])

    assert event.host_id == delta.host_id
    assert result.status == ReconciliationStatus.UNEXPLAINED
    assert result.matched_evidence_ids == []


def test_service_display_name_alone_does_not_explain_native_service_delta() -> None:
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("new_service.json"))[0]
    event = _events("svc-create-consistent.json")[0].model_copy(
        update={
            "target": {"key": "service:display-name"},
            "attributes": {"service_name": "Display Name"},
        }
    )
    aliased_delta = delta.model_copy(
        update={
            "after": delta.after.model_copy(
                update={
                    "attributes": {
                        "service_name": "internal_name",
                        "display_name": "Display Name",
                    }
                }
            )
        }
    )

    result = ReconciliationEngine().reconcile_delta(aliased_delta, [event])

    assert result.status == ReconciliationStatus.UNEXPLAINED
    assert result.matched_evidence_ids == []


def test_wrong_event_type_with_matching_key_is_not_supporting_evidence() -> None:
    delta = DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("new_service.json"))[0]
    event = _events("svc-create-consistent.json")[0].model_copy(
        update={"normalized_type": "wazuh_alert"}
    )
    result = ReconciliationEngine().reconcile_delta(delta, [event])
    assert result.status == ReconciliationStatus.UNEXPLAINED


def test_service_modify_requires_matching_before_and_after_start_mode() -> None:
    delta = next(
        item
        for item in DeltaEngine().diff(
            _snapshot("baseline.json"), _snapshot("modified_service.json")
        )
        if item.category == "service"
    )
    event = NormalizedEvent(
        event_id="evt-service-modify-wrong-transition",
        host_id=delta.host_id,
        event_time=datetime(2026, 9, 13, 20, 14, 30, tzinfo=UTC),
        normalized_type="service_modified",
        target={"key": delta.object_key},
        attributes={
            "service_name": "EventLog",
            "old_start_mode": "auto start",
            "new_start_mode": "manual start",
        },
        source="synthetic_fixture",
    )
    correct_event = event.model_copy(
        update={
            "event_id": "evt-service-modify-correct-transition",
            "attributes": {
                **event.attributes,
                "new_start_mode": "disabled start",
            },
        }
    )

    consistent = ReconciliationEngine(event_time_tolerance_seconds=5).reconcile_delta(
        delta, [correct_event]
    )
    assert consistent.status == ReconciliationStatus.CONSISTENT

    result = ReconciliationEngine(event_time_tolerance_seconds=5).reconcile_delta(delta, [event])

    assert result.status == ReconciliationStatus.UNEXPLAINED
    assert result.matched_evidence_ids == []
    assert result.metadata["transition_mismatches"] == [
        {
            "event_id": "evt-service-modify-wrong-transition",
            "event_type": "service_modified",
            "reason": "same object and operation type but incompatible transition",
        }
    ]


def test_service_modify_matches_windows_demand_start_to_probe_manual() -> None:
    delta = next(
        item
        for item in DeltaEngine().diff(
            _snapshot("baseline.json"), _snapshot("modified_service.json")
        )
        if item.category == "service"
    )
    delta = delta.model_copy(
        update={
            "before": delta.before.model_copy(
                update={"attributes": {**delta.before.attributes, "start_mode": "Manual"}}
            ),
            "after": delta.after.model_copy(
                update={"attributes": {**delta.after.attributes, "start_mode": "Auto"}}
            ),
        }
    )
    event = NormalizedEvent(
        event_id="evt-service-modify-windows-alias",
        host_id=delta.host_id,
        event_time=datetime(2026, 9, 13, 20, 14, 30, tzinfo=UTC),
        normalized_type="service_modified",
        target={"key": delta.object_key},
        attributes={
            "service_name": "EventLog",
            "old_start_mode": "demand start",
            "new_start_mode": "auto start",
        },
        source="synthetic_fixture",
    )

    result = ReconciliationEngine(event_time_tolerance_seconds=5).reconcile_delta(delta, [event])

    assert result.status == ReconciliationStatus.CONSISTENT
    assert result.matched_evidence_ids == [event.event_id]


def test_event_window_uses_snapshot_interval_plus_tolerance() -> None:
    delta = next(
        item
        for item in DeltaEngine().diff(_snapshot("baseline.json"), _snapshot("new_service.json"))
        if item.category == "service"
    )
    window = ReconciliationEngine(event_time_tolerance_seconds=5).observation_window_for_delta(
        delta
    )

    assert window.start == datetime(2026, 9, 13, 19, 59, 55, tzinfo=UTC)
    assert window.end == datetime(2026, 9, 13, 20, 15, 5, tzinfo=UTC)
