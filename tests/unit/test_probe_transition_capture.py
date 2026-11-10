from __future__ import annotations

from datetime import UTC, datetime, timedelta

from csg.state.normalize import stable_object_key
from cyberstateguardian_probe.config import ProbeSettings
from cyberstateguardian_probe.transition_capture import (
    CategoryPollingMonitor,
    TransitionCaptureManager,
    WindowsProcessLifecycleMonitor,
    _object_key,
)
from cyberstateguardian_probe.transition_transport import (
    DurableTransitionTransport,
    transition_endpoint,
)


def test_probe_transition_keys_match_authoritative_snapshot_keys() -> None:
    samples = {
        "service": {"service_name": "CSGResearchSvc"},
        "scheduled_task": {"task_name": "\\CSG\\Research"},
        "privileged_group": {"group": "Administrators", "member": "LAB\\Analyst"},
        "listener": {"protocol": "TCP", "local_address": "127.0.0.1", "local_port": 8443},
        "process": {
            "name": "cmd.exe",
            "executable_path": "C:\\Windows\\System32\\cmd.exe",
            "username": "NT AUTHORITY\\SYSTEM",
            "create_time": "2026-10-04T18:00:00+00:00",
        },
        "registry": {"object_key": "registry:HKLM:\\Software\\Microsoft\\Windows\\Run/Research"},
    }
    for category, item in samples.items():
        assert _object_key(category, item) == stable_object_key(category, item)


def test_scoped_monitor_emits_exact_service_modify_and_stable_identity(monkeypatch) -> None:
    t0 = datetime(2026, 10, 4, 18, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=5)
    now_values = iter([t0, t0, t1, t1, t1])
    monkeypatch.setattr(
        "cyberstateguardian_probe.transition_capture._now", lambda: next(now_values)
    )
    submitted = []
    state = {"start_mode": "Manual", "status": "Stopped", "service_name": "ResearchSvc"}
    monkeypatch.setattr(
        "cyberstateguardian_probe.transition_capture.collectors.collect_services",
        lambda: {"status": "healthy", "items": [dict(state)]},
    )
    monitor = CategoryPollingMonitor(
        host_id="win-lab",
        category="service",
        interval_seconds=5,
        submit=lambda batch: submitted.append(batch) or True,
    )

    monitor._sample()
    state["start_mode"] = "Automatic"
    monitor._sample()

    record = submitted[-1]["records"][0]
    assert record["object_key"] == "service:researchsvc"
    assert record["transition_type"] == "SERVICE_START_MODE_CHANGED"
    assert record["changed_fields"] == ["start_mode"]
    assert record["old_state"]["start_mode"] == "Manual"
    assert record["new_state"]["start_mode"] == "Automatic"
    assert record["window_start"] == t0.isoformat().replace("+00:00", "Z")


def test_category_poll_failure_preserves_baseline_and_reports_degraded_health(monkeypatch) -> None:
    submitted = []
    results = iter(
        [
            {
                "status": "healthy",
                "items": [{"service_name": "ResearchSvc", "start_mode": "Manual"}],
            },
            {"status": "error", "items": [], "message": "temporary access error"},
        ]
    )
    monkeypatch.setattr(
        "cyberstateguardian_probe.transition_capture.collectors.collect_services",
        lambda: next(results),
    )
    monitor = CategoryPollingMonitor(
        host_id="win-lab",
        category="service",
        interval_seconds=5,
        submit=lambda batch: submitted.append(batch) or True,
    )

    monitor._sample()
    baseline = dict(monitor.states)
    monitor._sample()

    assert monitor.states == baseline
    assert monitor.status == "DEGRADED"
    assert submitted[-1]["monitor_health"][0]["baseline_established"] is True
    assert submitted[-1]["monitor_health"][0]["message"] == "temporary access error"


def test_capture_manager_creates_only_opted_in_monitors() -> None:
    settings = ProbeSettings(
        CSG_TRANSITION_CAPTURE_ENABLED=True,
        CSG_TRANSITION_SERVICES_ENABLED=True,
        CSG_TRANSITION_PROCESSES_ENABLED=True,
        CSG_TRANSITION_POLL_INTERVAL_SECONDS=7,
    )
    manager = TransitionCaptureManager(settings, lambda _: True)

    assert {monitor.category for monitor in manager.monitors} == {"service", "process"}
    service_monitor = next(m for m in manager.monitors if m.category == "service")
    assert service_monitor.interval_seconds == 7
    assert settings.transition_capture_enabled is True
    assert ProbeSettings(_env_file=None).transition_capture_enabled is False


def test_process_lifecycle_monitor_reports_offline_outside_windows(monkeypatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    submitted = []
    monitor = WindowsProcessLifecycleMonitor(
        host_id="win-lab",
        submit=lambda batch: submitted.append(batch) or True,
    )

    monitor.start()

    health = submitted[0]["monitor_health"][0]
    assert health["status"] == "OFFLINE"
    assert "unavailable" in health["message"]


def test_process_wmi_transitions_preserve_snapshot_identity_and_start_exit_pair(
    monkeypatch,
) -> None:
    submitted = []
    created = "2026-10-04T18:00:00+00:00"
    state = {
        "pid": 3021,
        "ppid": 912,
        "name": "Research.exe",
        "executable_path": "c:/lab/research.exe",
        "username": "lab/analyst",
        "create_time": created,
    }
    monkeypatch.setattr(
        WindowsProcessLifecycleMonitor,
        "_read_process",
        staticmethod(lambda _: dict(state)),
    )
    monkeypatch.setattr(
        "cyberstateguardian_probe.transition_capture._now",
        lambda: datetime(2026, 10, 4, 18, 0, 2, tzinfo=UTC),
    )
    monitor = WindowsProcessLifecycleMonitor(
        host_id="win-lab",
        submit=lambda batch: submitted.append(batch) or True,
    )
    monitor.coverage_start = datetime(2026, 10, 4, 17, 59, 59, tzinfo=UTC)
    monitor.status = "HEALTHY"

    monitor._handle(
        {
            "kind": "PROCESS_START",
            "pid": 3021,
            "ppid": 912,
            "name": "Research.exe",
            "source_time": "2026-10-04T18:00:01Z",
        }
    )
    monitor._handle(
        {
            "kind": "PROCESS_EXIT",
            "pid": 3021,
            "ppid": 912,
            "name": "Research.exe",
            "source_time": "2026-10-04T18:00:03Z",
        }
    )

    start, exit_record = [batch["records"][0] for batch in submitted]
    assert start["object_key"] == stable_object_key("process", state)
    assert start["transition_type"] == "PROCESS_START"
    assert exit_record["object_key"] == start["object_key"]
    assert exit_record["transition_type"] == "PROCESS_EXIT"
    assert exit_record["old_state"] == state
    assert monitor.processes == {}


def test_process_filters_are_auditable_and_exclude_wins(monkeypatch) -> None:
    submitted = []
    state = {
        "pid": 3021,
        "ppid": 912,
        "name": "Research.exe",
        "executable_path": "c:/lab/research.exe",
        "username": "lab/analyst",
        "create_time": "2026-10-04T18:00:00+00:00",
    }
    monkeypatch.setattr(
        WindowsProcessLifecycleMonitor,
        "_read_process",
        staticmethod(lambda _: dict(state)),
    )
    monitor = WindowsProcessLifecycleMonitor(
        host_id="win-lab",
        submit=lambda batch: submitted.append(batch) or True,
        include_patterns=["*.exe"],
        exclude_patterns=["research.exe"],
    )
    monitor.coverage_start = datetime(2026, 10, 4, 17, 59, 59, tzinfo=UTC)
    monitor.status = "HEALTHY"

    monitor._handle(
        {
            "kind": "PROCESS_START",
            "pid": 3021,
            "ppid": 912,
            "name": "Research.exe",
            "source_time": "2026-10-04T18:00:01Z",
        }
    )

    assert submitted == []
    assert monitor.filtered_transition_count == 1
    assert monitor.processes[3021] == state


def test_transition_endpoint_is_derived_without_changing_query_parameters() -> None:
    assert transition_endpoint("http://lab:8000/api/probe/observations?source=probe") == (
        "http://lab:8000/api/probe/transitions?source=probe"
    )


def test_durable_spool_retains_failed_upload_then_removes_after_success(
    tmp_path, monkeypatch
) -> None:
    import requests

    spool = tmp_path / "transition.jsonl"
    transport = DurableTransitionTransport(
        api_url="http://lab/api/probe/transitions",
        token="test-token",
        spool_path=spool,
        max_spool_bytes=100_000,
        timeout_seconds=1,
        max_retries=1,
    )
    batch = {"host_id": "win-lab", "records": [{"transition_id": "stable-id"}]}

    def unavailable(*args, **kwargs):
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(requests, "post", unavailable)
    assert transport.submit(batch) is True
    assert transport.flush_one() is False
    assert spool.read_text().count("stable-id") == 1

    class Response:
        ok = True

    calls = []
    monkeypatch.setattr(requests, "post", lambda *a, **k: calls.append((a, k)) or Response())
    assert transport.flush_one() is False
    assert spool.read_bytes() == b""
    assert transport.metrics["batches_sent"] == 1
    assert calls[0][1]["headers"]["Authorization"] == "Bearer test-token"


def test_spool_full_refuses_batch_without_overwriting_existing_data(tmp_path) -> None:
    spool = tmp_path / "transition.jsonl"
    transport = DurableTransitionTransport(
        api_url="http://lab/api/probe/transitions",
        token="test-token",
        spool_path=spool,
        max_spool_bytes=10,
        timeout_seconds=1,
        max_retries=1,
    )
    assert transport.submit({"records": ["this record exceeds the spool limit"]}) is False
    assert not spool.exists()
    assert transport.metrics["spool_full_batches"] == 1
