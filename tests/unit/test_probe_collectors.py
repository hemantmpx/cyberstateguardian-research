from __future__ import annotations

import pytest

from cyberstateguardian_probe.collectors.listeners import collect_listeners
from cyberstateguardian_probe.collectors.privileged_groups import collect_privileged_groups
from cyberstateguardian_probe.collectors.registry import collect_registry_security_state
from cyberstateguardian_probe.collectors.scheduled_tasks import collect_scheduled_tasks

psutil = pytest.importorskip("psutil")


def test_listener_collector_reports_access_denied(monkeypatch) -> None:
    def deny_connections(kind: str):
        raise psutil.AccessDenied(pid=123)

    monkeypatch.setattr(psutil, "net_connections", deny_connections)

    result = collect_listeners()

    assert result["category"] == "listener"
    assert result["status"] == "error"
    assert result["items"] == []
    assert "elevated permissions" in result["message"]


def test_windows_scheduled_task_collector_normalizes_rows(monkeypatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "cyberstateguardian_probe.collectors.scheduled_tasks.run_powershell_json",
        lambda _script: [
            {
                "TaskName": "\\Lab\\Updater",
                "State": "Ready",
                "Author": "LAB\\Admin",
                "Principal": "SYSTEM",
                "Actions": "C:\\Lab\\update.exe -quiet",
            }
        ],
    )

    result = collect_scheduled_tasks()

    assert result["status"] == "healthy"
    assert result["items"][0]["task_name"] == "\\Lab\\Updater"
    assert result["items"][0]["actions"] == ["c:/lab/update.exe -quiet"]


def test_windows_privileged_group_collector_normalizes_member(monkeypatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "cyberstateguardian_probe.collectors.privileged_groups.run_powershell_json",
        lambda _script: [{"Group": "Administrators", "Member": "LAB\\Analyst"}],
    )

    result = collect_privileged_groups()

    assert result["status"] == "healthy"
    assert result["items"][0]["member"] == "lab/analyst"


def test_windows_registry_collector_preserves_stable_object_key(monkeypatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "cyberstateguardian_probe.collectors.registry.run_powershell_json",
        lambda _script: [
            {
                "ObjectKey": (
                    "registry:HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/Updater"
                ),
                "StateType": "autorun",
                "Path": "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Name": "Updater",
                "Value": "C:\\Lab\\update.exe",
            }
        ],
    )

    result = collect_registry_security_state()

    assert result["status"] == "healthy"
    assert result["items"][0]["object_key"].startswith("registry:hklm:/software")


def test_windows_current_user_registry_key_uses_sid_hive(monkeypatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "cyberstateguardian_probe.collectors.registry.run_powershell_json",
        lambda _script: [
            {
                "ObjectKey": (
                    "registry:HKU:\\S-1-5-21-100-200-300-1001\\Software\\"
                    "Microsoft\\Windows\\CurrentVersion\\Run/Updater"
                ),
                "StateType": "autorun",
                "Path": "HKU:\\S-1-5-21-100-200-300-1001\\Software\\Microsoft\\"
                "Windows\\CurrentVersion\\Run",
                "Name": "Updater",
                "Value": "C:\\Lab\\update.exe",
            }
        ],
    )

    result = collect_registry_security_state()

    assert result["status"] == "healthy"
    assert result["items"][0]["object_key"].startswith(
        "registry:hku:/s-1-5-21-100-200-300-1001/"
    )


def test_defender_access_failure_is_partial_not_healthy(monkeypatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "cyberstateguardian_probe.collectors.registry.run_powershell_json",
        lambda _script: [{"CollectorError": "Defender preferences: access denied"}],
    )
    result = collect_registry_security_state()
    assert result["status"] == "partial"
    assert result["items"] == []
    assert "access denied" in result["message"]
