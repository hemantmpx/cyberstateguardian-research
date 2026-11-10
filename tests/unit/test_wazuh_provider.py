from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest

from csg.config import Settings
from csg.providers.wazuh import WazuhConfig, WazuhEventProvider, WazuhStateProvider
from csg.services.wazuh_status import WazuhStatusService


class FakeWazuhClient:
    def __init__(self, config: WazuhConfig) -> None:
        self.config = config

    async def __aenter__(self) -> FakeWazuhClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None

    async def indexer_search(self, index_pattern: str, _body: dict[str, Any]) -> dict[str, Any]:
        return WAZUH_PAYLOADS[index_pattern]

    async def indexer_get(self, _path: str = "/") -> dict[str, Any]:
        return {
            "cluster_name": "wazuh-cluster",
            "cluster_uuid": "test-cluster",
            "version": {"number": "4.14.7"},
        }

    async def list_agents(self) -> list[dict[str, Any]]:
        return [
            {"id": "000", "name": "wazuh.manager", "status": "active"},
            {
                "id": "001",
                "name": "win11-arm-lab",
                "ip": "10.0.0.20",
                "status": "active",
                "os": {"name": "Windows 11"},
            },
        ]


class RecordingWazuhClient(FakeWazuhClient):
    last_instance: RecordingWazuhClient | None = None

    def __init__(self, config: WazuhConfig) -> None:
        super().__init__(config)
        self.searches: list[tuple[str, dict[str, Any]]] = []
        type(self).last_instance = self

    async def indexer_search(
        self,
        index_pattern: str,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        self.searches.append((index_pattern, body))
        return await super().indexer_search(index_pattern, body)


def _config() -> WazuhConfig:
    return WazuhConfig(
        api_url="https://wazuh.example:55000",
        indexer_url="https://wazuh.example:9200",
        api_user="wazuh",
        api_password="test-api-password",
        indexer_user="admin",
        indexer_password="test-indexer-password",
    )


WAZUH_PAYLOADS: dict[str, dict[str, Any]] = {
    "wazuh-states-inventory-processes-*": {
        "hits": {
            "hits": [
                {
                    "_index": "wazuh-states-inventory-processes-win11-arm-lab",
                    "_id": "process-1",
                    "_source": {
                        "@timestamp": "2026-09-14T10:00:00Z",
                        "agent": {
                            "id": "001",
                            "name": "win11-arm-lab",
                            "ip": "10.0.0.20",
                            "os": {"name": "Windows 11"},
                            "architecture": "arm64",
                        },
                        "process": {
                            "pid": 4900,
                            "name": "powershell.exe",
                            "executable": (
                                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                            ),
                            "command_line": "powershell.exe -NoProfile",
                            "parent": {"pid": 840},
                            "user": {"name": "LAB\\analyst"},
                        },
                    },
                }
            ]
        }
    },
    "wazuh-states-inventory-ports-*": {
        "hits": {
            "hits": [
                {
                    "_index": "wazuh-states-inventory-ports-win11-arm-lab",
                    "_id": "port-1",
                    "_source": {
                        "@timestamp": "2026-09-14T10:00:00Z",
                        "agent": {"id": "001", "name": "win11-arm-lab"},
                        "local": {"ip": "0.0.0.0", "port": 8080},
                        "protocol": "tcp",
                        "state": "listening",
                        "process": "python.exe",
                        "pid": 3200,
                    },
                }
            ]
        }
    },
    "wazuh-states-inventory-services-*": {
        "hits": {
            "hits": [
                {
                    "_index": "wazuh-states-inventory-services-win11-arm-lab",
                    "_id": "service-1",
                    "_source": {
                        "@timestamp": "2026-09-14T10:00:00Z",
                        "agent": {"id": "001", "name": "win11-arm-lab"},
                        "service": {
                            "name": "Spooler",
                            "display_name": "Print Spooler",
                            "state": "running",
                            "start_type": "auto",
                            "path": "C:\\Windows\\System32\\spoolsv.exe",
                            "account": "LocalSystem",
                        },
                    },
                }
            ]
        }
    },
    "wazuh-alerts-*": {
        "hits": {
            "hits": [
                {
                    "_index": "wazuh-alerts-4.x-2026.09.14",
                    "_id": "alert-7045",
                    "_source": {
                        "@timestamp": "2026-09-14T10:05:00Z",
                        "agent": {"id": "001", "name": "win11-arm-lab"},
                        "rule": {
                            "id": "61138",
                            "level": 12,
                            "description": "Windows service installed.",
                        },
                        "data": {
                            "win": {
                                "system": {
                                    "eventID": "7045",
                                    "providerName": "Service Control Manager",
                                },
                                "eventdata": {
                                    "ServiceName": "SystemUpdate",
                                    "ImagePath": "C:\\ProgramData\\SystemUpdate\\systemupdate.exe",
                                    "StartType": "auto start",
                                    "AccountName": "LocalSystem",
                                },
                            }
                        },
                    },
                }
            ]
        }
    },
}


@pytest.mark.asyncio
async def test_wazuh_state_provider_normalizes_inventory_snapshot() -> None:
    provider = WazuhStateProvider(_config(), client_factory=FakeWazuhClient)
    snapshot = await provider.get_snapshot("001")

    assert snapshot.source == "wazuh"
    assert snapshot.metadata["host"]["hostname"] == "win11-arm-lab"
    assert {status.category: status.status for status in snapshot.category_statuses} == {
        "process": "healthy",
        "listener": "healthy",
        "service": "healthy",
    }
    assert {item.category for item in snapshot.objects} == {"process", "listener", "service"}
    assert "service:spooler" in {item.object_key for item in snapshot.objects}
    assert "listener:tcp:0.0.0.0:8080" in {item.object_key for item in snapshot.objects}


@pytest.mark.asyncio
async def test_wazuh_event_provider_normalizes_service_creation_alert() -> None:
    provider = WazuhEventProvider(_config(), client_factory=FakeWazuhClient)
    events = await provider.get_events(
        "001",
        datetime(2026, 9, 14, 10, 0, tzinfo=UTC),
        datetime(2026, 9, 14, 10, 10, tzinfo=UTC),
    )

    assert len(events) == 1
    event = events[0]
    assert event.source == "wazuh"
    assert event.synthetic is False
    assert event.normalized_type == "service_created"
    assert event.target["key"] == "service:systemupdate"
    assert event.attributes["service_name"] == "SystemUpdate"
    assert event.attributes["binary_path"] == "C:\\ProgramData\\SystemUpdate\\systemupdate.exe"
    query_completed_at = datetime.fromisoformat(event.metadata["retrieval"]["query_completed_at"])
    assert query_completed_at.tzinfo is not None
    assert event.metadata["retrieval"]["complete"] is True


@pytest.mark.asyncio
async def test_wazuh_event_provider_normalizes_camel_case_group_sid_without_fake_member(
    monkeypatch,
) -> None:
    monkeypatch.setitem(
        WAZUH_PAYLOADS,
        "wazuh-alerts-*",
        {
            "hits": {
                "hits": [
                    {
                        "_index": "wazuh-alerts-4.x-2026.10.16",
                        "_id": "event-4732-camel-case",
                        "_source": {
                            "@timestamp": "2026-10-16T17:16:07.594Z",
                            "agent": {"id": "001", "name": "win11-arm-lab"},
                            "rule": {"id": "60154", "level": 12},
                            "data": {
                                "win": {
                                    "system": {
                                        "eventID": "4732",
                                        "eventRecordID": "182963",
                                        "providerName": "Microsoft-Windows-Security-Auditing",
                                        "channel": "Security",
                                    },
                                    "eventdata": {
                                        "targetUserName": "Administrators",
                                        "memberName": "-",
                                        "memberSid": "S-1-5-21-1-2-3-1002",
                                        "subjectUserName": "Hemant",
                                    },
                                }
                            },
                        },
                    }
                ]
            }
        },
    )
    provider = WazuhEventProvider(_config(), client_factory=FakeWazuhClient)

    events = await provider.get_events(
        "001",
        datetime(2026, 10, 16, 17, 16, tzinfo=UTC),
        datetime(2026, 10, 16, 17, 17, tzinfo=UTC),
    )

    assert len(events) == 1
    event = events[0]
    assert event.normalized_type == "privileged_group_member_added"
    assert event.attributes["group"] == "Administrators"
    assert event.attributes["member_sid"] == "S-1-5-21-1-2-3-1002"
    assert "member" not in event.attributes
    assert event.target == {
        "group": "Administrators",
        "member_sid": "S-1-5-21-1-2-3-1002",
    }
    assert event.metadata["windows_event_identity"]["event_record_id"] == "182963"


@pytest.mark.asyncio
async def test_wazuh_event_provider_normalizes_wfp_listener_permitted_event(monkeypatch) -> None:
    monkeypatch.setitem(
        WAZUH_PAYLOADS,
        "wazuh-alerts-*",
        {
            "hits": {
                "hits": [
                    {
                        "_index": "wazuh-archives-test",
                        "_id": "security-event-5154-178250",
                        "_source": {
                            "@timestamp": "2026-10-16T14:12:53.018Z",
                            "agent": {"id": "001", "name": "win11-arm-lab"},
                            "data": {
                                "win": {
                                    "system": {
                                        "eventID": "5154",
                                        "eventRecordID": "178250",
                                        "channel": "Security",
                                        "providerName": "Microsoft-Windows-Security-Auditing",
                                    },
                                    "eventdata": {
                                        "ProcessId": "5148",
                                        "Application": (
                                            r"\device\harddiskvolume3\windows\system32"
                                            r"\windowspowershell\v1.0\powershell.exe"
                                        ),
                                        "SourceAddress": "127.0.0.1",
                                        "SourcePort": "49389",
                                        "Protocol": "6",
                                    },
                                }
                            },
                        },
                    }
                ]
            }
        },
    )
    provider = WazuhEventProvider(_config(), client_factory=FakeWazuhClient)

    events = await provider.get_events(
        "001",
        datetime(2026, 10, 16, 14, 12, tzinfo=UTC),
        datetime(2026, 10, 16, 14, 14, tzinfo=UTC),
    )

    event = events[0]
    assert event.normalized_type == "listener_created"
    assert event.target["key"] == "listener:tcp:127.0.0.1:49389"
    assert event.attributes["local_address"] == "127.0.0.1"
    assert event.attributes["local_port"] == 49389
    assert event.attributes["protocol"] == "tcp"
    assert event.metadata["windows_event_identity"]["event_record_id"] == "178250"


@pytest.mark.asyncio
async def test_wazuh_listener_event_rejects_unknown_protocol(monkeypatch) -> None:
    monkeypatch.setitem(
        WAZUH_PAYLOADS,
        "wazuh-alerts-*",
        {
            "hits": {
                "hits": [
                    {
                        "_index": "wazuh-archives-test",
                        "_id": "security-event-5154-unknown-protocol",
                        "_source": {
                            "@timestamp": "2026-10-16T14:12:53.018Z",
                            "agent": {"id": "001", "name": "win11-arm-lab"},
                            "data": {
                                "win": {
                                    "system": {
                                        "eventID": "5154",
                                        "providerName": "Microsoft-Windows-Security-Auditing",
                                    },
                                    "eventdata": {
                                        "SourceAddress": "127.0.0.1",
                                        "SourcePort": "49389",
                                        "Protocol": "99",
                                    },
                                }
                            },
                        },
                    }
                ]
            }
        },
    )
    provider = WazuhEventProvider(_config(), client_factory=FakeWazuhClient)

    events = await provider.get_events(
        "001",
        datetime(2026, 10, 16, 14, 12, tzinfo=UTC),
        datetime(2026, 10, 16, 14, 14, tzinfo=UTC),
    )

    assert events[0].normalized_type == "listener_created"
    assert "protocol" not in events[0].attributes
    assert "key" not in events[0].target


@pytest.mark.asyncio
async def test_wazuh_task_event_canonicalizes_repeated_windows_separators() -> None:
    task_name = r"\\CSG\Research"

    class ScheduledTaskClient(FakeWazuhClient):
        async def indexer_search(self, index_pattern: str, _body: dict[str, Any]) -> dict[str, Any]:
            if index_pattern != self.config.alert_index_pattern:
                return {"hits": {"total": {"value": 0}, "hits": []}}
            return {
                "hits": {
                    "total": {"value": 1},
                    "hits": [
                        {
                            "_index": "wazuh-alerts-4.x-2026.10.11",
                            "_id": "scheduled-task-4698",
                            "_source": {
                                "@timestamp": "2026-10-11T01:28:01.239Z",
                                "agent": {"id": "001", "name": "win11-arm-lab"},
                                "rule": {"id": "60228", "level": 4},
                                "data": {
                                    "win": {
                                        "system": {"eventID": "4698"},
                                        "eventdata": {"TaskName": task_name},
                                    }
                                },
                            },
                        }
                    ],
                }
            }

    events = await WazuhEventProvider(_config(), client_factory=ScheduledTaskClient).get_events(
        "win11-arm-lab",
        datetime(2026, 10, 11, 1, 28, tzinfo=UTC),
        datetime(2026, 10, 11, 1, 29, tzinfo=UTC),
    )

    assert events.query_complete is True
    assert len(events.events) == 1
    assert events.events[0].normalized_type == "scheduled_task_created"
    assert events.events[0].target["key"] == r"scheduled_task:\csg\research"


@pytest.mark.asyncio
async def test_wazuh_event_provider_normalizes_service_modification(monkeypatch) -> None:
    monkeypatch.setitem(
        WAZUH_PAYLOADS,
        "wazuh-alerts-*",
        {
            "hits": {
                "hits": [
                    {
                        "_index": "wazuh-alerts-test",
                        "_id": "alert-7040",
                        "_source": {
                            "@timestamp": "2026-09-14T10:05:00Z",
                            "agent": {"id": "001", "name": "win11-arm-lab"},
                            "data": {
                                "win": {
                                    "system": {"eventID": "7040"},
                                    "eventdata": {
                                        "param1": "SystemUpdate",
                                        "param2": "demand start",
                                        "param3": "auto start",
                                        "param4": "SystemUpdate",
                                    },
                                }
                            },
                        },
                    }
                ]
            }
        },
    )
    provider = WazuhEventProvider(_config(), client_factory=FakeWazuhClient)

    events = await provider.get_events(
        "001",
        datetime(2026, 9, 14, 10, 0, tzinfo=UTC),
        datetime(2026, 9, 14, 10, 10, tzinfo=UTC),
    )

    assert events[0].normalized_type == "service_modified"
    assert events[0].target["key"] == "service:systemupdate"
    assert events[0].attributes["new_start_mode"] == "auto start"


@pytest.mark.asyncio
async def test_wazuh_event_provider_normalizes_sysmon_registry_write(monkeypatch) -> None:
    monkeypatch.setitem(
        WAZUH_PAYLOADS,
        "wazuh-alerts-*",
        {
            "hits": {
                "hits": [
                    {
                        "_index": "wazuh-alerts-test",
                        "_id": "sysmon-registry-13",
                        "_source": {
                            "@timestamp": "2026-10-03T10:05:00Z",
                            "agent": {"id": "001", "name": "win11-arm-lab"},
                            "data": {
                                "win": {
                                    "system": {
                                        "eventID": "13",
                                        "providerName": "Microsoft-Windows-Sysmon",
                                    },
                                    "eventdata": {
                                        "TargetObject": (
                                            "HKU\\S-1-5-21-100-200-300-1001\\Software\\"
                                            "Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
                                        ),
                                        "Details": "C:\\Lab\\update.exe",
                                    },
                                }
                            },
                        },
                    }
                ]
            }
        },
    )
    provider = WazuhEventProvider(_config(), client_factory=FakeWazuhClient)

    events = await provider.get_events(
        "001",
        datetime(2026, 10, 3, 10, 0, tzinfo=UTC),
        datetime(2026, 10, 3, 10, 10, tzinfo=UTC),
    )

    assert events[0].normalized_type == "registry_value_modified"
    assert events[0].target["key"] == (
        "registry:hku/s-1-5-21-100-200-300-1001/software/microsoft/windows/"
        "currentversion/run/updater"
    )


@pytest.mark.asyncio
async def test_wazuh_archive_provider_normalizes_unalerted_sysmon_registry_write(
    monkeypatch,
) -> None:
    archive_target = (
        r"HKU\\S-1-5-21-100-200-300-1001\\Software\\Microsoft\\Windows"
        r"\\CurrentVersion\\Run\\CSGAPTRun1234567890"
    )
    monkeypatch.setitem(
        WAZUH_PAYLOADS,
        "wazuh-alerts-*",
        {"hits": {"hits": []}},
    )
    monkeypatch.setitem(
        WAZUH_PAYLOADS,
        "wazuh-archives-*",
        {
            "hits": {
                "total": {"value": 1},
                "hits": [
                    {
                        "_index": "wazuh-archives-4.x-2026.10.03",
                        "_id": "archive-event-373094",
                        "_source": {
                            "timestamp": "2026-10-03T22:13:12.131+0000",
                            "agent": {"id": "001", "name": "win11-arm-lab"},
                            "data": {
                                "win": {
                                    "system": {
                                        "eventID": "13",
                                        "eventRecordID": "373094",
                                        "channel": "Microsoft-Windows-Sysmon/Operational",
                                        "providerName": "Microsoft-Windows-Sysmon",
                                    },
                                    "eventdata": {
                                        "TargetObject": archive_target,
                                        "Details": "C:\\Lab\\payload.exe",
                                        "EventType": "SetValue",
                                        "Image": "C:\\Windows\\System32\\reg.exe",
                                    },
                                }
                            },
                        },
                    }
                ],
            }
        },
    )
    config = replace(_config(), archive_index_pattern="wazuh-archives-*")
    provider = WazuhEventProvider(config, client_factory=RecordingWazuhClient)

    result = await provider.get_events(
        "001",
        datetime(2026, 10, 3, 22, 13, tzinfo=UTC),
        datetime(2026, 10, 3, 22, 14, tzinfo=UTC),
    )

    assert result.coverage_status == "COMPLETE"
    assert len(result.events) == 1
    event = result.events[0]
    assert event.normalized_type == "registry_value_modified"
    assert event.target["key"] == (
        "registry:hku/s-1-5-21-100-200-300-1001/software/microsoft/windows/"
        "currentversion/run/csgaptrun1234567890"
    )
    assert event.metadata["source_kind"] == "wazuh_archive"
    assert event.event_time == datetime(2026, 10, 3, 22, 13, 12, 131000, tzinfo=UTC)
    archive_query = next(
        body
        for index, body in RecordingWazuhClient.last_instance.searches
        if index == "wazuh-archives-*"
    )
    assert "timestamp" in archive_query["query"]["bool"]["filter"][0]["range"]


@pytest.mark.asyncio
async def test_configured_archive_failure_marks_event_coverage_partial() -> None:
    class ArchiveUnavailableClient(FakeWazuhClient):
        async def indexer_search(
            self,
            index_pattern: str,
            body: dict[str, Any],
        ) -> dict[str, Any]:
            if index_pattern == "wazuh-archives-*":
                raise RuntimeError("archive index unavailable")
            return await super().indexer_search(index_pattern, body)

    config = replace(_config(), archive_index_pattern="wazuh-archives-*")
    result = await WazuhEventProvider(
        config,
        client_factory=ArchiveUnavailableClient,
    ).get_events(
        "001",
        datetime(2026, 9, 14, 10, 0, tzinfo=UTC),
        datetime(2026, 9, 14, 10, 10, tzinfo=UTC),
    )

    assert result.coverage_status == "PARTIAL"
    assert result.query_complete is False
    assert result.index_status == "DEGRADED"
    assert result.metadata["retrieval"]["sources"]["wazuh_archive"]["status"] == "UNAVAILABLE"
    retrieval = result.metadata["retrieval"]
    assert retrieval["duration_seconds"] >= 0
    assert retrieval["endpoint_status_duration_seconds"] >= 0
    assert datetime.fromisoformat(retrieval["query_started_at"]).tzinfo is not None
    assert retrieval["sources"]["wazuh_alert"]["duration_seconds"] >= 0
    assert retrieval["sources"]["wazuh_archive"]["duration_seconds"] >= 0


@pytest.mark.asyncio
async def test_alert_and_archive_copies_of_one_windows_record_are_deduplicated(monkeypatch) -> None:
    event_source = {
        "agent": {"id": "001", "name": "win11-arm-lab"},
        "data": {
            "win": {
                "system": {
                    "eventID": "13",
                    "eventRecordID": "373094",
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "providerName": "Microsoft-Windows-Sysmon",
                },
                "eventdata": {
                    "TargetObject": r"HKU\S-1-5-21-100\Software\Run\SameValue",
                    "EventType": "SetValue",
                },
            }
        },
    }
    monkeypatch.setitem(
        WAZUH_PAYLOADS,
        "wazuh-alerts-*",
        {
            "hits": {
                "hits": [
                    {
                        "_index": "wazuh-alerts-4.x-test",
                        "_id": "alert-record-373094",
                        "_source": {
                            **event_source,
                            "@timestamp": "2026-10-03T22:13:12Z",
                            "rule": {"id": "100510", "level": 5},
                        },
                    }
                ]
            }
        },
    )
    monkeypatch.setitem(
        WAZUH_PAYLOADS,
        "wazuh-archives-*",
        {
            "hits": {
                "hits": [
                    {
                        "_index": "wazuh-archives-4.x-test",
                        "_id": "archive-record-373094",
                        "_source": {
                            **event_source,
                            "timestamp": "2026-10-03T22:13:12Z",
                        },
                    }
                ]
            }
        },
    )
    provider = WazuhEventProvider(
        replace(_config(), archive_index_pattern="wazuh-archives-*"),
        client_factory=FakeWazuhClient,
    )

    result = await provider.get_events(
        "001",
        datetime(2026, 10, 3, 22, 13, tzinfo=UTC),
        datetime(2026, 10, 3, 22, 14, tzinfo=UTC),
    )

    assert len(result.events) == 1
    event = result.events[0]
    assert event.source_reference == {
        "index": "wazuh-alerts-4.x-test",
        "document_id": "alert-record-373094",
    }
    assert event.metadata["rule"]["id"] == "100510"
    assert event.metadata["additional_source_references"] == [
        {
            "source_kind": "wazuh_archive",
            "index": "wazuh-archives-4.x-test",
            "document_id": "archive-record-373094",
        }
    ]
    assert event.metadata["windows_event_identity"] == {
        "agent_id": "001",
        "channel": "microsoft-windows-sysmon/operational",
        "event_record_id": "373094",
        "event_code": "13",
        "provider_name": "microsoft-windows-sysmon",
    }


@pytest.mark.asyncio
async def test_wazuh_status_reports_indexer_and_agents() -> None:
    settings = Settings(
        CSG_STATE_PROVIDER="wazuh",
        CSG_EVENT_PROVIDER="wazuh",
        CSG_WAZUH_API_PASSWORD="test-api-password",
        CSG_WAZUH_INDEXER_PASSWORD="test-indexer-password",
    )

    status = await WazuhStatusService(settings, client_factory=FakeWazuhClient).status()

    assert status["ok"] is True
    assert status["configured"] is True
    assert status["enabled"] is True
    assert status["indexer"]["cluster_name"] == "wazuh-cluster"
    assert status["agent_count"] == 2
    assert status["endpoint_agent_count"] == 1
    assert status["agents"][1]["name"] == "win11-arm-lab"
