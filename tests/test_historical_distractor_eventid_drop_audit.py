from __future__ import annotations

import pytest
from experiments.audit_historical_distractor_eventid_drop import (
    is_exact_task_event,
    physical_identity_group,
    represents_physical_event,
    scheduled_task_scenario,
)


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({}, True),
        ({"host_id": "other-host"}, False),
        ({"source": "fixture"}, False),
        ({"normalized_type": "service_created"}, False),
        ({"target": {"key": "scheduled_task:\\other"}}, False),
    ],
)
def test_exact_task_identity_requires_every_discriminator(
    change: dict[str, object], expected: bool
) -> None:
    event: dict[str, object] = {
        "event_id": "wazuh-expected",
        "host_id": "win11-arm-lab",
        "source": "wazuh",
        "normalized_type": "scheduled_task_created",
        "target": {"key": "scheduled_task:\\csgapttask1234567890"},
    }
    if "target" in change:
        event["target"] = change["target"]
        change = {key: value for key, value in change.items() if key != "target"}
    event.update(change)

    assert (
        is_exact_task_event(
            event,
            host_id="win11-arm-lab",
            object_key="scheduled_task:\\csgapttask1234567890",
        )
        is expected
    )


def test_scheduled_task_scenario_requires_exactly_one_trial() -> None:
    scenario = {"kind": "scheduled_task", "object_name": "target"}
    assert scheduled_task_scenario({"scenarios": [scenario]}, "trial") is scenario

    with pytest.raises(ValueError, match="exactly one"):
        scheduled_task_scenario({"scenarios": []}, "trial")


def test_alert_and_archive_documents_are_one_physical_event() -> None:
    identity = ["001", "security", "12345", "4698", "microsoft-windows-security-auditing"]
    documents = [
        {
            "document_found": True,
            "event_id": "wazuh-alert",
            "index": "wazuh-alerts-4.x-2026.10.13",
            "document_id": "alert-doc",
            "raw_task_name": "\\\\CSGAPTTask1234567890",
            "stable_windows_event_identity": identity,
        },
        {
            "document_found": True,
            "event_id": "wazuh-archive",
            "index": "wazuh-archives-4.x-2026.10.13",
            "document_id": "archive-doc",
            "raw_task_name": "\\CSGAPTTask1234567890",
            "stable_windows_event_identity": identity,
        },
    ]
    audit = {"stable_identity_groups": [{"identity": identity, "documents": documents}]}

    _, physical, aliases, references = physical_identity_group(
        audit, "CSGAPTTask1234567890"
    )

    assert list(physical) == identity
    assert aliases == {"wazuh-alert", "wazuh-archive"}
    assert len(references) == 2
    assert represents_physical_event(
        {
            "event_id": "wazuh-alert",
            "source_reference": {
                "index": "wazuh-alerts-4.x-2026.10.13",
                "document_id": "alert-doc",
            },
        },
        aliases=aliases,
        references=references,
    )
