from experiments.query_service_dwell_wazuh_visibility import exact_service_events


def test_wazuh_event_requires_exact_service_object_key():
    events = [
        {
            "event_id": "wazuh-exact",
            "normalized_type": "service_modified",
            "target": {"key": "service:csgone", "service_name": "CSGOne"},
            "attributes": {"service_name": "CSGOne"},
        },
        {
            "event_id": "wazuh-distractor",
            "normalized_type": "service_modified",
            "target": {"key": "service:csgtwo", "service_name": "CSGTwo"},
            "attributes": {"service_name": "CSGTwo"},
        },
        {
            "event_id": "wrong-type",
            "normalized_type": "service_created",
            "target": {"key": "service:csgone", "service_name": "CSGOne"},
            "attributes": {"service_name": "CSGOne"},
        },
    ]

    matched = exact_service_events({"events": events}, "CSGOne", "service:csgone")

    assert [event["event_id"] for event in matched] == ["wazuh-exact"]


def test_wazuh_event_rejects_conflicting_service_name():
    observation = {
        "events": [
            {
                "event_id": "wazuh-conflict",
                "normalized_type": "service_modified",
                "target": {"key": "service:csgone"},
                "attributes": {"service_name": "OtherService"},
            }
        ]
    }
    assert exact_service_events(observation, "CSGOne", "service:csgone") == []
