from datetime import UTC, datetime

from experiments.build_common_pool_comparison_input import (
    _event_record,
    _latest_usable_poll,
    merge_captures,
)


def _poll(when: str, *, start: str = "2026-10-10T12:00:00Z", end: str = "2026-10-10T12:01:00Z"):
    return {
        "query_complete": True,
        "coverage_status": "COMPLETE",
        "response_received_at": when,
        "retrieval_metadata": {"complete": True, "start": start, "end": end},
    }


def test_as_of_poll_requires_timely_complete_covered_query():
    capture = {"polls": [_poll("2026-10-10T12:01:50Z")], "poll_interval_seconds": 15}
    poll, issue = _latest_usable_poll(
        capture,
        datetime(2026, 10, 10, 12, 2, tzinfo=UTC),
        datetime(2026, 10, 10, 12, 0, 10, tzinfo=UTC),
        datetime(2026, 10, 10, 12, 0, 50, tzinfo=UTC),
    )
    assert poll is capture["polls"][0]
    assert issue is None

    _, stale_issue = _latest_usable_poll(
        capture,
        datetime(2026, 10, 10, 12, 2, 30, tzinfo=UTC),
        datetime(2026, 10, 10, 12, 0, 10, tzinfo=UTC),
        datetime(2026, 10, 10, 12, 0, 50, tzinfo=UTC),
    )
    assert stale_issue and "before cutoff" in stale_issue


def test_as_of_poll_selects_latest_query_that_covers_window():
    covering = _poll("2026-10-10T12:01:40Z")
    newer_but_narrow = _poll(
        "2026-10-10T12:01:50Z",
        start="2026-10-10T12:00:30Z",
        end="2026-10-10T12:01:30Z",
    )
    capture = {"polls": [covering, newer_but_narrow], "poll_interval_seconds": 15}

    poll, issue = _latest_usable_poll(
        capture,
        datetime(2026, 10, 10, 12, 2, tzinfo=UTC),
        datetime(2026, 10, 10, 12, 0, 10, tzinfo=UTC),
        datetime(2026, 10, 10, 12, 0, 50, tzinfo=UTC),
    )

    assert poll is covering
    assert issue is None


def test_event_record_uses_conservative_first_seen_upper_bound():
    row = {
        "first_observed_at": "2026-10-10T12:00:05Z",
        "first_seen_upper_bound": "2026-10-10T12:00:08Z",
        "event": {
            "event_id": "evt-1",
            "host_id": "host-1",
            "normalized_type": "service_created",
            "source": "wazuh",
            "event_time": "2026-10-10T12:00:04Z",
            "target": {"key": "service:other"},
            "attributes": {"rule_id": "61138"},
            "metadata": {"source_kind": "wazuh_archive"},
            "source_reference": {"document_id": "doc-1"},
            "synthetic": False,
        },
    }
    result = _event_record(row)
    assert result["first_observed_at"] == "2026-10-10T12:00:08Z"
    assert result["object_key"] == "service:other"
    assert result["source_document_id"] == "doc-1"


def test_merge_captures_keeps_earliest_observation_for_duplicate_document():
    event = {"event_id": "evt-1"}
    earlier = {
        "capture_status": "COMPLETE",
        "poll_interval_seconds": 15,
        "polls": [_poll("2026-10-10T12:00:15Z")],
        "events": {
            "evt-1": {
                "event": event,
                "first_observed_at": "2026-10-10T12:00:15Z",
                "first_seen_upper_bound": "2026-10-10T12:00:15Z",
            }
        },
    }
    later = {
        "capture_status": "COMPLETE",
        "poll_interval_seconds": 15,
        "polls": [_poll("2026-10-10T12:01:15Z")],
        "events": {
            "evt-1": {
                "event": event,
                "first_observed_at": "2026-10-10T12:01:15Z",
                "first_seen_upper_bound": "2026-10-10T12:01:15Z",
            }
        },
    }
    result = merge_captures([later, earlier])
    assert result["events"]["evt-1"]["first_seen_upper_bound"] == "2026-10-10T12:00:15Z"
    assert result["polls"][0]["response_received_at"] == "2026-10-10T12:00:15Z"
    assert result["capture_status"] == "COMPLETE"
