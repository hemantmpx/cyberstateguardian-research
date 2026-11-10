from datetime import UTC, datetime
from pathlib import Path

import pytest
from experiments.wazuh_common_pool_capture import _record_poll, capture_window


def _time(second: int) -> datetime:
    return datetime(2026, 10, 10, 12, 0, second, tzinfo=UTC)


def _response(event_ids: list[str], *, complete: bool = True) -> dict:
    return {
        "query_complete": complete,
        "endpoint_collection_status": "AVAILABLE",
        "transport_status": "AVAILABLE",
        "index_status": "AVAILABLE",
        "coverage_status": "COMPLETE" if complete else "PARTIAL",
        "retrieved_count": len(event_ids),
        "metadata": {"retrieval": {"query_completed_at": _time(1 + len(event_ids)).isoformat()}},
        "events": [
            {"event_id": event_id, "host_id": "lab", "source": "wazuh"}
            for event_id in event_ids
        ],
    }


def test_first_observation_is_bounded_by_last_complete_absence_and_first_presence() -> None:
    capture = {"polls": [], "events": {}}
    _record_poll(
        capture,
        _response([]),
        request_started_at=_time(0),
        response_received_at=_time(1),
    )
    _record_poll(
        capture,
        _response(["event-1"]),
        request_started_at=_time(2),
        response_received_at=_time(3),
    )

    observed = capture["events"]["event-1"]
    assert observed["first_seen_lower_bound"] == _time(1).isoformat()
    assert observed["first_seen_upper_bound"] == _time(2).isoformat()
    assert observed["first_seen_query_complete"] is True
    assert len(capture["polls"]) == 2


def test_partial_absence_does_not_advance_lower_bound() -> None:
    capture = {"polls": [], "events": {}}
    _record_poll(
        capture,
        _response([]),
        request_started_at=_time(0),
        response_received_at=_time(1),
    )
    _record_poll(
        capture,
        _response([], complete=False),
        request_started_at=_time(2),
        response_received_at=_time(3),
    )
    _record_poll(
        capture,
        _response(["event-1"]),
        request_started_at=_time(4),
        response_received_at=_time(5),
    )

    assert capture["events"]["event-1"]["first_seen_lower_bound"] == _time(1).isoformat()


def test_repeated_documents_are_kept_in_poll_history_but_one_event_record() -> None:
    capture = {"polls": [], "events": {}}
    for second in (1, 2):
        _record_poll(
            capture,
            _response(["event-1"]),
            request_started_at=_time(second - 1),
            response_received_at=_time(second),
        )

    assert len(capture["events"]) == 1
    assert capture["polls"][0]["event_ids"] == ["event-1"]
    assert capture["polls"][1]["event_ids"] == ["event-1"]


def test_capture_rejects_naive_timestamps(tmp_path: Path) -> None:
    naive = datetime(2026, 10, 10, 12, 0, 0)
    with pytest.raises(ValueError, match="window_start must be timezone-aware"):
        capture_window(
            api_url="http://localhost:8000",
            host_id="lab",
            window_start=naive,
            window_end=_time(5),
            capture_until=_time(5),
            poll_interval_seconds=5,
            timeout_seconds=10,
            output_path=tmp_path / "capture.json",
        )
