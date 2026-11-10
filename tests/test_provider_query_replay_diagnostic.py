from datetime import UTC, datetime

from experiments.diagnose_provider_query_replay import (
    _read_json,
    _replay_one,
    _target_event_ids,
    _timestamp,
)


def test_target_ids_accept_string_and_list_shapes() -> None:
    assert _target_event_ids({"matched_evidence_ids": "evt-a, evt-b"}) == ["evt-a", "evt-b"]
    assert _target_event_ids({"matched_evidence_ids": ["evt-a", "evt-b"]}) == [
        "evt-a",
        "evt-b",
    ]


def test_timestamp_requires_timezone_and_normalizes_to_utc() -> None:
    value = _timestamp("2026-10-11T10:00:00+01:00")
    assert value == datetime(2026, 10, 11, 9, 0, tzinfo=UTC)


def test_windows_json_utf8_bom_is_supported(tmp_path) -> None:
    path = tmp_path / "windows.json"
    path.write_bytes(b'\xef\xbb\xbf{"ok": true}')
    assert _read_json(path) == {"ok": True}


def test_replay_failure_is_retained_as_diagnostic(monkeypatch) -> None:
    def fail_urlopen(*_args, **_kwargs):
        raise TimeoutError("diagnostic timeout")

    monkeypatch.setattr("experiments.diagnose_provider_query_replay.urlopen", fail_urlopen)
    result = _replay_one(
        api_base="http://127.0.0.1:8000",
        host_id="host-1",
        trial_id="trial-1",
        original_trial_status="FAIL",
        action={
            "started_at": "2026-10-11T09:00:00Z",
            "ended_at": "2026-10-11T09:01:00Z",
        },
        expected_event_ids=["event-1"],
        timeout_seconds=1,
    )
    assert result["query_complete"] is False
    assert result["target_event_ids_retrievable_now"] == []
    assert "TimeoutError" in result["error"]
