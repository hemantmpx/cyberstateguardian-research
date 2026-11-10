from __future__ import annotations

import json

from scripts.aggregate_live_telemetry_campaign import _status_for_transition, _trial


def test_exact_event_linked_delta_wins_over_unexplained_duplicate() -> None:
    findings = [
        {
            "category": "service",
            "object_key": "service:target",
            "reconciliation": {
                "status": "UNEXPLAINED",
                "version": 2,
                "finalized": True,
                "delta_id": "duplicate-delta",
                "missing_expected_evidence_types": ["service_modified"],
            },
        },
        {
            "category": "service",
            "object_key": "service:target",
            "reconciliation": {
                "status": "CONSISTENT",
                "version": 1,
                "finalized": True,
                "delta_id": "action-delta",
                "matched_evidence_ids": ["event-target"],
                "match_reasons": [{"event_type": "service_modified"}],
            },
        },
        {
            "category": "service",
            "object_key": "service:other",
            "reconciliation": {
                "status": "CONSISTENT",
                "version": 9,
                "finalized": True,
                "delta_id": "other-object-delta",
                "matched_evidence_ids": ["event-target"],
                "match_reasons": [{"event_type": "service_modified"}],
            },
        },
    ]

    assert _status_for_transition(
        findings,
        "MODIFY",
        "service:target",
        {"event-target"},
    ) == ("CONSISTENT", True)


def test_trial_aggregate_uses_indexer_status_field(tmp_path) -> None:
    run_path = tmp_path / "run.json"
    run_path.write_text(
        json.dumps({"event_plane_status": {"indexer_status": "AVAILABLE"}}),
        encoding="utf-8",
    )

    summary = _trial(run_path)

    assert summary["event_plane_status"]["central_index_status"] == "AVAILABLE"
