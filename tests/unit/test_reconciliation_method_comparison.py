import pytest
from experiments.reconciliation_method_comparison import (
    CampaignInput,
    EventRecord,
    evaluate_campaign,
)

BASE = "2026-10-10T12:00:00+00:00"


def _assignment(trial_id: str, *, target_changed: bool = True, condition: str = "complete"):
    return {
        "trial_id": trial_id,
        "session_id": "session-1",
        "family": "service",
        "condition": condition,
        "status": "COMPLETED",
        "target_changed": target_changed,
    }


def _event(
    event_id: str,
    *,
    object_key: str | None = "service:target",
    event_type: str = "service_modified",
    source_kind: str = "wazuh_archive",
    occurrence_id: str | None = None,
    rule_id: str | None = None,
    document_id: str | None = "doc-1",
    first_observed_at: str = "2026-10-10T12:00:06+00:00",
):
    return {
        "event_id": event_id,
        "occurrence_id": occurrence_id,
        "host_id": "host-1",
        "object_key": object_key,
        "normalized_type": event_type,
        "source": "wazuh",
        "source_kind": source_kind,
        "event_time": "2026-10-10T12:00:05+00:00",
        "first_observed_at": first_observed_at,
        "rule_id": rule_id,
        "source_document_id": document_id,
        "synthetic": False,
    }


def _observation(
    trial_id: str,
    *,
    events=None,
    target_key="service:target",
    expected_types=None,
    query_complete=True,
    state_observed=True,
    csg_status="CONSISTENT",
    csg_matches=None,
    finding_present=True,
    expected_status="CONSISTENT",
    truth_ids=None,
    cutoff="2026-10-10T12:00:10+00:00",
    condition_attained=True,
):
    return {
        "trial_id": trial_id,
        "host_id": "host-1",
        "target_object_key": target_key,
        "expected_event_types": expected_types or ["service_modified"],
        "window_start": BASE,
        "window_end": "2026-10-10T12:00:08+00:00",
        "cutoff_at": cutoff,
        "time_tolerance_seconds": 2,
        "event_query_complete": query_complete,
        "action_verified": True,
        "condition_attained": condition_attained,
        "cleanup_verified": True,
        "state_observed": state_observed,
        "expected_reconciliation_status": expected_status,
        "truth_supporting_occurrence_ids": truth_ids or [],
        "events": events or [],
        "full_csg": {
            "status": csg_status,
            "finalized": True,
            "finding_present": finding_present,
            "matched_event_ids": csg_matches or [],
            "source_coverage_status": "HEALTHY",
        },
    }


def _campaign(assignments, observations):
    return CampaignInput.model_validate(
        {
            "campaign_id": "unit-campaign",
            "config": {
                "wazuh_alert_rule_ids": ["61104"],
                "wazuh_fim_rule_ids": ["100500"],
            },
            "assignments": assignments,
            "observations": observations,
        }
    )


def _outcome(result, trial_id: str, method: str):
    return next(
        row
        for row in result["method_outcomes"]
        if row["trial_id"] == trial_id and row["method"] == method
    )


def test_exact_matchers_link_same_occurrence_without_double_counting_alert_archive():
    events = [
        _event(
            "alert-1",
            source_kind="wazuh_alert",
            occurrence_id="windows:System:record-42",
            rule_id="61104",
        ),
        _event(
            "archive-1",
            source_kind="wazuh_archive",
            occurrence_id="windows:System:record-42",
            document_id="archive-doc-1",
        ),
    ]
    result = evaluate_campaign(
        _campaign(
            [_assignment("t1")],
            [
                _observation(
                    "t1",
                    events=events,
                    truth_ids=["windows:System:record-42"],
                    csg_matches=["alert-1"],
                )
            ],
        )
    )

    alerts = _outcome(result, "t1", "configured_wazuh_alert_fim")
    strong = _outcome(result, "t1", "strong_identity_matcher")
    full = _outcome(result, "t1", "full_csg")
    assert alerts["selected_event_ids"] == ["alert-1"]
    assert strong["selected_event_ids"] == ["alert-1", "archive-1"]
    assert strong["selected_occurrence_ids"] == ["windows:System:record-42"]
    assert strong["link_precision"] == 1.0
    assert strong["link_recall"] == 1.0
    assert full["reconciliation_status_correct"] is True
    assert result["assignment_count"] == 1


def test_same_host_wrong_object_only_fools_loose_matcher():
    wrong = _event("wrong", object_key="service:other")
    result = evaluate_campaign(
        _campaign(
            [_assignment("distractor", condition="suppressed_distractor")],
            [
                _observation(
                    "distractor",
                    events=[wrong],
                    csg_status="UNEXPLAINED",
                    csg_matches=[],
                    expected_status="UNEXPLAINED",
                    truth_ids=[],
                )
            ],
        )
    )

    assert _outcome(result, "distractor", "native_probe_only")[
        "target_change_detection_correct"
    ] is True
    assert _outcome(result, "distractor", "strong_identity_matcher")[
        "target_change_signal"
    ] is False
    loose = _outcome(result, "distractor", "loose_host_type_time_matcher")
    assert loose["selected_event_ids"] == ["wrong"]
    assert loose["false_corroboration"] is True
    assert _outcome(result, "distractor", "full_csg")[
        "reconciliation_status_correct"
    ] is True


def test_no_change_distractor_is_a_loose_match_false_target_not_a_probe_false_positive():
    wrong = _event(
        "unrelated-service-event",
        object_key="service:other",
        event_type="service_created",
    )
    assignment = _assignment("no-change", target_changed=False, condition="no_change_distractor")
    observation = _observation(
        "no-change",
        events=[wrong],
        state_observed=False,
        csg_status="NOT_APPLICABLE",
        csg_matches=[],
        finding_present=False,
        expected_status="NOT_APPLICABLE",
        expected_types=["service_created"],
    )
    result = evaluate_campaign(_campaign([assignment], [observation]))

    assert _outcome(result, "no-change", "native_probe_only")[
        "target_change_detection_correct"
    ] is True
    assert _outcome(result, "no-change", "strong_identity_matcher")[
        "target_change_signal"
    ] is False
    loose = _outcome(result, "no-change", "loose_host_type_time_matcher")
    assert loose["target_change_signal"] is True
    assert loose["target_change_detection_correct"] is False
    summary = next(
        row
        for row in result["method_summaries"]
        if row["method"] == "loose_host_type_time_matcher"
        and row["session_id"] is None
    )
    false_targets = summary["no_change_false_target_findings"]
    assert false_targets["successes"] == 1
    assert false_targets["denominator"] == 1
    assert false_targets["estimate"] == 1.0
    assert false_targets["wilson_95"] == pytest.approx([0.2065493144, 1.0])


def test_raw_event_method_can_overaccept_wrong_transition_while_strong_match_rejects():
    wrong_transition = _event("wrong-op", event_type="service_created")
    observation = _observation(
        "wrong-transition",
        events=[wrong_transition],
        csg_status="UNEXPLAINED",
        csg_matches=[],
        expected_status="UNEXPLAINED",
    )
    result = evaluate_campaign(
        _campaign([_assignment("wrong-transition")], [observation])
    )

    raw = _outcome(result, "wrong-transition", "raw_event_only")
    strong = _outcome(result, "wrong-transition", "strong_identity_matcher")
    assert raw["selected_event_ids"] == ["wrong-op"]
    assert raw["false_corroboration"] is True
    assert strong["selected_event_ids"] == []


def test_receipt_after_cutoff_is_not_backdated_by_source_event_time():
    late = _event(
        "late",
        first_observed_at="2026-10-10T12:00:11+00:00",
    )
    result = evaluate_campaign(
        _campaign(
            [_assignment("late")],
            [
                _observation(
                    "late",
                    events=[late],
                    cutoff="2026-10-10T12:00:10+00:00",
                    csg_status="UNEXPLAINED",
                    csg_matches=[],
                    expected_status="UNEXPLAINED",
                )
            ],
        )
    )

    assert _outcome(result, "late", "strong_identity_matcher")["selected_event_ids"] == []
    assert _outcome(result, "late", "native_probe_only")[
        "target_change_detection_correct"
    ] is True
    assert _outcome(result, "late", "full_csg")["reconciliation_status_correct"] is True


def test_incomplete_query_does_not_turn_missing_event_into_negative_evidence():
    result = evaluate_campaign(
        _campaign(
            [_assignment("partial")],
            [
                _observation(
                    "partial",
                    query_complete=False,
                    events=[],
                    csg_status="PENDING_EVIDENCE",
                    finding_present=True,
                    expected_status="UNEXPLAINED",
                )
            ],
        )
    )

    assert _outcome(result, "partial", "raw_event_only")[
        "target_change_detection_correct"
    ] is None
    assert _outcome(result, "partial", "native_probe_only")[
        "target_change_detection_correct"
    ] is True
    assert _outcome(result, "partial", "full_csg")["pending_at_cutoff"] is True
    assert _outcome(result, "partial", "full_csg")["reconciliation_status_correct"] is None


def test_missing_assignment_is_preserved_in_ledger_and_not_in_outcome_denominator():
    result = evaluate_campaign(
        _campaign(
            [_assignment("present"), _assignment("missing")],
            [_observation("present", events=[])],
        )
    )

    missing = next(row for row in result["trial_ledger"] if row["trial_id"] == "missing")
    assert missing["artifact_present"] is False
    assert missing["outcome_status"] == "MISSING_OBSERVATION"
    assert result["assignment_count"] == 2
    assert result["observations_found"] == 1
    assert len(result["method_outcomes"]) == 6


def test_naive_event_time_and_duplicate_trial_evidence_ids_are_rejected():
    with pytest.raises(ValueError, match="timezone"):
        EventRecord.model_validate(_event("naive") | {"event_time": "2026-10-10T12:00:05"})

    duplicated = _event("duplicate")
    with pytest.raises(ValueError, match="event_id must be unique"):
        _campaign(
            [_assignment("dup")],
            [_observation("dup", events=[duplicated, duplicated])],
        )
