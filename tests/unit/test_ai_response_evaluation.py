from __future__ import annotations

import pytest
from experiments.ai_response_evaluation import (
    CONDITIONS,
    RATING_FIELDS,
    aggregate_completed_reviews,
    blank_scores,
    validate_scores,
)


def _submitted_review(reviewer: str) -> dict[str, object]:
    items = []
    for index, condition in enumerate(CONDITIONS):
        scores = blank_scores()
        scores.update({field: 3 + index for field in RATING_FIELDS})
        scores.update(
            {
                "unsupported_factual_claim_count": 0,
                "invented_evidence_id_count": 0,
                "unsafe_recommendation_count": 0,
                "generic_action_count": 0,
                "duplicate_recommendation_count": 0,
                "highest_priority_action_reduces_uncertainty": True,
                "would_use_during_investigation": True,
            }
        )
        items.append({"review_id": f"review-{condition}", "subject_id": "case-1", "scores": scores})
    return {"reviewer_id": reviewer, "status": "SUBMITTED", "items": items}


def test_rubric_requires_complete_range_checked_scores() -> None:
    scores = blank_scores()
    assert validate_scores(scores)
    for field in RATING_FIELDS:
        scores[field] = 5
    scores.update(
        {
            "unsupported_factual_claim_count": 0,
            "invented_evidence_id_count": 0,
            "unsafe_recommendation_count": 0,
            "generic_action_count": 0,
            "duplicate_recommendation_count": 0,
            "highest_priority_action_reduces_uncertainty": True,
            "would_use_during_investigation": False,
        }
    )
    assert validate_scores(scores) == []
    scores[RATING_FIELDS[0]] = 6
    assert any("0 to 5" in error for error in validate_scores(scores))


def test_aggregate_requires_two_distinct_submitted_reviewers_and_pairs_by_case() -> None:
    reviews = [_submitted_review("reviewer-1"), _submitted_review("reviewer-2")]
    key = {f"review-{condition}": condition for condition in CONDITIONS}

    result = aggregate_completed_reviews(reviews, key)

    assert result["reviewer_count"] == 2
    assert result["completed_rating_count"] == 6
    assert result["paired_mean_differences"]["ai_minus_csg"]["n_reviewer_subject_pairs"] == 2
    with pytest.raises(ValueError, match="two distinct"):
        aggregate_completed_reviews(reviews[:1], key)


def test_aggregate_does_not_call_repeated_reviewer_ratings_independent_cases() -> None:
    result = aggregate_completed_reviews(
        [_submitted_review("reviewer-1"), _submitted_review("reviewer-2")],
        {f"review-{condition}": condition for condition in CONDITIONS},
    )

    for condition in CONDITIONS:
        assert result["conditions"][condition]["subjects"] == 1
    assert "experimental unit" in result["interpretation"]
