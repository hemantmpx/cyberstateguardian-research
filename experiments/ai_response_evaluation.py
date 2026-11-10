from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Any

CONDITIONS = ("csg_only", "static_playbook", "ai_response_assistant")
RATING_FIELDS = (
    "investigative_actionability_0_to_5",
    "evidence_prioritization_0_to_5",
    "uncertainty_reduction_0_to_5",
    "technical_specificity_0_to_5",
    "hypothesis_quality_0_to_5",
    "response_appropriateness_0_to_5",
    "evidence_grounding_0_to_5",
    "analyst_usefulness_0_to_5",
    "confidence_calibration_0_to_5",
    "incremental_value_beyond_csg_0_to_5",
)
COUNT_FIELDS = (
    "unsupported_factual_claim_count",
    "invented_evidence_id_count",
    "unsafe_recommendation_count",
    "generic_action_count",
    "duplicate_recommendation_count",
)
BOOLEAN_FIELDS = (
    "highest_priority_action_reduces_uncertainty",
    "would_use_during_investigation",
)
ALL_SCORE_FIELDS = (*RATING_FIELDS, *COUNT_FIELDS, *BOOLEAN_FIELDS, "reviewer_notes")


def blank_scores() -> dict[str, Any]:
    return {**dict.fromkeys((*RATING_FIELDS, *COUNT_FIELDS, *BOOLEAN_FIELDS)), "reviewer_notes": ""}


def validate_scores(scores: dict[str, Any]) -> list[str]:
    errors = []
    for field in RATING_FIELDS:
        value = scores.get(field)
        if type(value) not in (int, float) or not 0 <= value <= 5:
            errors.append(f"{field} must be a number from 0 to 5")
    for field in COUNT_FIELDS:
        value = scores.get(field)
        if type(value) is not int or value < 0:
            errors.append(f"{field} must be a non-negative integer")
    for field in BOOLEAN_FIELDS:
        if type(scores.get(field)) is not bool:
            errors.append(f"{field} must be boolean")
    if not isinstance(scores.get("reviewer_notes", ""), str):
        errors.append("reviewer_notes must be text")
    return errors


def aggregate_completed_reviews(
    reviews: list[dict[str, Any]], condition_key: dict[str, str]
) -> dict[str, Any]:
    submitted_reviewers = {
        str(review.get("reviewer_id"))
        for review in reviews
        if review.get("status") == "SUBMITTED" and review.get("reviewer_id")
    }
    if len(submitted_reviewers) < 2:
        raise ValueError("at least two distinct submitted reviewers are required")

    records: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    skipped = 0
    for review in reviews:
        reviewer_id = str(review.get("reviewer_id", ""))
        if review.get("status") != "SUBMITTED":
            skipped += len(review.get("items", []))
            continue
        for item in review.get("items", []):
            review_id = str(item.get("review_id", ""))
            condition = condition_key.get(review_id)
            scores = item.get("scores") or {}
            identity = (reviewer_id, review_id)
            if identity in seen:
                if seen[identity] != item:
                    raise ValueError("conflicting duplicate reviewer score")
                continue
            seen[identity] = item
            if condition not in CONDITIONS or validate_scores(scores):
                skipped += 1
                continue
            records.append(
                {
                    "reviewer_id": reviewer_id,
                    "subject_id": str(item.get("subject_id", "")),
                    "review_id": review_id,
                    "condition": condition,
                    "scores": scores,
                }
            )

    per_condition: dict[str, list[dict[str, Any]]] = {condition: [] for condition in CONDITIONS}
    for record in records:
        per_condition[record["condition"]].append(record)
    summaries = {condition: _condition_summary(rows) for condition, rows in per_condition.items()}
    return {
        "schema_version": "csg-ai-response-assistance-aggregate-v1",
        "reviewer_count": len(submitted_reviewers),
        "completed_rating_count": len(records),
        "skipped_incomplete_or_invalid_items": skipped,
        "conditions": summaries,
        "paired_mean_differences": {
            "ai_minus_csg": _paired_differences(records, "ai_response_assistant", "csg_only"),
            "static_minus_csg": _paired_differences(records, "static_playbook", "csg_only"),
            "ai_minus_static": _paired_differences(
                records, "ai_response_assistant", "static_playbook"
            ),
        },
        "interpretation": (
            "Descriptive, reviewer-scored results. Treat the subject/case as the experimental "
            "unit; repeated reviewer ratings do not increase the number of independent cases. "
            "Do not claim incremental value without adequate independent cases and uncertainty "
            "analysis."
        ),
    }


def _condition_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    for field in RATING_FIELDS:
        metrics[field] = _summary([float(row["scores"][field]) for row in rows])
    for field in COUNT_FIELDS:
        metrics[field] = _summary([float(row["scores"][field]) for row in rows])
    for field in BOOLEAN_FIELDS:
        values = [float(row["scores"][field]) for row in rows]
        metrics[field] = {
            "n": len(values),
            "yes_rate": round(statistics.mean(values), 4) if values else None,
        }
    return {
        "completed_ratings": len(rows),
        "reviewers": len({row["reviewer_id"] for row in rows}),
        "subjects": len({row["subject_id"] for row in rows}),
        "metrics": metrics,
    }


def _summary(values: list[float]) -> dict[str, float | int | None]:
    return {
        "n": len(values),
        "mean": round(statistics.mean(values), 4) if values else None,
        "median": round(statistics.median(values), 4) if values else None,
        "stdev": round(statistics.stdev(values), 4) if len(values) > 1 else 0.0 if values else None,
    }


def _paired_differences(rows: list[dict[str, Any]], left: str, right: str) -> dict[str, Any]:
    paired: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    for row in rows:
        key = (row["reviewer_id"], row["subject_id"])
        paired.setdefault(key, {})[row["condition"]] = row
    eligible = [pair for pair in paired.values() if left in pair and right in pair]
    differences = {
        field: [
            float(pair[left]["scores"][field]) - float(pair[right]["scores"][field])
            for pair in eligible
        ]
        for field in RATING_FIELDS
    }
    return {
        "n_reviewer_subject_pairs": len(eligible),
        "metrics": {field: _summary(values) for field, values in differences.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate blinded AI response-assistance reviews")
    parser.add_argument("condition_key", type=Path)
    parser.add_argument("reviews", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    condition_key = json.loads(args.condition_key.read_text(encoding="utf-8"))
    reviews = [json.loads(path.read_text(encoding="utf-8")) for path in args.reviews]
    result = aggregate_completed_reviews(reviews, condition_key)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
