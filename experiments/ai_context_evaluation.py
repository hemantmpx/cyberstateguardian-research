from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
from pathlib import Path
from typing import Any

SCORE_FIELDS = (
    "attack_chain_reconstruction_accuracy_0_to_5",
    "mitre_attack_mapping_accuracy_0_to_5",
    "evidence_grounding_accuracy_0_to_5",
    "analyst_usefulness_0_to_5",
    "confidence_calibration_0_to_5",
)


def create_blinded_review_package(
    study: dict[str, Any],
    *,
    seed: int = 530,
) -> tuple[dict[str, Any], dict[str, str]]:
    items: list[dict[str, Any]] = []
    answer_key: dict[str, str] = {}
    subject = study.get("subject", {})
    for condition, payload in study.get("conditions", {}).items():
        trials = payload.get("trials") or [
            {
                "trial": 1,
                "analysis": payload.get("analysis"),
                "human_evaluation": payload.get("human_evaluation", {}),
            }
        ]
        for trial in trials:
            identity = json.dumps(
                {
                    "study_id": study.get("study_id"),
                    "subject": subject,
                    "condition": condition,
                    "trial": trial.get("trial", 1),
                    "package_hash": payload.get("package_hash"),
                },
                sort_keys=True,
            )
            review_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
            answer_key[review_id] = condition
            items.append(
                {
                    "review_id": review_id,
                    "subject": subject,
                    "analysis": (trial.get("analysis") or {}).get("response_json"),
                    "scores": trial.get("human_evaluation", {}),
                }
            )
    random.Random(seed).shuffle(items)
    return (
        {
            "schema_version": "csg-ai-blinded-review-v2",
            "study_version": study.get("study_version"),
            "review_instructions": (
                "Score the response against the separately supplied study rubric. The answer key "
                "is private and must not be shown to the reviewer. Do not infer condition identity "
                "and do not treat another AI answer as evidence. Configuration metadata is hidden; "
                "response content may still reveal context richness."
            ),
            "items": items,
        },
        answer_key,
    )


def aggregate_completed_reviews(
    reviews: list[dict[str, Any]],
    answer_key: dict[str, str],
) -> dict[str, Any]:
    conditions = ("A", "B", "C", "D")
    values: dict[str, dict[str, list[float]]] = {
        condition: {field: [] for field in SCORE_FIELDS} for condition in conditions
    }
    unsupported: dict[str, list[float]] = {condition: [] for condition in conditions}
    root_cause: dict[str, list[float]] = {condition: [] for condition in conditions}
    skipped = 0
    completed = 0
    seen = {}
    for review in reviews:
        for item in review.get("items", []):
            identity = (review.get("reviewer_id", "unspecified"), str(item.get("review_id")))
            if identity in seen:
                if seen[identity] != item:
                    raise ValueError(
                        "Conflicting duplicate rating; supply distinct reviewer_id values"
                    )
                continue
            seen[identity] = item
            condition = answer_key.get(str(item.get("review_id")))
            if condition not in values:
                skipped += 1
                continue
            scores = item.get("scores", {})
            if not item.get("analysis") or not all(
                _valid_score(scores.get(field)) for field in SCORE_FIELDS
            ):
                skipped += 1
                continue
            unsupported_count = scores.get("unsupported_claim_count")
            root_correct = scores.get("root_cause_identification_correct")
            if (
                type(unsupported_count) is not int
                or unsupported_count < 0
                or type(root_correct) is not bool
            ):
                skipped += 1
                continue
            completed += 1
            for field in SCORE_FIELDS:
                values[condition][field].append(float(scores[field]))
            unsupported[condition].append(float(unsupported_count))
            root_cause[condition].append(float(root_correct))

    conditions = {
        condition: {
            "completed_reviews": len(unsupported[condition]),
            "metrics": {
                **{
                    field: _summary(field_values)
                    for field, field_values in values[condition].items()
                },
                "unsupported_claim_count": _summary(unsupported[condition]),
                "root_cause_identification_correct": _summary(root_cause[condition]),
            },
        }
        for condition in conditions
    }
    return {
        "schema_version": "csg-ai-context-aggregate-v1",
        "completed_reviews": completed,
        "skipped_incomplete_or_invalid_reviews": skipped,
        "conditions": conditions,
        "mean_differences": {
            "C_minus_A": _mean_differences(conditions, "C", "A"),
            "C_minus_B": _mean_differences(conditions, "C", "B"),
            "D_minus_B": _mean_differences(conditions, "D", "B"),
            "D_minus_C": _mean_differences(conditions, "D", "C"),
        },
        "interpretation_warning": (
            "Descriptive statistics only. Report reviewer count, repeated incidents, uncertainty, "
            "and an appropriate paired significance test before drawing research conclusions."
        ),
    }


def _valid_score(value: Any) -> bool:
    return type(value) in (int, float) and 0 <= value <= 5


def _summary(values: list[float]) -> dict[str, float | int | None]:
    return {
        "n": len(values),
        "mean": round(statistics.mean(values), 4) if values else None,
        "median": round(statistics.median(values), 4) if values else None,
        "stdev": round(statistics.stdev(values), 4) if len(values) > 1 else 0.0 if values else None,
    }


def _mean_differences(
    conditions: dict[str, Any],
    left: str,
    right: str,
) -> dict[str, float | None]:
    fields = (*SCORE_FIELDS, "unsupported_claim_count", "root_cause_identification_correct")
    differences: dict[str, float | None] = {}
    for field in fields:
        left_mean = conditions[left]["metrics"][field]["mean"]
        right_mean = conditions[right]["metrics"][field]["mean"]
        differences[field] = (
            round(float(left_mean) - float(right_mean), 4)
            if left_mean is not None and right_mean is not None
            else None
        )
    return differences


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare or aggregate blinded AI context reviews")
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("study", type=Path)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--key-output", type=Path, required=True)
    prepare.add_argument("--seed", type=int, default=530)
    aggregate = subparsers.add_parser("aggregate")
    aggregate.add_argument("reviews", nargs="+", type=Path)
    aggregate.add_argument("--answer-key", type=Path, required=True)
    aggregate.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.command == "prepare":
        study = json.loads(args.study.read_text(encoding="utf-8"))
        review, key = create_blinded_review_package(study, seed=args.seed)
        _write_json(args.output, review)
        _write_json(args.key_output, key)
        return

    reviews = [json.loads(path.read_text(encoding="utf-8")) for path in args.reviews]
    key = json.loads(args.answer_key.read_text(encoding="utf-8"))
    _write_json(args.output, aggregate_completed_reviews(reviews, key))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
