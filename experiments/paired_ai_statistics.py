"""Subject-level paired analysis with explicit reviewer identity and duplicate checks."""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from itertools import combinations
from pathlib import Path

from experiments.ai_context_evaluation import SCORE_FIELDS, _valid_score

FIELDS = (*SCORE_FIELDS, "root_cause_identification_correct", "unsupported_claim_count")


def paired_statistics(
    reviews: list[dict], answer_key: dict[str, str], *, seed=530, resamples=9999
) -> dict:
    import numpy as np
    from scipy.stats import binomtest, bootstrap

    if resamples < 100:
        raise ValueError("at least 100 bootstrap resamples are required")
    seen = {}
    blocks = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    rating_pairs = defaultdict(dict)
    excluded = 0
    for review in reviews:
        reviewer = review.get("reviewer_id")
        if not isinstance(reviewer, str) or not reviewer.strip():
            raise ValueError("each review requires a nonempty reviewer_id")
        for item in review.get("items", []):
            identity = (reviewer, item["review_id"])
            if identity in seen:
                if seen[identity] != item:
                    raise ValueError(f"conflicting duplicate review: {identity}")
                continue
            seen[identity] = item
            scores = item.get("scores", {})
            condition = answer_key.get(item["review_id"])
            subject = item.get("subject")
            if (
                condition not in ("A", "B", "C", "D")
                or not subject
                or not item.get("analysis")
                or not all(_valid_score(scores.get(field)) for field in SCORE_FIELDS)
                or type(scores.get("root_cause_identification_correct")) is not bool
                or type(scores.get("unsupported_claim_count")) is not int
                or scores["unsupported_claim_count"] < 0
            ):
                excluded += 1
                continue
            subject_id = json.dumps(subject, sort_keys=True)
            blocks[subject_id][reviewer][condition].append(scores)
            rating_pairs[item["review_id"]][reviewer] = scores

    results = {}
    for left, right in (("C", "A"), ("C", "B"), ("D", "B"), ("D", "C")):
        differences = {field: [] for field in FIELDS}
        subjects = []
        for subject, reviewers in sorted(blocks.items()):
            paired_reviewers = [
                ratings for ratings in reviewers.values() if left in ratings and right in ratings
            ]
            if not paired_reviewers:
                continue
            subjects.append(json.loads(subject))
            for field in FIELDS:
                # Average trials per reviewer, then reviewers per subject. Subjects are the unit.
                differences[field].append(
                    statistics.mean(
                        statistics.mean(float(r[field]) for r in ratings[left])
                        - statistics.mean(float(r[field]) for r in ratings[right])
                        for ratings in paired_reviewers
                    )
                )
        metrics = {}
        for field, values in differences.items():
            n = len(values)
            nonzero = [value for value in values if value != 0]
            pvalue = None
            interval = None
            if n >= 2:
                pvalue = (
                    float(binomtest(sum(v > 0 for v in nonzero), len(nonzero)).pvalue)
                    if nonzero
                    else 1.0
                )
                if len(set(values)) == 1:
                    interval = [values[0], values[0]]
                else:
                    ci = bootstrap(
                        (np.asarray(values),),
                        np.mean,
                        method="percentile",
                        n_resamples=resamples,
                        rng=np.random.default_rng(seed),
                    ).confidence_interval
                    interval = [float(ci.low), float(ci.high)]
            metrics[field] = {
                "n_subjects": n,
                "n_nonzero_pairs": len(nonzero),
                "mean_difference": statistics.mean(values) if n else None,
                "bootstrap_95_percentile_ci": interval,
                "sign_test_two_sided_p": pvalue,
                "bonferroni_p": min(1.0, pvalue * 2 * len(FIELDS)) if pvalue is not None else None,
            }
        results[f"{left}_minus_{right}"] = {"subjects": subjects, "metrics": metrics}
    agreement = {}
    for field in FIELDS:
        gaps = [
            abs(float(a[field]) - float(b[field]))
            for ratings in rating_pairs.values()
            for a, b in combinations(ratings.values(), 2)
        ]
        agreement[field] = {
            "reviewer_pairs": len(gaps),
            "mean_absolute_difference": statistics.mean(gaps) if gaps else None,
        }
    return {
        "schema_version": "csg-ai-paired-statistics-v1",
        "seed": seed,
        "bootstrap_resamples": resamples,
        "excluded_invalid": excluded,
        "unique_rating_records": len(seen),
        "comparisons": results,
        "descriptive_reviewer_agreement": agreement,
        "method": "Trial means within reviewer, paired reviewer differences within subject; "
        "independent subjects resampled. Exact sign tests exclude ties. Bonferroni "
        "family is both comparisons across all seven metrics. CIs are not simultaneous.",
        "limitations": "At least two subjects required for inference; small samples are unstable. "
        "Independence and prespecified hypotheses require researcher justification. "
        "Negative unsupported-claim differences favor C; higher other scores favor C.",
    }


def main():
    parser = argparse.ArgumentParser(description="Paired subject-level AI review statistics")
    parser.add_argument("reviews", nargs="+", type=Path)
    parser.add_argument("--answer-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seed", default=530, type=int)
    parser.add_argument("--resamples", default=9999, type=int)
    args = parser.parse_args()
    result = paired_statistics(
        [json.loads(p.read_text()) for p in args.reviews],
        json.loads(args.answer_key.read_text()),
        seed=args.seed,
        resamples=args.resamples,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
