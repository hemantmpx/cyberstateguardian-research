import json
from pathlib import Path

import pytest
from experiments.service_install_reconciliation_addendum import (
    V16_REL,
    build_addendum,
    summarize_trials,
)

ROOT = Path(__file__).resolve().parents[1]


def _v16_rows():
    analysis = json.loads((ROOT / V16_REL / "analysis/analysis.json").read_text())
    return analysis["trial_results"]


def test_v16_addendum_verifies_source_and_expected_three_arm_results():
    result = build_addendum(ROOT)

    assert result["artifact_manifest_verification"] == {
        "entries": 49,
        "verified": 49,
        "missing": 0,
        "mismatched": 0,
    }
    assert [arm["passed"] for arm in result["arm_summaries"]] == [10, 10, 10]
    assert [arm["state_add_observed"] for arm in result["arm_summaries"]] == [10, 10, 0]
    assert [arm["exact_target_event"] for arm in result["arm_summaries"]] == [10, 0, 0]
    assert [arm["wrong_object_event"] for arm in result["arm_summaries"]] == [10, 10, 10]


def test_reconciliation_cannot_cite_a_wrong_object_event():
    rows = _v16_rows()
    no_change = next(
        row for row in rows if row["condition"] == "target_no_change_with_wrong_object_event"
    )
    no_change["matched_evidence_ids"] = list(no_change["distractor_evidence_ids"])

    with pytest.raises(ValueError, match="cited non-target evidence"):
        summarize_trials(rows)


def test_same_evidence_id_cannot_be_reused_for_different_services():
    rows = _v16_rows()
    complete = next(row for row in rows if row["condition"] == "complete")
    no_change = next(
        row for row in rows if row["condition"] == "target_no_change_with_wrong_object_event"
    )
    no_change["distractor_evidence_ids"] = [complete["target_evidence_ids"][0]]

    with pytest.raises(ValueError, match="reused across objects"):
        summarize_trials(rows)
