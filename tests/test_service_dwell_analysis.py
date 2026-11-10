import json

from experiments.analyze_service_dwell_campaign import summarize, wilson_interval


def test_wilson_interval_handles_empty_and_small_samples():
    assert wilson_interval(0, 0) is None
    low, high = wilson_interval(2, 2)
    assert 0 < low < 1
    assert low < high == 1


def test_summary_keeps_incomplete_trials_out_of_rate_but_visible(tmp_path):
    (tmp_path / "campaign-manifest.json").write_text(
        json.dumps(
            {
                "campaign_id": "test",
                "status": "INCOMPLETE",
                "host_id": "lab",
                "scheduled_trials": 3,
                "completed_trials": 3,
                "not_run_trials": 0,
                "trials": [],
            }
        ),
        encoding="utf-8",
    )
    for name, condition, dwell, outcome in [
        ("trial-001", "dwell", 2, "CAPTURED"),
        ("trial-002", "dwell", 2, "NOT_CAPTURED"),
        ("trial-003", "dwell", 2, "INCOMPLETE_MONITOR_UNHEALTHY"),
    ]:
        trial_dir = tmp_path / name
        trial_dir.mkdir()
        (trial_dir / "run.json").write_text(
            json.dumps(
                {
                    "trial_id": name,
                    "condition": condition,
                    "planned_dwell_seconds": dwell,
                    "actual_dwell_seconds": 2.01,
                    "validation": {"outcome": outcome},
                    "cleanup": {"attempted": True, "completed": True},
                }
            ),
            encoding="utf-8",
        )

    result = summarize(tmp_path)
    row = result["condition_summaries"][0]
    assert row["scheduled"] == 3
    assert row["evaluable"] == 2
    assert row["primary_numerator"] == 1
    assert row["incomplete_or_integrity_failures"] == 1
    assert row["outcomes"]["INCOMPLETE_MONITOR_UNHEALTHY"] == 1
