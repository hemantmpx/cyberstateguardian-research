from __future__ import annotations

import json

from experiments.audit_scheduled_task_event_filter_api import raw_trial_ids


def _write_trial(tmp_path, task_name: str, deltas: list[dict], findings: list[dict]):
    trial_dir = tmp_path / "trial-01" / "runner"
    trial_dir.mkdir(parents=True)
    runner_path = trial_dir / "run.json"
    runner_path.write_text(
        json.dumps(
            {
                "scenarios": [
                    {
                        "kind": "scheduled_task",
                        "expected_object_key": f"scheduled_task:\\{task_name.casefold()}",
                        "deltas": deltas,
                        "findings": findings,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return runner_path.parent.parent.parent / "campaign-manifest.json"


def test_raw_trial_ids_recovers_one_exact_add_and_linked_finding(tmp_path) -> None:
    manifest_path = _write_trial(
        tmp_path,
        "CSGAPTTaskABC",
        [
            {
                "delta_id": "delta-add",
                "delta_type": "ADD",
                "object_key": "scheduled_task:\\csgapttaskabc",
            },
            {
                "delta_id": "delta-remove",
                "delta_type": "REMOVE",
                "object_key": "scheduled_task:\\csgapttaskabc",
            },
        ],
        [{"finding_id": "finding-add", "delta_id": "delta-add"}],
    )

    result = raw_trial_ids(
        manifest_path,
        {"order": 1, "target_task_name": "CSGAPTTaskABC"},
    )

    assert result["status"] == "EXACT_LINKED_IDS_FOUND"
    assert result["delta_id"] == "delta-add"
    assert result["finding_id"] == "finding-add"
    assert result["exact_add_count"] == result["linked_finding_count"] == 1


def test_raw_trial_ids_rejects_duplicate_adds_and_unlinked_findings(tmp_path) -> None:
    manifest_path = _write_trial(
        tmp_path,
        "CSGAPTTaskABC",
        [
            {
                "delta_id": "delta-add-1",
                "delta_type": "ADD",
                "object_key": "scheduled_task:\\csgapttaskabc",
            },
            {
                "delta_id": "delta-add-2",
                "delta_type": "ADD",
                "object_key": "scheduled_task:\\csgapttaskabc",
            },
        ],
        [{"finding_id": "finding-other", "delta_id": "unrelated-delta"}],
    )

    result = raw_trial_ids(
        manifest_path,
        {"order": 1, "target_task_name": "CSGAPTTaskABC"},
    )

    assert result["status"] == "IDS_NOT_UNIQUE"
    assert result["delta_id"] is None
    assert result["finding_id"] is None
    assert result["exact_add_count"] == 2
    assert result["linked_finding_count"] == 0
