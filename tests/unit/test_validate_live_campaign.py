import json

from scripts.validate_live_campaign import validate_manifest


def _write_campaign(tmp_path, *, counts=(2, 2), schema="csg-live-telemetry-campaign-v5"):
    conditions = ["complete", "target_selective_drop"]
    schedule = []
    for condition, count in zip(conditions, counts, strict=True):
        for index in range(count):
            trial_id = f"{condition}-{index + 1}"
            trial_dir = tmp_path / trial_id
            trial_dir.mkdir()
            (trial_dir / "run.json").write_text("{}", encoding="utf-8")
            schedule.append(
                {
                    "condition": condition,
                    "trial_id": trial_id,
                    "status": "COMPLETED",
                    "output": f"{trial_id}/run.json",
                }
            )
    manifest = {
        "schema_version": schema,
        "experiment_id": "test-campaign",
        "status": "COMPLETED",
        "conditions": conditions,
        "schedule": schedule,
    }
    if schema == "csg-live-telemetry-campaign-v5":
        manifest.update(
            {
                "execution_kind": "engineering_pilot_not_pooled",
                "protocol_sha256": "a" * 64,
                "controller_sha256": "b" * 64,
                "drill_sha256": "c" * 64,
                "declared_event_time_tolerance_seconds": 10,
                "declared_wazuh_event_lookback_seconds": 300,
            }
        )
    path = tmp_path / "campaign-manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_v5_manifest_validates_balanced_trials_and_frozen_hashes(tmp_path):
    result = validate_manifest(_write_campaign(tmp_path))

    assert result["passed"] is True
    assert result["campaign_schema_version"] == "csg-live-telemetry-campaign-v5"
    assert result["condition_counts"] == {"complete": 2, "target_selective_drop": 2}


def test_v5_manifest_rejects_unbalanced_conditions(tmp_path):
    result = validate_manifest(_write_campaign(tmp_path, counts=(2, 1)))

    assert result["passed"] is False
    assert "v5 condition schedule is unbalanced" in result["errors"]


def test_v5_manifest_rejects_invalid_protocol_digest(tmp_path):
    path = _write_campaign(tmp_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["protocol_sha256"] = "not-a-digest"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    result = validate_manifest(path)

    assert result["passed"] is False
    assert "protocol_sha256 must be a 64-character SHA-256" in result["errors"]


def test_v4_manifest_remains_supported(tmp_path):
    path = _write_campaign(tmp_path, schema="csg-live-telemetry-campaign-v4")

    result = validate_manifest(path)

    assert result["passed"] is True
