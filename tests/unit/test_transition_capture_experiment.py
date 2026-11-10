from __future__ import annotations

import hashlib
import json

from experiments.runner.transition_capture_fixtures import run_campaign


def test_transition_fixture_campaign_writes_isolated_auditable_runs(tmp_path) -> None:
    result = run_campaign(tmp_path, repetitions=1)
    campaign_dir = tmp_path / result["campaign_id"]
    manifest = json.loads((campaign_dir / "campaign-manifest.json").read_text())

    assert result["run_count"] == 7
    assert result["passed"] == 7
    assert result["failed"] == 0
    assert manifest["execution_kind"] == "deterministic_fixture_software_validation"
    assert len(list(campaign_dir.glob("*/run.json"))) == 7
    assert len(list(campaign_dir.glob("*/validation.json"))) == 7
    assert result["conditions"]["reverted"]["passed"] == 1
    assert result["conditions"]["snapshot_only_capture_gap"]["passed"] == 1
    checksums = (campaign_dir / "SHA256SUMS.txt").read_text().splitlines()
    assert len(checksums) == 17
    for line in checksums:
        expected, relative_path = line.split("  ", 1)
        artifact = campaign_dir / relative_path
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == expected
