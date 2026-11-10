"""Validate a checkpointed Windows live telemetry campaign manifest."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path, PureWindowsPath
from typing import Any

VALID_STATUSES = {"PENDING", "RUNNING", "COMPLETED", "FAILED"}


def _resolve_trial_output(root: Path, trial_id: str, output: str) -> Path | None:
    """Resolve local and copied Windows paths without relaxing root containment."""
    if len(output) >= 3 and output[1] == ":" and output[2] in {"\\", "/"}:
        windows_name = PureWindowsPath(output).name
        if windows_name != "run.json":
            return None
        return root / trial_id / windows_name

    candidate = Path(output)
    resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    if root not in resolved.parents:
        return None
    return resolved


def validate_manifest(path: Path, *, require_complete: bool = True) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    errors: list[str] = []
    schedule = manifest.get("schedule")
    conditions = manifest.get("conditions")
    if manifest.get("schema_version") not in {
        "csg-live-telemetry-campaign-v3",
        "csg-live-telemetry-campaign-v4",
        "csg-live-telemetry-campaign-v5",
    }:
        errors.append("unsupported campaign manifest schema")
    if manifest.get("schema_version") == "csg-live-telemetry-campaign-v5":
        for field in ("protocol_sha256", "controller_sha256", "drill_sha256"):
            value = manifest.get(field)
            if not isinstance(value, str) or re.fullmatch(r"[a-fA-F0-9]{64}", value) is None:
                errors.append(f"{field} must be a 64-character SHA-256")
        if manifest.get("execution_kind") not in {
            "engineering_pilot_not_pooled",
            "prospective_same_host_confirmatory_controlled_holdout",
        }:
            errors.append("v5 execution_kind is missing or unsupported")
        tolerance = manifest.get("declared_event_time_tolerance_seconds")
        lookback = manifest.get("declared_wazuh_event_lookback_seconds")
        if not isinstance(tolerance, int) or not 0 <= tolerance <= 120:
            errors.append("v5 event-time tolerance must be an integer in [0, 120]")
        if not isinstance(lookback, int) or not 60 <= lookback <= 86400:
            errors.append("v5 Wazuh event lookback must be an integer in [60, 86400]")
    if not isinstance(schedule, list) or not schedule:
        errors.append("schedule must contain at least one trial")
        schedule = []
    if not isinstance(conditions, list) or not conditions:
        errors.append("conditions must be a non-empty list")
        conditions = []

    trial_ids: set[str] = set()
    condition_counts: dict[str, int] = {}
    root = path.parent.resolve()
    for entry in schedule:
        trial_id = str(entry.get("trial_id", ""))
        if not trial_id:
            errors.append("schedule entry has no trial_id")
            continue
        if trial_id in trial_ids:
            errors.append(f"duplicate trial_id: {trial_id}")
        trial_ids.add(trial_id)
        condition = str(entry.get("condition", ""))
        condition_counts[condition] = condition_counts.get(condition, 0) + 1
        status = entry.get("status")
        if status not in VALID_STATUSES:
            errors.append(f"{trial_id}: invalid status {status!r}")
        output = entry.get("output")
        if not isinstance(output, str) or not output:
            errors.append(f"{trial_id}: missing output path")
            continue
        output_path = _resolve_trial_output(root, trial_id, output)
        if output_path is None:
            errors.append(f"{trial_id}: output path escapes campaign directory")
            continue
        failure_path = output_path.parent / "failure.json"
        if status == "COMPLETED" and not output_path.exists():
            errors.append(f"{trial_id}: completed trial output is missing")
        if status == "FAILED":
            if not failure_path.exists():
                errors.append(f"{trial_id}: failed trial has no failure.json")
            if not entry.get("failure_reason"):
                errors.append(f"{trial_id}: failed trial has no failure_reason")
        if require_complete and status in {"PENDING", "RUNNING"}:
            errors.append(f"{trial_id}: campaign is incomplete ({status})")

    unexpected = sorted(set(condition_counts) - set(conditions))
    if unexpected:
        errors.append(f"schedule contains undeclared conditions: {', '.join(unexpected)}")
    if manifest.get("schema_version") == "csg-live-telemetry-campaign-v5":
        missing = sorted(set(conditions) - set(condition_counts))
        if missing:
            errors.append(f"declared conditions have no scheduled trials: {', '.join(missing)}")
        if len(set(condition_counts.values())) > 1:
            errors.append("v5 condition schedule is unbalanced")
    if require_complete and manifest.get("status") not in {"COMPLETED", "COMPLETED_WITH_FAILURES"}:
        errors.append(f"campaign status is not final: {manifest.get('status')!r}")

    return {
        "schema_version": "csg-live-telemetry-campaign-validation-v1",
        "campaign_schema_version": manifest.get("schema_version"),
        "experiment_id": manifest.get("experiment_id"),
        "campaign_status": manifest.get("status"),
        "trial_count": len(schedule),
        "condition_counts": dict(sorted(condition_counts.items())),
        "completed_trials": sum(entry.get("status") == "COMPLETED" for entry in schedule),
        "failed_trials": sum(entry.get("status") == "FAILED" for entry in schedule),
        "passed": not errors,
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a CSG live campaign manifest")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = validate_manifest(args.manifest, require_complete=not args.allow_incomplete)
    payload = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
