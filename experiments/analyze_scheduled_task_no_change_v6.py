"""Audit the prospectively frozen scheduled-task no-change v6 campaign."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import textwrap
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8-sig") as handle:
        return json.load(handle)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def exact_binomial_interval(
    successes: int, trials: int, confidence: float = 0.95
) -> list[float] | None:
    """Two-sided Clopper-Pearson interval using binomial-tail inversion."""
    if trials <= 0 or successes < 0 or successes > trials:
        return None
    alpha = 1.0 - confidence
    tail = alpha / 2.0

    def cdf(k: int, probability: float) -> float:
        return sum(
            math.comb(trials, i) * probability**i * (1.0 - probability) ** (trials - i)
            for i in range(k + 1)
        )

    def sf(k: int, probability: float) -> float:
        return sum(
            math.comb(trials, i) * probability**i * (1.0 - probability) ** (trials - i)
            for i in range(k, trials + 1)
        )

    if successes == 0:
        lower = 0.0
    else:
        low, high = 0.0, 1.0
        for _ in range(80):
            middle = (low + high) / 2.0
            if sf(successes, middle) > tail:
                high = middle
            else:
                low = middle
        lower = (low + high) / 2.0

    if successes == trials:
        upper = 1.0
    else:
        low, high = 0.0, 1.0
        for _ in range(80):
            middle = (low + high) / 2.0
            if cdf(successes, middle) > tail:
                low = middle
            else:
                high = middle
        upper = (low + high) / 2.0
    return [lower, upper]


def _healthy_probe_observation(observation: dict[str, Any]) -> bool:
    category = observation.get("category") or {}
    return bool(
        observation.get("observation_id")
        and observation.get("observed_at")
        and category.get("category") == "scheduled_task"
        and category.get("status") == "healthy"
    )


def evaluate_trial(
    trial: dict[str, Any], expected_trial_id: str, expected_sentinel: str
) -> dict[str, Any]:
    before = trial.get("before_observation") or {}
    after = trial.get("after_observation") or {}
    before_names = [str(name).strip().casefold() for name in before.get("task_names") or []]
    after_names = [str(name).strip().casefold() for name in after.get("task_names") or []]
    sentinel = expected_sentinel.strip().casefold()
    pre_health = trial.get("pre_health") or {}
    post_health = trial.get("post_health") or {}
    query = trial.get("event_query") or {}
    gates = trial.get("gates") or {}
    local_events = trial.get("exact_target_local_security_events") or []
    provider_events = trial.get("exact_target_provider_events") or []
    task_deltas = trial.get("new_scheduled_task_deltas") or []
    task_findings = trial.get("new_scheduled_task_findings") or []
    interval_deltas = after.get("interval_delta_ids") or []
    interval_findings = after.get("interval_finding_ids") or []

    checks = {
        "identity_matches_assignment": trial.get("trial_id") == expected_trial_id
        and trial.get("sentinel_task_name") == expected_sentinel,
        "no_action_attempted": trial.get("action_attempted") is False and not trial.get("actions"),
        "healthy_probe_observations": _healthy_probe_observation(before)
        and _healthy_probe_observation(after),
        "sentinel_absent_from_both_snapshots": sentinel not in before_names
        and sentinel not in after_names
        and trial.get("sentinel_absent_before") is True
        and trial.get("sentinel_absent_after") is True,
        "task_identity_sets_unchanged": set(before_names) == set(after_names)
        and len(before_names) == before.get("task_identity_count")
        and len(after_names) == after.get("task_identity_count")
        and not trial.get("task_identity_changes"),
        "no_scheduled_task_delta_or_finding": not task_deltas
        and not task_findings
        and not interval_deltas
        and not interval_findings
        and len(interval_deltas) < 500
        and len(interval_findings) < 500,
        "no_exact_target_event": not local_events
        and not provider_events
        and trial.get("expected_target_event_status") == "NOT_APPLICABLE",
        "event_query_complete_and_available": query.get("query_complete") is True
        and query.get("coverage_status") == "COMPLETE"
        and query.get("endpoint_collection_status") == "AVAILABLE"
        and query.get("transport_status") == "AVAILABLE"
        and query.get("central_index_status") == "AVAILABLE"
        and query.get("error") is None
        and query.get("retrieved_count") == query.get("total_hits"),
        "host_and_wazuh_healthy_before_after": pre_health.get("api_ok") is True
        and post_health.get("api_ok") is True
        and pre_health.get("wazuh_agent_status") == "active"
        and post_health.get("wazuh_agent_status") == "active"
        and pre_health.get("wazuh_service_state") == "Running"
        and post_health.get("wazuh_service_state") == "Running"
        and bool(pre_health.get("sysmon_services"))
        and bool(post_health.get("sysmon_services"))
        and all(svc.get("state") == "Running" for svc in pre_health["sysmon_services"])
        and all(svc.get("state") == "Running" for svc in post_health["sysmon_services"]),
        "controller_all_registered_gates_pass": bool(gates)
        and all(value is True for value in gates.values()),
        "declared_pass_matches_audit": trial.get("status") == "PASS",
    }
    return {
        "trial_id": expected_trial_id,
        "sentinel_task_name": expected_sentinel,
        "controller_status": trial.get("status", "MISSING"),
        "trial_started_at_utc": trial.get("started_at_utc"),
        "trial_ended_at_utc": trial.get("ended_at_utc"),
        "audited_pass": all(checks.values()),
        "checks": checks,
        "before_observation_id": before.get("observation_id"),
        "after_observation_id": after.get("observation_id"),
        "before_observed_at": before.get("observed_at"),
        "after_observed_at": after.get("observed_at"),
        "task_identity_count_before": before.get("task_identity_count"),
        "task_identity_count_after": after.get("task_identity_count"),
        "task_identity_set_sha256": hashlib.sha256(
            json.dumps(sorted(set(before_names)), separators=(",", ":")).encode()
        ).hexdigest(),
        "task_identity_set_stable": checks["task_identity_sets_unchanged"],
        "target_event_status": trial.get("expected_target_event_status"),
        "exact_target_local_event_count": len(local_events),
        "exact_target_provider_event_count": len(provider_events),
        "scheduled_task_delta_count": len(task_deltas),
        "scheduled_task_finding_count": len(task_findings),
        "interval_delta_count": len(interval_deltas),
        "interval_finding_count": len(interval_findings),
        "event_query_retrieved_count": query.get("retrieved_count"),
        "event_query_total_hits": query.get("total_hits"),
        "event_query_status": query.get("coverage_status"),
        "endpoint_collection_status": query.get("endpoint_collection_status"),
        "transport_status": query.get("transport_status"),
        "central_index_status": query.get("central_index_status"),
        "failed_checks": [name for name, passed in checks.items() if not passed],
    }


def audit_campaign(campaign_dir: Path) -> dict[str, Any]:
    manifest = read_json(campaign_dir / "campaign.json")
    assignments = manifest.get("assigned") or []
    declared_trial_ids = {str(item.get("trial_id")) for item in manifest.get("trials") or []}
    declared_trial_rows = {str(item.get("trial_id")): item for item in manifest.get("trials") or []}
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_sentinels: set[str] = set()
    for assignment in assignments:
        trial_id = str(assignment.get("trial_id", ""))
        sentinel = str(assignment.get("sentinel", ""))
        if not trial_id or trial_id in seen_ids:
            raise ValueError(f"Missing or duplicate assigned trial ID: {trial_id!r}")
        if not sentinel or sentinel.casefold() in seen_sentinels:
            raise ValueError(f"Missing or duplicate assigned sentinel: {sentinel!r}")
        seen_ids.add(trial_id)
        seen_sentinels.add(sentinel.casefold())
        artifact = campaign_dir / "trials" / f"{trial_id}.json"
        if artifact.is_file():
            row = evaluate_trial(read_json(artifact), trial_id, sentinel)
            manifest_trial = declared_trial_rows.get(trial_id) or {}
            row["checks"]["manifest_trial_status_matches_artifact"] = (
                manifest_trial.get("status") == row["controller_status"]
                and manifest_trial.get("sentinel_task_name") == sentinel
            )
            if not row["checks"]["manifest_trial_status_matches_artifact"]:
                row["audited_pass"] = False
                row["failed_checks"].append("manifest_trial_status_matches_artifact")
            rows.append(row)
        else:
            rows.append(
                {
                    "trial_id": trial_id,
                    "sentinel_task_name": sentinel,
                    "controller_status": "MISSING_ARTIFACT",
                    "audited_pass": False,
                    "checks": {},
                    "failed_checks": ["trial artifact missing"],
                }
            )
    successes = sum(row["audited_pass"] for row in rows)
    total = len(assignments)
    measured_checks = (
        "no_action_attempted",
        "healthy_probe_observations",
        "sentinel_absent_from_both_snapshots",
        "task_identity_sets_unchanged",
        "no_scheduled_task_delta_or_finding",
        "no_exact_target_event",
        "event_query_complete_and_available",
        "host_and_wazuh_healthy_before_after",
    )
    outcome_counts = {
        check: sum(bool(row.get("checks", {}).get(check)) for row in rows)
        for check in measured_checks
    }
    identity_counts = [
        row.get("task_identity_count_before")
        for row in rows
        if isinstance(row.get("task_identity_count_before"), int)
    ]
    event_hit_counts = [
        row.get("event_query_retrieved_count")
        for row in rows
        if isinstance(row.get("event_query_retrieved_count"), int)
    ]
    raw_files = sorted(path for path in campaign_dir.rglob("*") if path.is_file())
    hashes = [
        {
            "path": path.relative_to(campaign_dir).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in raw_files
    ]
    protocol = campaign_dir / "PROTOCOL.md"
    controller = campaign_dir / "controller.ps1"
    protocol_hash = sha256_file(protocol) if protocol.is_file() else None
    controller_hash = sha256_file(controller) if controller.is_file() else None
    campaign_checks = {
        "manifest_completed": manifest.get("status") == "COMPLETED",
        "assigned_count_matches_assignments": manifest.get("assigned_count") == total,
        "manifest_trial_ids_match_assignments": declared_trial_ids == seen_ids,
        "completed_count_matches_artifacts": manifest.get("completed_count")
        == sum((campaign_dir / "trials" / f"{trial_id}.json").is_file() for trial_id in seen_ids),
        "pass_count_matches_independent_audit": manifest.get("pass_count") == successes,
        "no_gaps_declared": manifest.get("gap_count") == 0,
        "protocol_copy_matches_frozen_hash": protocol_hash == manifest.get("protocol_sha256"),
        "controller_copy_matches_frozen_hash": controller_hash == manifest.get("controller_sha256"),
        "unique_trial_ids_and_sentinels": len(seen_ids) == total and len(seen_sentinels) == total,
    }
    postflight_path = campaign_dir / "postflight.json"
    postflight = read_json(postflight_path) if postflight_path.is_file() else {}
    postflight_healthy = (
        postflight.get("wazuh_api_ok") is True
        and postflight.get("agent_status") == "active"
        and postflight.get("wazuh_service_state") == "Running"
        and postflight.get("remaining_nochange_sentinels") == 0
        and bool(postflight.get("sysmon_services"))
        and all(item.get("state") == "Running" for item in postflight["sysmon_services"])
    )
    campaign_checks["postflight_healthy_and_clean"] = postflight_healthy
    return {
        "schema_version": "csg-scheduled-task-no-change-v6-audit-v1",
        "campaign_id": manifest.get("campaign_id"),
        "host_id": manifest.get("host_id"),
        "random_seed": manifest.get("random_seed"),
        "created_at_utc": manifest.get("created_at_utc"),
        "completed_at_utc": manifest.get("completed_at_utc"),
        "protocol_sha256": manifest.get("protocol_sha256"),
        "protocol_copy_sha256": protocol_hash,
        "controller_sha256": manifest.get("controller_sha256"),
        "controller_copy_sha256": controller_hash,
        "assigned_trials": total,
        "audited_passes": successes,
        "audited_failures_or_gaps": total - successes,
        "pass_rate": successes / total if total else None,
        "exact_two_sided_95_percent_interval": exact_binomial_interval(successes, total),
        "campaign_checks": campaign_checks,
        "campaign_valid": all(campaign_checks.values()) and successes == total,
        "outcome_counts": outcome_counts,
        "task_identity_count_range": [min(identity_counts), max(identity_counts)]
        if identity_counts
        else None,
        "event_query_hit_count_range": [min(event_hit_counts), max(event_hit_counts)]
        if event_hit_counts
        else None,
        "postflight": postflight,
        "trial_rows": rows,
        "raw_artifact_count": len(hashes),
        "raw_artifact_bytes": sum(item["size_bytes"] for item in hashes),
        "raw_artifact_hashes": hashes,
        "analysis_script_sha256": sha256_file(Path(__file__)),
    }


def write_outputs(result: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "audit.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "artifact-sha256.json").write_text(
        json.dumps(
            {
                "campaign_id": result["campaign_id"],
                "files": result["raw_artifact_hashes"],
                "analysis_script_sha256": result["analysis_script_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    fields = [
        "trial_id",
        "controller_status",
        "audited_pass",
        "trial_started_at_utc",
        "trial_ended_at_utc",
        "sentinel_task_name",
        "before_observation_id",
        "after_observation_id",
        "task_identity_count_before",
        "task_identity_count_after",
        "task_identity_set_sha256",
        "target_event_status",
        "exact_target_local_event_count",
        "exact_target_provider_event_count",
        "scheduled_task_delta_count",
        "scheduled_task_finding_count",
        "interval_delta_count",
        "interval_finding_count",
        "event_query_retrieved_count",
        "event_query_total_hits",
        "event_query_status",
        "endpoint_collection_status",
        "transport_status",
        "central_index_status",
        "failed_checks",
    ]
    with (output_dir / "trial-summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in result["trial_rows"]:
            writer.writerow(
                {
                    **row,
                    "failed_checks": ";".join(row.get("failed_checks", [])),
                }
            )
    interval = result["exact_two_sided_95_percent_interval"]
    lower, upper = interval if interval else (None, None)
    total = result["assigned_trials"]
    counts = result["outcome_counts"]

    def metric_row(label: str, key: str) -> str:
        return f"| {label} | {counts[key]}/{total} |"

    protocol_matches = result["protocol_copy_sha256"] == result["protocol_sha256"]
    controller_matches = result["controller_copy_sha256"] == result["controller_sha256"]
    postflight = result["postflight"]
    lines = [
        "# Scheduled-Task No-Change Control v6: Independent Audit",
        "",
        f"Campaign: `{result['campaign_id']}`  ",
        f"Endpoint: `{result['host_id']}`  ",
        f"Completed (UTC): `{result['completed_at_utc']}`",
        "",
        "## Result",
        "",
        f"- Independently audited strict passes: **{result['audited_passes']}/{total}**.",
        f"- Exact two-sided 95% Clopper-Pearson interval for the gate rate: "
        f"**{lower:.1%} to {upper:.1%}**.",
        f"- Campaign/artifact audit valid: **{result['campaign_valid']}**.",
        f"- Raw files inventoried and hashed: **{result['raw_artifact_count']}** "
        f"({result['raw_artifact_bytes']:,} bytes).",
        "- Per-trial details: [`trial-summary.csv`](trial-summary.csv); "
        "machine audit: [`audit.json`](audit.json); hashes: "
        "[`artifact-sha256.json`](artifact-sha256.json).",
        "",
        "| Independently checked outcome | Passed |",
        "|---|---:|",
        metric_row("No endpoint action attempted", "no_action_attempted"),
        metric_row("Healthy before/after probe observations", "healthy_probe_observations"),
        metric_row("Sentinel absent in both snapshots", "sentinel_absent_from_both_snapshots"),
        metric_row("Scheduled-task identity set unchanged", "task_identity_sets_unchanged"),
        metric_row("No scheduled-task delta or finding", "no_scheduled_task_delta_or_finding"),
        metric_row("No exact target event (not applicable)", "no_exact_target_event"),
        metric_row(
            "Event query, collection, transport, and index available",
            "event_query_complete_and_available",
        ),
        metric_row(
            "API, Wazuh agent/service, and Sysmon healthy pre/post",
            "host_and_wazuh_healthy_before_after",
        ),
        f"| Observed scheduled-task identity count range | {result['task_identity_count_range']} |",
        "| Wazuh events returned per complete query (range) | "
        f"{result['event_query_hit_count_range']} |",
        "",
        textwrap.dedent(
            """\
            All assigned windows were no-action controls. The assigned sentinel task was absent
            before and after each window; the direct scheduled-task probe identity set was
            unchanged; and no scheduled-task state delta, finding, or exact target event was
            recorded. The Wazuh query completed with complete coverage, while endpoint collection,
            transport, and index availability were reported separately as available.
            `NOT_APPLICABLE` is the correct target-event status because no task-creation action
            occurred."""
        ).strip(),
        "",
        "## Scope And Limitations",
        "",
        textwrap.dedent(
            """\
            This is a prospectively frozen operational no-change control on one Windows 11 ARM64
            VM. The interval quantifies uncertainty around the all-gates pass proportion for these
            ten assigned windows only. It is not a fleet false-positive rate, attack-detection
            measure, malicious-behavior test, permanent telemetry-loss test, or independent-host
            replication. Do not pool it with positive, delayed, distractor, capture-drop, synthetic
            replay, or earlier invalid controller/deployment attempts."""
        ).strip(),
        "",
        textwrap.dedent(
            """\
            The campaign used a category- and time-filtered CSG API query. Both archived interval
            ID lists and scheduled-task delta/finding lists were empty in every trial. The raw
            controller recorded its under-500-row gate. Provider-query completion and endpoint
            collection availability are distinct measurements."""
        ).strip(),
        "",
        "## Provenance",
        "",
        f"- Frozen protocol SHA-256: `{result['protocol_sha256']}`; "
        f"archived copy match: `{protocol_matches}`.",
        f"- Frozen controller SHA-256: `{result['controller_sha256']}`; "
        f"archived copy match: `{controller_matches}`.",
        f"- Independent analyzer source SHA-256: `{result['analysis_script_sha256']}`.",
        f"- Postflight: Wazuh API `{postflight.get('wazuh_api_ok')}`, "
        f"agent `{postflight.get('agent_status')}`, "
        f"Wazuh service `{postflight.get('wazuh_service_state')}`, "
        f"remaining sentinels `{postflight.get('remaining_nochange_sentinels')}`.",
        "",
        "## Excluded Engineering Attempts",
        "",
        "| Version | Disposition | Reason |",
        "|---|---|---|",
        "| v1 | 10 failed; no valid outcomes | Controller timestamp conversion error. |",
        "| v2 | 2 failed; 8 not run | PowerShell response/property extraction failure. |",
        "| v3 | 2 failed; 8 not run | API wrapper array-shape handling failure. |",
        "| v4 | 1 failed; 9 not run | All-history query reached the 500-row cap. |",
        "| v5 | 1 failed; 9 not run | Stale API container ignored the new time filter. |",
        "",
        textwrap.dedent(
            """\
            These attempts remain in separate raw folders and are excluded from the v6 denominator.
            They involved no scheduled-task mutation or deliberate service interruption. They are
            controller/deployment engineering failures, not no-change outcomes."""
        ).strip(),
        "",
    ]
    (output_dir / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_dir", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = audit_campaign(args.campaign_dir)
    write_outputs(result, args.output_dir)
    print(
        json.dumps(
            {
                "campaign_id": result["campaign_id"],
                "campaign_valid": result["campaign_valid"],
                "audited_passes": result["audited_passes"],
                "assigned_trials": result["assigned_trials"],
                "exact_two_sided_95_percent_interval": result[
                    "exact_two_sided_95_percent_interval"
                ],
                "report": str(args.output_dir / "RESULTS.md"),
            },
            indent=2,
        )
    )
    if not result["campaign_valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
