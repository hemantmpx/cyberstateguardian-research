from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import statistics
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

CONDITIONS = ("registry_complete", "registry_wrong_object", "registry_no_change")
Z_95 = 1.959963984540054


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_registry_identity(value: Any) -> str:
    text = str(value or "").strip().lower().replace("\\", "/")
    while "//" in text:
        text = text.replace("//", "/")
    text = text.replace(":/", "/")
    if text.startswith("registry:"):
        text = text[len("registry:") :]
    return text.rstrip("/")


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if result.tzinfo is None:
        return result.replace(tzinfo=UTC)
    return result.astimezone(UTC)


def wilson_interval(successes: int, trials: int) -> tuple[float, float] | None:
    if trials <= 0:
        return None
    p = successes / trials
    z2 = Z_95**2
    denominator = 1 + z2 / trials
    center = (p + z2 / (2 * trials)) / denominator
    radius = Z_95 * math.sqrt(p * (1 - p) / trials + z2 / (4 * trials**2)) / denominator
    return max(0.0, center - radius), min(1.0, center + radius)


def _rows(value: Any) -> list[dict[str, Any]]:
    return [row for row in value or [] if isinstance(row, dict)]


def _target_deltas(trial: dict[str, Any]) -> list[dict[str, Any]]:
    key = normalize_registry_identity(trial.get("target_object_key"))
    return [
        row
        for row in _rows(trial.get("target", {}).get("deltas"))
        if normalize_registry_identity(row.get("object_key")) == key
    ]


def _target_findings(trial: dict[str, Any]) -> list[dict[str, Any]]:
    key = normalize_registry_identity(trial.get("target_object_key"))
    return [
        row
        for row in _rows(trial.get("target", {}).get("findings"))
        if normalize_registry_identity(row.get("object_key")) == key
    ]


def _latest_reconciliations(trial: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        latest
        for row in _rows(trial.get("target", {}).get("reconciliation_history"))
        if isinstance((latest := row.get("latest")), dict)
    ]


def _exact_wazuh_event(event: dict[str, Any], trial: dict[str, Any]) -> bool:
    expected = normalize_registry_identity(trial.get("target_object_key"))
    target = event.get("target") or {}
    attributes = event.get("attributes") or {}
    event_key = normalize_registry_identity(target.get("key"))
    raw_key = normalize_registry_identity(attributes.get("target_object"))
    if event_key != expected and raw_key != expected:
        return False
    if event.get("host_id") != trial.get("host_id"):
        return False
    if event.get("source") != "wazuh" or event.get("normalized_type") != "registry_value_modified":
        return False

    deltas = [delta for delta in _target_deltas(trial) if delta.get("delta_type") == "ADD"]
    if not deltas:
        return False
    window = deltas[0].get("observation_window") or {}
    event_time = parse_time(event.get("event_time"))
    start, end = parse_time(window.get("start")), parse_time(window.get("end"))
    tolerance = int(trial.get("protocol_parameters", {}).get("event_time_tolerance_seconds", 0))
    if not all((event_time, start, end)):
        return False
    return start - timedelta(seconds=tolerance) <= event_time <= end + timedelta(seconds=tolerance)


def _event_is_in_target_window(event: dict[str, Any], trial: dict[str, Any]) -> bool:
    deltas = [delta for delta in _target_deltas(trial) if delta.get("delta_type") == "ADD"]
    if not deltas:
        return False
    window = deltas[0].get("observation_window") or {}
    start, end = parse_time(window.get("start")), parse_time(window.get("end"))
    event_time = parse_time(event.get("event_time"))
    if not start or not end or not event_time:
        return False
    tolerance = int(trial.get("protocol_parameters", {}).get("event_time_tolerance_seconds", 0))
    return start - timedelta(seconds=tolerance) <= event_time <= end + timedelta(seconds=tolerance)


def _matched_ids(trial: dict[str, Any]) -> set[str]:
    matched: set[str] = set()
    for reconciliation in _latest_reconciliations(trial):
        matched.update(str(value) for value in reconciliation.get("matched_evidence_ids") or [])
    return matched


def _exact_target_events(trial: dict[str, Any]) -> list[dict[str, Any]]:
    events = _rows(trial.get("target", {}).get("database_exact_events")) + _rows(
        trial.get("target", {}).get("wazuh_provider_exact_events")
    )
    unique: dict[str, dict[str, Any]] = {}
    for event in events:
        event_id = str(event.get("event_id") or "")
        if event_id and _exact_wazuh_event(event, trial):
            unique[event_id] = event
    return list(unique.values())


def _condition_outcome(trial: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    condition = trial.get("condition")
    deltas = _target_deltas(trial)
    findings = _target_findings(trial)
    exact_events = _exact_target_events(trial)
    latest = _latest_reconciliations(trial)
    statuses = [str(row.get("status")) for row in latest]
    finalized_statuses = {str(row.get("status")) for row in latest if row.get("finalized") is True}
    matched = _matched_ids(trial)
    state = trial.get("target_state") or {}
    cleanup = trial.get("cleanup") or {}
    common = bool(trial.get("protocol_adherent")) and bool(trial.get("trial_pass"))

    if condition == "registry_complete":
        exact_ids = {str(event["event_id"]) for event in exact_events}
        outcome = (
            common
            and state.get("absent_before") is True
            and state.get("present_after") is True
            and sum(delta.get("delta_type") == "ADD" for delta in deltas) == 1
            and len(findings) == 1
            and bool(_rows(trial.get("target", {}).get("sysmon_exact_events")))
            and bool(exact_ids)
            and "CONSISTENT" in finalized_statuses
            and bool(exact_ids & matched)
        )
        detail = {"target_event_count": len(exact_ids), "reconciliation_statuses": statuses}
    elif condition == "registry_wrong_object":
        source_events = _rows(trial.get("source_event_ingestion", {}).get("database_verified"))
        distractor_ids = {
            str(event.get("event_id")) for event in source_events if event.get("event_id")
        }
        distractor_key = normalize_registry_identity(trial.get("distractor_object_key"))
        distractor_exact = [
            event
            for event in source_events
            if event.get("host_id") == trial.get("host_id")
            and event.get("source") == "wazuh"
            and event.get("normalized_type") == "registry_value_modified"
            and normalize_registry_identity((event.get("target") or {}).get("key"))
            == distractor_key
        ]
        distractor_in_window = [
            event for event in distractor_exact if _event_is_in_target_window(event, trial)
        ]
        outcome = (
            common
            and state.get("absent_before") is True
            and state.get("present_after") is True
            and sum(delta.get("delta_type") == "ADD" for delta in deltas) == 1
            and len(findings) == 1
            and bool(_rows(trial.get("target", {}).get("sysmon_exact_events")))
            and bool(distractor_in_window)
            and bool(
                (trial.get("bounded_distractor") or {}).get(
                    "wrong_object_event_inside_target_window"
                )
            )
            and "UNEXPLAINED" in finalized_statuses
            and (trial.get("bounded_distractor") or {}).get("finalized_status") == "UNEXPLAINED"
            and not (matched & distractor_ids)
            and not exact_events
        )
        detail = {
            "target_event_count_at_bounded_decision": len(exact_events),
            "verified_distractor_count": len(distractor_in_window),
            "reconciliation_statuses": statuses,
            "distractor_cited": bool(matched & distractor_ids),
        }
    elif condition == "registry_no_change":
        no_change = trial.get("no_change_control") or {}
        outcome = (
            common
            and no_change.get("target_absent_before") is True
            and no_change.get("target_absent_after") is True
            and no_change.get("new_delta_count") == 0
            and no_change.get("new_finding_count") == 0
            and not deltas
            and not findings
            and not _rows(trial.get("target", {}).get("sysmon_exact_events"))
            and not _rows(trial.get("target", {}).get("database_exact_events"))
        )
        detail = {"delta_count": len(deltas), "finding_count": len(findings)}
    else:
        outcome = False
        detail = {"error": f"Unknown condition {condition!r}"}

    return bool(outcome), {
        "condition": condition,
        "outcome_pass": bool(outcome),
        "runner_pass": bool(trial.get("trial_pass")),
        "protocol_adherent": bool(trial.get("protocol_adherent")),
        "target_name": trial.get("target_name"),
        "target_object_key": trial.get("target_object_key"),
        "target_state_absent_before": state.get("absent_before"),
        "target_state_present_after": state.get("present_after"),
        "delta_count": len(deltas),
        "finding_count": len(findings),
        "matched_evidence_ids": sorted(matched),
        "cleanup_pass": bool(
            cleanup.get("target_absent")
            and cleanup.get("distractor_absent")
            and cleanup.get("cleanup_probe_succeeded")
        ),
        **detail,
    }


def _trial_latencies(trial: dict[str, Any]) -> dict[str, float | None]:
    journal = trial.get("action_journal") or {}
    target_action = journal.get("target_create") or {}
    action_end = parse_time(target_action.get("completed_at"))
    observed = parse_time((trial.get("observations", {}).get("after") or {}).get("observed_at"))
    state_seconds = (observed - action_end).total_seconds() if observed and action_end else None
    state_negative = state_seconds is not None and state_seconds < 0
    if state_negative:
        state_seconds = None
    events = _exact_target_events(trial)
    event_seconds = None
    event_negative_count = 0
    if action_end and events:
        event_times = [parse_time(event.get("event_time")) for event in events]
        event_negative_count = sum(
            value is not None and value < action_end for value in event_times
        )
        offsets = [
            (value - action_end).total_seconds()
            for value in event_times
            if value and value >= action_end
        ]
        if offsets:
            event_seconds = min(offsets)
    finalized = [parse_time(row.get("finalized_at")) for row in _latest_reconciliations(trial)]
    reconciled_seconds = None
    reconciliation_negative = False
    if action_end and any(finalized):
        terminal_time = max(value for value in finalized if value)
        if terminal_time >= action_end:
            reconciled_seconds = (terminal_time - action_end).total_seconds()
        else:
            reconciliation_negative = True
    return {
        "state_observation_seconds_after_action": state_seconds,
        "state_observation_negative_excluded_count": int(state_negative),
        "target_wazuh_event_seconds_after_action": event_seconds,
        "target_wazuh_event_negative_excluded_count": event_negative_count,
        "terminal_reconciliation_seconds_after_action": reconciled_seconds,
        "terminal_reconciliation_negative_excluded_count": int(reconciliation_negative),
    }


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _metric(successes: int, trials: int) -> dict[str, Any]:
    interval = wilson_interval(successes, trials)
    return {
        "successes": successes,
        "trials": trials,
        "rate": successes / trials if trials else None,
        "wilson_95": list(interval) if interval else None,
    }


def analyze_campaign(
    campaign_dir: Path, protocol_path: Path, expected_repetitions: int = 30
) -> dict[str, Any]:
    manifest_path = campaign_dir / "campaign-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    protocol_hash = sha256_file(protocol_path)
    if manifest.get("protocol_sha256", "").lower() != protocol_hash:
        raise ValueError("Campaign protocol SHA-256 does not match the frozen protocol file.")
    protocol_text = protocol_path.read_text(encoding="utf-8")
    declared = {
        "analysis": re.search(r"Analyzer SHA-256: `([a-f0-9]{64})`", protocol_text),
        "controller": re.search(r"Windows controller SHA-256: `([a-f0-9]{64})`", protocol_text),
        "trial_runner": re.search(r"Windows trial runner SHA-256: `([a-f0-9]{64})`", protocol_text),
    }
    if any(value is None for value in declared.values()):
        raise ValueError("Frozen protocol is missing a required analysis/controller/runner hash.")
    if declared["analysis"].group(1) != sha256_file(Path(__file__)):
        raise ValueError("Analyzer does not match the SHA-256 in the frozen protocol.")
    if manifest.get("controller_script_sha256", "").lower() != declared["controller"].group(1):
        raise ValueError("Windows controller does not match the frozen protocol.")
    if manifest.get("trial_script_sha256", "").lower() != declared["trial_runner"].group(1):
        raise ValueError("Windows trial runner does not match the frozen protocol.")
    if manifest.get("execution_kind") != "prospective_same_host_controlled_holdout":
        raise ValueError("Campaign execution kind differs from the frozen holdout protocol.")
    if manifest.get("host_id") != "win11-arm-lab":
        raise ValueError("Campaign host differs from the frozen holdout protocol.")
    if manifest.get("random_seed") != 20261017:
        raise ValueError("Campaign random seed differs from the frozen protocol.")

    manifest_rows = manifest.get("schedule") or []
    condition_counts = {
        condition: sum(row.get("condition") == condition for row in manifest_rows)
        for condition in CONDITIONS
    }
    if any(count != expected_repetitions for count in condition_counts.values()):
        raise ValueError(
            f"Expected {expected_repetitions} assigned trials per condition; "
            f"found {condition_counts}."
        )
    if manifest.get("tolerance_seconds") != 10 or manifest.get("event_lookback_seconds") != 300:
        raise ValueError("Campaign timing values differ from the frozen protocol.")
    seen_trials: set[str] = set()
    trial_results: list[dict[str, Any]] = []
    for scheduled in manifest_rows:
        trial_id = str(scheduled.get("trial_id") or "")
        if not trial_id or trial_id in seen_trials:
            raise ValueError(f"Missing or duplicate scheduled trial ID: {trial_id!r}")
        seen_trials.add(trial_id)
        trial_path = campaign_dir / trial_id / "run.json"
        if not trial_path.is_file():
            trial_results.append(
                {
                    "trial_id": trial_id,
                    "condition": scheduled.get("condition"),
                    "outcome_pass": False,
                    "missing_artifact": True,
                }
            )
            continue
        trial = json.loads(trial_path.read_text(encoding="utf-8-sig"))
        if trial.get("trial_id") != trial_id:
            raise ValueError(f"Trial ID in artifact does not match manifest: {trial_id}")
        passed, result = _condition_outcome(trial)
        result["trial_id"] = trial_id
        result["scheduled_status"] = scheduled.get("status")
        result["artifact_sha256"] = sha256_file(trial_path)
        result.update(_trial_latencies(trial))
        trial_results.append(result)

    condition_summaries: dict[str, Any] = {}
    for condition in CONDITIONS:
        assigned = [row for row in trial_results if row.get("condition") == condition]
        successful = sum(bool(row.get("outcome_pass")) for row in assigned)
        condition_summaries[condition] = {
            "outcome": _metric(successful, len(assigned)),
            "assigned": len(assigned),
            "missing_artifacts": sum(bool(row.get("missing_artifact")) for row in assigned),
        }

    target_names = [str(row.get("target_name")) for row in trial_results if row.get("target_name")]
    target_keys = [
        normalize_registry_identity(row.get("target_object_key"))
        for row in trial_results
        if row.get("target_object_key")
    ]
    if len(target_names) != len(set(target_names)) or len(target_keys) != len(set(target_keys)):
        raise ValueError("Target object names/keys are not unique across campaign trials.")

    positive_conditions = {"registry_complete", "registry_wrong_object"}
    positive_rows = [row for row in trial_results if row.get("condition") in positive_conditions]
    state_detected = sum(row.get("target_state_present_after") is True for row in positive_rows)
    cleanup_passes = sum(bool(row.get("cleanup_pass")) for row in trial_results)
    latency_summary: dict[str, Any] = {}
    latency_fields = (
        "state_observation_seconds_after_action",
        "target_wazuh_event_seconds_after_action",
        "terminal_reconciliation_seconds_after_action",
    )
    for field in latency_fields:
        values = [
            float(row[field]) for row in trial_results if isinstance(row.get(field), (int, float))
        ]
        latency_summary[field] = {
            "n": len(values),
            "excluded_negative_count": sum(
                int(
                    row.get(
                        f"{field.removesuffix('_seconds_after_action')}_negative_excluded_count", 0
                    )
                )
                for row in trial_results
            ),
            "median": statistics.median(values) if values else None,
            "p95": _percentile(values, 0.95),
            "minimum": min(values) if values else None,
            "maximum": max(values) if values else None,
        }

    return {
        "schema_version": "csg-registry-reconciliation-holdout-analysis-v1",
        "campaign_id": manifest.get("experiment_id"),
        "campaign_status": manifest.get("status"),
        "execution_kind": manifest.get("execution_kind"),
        "host_id": manifest.get("host_id"),
        "protocol_sha256": protocol_hash,
        "manifest_sha256": sha256_file(manifest_path),
        "analysis_script_sha256": sha256_file(Path(__file__)),
        "random_seed": manifest.get("random_seed"),
        "tolerance_seconds": manifest.get("tolerance_seconds"),
        "event_lookback_seconds": manifest.get("event_lookback_seconds"),
        "assigned_trials": len(manifest_rows),
        "unique_targets": len(set(target_keys)),
        "condition_outcomes": condition_summaries,
        "state_plane_detection_on_changed_trials": _metric(state_detected, len(positive_rows)),
        "cleanup": _metric(cleanup_passes, len(trial_results)),
        "latency_seconds": latency_summary,
        "all_trial_protocol_pass": len(trial_results) == len(manifest_rows)
        and all(bool(row.get("protocol_adherent")) for row in trial_results),
        "all_outcomes_pass": all(bool(row.get("outcome_pass")) for row in trial_results),
        "trials": trial_results,
    }


def render_markdown(analysis: dict[str, Any]) -> str:
    def rate(metric: dict[str, Any]) -> str:
        ci = metric.get("wilson_95")
        if metric.get("rate") is None:
            return "not estimable"
        return (
            f"{metric['successes']}/{metric['trials']} ({metric['rate']:.1%}; "
            f"Wilson 95% CI {ci[0]:.1%}–{ci[1]:.1%})"
        )

    lines = [
        "# Registry Reconciliation Confirmatory Holdout",
        "",
        "## Interpretation",
        "",
        (
            "This is a controlled, single-Windows-host evaluation of exact-object state/event "
            "reconciliation. The randomized targets are inert HKCU Run values whose data is never "
            "executed. These are benign persistence-like mutations, not labeled attacks. Results "
            "do not establish malicious-activity detection accuracy or cross-host generalization."
        ),
        "",
        (
            "A bounded Wazuh service pause is used for the wrong-object control. It tests whether "
            "a previously ingested same-host, same-event-type event for a different registry value "
            "is rejected during the target decision window. It is not a permanent event-loss test; "
            "events may be buffered and recovered after restoration."
        ),
        "",
        "## Frozen Run",
        "",
        f"- Campaign: `{analysis.get('campaign_id')}` ({analysis.get('campaign_status')})",
        f"- Execution kind: `{analysis.get('execution_kind')}`",
        f"- Host: `{analysis.get('host_id')}`",
        f"- Assigned trials: {analysis.get('assigned_trials')}; unique randomized targets: "
        f"{analysis.get('unique_targets')}",
        f"- Timing rule: {analysis.get('tolerance_seconds')} s event-time tolerance; "
        f"{analysis.get('event_lookback_seconds')} s Wazuh retrieval lookback.",
        f"- Random seed: `{analysis.get('random_seed')}`",
        f"- Frozen protocol SHA-256: `{analysis.get('protocol_sha256')}`",
        f"- Campaign manifest SHA-256: `{analysis.get('manifest_sha256')}`",
        f"- Analyzer SHA-256: `{analysis.get('analysis_script_sha256')}`",
        "",
        (
            "The tolerance was selected from prior same-host calibration; it is frozen before this "
            "holdout, but this is not an independent-host or independent-calibration estimate."
        ),
        "",
        "## Primary Outcomes",
        "",
        (
            "Outcome counts use all trials assigned to the condition. Wilson 95% intervals are "
            "descriptive binomial intervals and do not account for dependence among repeated "
            "trials on one VM."
        ),
        "",
        "| Condition | Trial-level success |",
        "|---|---:|",
    ]
    labels = {
        "registry_complete": "Complete telemetry: exact target corroboration and CONSISTENT "
        "citation",
        "registry_wrong_object": "Wrong-object control: target remains UNEXPLAINED without "
        "distractor citation",
        "registry_no_change": "No-change control: no target delta/finding/event",
    }
    for condition in CONDITIONS:
        summary = analysis["condition_outcomes"][condition]
        lines.append(f"| {labels[condition]} | {rate(summary['outcome'])} |")
    lines.extend(
        [
            "",
            "- Direct-probe target presence on changed trials: "
            f"{rate(analysis['state_plane_detection_on_changed_trials'])}.",
            f"- Cleanup completed across assigned trials: {rate(analysis['cleanup'])}.",
            "- Per-trial results and artifact IDs are in `analysis.json` and raw `run.json` files.",
            "",
            "## Timing",
            "",
            (
                "Latency is reported only where timestamps are present and parseable; negative "
                "intervals are excluded and counted. State "
                "observation is measured from target mutation completion to the probe observation "
                "timestamp; Wazuh event latency is measured from mutation completion to the "
                "matching event timestamp; terminal reconciliation includes the configured "
                "lifecycle wait. "
                "These quantities are descriptive for this runner and endpoint, not a general "
                "sensor-latency model."
            ),
            "",
            "| Measure | n | Median (s) | P95 (s) | Min–max (s) |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for key, label in (
        ("state_observation_seconds_after_action", "State observation after mutation"),
        ("target_wazuh_event_seconds_after_action", "Exact Wazuh event after mutation"),
        ("terminal_reconciliation_seconds_after_action", "Terminal reconciliation after mutation"),
    ):
        item = analysis["latency_seconds"][key]
        median = "—" if item["median"] is None else f"{item['median']:.3f}"
        p95 = "—" if item["p95"] is None else f"{item['p95']:.3f}"
        span = "—" if item["minimum"] is None else f"{item['minimum']:.3f}–{item['maximum']:.3f}"
        lines.append(f"| {label} | {item['n']} | {median} | {p95} | {span} |")
    lines.extend(
        [
            "",
            "## Trial Table",
            "",
            "| Trial | Condition | Target | State seen | Target events | Distractor events | "
            "Reconciliation | Pass | Cleanup |",
            "|---|---|---|:---:|---:|---:|---|:---:|:---:|",
        ]
    )
    for row in analysis["trials"]:
        status = ",".join(row.get("reconciliation_statuses", [])) or "—"
        target_event_count = row.get(
            "target_event_count", row.get("target_event_count_at_bounded_decision", 0)
        )
        lines.append(
            f"| {row.get('trial_id', '—')} | {row.get('condition', '—')} | "
            f"`{row.get('target_name', '—')}` | "
            f"{'yes' if row.get('target_state_present_after') else 'no'} | "
            f"{target_event_count} | "
            f"{row.get('verified_distractor_count', 0)} | {status} | "
            f"{'yes' if row.get('outcome_pass') else 'no'} | "
            f"{'yes' if row.get('cleanup_pass') else 'no'} |"
        )
    lines.extend(
        [
            "",
            "## Scope And Limitations",
            "",
            "- Same-host repetitions are not independent endpoint replications; binomial intervals "
            "are not population-level Windows estimates.",
            "- The positive condition tests corroboration of a benign registry value write, not "
            "whether CSG distinguishes malicious from benign intent.",
            "- The wrong-object control tests rejection of a temporally nearby, same-host, "
            "same-type event for a different object. Wazuh may later recover the target event "
            "after "
            "restoration.",
            "- The fixed tolerance was informed by prior same-host calibration, not an independent "
            "calibration cohort.",
            "- This campaign does not replace independent security-behavior labels, another "
            "Windows host, human AI scoring, or venue-specific statistical review.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-repetitions", type=int, default=30)
    args = parser.parse_args()
    analysis = analyze_campaign(
        args.campaign_dir, args.protocol, expected_repetitions=args.expected_repetitions
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    analysis_path = args.output_dir / "analysis.json"
    report_path = args.output_dir / "RESULTS.md"
    analysis_path.write_text(json.dumps(analysis, indent=2) + "\n", encoding="utf-8")
    report_path.write_text(render_markdown(analysis), encoding="utf-8")
    campaign_dir = args.campaign_dir
    protocol_path = args.protocol
    provenance_path = protocol_path.parent / "provenance-pretrial.json"
    files: list[tuple[str, Path]] = [
        ("PROTOCOL.md", protocol_path),
        ("campaign-manifest.json", campaign_dir / "campaign-manifest.json"),
        ("analysis.json", analysis_path),
        ("RESULTS.md", report_path),
        ("experiments/analyze_registry_reconciliation_holdout.py", Path(__file__)),
    ]
    if provenance_path.is_file():
        files.append(("provenance-pretrial.json", provenance_path))
    for trial in analysis["trials"]:
        trial_id = trial.get("trial_id")
        if trial_id:
            trial_path = campaign_dir / str(trial_id) / "run.json"
            if trial_path.is_file():
                files.append((f"trials/{trial_id}/run.json", trial_path))
    hash_catalog = {
        "schema_version": "csg-campaign-sha256-catalog-v1",
        "campaign_id": analysis.get("campaign_id"),
        "catalog_created_at_utc": datetime.now(UTC).isoformat(),
        "self_hash_note": "This catalog intentionally does not hash itself.",
        "files": [{"path": label, "sha256": sha256_file(path)} for label, path in files],
    }
    (args.output_dir / "hash_catalog.json").write_text(
        json.dumps(hash_catalog, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote analysis to {args.output_dir}; all_outcomes_pass={analysis['all_outcomes_pass']}")


if __name__ == "__main__":
    main()
