"""Paired, post-hoc method comparison for target-selective service suppression trials."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

CONDITION_KEY = "target_selective_suppression_with_same_host_distractor"
CHECK_NAME = "target_selective_suppression_and_distractor"
EVENT_TYPE = "service_modified"
Z_95 = 1.959963984540054


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _event_param(raw_xml: str, name: str) -> str | None:
    root = ElementTree.fromstring(raw_xml)
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "Data" and element.attrib.get("Name") == name:
            return element.text
    return None


def wilson_interval(successes: int, total: int) -> list[float] | None:
    if total <= 0:
        return None
    p = successes / total
    z2 = Z_95**2
    denominator = 1 + z2 / total
    center = (p + z2 / (2 * total)) / denominator
    margin = Z_95 * math.sqrt(p * (1 - p) / total + z2 / (4 * total**2)) / denominator
    return [max(0.0, center - margin), min(1.0, center + margin)]


def exact_mcnemar_two_sided(discordant_a: int, discordant_b: int) -> float:
    """Exact two-sided McNemar p-value from discordant paired outcomes."""
    n = discordant_a + discordant_b
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, k) for k in range(min(discordant_a, discordant_b) + 1)) / 2**n
    return min(1.0, 2 * tail)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def analyze_trial(
    trial_id: str,
    run: dict[str, Any],
    validation: dict[str, Any],
    *,
    run_sha256: str | None = None,
    validation_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify a trial's paired evidence and derive explicit matcher ablations."""
    _require(validation.get("passed") is True, f"{trial_id}: strict validation failed")
    checks = {row.get("name"): row.get("status") for row in validation.get("checks", [])}
    _require(checks.get(CHECK_NAME) == "PASS", f"{trial_id}: suppression check did not pass")
    _require(run.get("run_status") == "COMPLETED", f"{trial_id}: run is not completed")
    _require(
        run.get("telemetry_condition") == "target_selective_drop",
        f"{trial_id}: unexpected telemetry condition",
    )

    host_id = str(run.get("host_id") or "")
    service_name = str(run.get("service_name") or "")
    object_key = f"service:{service_name.casefold()}"
    _require(host_id and service_name, f"{trial_id}: missing host or target identity")

    target_deltas = [
        delta
        for delta in run.get("target_state_deltas", [])
        if str(delta.get("object_key", "")).casefold() == object_key
        and delta.get("delta_type") == "MODIFY"
    ]
    _require(len(target_deltas) == 1, f"{trial_id}: expected one target MODIFY delta")
    delta = target_deltas[0]
    before = delta.get("before") or {}
    after = delta.get("after") or {}
    before_attrs = before.get("attributes") or {}
    after_attrs = after.get("attributes") or {}
    _require(
        before_attrs.get("start_mode") == "manual" and after_attrs.get("start_mode") == "auto",
        f"{trial_id}: state delta is not the registered Manual-to-Auto transition",
    )
    _require(
        (before.get("metadata") or {}).get("source") == "direct_probe"
        and (after.get("metadata") or {}).get("source") == "direct_probe"
        and (before.get("metadata") or {}).get("observation_id")
        and (after.get("metadata") or {}).get("observation_id"),
        f"{trial_id}: both transition states must be direct-probe observations",
    )

    findings = [
        finding
        for finding in run.get("findings", [])
        if finding.get("object_key", "").casefold() == object_key
        and (finding.get("reconciliation") or {}).get("delta_id") == delta.get("delta_id")
    ]
    _require(len(findings) == 1, f"{trial_id}: target MODIFY finding is not uniquely linked")
    reconciliation = findings[0].get("reconciliation") or {}
    window = reconciliation.get("observation_window") or {}
    _require(window.get("start") and window.get("end"), f"{trial_id}: missing CSG time window")
    window_start, window_end = _time(window["start"]), _time(window["end"])
    _require(
        reconciliation.get("status") == "UNEXPLAINED"
        and not reconciliation.get("matched_evidence_ids"),
        f"{trial_id}: target MODIFY must be UNEXPLAINED with no evidence links",
    )

    source = run.get("windows_source_evidence") or {}
    source_query = source.get("query") or {}
    _require(source.get("query_status") == "SUCCEEDED", f"{trial_id}: local Windows query failed")
    _require(
        str(source_query.get("exact_service_name", "")).casefold() == service_name.casefold(),
        f"{trial_id}: local Windows source query is not scoped to the target",
    )
    local_target_events = [
        event
        for event in source.get("events", [])
        if event.get("event_id") == 7040
        and _event_param(str(event.get("raw_xml") or ""), "param1") == service_name
    ]
    _require(
        len(local_target_events) == 1,
        f"{trial_id}: expected exactly one target-named local Event 7040",
    )
    local_target_event = local_target_events[0]
    local_time = _time(str(local_target_event["event_time"]))
    _require(
        window_start <= local_time <= window_end,
        f"{trial_id}: target local event is outside the target reconciliation window",
    )

    suppression = run.get("target_selective_suppression_proof") or {}
    observation = suppression.get("observation") or {}
    restoration = suppression.get("restoration") or {}
    _require(
        suppression.get("status") == "APPLIED_AND_HEALTHY"
        and suppression.get("manipulation_valid") is True,
        f"{trial_id}: target-specific suppression manipulation was not verified",
    )
    _require(
        observation.get("target_reconciliation_status") == "UNEXPLAINED"
        and observation.get("csg_database_target_service_modified_count") == 0,
        f"{trial_id}: suppression proof reports target evidence or unexpected status",
    )
    _require(
        observation.get("endpoint_collection_status") == "active"
        and observation.get("manager_status") == "AVAILABLE"
        and observation.get("indexer_status") == "AVAILABLE",
        f"{trial_id}: required Wazuh services were not healthy",
    )
    _require(
        run.get("event_plane_status", {}).get("expected_events", {}).get(EVENT_TYPE) == "ABSENT",
        f"{trial_id}: target modification event absence was not recorded",
    )
    exact_target_events = [
        event
        for event in (run.get("verified_exact_wazuh_evidence") or {}).get(EVENT_TYPE, [])
        if event.get("host_id") == host_id
        and event.get("normalized_type") == EVENT_TYPE
        and str(event.get("target_key", "")).casefold() == object_key
        and str(event.get("service_name", "")).casefold() == service_name.casefold()
        and event.get("event_time")
        and window_start <= _time(str(event["event_time"])) <= window_end
    ]
    _require(not exact_target_events, f"{trial_id}: exact target Wazuh event unexpectedly exists")

    detail = (run.get("same_host_distractor_proof") or {}).get("details") or {}
    wrong_object_events = [
        event
        for event in (detail.get("modify") or {}).get("exact_wazuh_events", [])
        if event.get("source") == "wazuh"
        and event.get("host_id") == host_id
        and event.get("normalized_type") == EVENT_TYPE
        and str(event.get("target_key", "")).casefold() != object_key
        and str(event.get("service_name", "")).casefold() != service_name.casefold()
        and event.get("event_time")
        and window_start <= _time(str(event["event_time"])) <= window_end
    ]
    _require(
        bool(wrong_object_events),
        f"{trial_id}: no fully materialized wrong-object event falls in target window",
    )

    candidate_ids = set(observation.get("distractor_exact_event_ids") or [])
    expanded_ids = {str(event.get("event_id")) for event in wrong_object_events}
    source_event = local_target_event
    return {
        "trial_id": trial_id,
        "run_id": run.get("run_id"),
        "host_id": host_id,
        "target_service": service_name,
        "target_object_key": object_key,
        "target_delta_id": delta.get("delta_id"),
        "target_finding_id": findings[0].get("finding_id"),
        "target_transition": {
            "before_start_mode": before_attrs.get("start_mode"),
            "after_start_mode": after_attrs.get("start_mode"),
            "before_observation_id": (before.get("metadata") or {}).get("observation_id"),
            "after_observation_id": (after.get("metadata") or {}).get("observation_id"),
        },
        "target_windows_event": {
            "log_name": source_query.get("log_name"),
            "event_id": source_event.get("event_id"),
            "record_id": source_event.get("record_id"),
            "event_time": source_event.get("event_time"),
            "service_name_verified_from_event_data_param1": service_name,
            "inside_target_window": True,
        },
        "target_reconciliation_window": window,
        "target_exact_wazuh_modify_event_count": 0,
        "wrong_object_events": [
            {
                "event_id": event.get("event_id"),
                "event_time": event.get("event_time"),
                "host_id": event.get("host_id"),
                "normalized_type": event.get("normalized_type"),
                "service_name": event.get("service_name"),
                "object_key": event.get("target_key"),
                "index": (event.get("source_reference") or {}).get("index"),
                "document_id": (event.get("source_reference") or {}).get("document_id"),
                "inside_target_window": True,
            }
            for event in wrong_object_events
        ],
        "wrong_object_event_id_references": sorted(candidate_ids),
        "unexpanded_wrong_object_event_id_references": sorted(candidate_ids - expanded_ids),
        "paired_method_outcomes": {
            "exact_target_event_only_detected_modify": False,
            "native_probe_only_detected_state_change": True,
            "loose_host_type_time_ablation_would_match_wrong_object": True,
            "exact_host_type_object_match_would_match_wrong_object": False,
            "csg_target_status": reconciliation.get("status"),
            "csg_false_consistent_for_target": reconciliation.get("status") == "CONSISTENT"
            and not exact_target_events,
            "csg_state_change_observed": True,
        },
        "source_and_cleanup_checks": {
            "event_query_complete": (detail.get("modify_sync") or {}).get("query_complete") is True,
            "endpoint_collection_status": observation.get("endpoint_collection_status"),
            "manager_status": observation.get("manager_status"),
            "indexer_status": observation.get("indexer_status"),
            "original_config_hash_restored": restoration.get("restored_config_sha256")
            == suppression.get("original_config_sha256"),
            "target_service_absent_from_cleanup_probe": not any(
                str(item.get("service_name", "")).casefold() == service_name.casefold()
                for item in (
                    ((detail.get("cleanup_probe_observation") or {}).get("categories") or {})
                    .get("service", {})
                    .get("items", [])
                )
            ),
            "distractor_service_absent_after_cleanup": (detail.get("cleanup") or {}).get(
                "absent_after_cleanup"
            )
            is True,
            "probe_task_running_after_trial": (run.get("probe_scheduled_task") or {}).get("after")
            == "Running",
        },
        "input_hashes": {
            "run_json_sha256": run_sha256,
            "validation_json_sha256": validation_sha256,
        },
    }


def analyze_campaign(campaign_dir: Path) -> dict[str, Any]:
    aggregate_path = campaign_dir / "aggregate.json"
    aggregate = _read_json(aggregate_path)
    condition = aggregate.get("conditions", {}).get(CONDITION_KEY) or {}
    trial_ids = condition.get("trial_ids") or []
    _require(len(trial_ids) == condition.get("included_trials"), "aggregate trial count mismatch")
    _require(bool(trial_ids), "aggregate has no target-selective trials")

    trials = []
    input_hashes: dict[str, str] = {"aggregate.json": _sha256(aggregate_path)}
    for trial_id in trial_ids:
        trial_dir = campaign_dir / trial_id
        run_path, validation_path = trial_dir / "run.json", trial_dir / "validation.json"
        run, validation = _read_json(run_path), _read_json(validation_path)
        run_hash, validation_hash = _sha256(run_path), _sha256(validation_path)
        trials.append(
            analyze_trial(
                trial_id,
                run,
                validation,
                run_sha256=run_hash,
                validation_sha256=validation_hash,
            )
        )
        input_hashes[f"{trial_id}/run.json"] = run_hash
        input_hashes[f"{trial_id}/validation.json"] = validation_hash

    n = len(trials)
    target_state = sum(
        row["paired_method_outcomes"]["native_probe_only_detected_state_change"] for row in trials
    )
    exact_event = sum(
        row["paired_method_outcomes"]["exact_target_event_only_detected_modify"] for row in trials
    )
    loose_false = sum(
        row["paired_method_outcomes"]["loose_host_type_time_ablation_would_match_wrong_object"]
        for row in trials
    )
    strong_false = sum(
        row["paired_method_outcomes"]["exact_host_type_object_match_would_match_wrong_object"]
        for row in trials
    )
    csg_false = sum(
        row["paired_method_outcomes"]["csg_false_consistent_for_target"] for row in trials
    )
    paired_state_event_a = sum(
        row["paired_method_outcomes"]["native_probe_only_detected_state_change"]
        and not row["paired_method_outcomes"]["exact_target_event_only_detected_modify"]
        for row in trials
    )
    paired_state_event_b = sum(
        row["paired_method_outcomes"]["exact_target_event_only_detected_modify"]
        and not row["paired_method_outcomes"]["native_probe_only_detected_state_change"]
        for row in trials
    )
    paired_loose_csg_a = sum(
        row["paired_method_outcomes"]["loose_host_type_time_ablation_would_match_wrong_object"]
        and not row["paired_method_outcomes"]["csg_false_consistent_for_target"]
        for row in trials
    )
    paired_loose_csg_b = sum(
        row["paired_method_outcomes"]["csg_false_consistent_for_target"]
        and not row["paired_method_outcomes"][
            "loose_host_type_time_ablation_would_match_wrong_object"
        ]
        for row in trials
    )

    return {
        "schema_version": "csg-target-selective-paired-analysis-v1",
        "analysis_type": "post_hoc_paired_descriptive_calibration",
        "confirmatory": False,
        "campaign_id": aggregate.get("campaign_id"),
        "condition": CONDITION_KEY,
        "scope": {
            "host_ids": sorted({row["host_id"] for row in trials}),
            "behavior": "benign Windows service Manual-to-Auto transition",
            "unit": "one randomized service transition; five repeated trials on one VM",
            "target_event": "Wazuh service_modified for the exact target service",
            "security_claim": "No maliciousness or attack detection is evaluated.",
        },
        "method_definitions": {
            "exact_target_event_only": (
                "Target visibility only if a Wazuh service_modified event matches host, "
                "event type, and exact target service identity."
            ),
            "native_probe_only": (
                "Target state visibility from direct-probe before/after state; "
                "it does not claim event corroboration."
            ),
            "loose_host_type_time_ablation": (
                "Offline weakened matcher that ignores object identity and treats a "
                "same-host service_modified event inside the CSG target window as if it "
                "referred to the target. This is an ablation, not a Wazuh product baseline."
            ),
            "exact_identity_matcher": (
                "Requires host, normalized event type, and exact target service identity; "
                "it rejects the captured distractor."
            ),
            "full_csg": (
                "Observed CSG finding and reconciliation status from the original run, "
                "paired with native state and event-query/source health."
            ),
        },
        "summary": {
            "trials": n,
            "native_probe_state_change_detected": {
                "successes": target_state,
                "rate": target_state / n,
                "wilson_95": wilson_interval(target_state, n),
            },
            "exact_target_wazuh_modify_detected": {
                "successes": exact_event,
                "rate": exact_event / n,
                "wilson_95": wilson_interval(exact_event, n),
            },
            "loose_ablation_false_target_matches": {
                "successes": loose_false,
                "rate": loose_false / n,
                "wilson_95": wilson_interval(loose_false, n),
            },
            "wrong_object_rejected_by_exact_identity": {
                "successes": n - strong_false,
                "rate": (n - strong_false) / n,
                "wilson_95": wilson_interval(n - strong_false, n),
            },
            "csg_false_consistent_decisions": {
                "successes": csg_false,
                "rate": csg_false / n,
                "wilson_95": wilson_interval(csg_false, n),
            },
            "csg_unexplained_with_native_state": sum(
                row["paired_method_outcomes"]["csg_target_status"] == "UNEXPLAINED"
                and row["paired_method_outcomes"]["csg_state_change_observed"]
                for row in trials
            ),
            "config_restored_trials": sum(
                row["source_and_cleanup_checks"]["original_config_hash_restored"] for row in trials
            ),
            "cleanup_verified_trials": sum(
                row["source_and_cleanup_checks"]["target_service_absent_from_cleanup_probe"]
                and row["source_and_cleanup_checks"]["distractor_service_absent_after_cleanup"]
                for row in trials
            ),
        },
        "paired_comparisons": {
            "native_probe_state_vs_exact_target_event": {
                "discordant_probe_detected_event_not_detected": paired_state_event_a,
                "discordant_event_detected_probe_not_detected": paired_state_event_b,
                "exact_two_sided_mcnemar_p_descriptive_only": exact_mcnemar_two_sided(
                    paired_state_event_a, paired_state_event_b
                ),
            },
            "loose_match_false_attribution_vs_csg_false_consistent": {
                "discordant_loose_false_match_csg_not_false_consistent": paired_loose_csg_a,
                "discordant_csg_false_consistent_loose_not_false_match": paired_loose_csg_b,
                "exact_two_sided_mcnemar_p_descriptive_only": exact_mcnemar_two_sided(
                    paired_loose_csg_a, paired_loose_csg_b
                ),
            },
        },
        "limitations": [
            (
                "Post-hoc analysis of an engineering calibration; outcomes and methods "
                "were not prospectively frozen for this five-trial comparison."
            ),
            (
                "All trials ran on one Windows 11 ARM UTM VM; repeated trials are not "
                "independent hosts."
            ),
            (
                "The target-specific event/FIM filters were intentional. This does not "
                "estimate natural Wazuh miss rates or permanent loss across every "
                "telemetry route."
            ),
            "The loose matcher is an offline ablation, not an observed Wazuh product decision.",
            (
                "The strong exact-identity matcher also rejects the distractor; these trials "
                "do not show an advantage of CSG over that matcher on false attribution. "
                "CSG's additional source-health and lifecycle value needs a separately "
                "designed comparison."
            ),
            (
                "Small-sample Wilson intervals and exact paired p-values are descriptive; "
                "no inferential or population claim is made."
            ),
            (
                "Four extra wrong-object event IDs in the raw artifacts lack expanded "
                "event objects; they are preserved but not counted as distinct events "
                "or assumed duplicates."
            ),
        ],
        "input_sha256": input_hashes,
        "analysis_source_sha256": _sha256(Path(__file__)),
        "trials": trials,
    }


def render_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# Paired Baseline Analysis: Target-Selective Suppression",
        "",
        (
            "**Status:** post-hoc descriptive calibration; not confirmatory or "
            "conference-ready evidence."
        ),
        "",
        "## Question",
        "",
        (
            "On the same five service transitions, what did the target-specific Wazuh "
            "event, native CSG probe, a loose host/type/time ablation, an exact-identity "
            "matcher, and CSG actually report?"
        ),
        "",
        "## Paired results",
        "",
        "| Method/outcome | Result | 95% Wilson interval | Meaning |",
        "|---|---:|---:|---|",
        (
            f"| Exact target Wazuh `service_modified` event | "
            f"{summary['exact_target_wazuh_modify_detected']['successes']}/{summary['trials']} | "
            f"{_fmt_interval(summary['exact_target_wazuh_modify_detected']['wilson_95'])} | "
            "Target event was intentionally filtered in this condition |"
        ),
        (
            f"| Native probe observes target state change | "
            f"{summary['native_probe_state_change_detected']['successes']}/{summary['trials']} | "
            f"{_fmt_interval(summary['native_probe_state_change_detected']['wilson_95'])} | "
            "Direct before/after state still identifies the change |"
        ),
        (
            f"| Loose host/type/time ablation would accept wrong object | "
            f"{summary['loose_ablation_false_target_matches']['successes']}/{summary['trials']} | "
            f"{_fmt_interval(summary['loose_ablation_false_target_matches']['wilson_95'])} | "
            "Candidate exists only because this ablation ignores service identity |"
        ),
        (
            f"| Exact-identity matcher rejects wrong object | "
            f"{summary['wrong_object_rejected_by_exact_identity']['successes']}/"
            f"{summary['trials']} | "
            f"{_fmt_interval(summary['wrong_object_rejected_by_exact_identity']['wilson_95'])} | "
            "Same host/type is insufficient when target service differs |"
        ),
        (
            f"| Actual CSG target `UNEXPLAINED`, not false `CONSISTENT` | "
            f"{summary['csg_unexplained_with_native_state']}/{summary['trials']} | "
            "n/a | Observed CSG status paired with visible native state |"
        ),
        "",
        (
            "The paired exact McNemar test is reported in `analysis.json` as descriptive "
            "only. With five discordant pairs, the two-sided p-value is 0.0625; this pilot "
            "is too small and post-hoc to support a confirmatory significance claim. "
            "The 0/5 and 5/5 Wilson intervals are wide."
        ),
        "",
        "## Per-trial audit",
        "",
        (
            "| Trial | Target | Target Windows 7040 record/time | "
            "Exact wrong-object Wazuh event/time | CSG MODIFY | Config restored | Cleanup |"
        ),
        "|---|---|---|---|---|---|---|",
    ]
    for row in result["trials"]:
        local = row["target_windows_event"]
        distractor = row["wrong_object_events"][0]
        checks = row["source_and_cleanup_checks"]
        cleanup_verified = (
            checks["target_service_absent_from_cleanup_probe"]
            and checks["distractor_service_absent_after_cleanup"]
        )
        lines.append(
            f"| `{row['trial_id']}` | `{row['target_service']}` | "
            f"{local['record_id']} / {local['event_time']} | "
            f"`{distractor['service_name']}` / {distractor['event_id']} / "
            f"{distractor['event_time']} | "
            f"`{row['paired_method_outcomes']['csg_target_status']}` | "
            f"{checks['original_config_hash_restored']} | "
            f"{cleanup_verified} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            (
                "This paired set supports two narrow observations. First, the probe "
                "preserved target-state visibility in all five deliberately filtered "
                "cases while the exact target Wazuh modification event was absent. "
                "Second, a same-host event of the right type and time but wrong service "
                "would pass a deliberately loose matcher; the exact-identity matcher and "
                "actual CSG reconciliation rejected it. Because the strong exact-identity "
                "comparator also rejects every distractor, this study does **not** establish "
                "that CSG is superior to a correctly implemented identity matcher. The "
                "possible added value of CSG's source-quality and lifecycle handling remains "
                "to be measured against that comparator."
            ),
            "",
            (
                "The filters intentionally suppressed the target's Windows System Event "
                "7040 and exact service-registry FIM route while Wazuh remained operational. "
                "This is not an estimate of natural event loss, comprehensive sensor "
                "disablement, malicious detection, or cross-host performance. One "
                "target-specific Windows Event 7040 and one fully materialized wrong-object "
                "Wazuh event were verified within the target observation window in every "
                "trial. Four additional Wazuh IDs were not expanded into event objects; "
                "they are not counted as independent events or asserted to be duplicates."
            ),
            "",
            "## Reproduction",
            "",
            "```bash",
            "python -m experiments.target_selective_suppression_analysis \\",
            "  --campaign-dir experiments/results/runs/20261010/reconciliation-calibration \\",
            "  --output-dir experiments/results/runs/20261010/reconciliation-calibration/analysis",
            "```",
            "",
            (
                "The machine-readable report stores run/validation hashes and raw "
                "target/distractor evidence fields. The analysis script and report were "
                "created after the live trials, so they are retrospective calibration "
                "artifacts."
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def _fmt_interval(interval: list[float] | None) -> str:
    if interval is None:
        return "n/a"
    return f"{interval[0]:.1%}-{interval[1]:.1%}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    result = analyze_campaign(args.campaign_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / "analysis.json"
    markdown_path = args.output_dir / "ANALYSIS.md"
    json_path.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(result), encoding="utf-8")
    print(
        json.dumps(
            {
                "trials": result["summary"]["trials"],
                "state_detected": result["summary"]["native_probe_state_change_detected"][
                    "successes"
                ],
                "exact_target_event": result["summary"]["exact_target_wazuh_modify_detected"][
                    "successes"
                ],
                "loose_wrong_object_matches": result["summary"][
                    "loose_ablation_false_target_matches"
                ]["successes"],
                "csg_false_consistent": result["summary"]["csg_false_consistent_decisions"][
                    "successes"
                ],
                "analysis_json": str(json_path),
                "report": str(markdown_path),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
