#!/usr/bin/env python3
"""Audit and summarize the frozen scheduled-task event-loss cohort v19."""

from __future__ import annotations

import hashlib
import json
import re
import statistics
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "experiments/results/runs/20261013/scheduled-task-event-loss-confirmatory-v19"
WINDOWS = RUN / "windows"
ANALYSIS = RUN / "analysis.json"


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_query(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def original_query_hash(path: Path) -> str:
    root = ET.parse(path).getroot()
    query = next(
        (
            node.findtext("query")
            for node in root.findall("localfile")
            if node.findtext("location") == "Security" and node.findtext("query")
        ),
        None,
    )
    if query is None:
        raise ValueError(f"Security EventChannel query missing from {path}")
    return hashlib.sha256(normalize_query(query).encode("utf-8")).hexdigest()


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def first_healthy_final(history: list[dict]) -> dict | None:
    for item in history:
        event_plane = item.get("metadata", {}).get("event_plane", {})
        if (
            item.get("finalized") is True
            and item.get("status") == "UNEXPLAINED"
            and event_plane.get("endpoint_collection_status") == "AVAILABLE"
            and event_plane.get("transport_status") == "AVAILABLE"
            and event_plane.get("index_status") == "AVAILABLE"
            and event_plane.get("coverage_status") == "COMPLETE"
            and event_plane.get("query_complete") is True
        ):
            return item
    return None


def main() -> int:
    frozen = read_json(RUN / "source-freeze.json")
    expected_tasks = frozen["assignments"]
    source_checks = []
    for item in frozen["source_files"]:
        working_path = ROOT / item["path"]
        archived_path = RUN / "source-frozen" / Path(item["path"]).name
        frozen_path = archived_path if archived_path.is_file() else working_path
        actual = sha256(frozen_path) if frozen_path.is_file() else None
        working_actual = sha256(working_path) if working_path.is_file() else None
        source_checks.append(
            {
                "path": item["path"],
                "expected_sha256": item["sha256"],
                "actual_sha256": actual,
                "matches": actual == item["sha256"],
                "verified_from": str(frozen_path.relative_to(ROOT)),
                "working_tree_sha256": working_actual,
                "working_tree_matches_frozen": working_actual == item["sha256"],
            }
        )

    trials = []
    for index, expected_task in enumerate(expected_tasks, start=1):
        controller = read_json(WINDOWS / "controller" / f"trial-{index:02d}" / "result.json")
        history = read_json(WINDOWS / f"final-reconciliations-trial-{index:02d}.json")
        pre_query = read_json(WINDOWS / f"active-query-verification-trial-{index:02d}.json")
        post_query = read_json(
            WINDOWS / f"postrestore-active-query-verification-trial-{index:02d}.json"
        )
        baseline_path = (
            WINDOWS / "controller" / f"trial-{index:02d}" / "ossec.conf.original.backup"
        )
        baseline_hash = original_query_hash(baseline_path)
        healthy = first_healthy_final(history)
        queries = controller.get("post_restore_provider_queries", [])
        target_delta = controller.get("final_target_reconciliation", {}).get("delta_id")
        if target_delta is None and healthy:
            target_delta = healthy.get("delta_id")

        gates = {
            "assigned_task_matches_frozen_list": controller.get("target_task_name") == expected_task,
            "active_suppression_query_verified": (
                pre_query.get("matches_expected_query") is True
                and pre_query.get("active_query_sha256_normalized")
                == controller.get("active_query_gate", {}).get("expected_query_sha256")
            ),
            "probe_absent_present_removed_sequence": controller.get(
                "direct_probe_state_sequence_passed"
            ) is True,
            "exact_local_security_4698_present": controller.get(
                "local_windows_4698_exact_count"
            ) == 1,
            "complete_wazuh_query_during_filter": (
                controller.get("query_complete_during_filter") is True
                and controller.get("query_coverage_and_source_availability_during_filter") is True
            ),
            "exact_target_absent_from_wazuh_during_filter": controller.get(
                "exact_wazuh_target_event_count_during_filter"
            ) == 0,
            "target_absent_from_csg_event_store": controller.get(
                "target_absent_from_csg_event_store_during_filter"
            ) is True,
            "healthy_final_unexplained_without_evidence_ids": (
                healthy is not None and not healthy.get("matched_evidence_ids")
            ),
            "six_complete_postrestore_queries_no_recovery": (
                len(queries) == 6
                and all(
                    query.get("query_complete") is True
                    and query.get("coverage_status") == "COMPLETE"
                    and query.get("endpoint_collection_status") == "AVAILABLE"
                    and query.get("transport_status") == "AVAILABLE"
                    and query.get("index_status") == "AVAILABLE"
                    and query.get("exact_target_event_count") == 0
                    for query in queries
                )
            ),
            "original_config_hash_restored": controller.get(
                "restored_hash_matches_original"
            ) is True,
            "original_active_query_restored": (
                post_query.get("active_query_sha256_normalized") == baseline_hash
            ),
            "task_cleanup_verified": (
                controller.get("cleanup_verified") is True
                and controller.get("residual_study_tasks") == []
            ),
            "controller_and_probe_capture_gates_passed": (
                controller.get("runner_exit_code") == 0
                and controller.get("capture_gates_passed") is True
            ),
        }

        latency_seconds = None
        if healthy:
            deadline = healthy.get("metadata", {}).get("evidence_deadline")
            if deadline:
                latency_seconds = (
                    parse_time(healthy["finalized_at"]) - parse_time(deadline)
                ).total_seconds()

        trials.append(
            {
                "assignment": index,
                "task_name": expected_task,
                "finding_id": healthy.get("finding_id") if healthy else None,
                "delta_id": target_delta,
                "healthy_final_reconciliation": {
                    "version": healthy.get("version"),
                    "status": healthy.get("status"),
                    "semantics": healthy.get("metadata", {}).get("reconciliation_semantics"),
                    "finalized_at_utc": healthy.get("finalized_at"),
                    "evidence_deadline_utc": healthy.get("metadata", {}).get("evidence_deadline"),
                    "matched_evidence_ids": healthy.get("matched_evidence_ids"),
                    "event_plane": healthy.get("metadata", {}).get("event_plane"),
                }
                if healthy
                else None,
                "reconciliation_latency_seconds": latency_seconds,
                "within_45_second_secondary_bound": (
                    latency_seconds <= 45 if latency_seconds is not None else None
                ),
                "native_state_transition_visible": controller.get(
                    "direct_probe_state_sequence_passed"
                ) is True,
                "exact_target_event_available_in_wazuh": controller.get(
                    "exact_wazuh_target_event_count_during_filter", 0
                )
                > 0,
                "gates": gates,
                "all_primary_gates_passed": all(gates.values()),
                "controller_artifact": str(
                    (WINDOWS / "controller" / f"trial-{index:02d}" / "result.json").relative_to(ROOT)
                ),
                "reconciliation_history_artifact": str(
                    (WINDOWS / f"final-reconciliations-trial-{index:02d}.json").relative_to(ROOT)
                ),
            }
        )

    latency_values = [
        trial["reconciliation_latency_seconds"]
        for trial in trials
        if trial["reconciliation_latency_seconds"] is not None
    ]
    primary_successes = sum(trial["all_primary_gates_passed"] for trial in trials)
    n = len(trials)
    result = {
        "schema_version": "csg-event-loss-v19-analysis-v1",
        "experiment_id": frozen["experiment_id"],
        "analysis_generated_utc": datetime.now().astimezone().isoformat(),
        "analysis_tool": {
            "path": str(Path(__file__).resolve().relative_to(ROOT)),
            "sha256": sha256(Path(__file__).resolve()),
        },
        "protocol": frozen["protocol"],
        "endpoint": frozen["endpoint"],
        "runtime_configuration": frozen["runtime_configuration"],
        "source_freeze_integrity": {
            "frozen_source_file_count": len(source_checks),
            "all_frozen_source_hashes_match": all(item["matches"] for item in source_checks),
            "files": source_checks,
        },
        "assigned_trial_count": n,
        "primary_mechanism_success_count": primary_successes,
        "primary_mechanism_success_rate": primary_successes / n if n else None,
        "nominal_two_sided_exact_95_percent_interval": (
            [0.025 ** (1 / n), 1.0] if n and primary_successes == n else None
        ),
        "trial_level_gates": {
            name: {
                "passed": sum(trial["gates"][name] for trial in trials),
                "assigned": n,
            }
            for name in trials[0]["gates"]
        },
        "paired_visibility_readout": {
            "native_state_transition_visible": sum(
                trial["native_state_transition_visible"] for trial in trials
            ),
            "exact_target_event_available_in_wazuh": sum(
                trial["exact_target_event_available_in_wazuh"] for trial in trials
            ),
            "state_visible_and_healthy_unexplained_while_target_event_absent": sum(
                trial["gates"]["probe_absent_present_removed_sequence"]
                and trial["gates"]["exact_target_absent_from_wazuh_during_filter"]
                and trial["gates"]["healthy_final_unexplained_without_evidence_ids"]
                for trial in trials
            ),
            "interpretation": "Exact target-event availability comparator only; this is not an evaluation of all Wazuh rules, alerting, or malicious-activity detection efficacy.",
        },
        "secondary_latency": {
            "definition": "first healthy-source finalized reconciliation minus evidence_deadline_utc",
            "bound_seconds": 45,
            "n": len(latency_values),
            "within_bound": sum(value <= 45 for value in latency_values),
            "mean_seconds": statistics.mean(latency_values) if latency_values else None,
            "median_seconds": statistics.median(latency_values) if latency_values else None,
            "minimum_seconds": min(latency_values) if latency_values else None,
            "maximum_seconds": max(latency_values) if latency_values else None,
            "values_include_all_trials": len(latency_values) == n,
        },
        "interpretation_limits": [
            "Ten repeated benign scheduled-task trials were run on one Windows 11 ARM64 VM; this is not ten-host validation.",
            "The treatment deliberately excluded Security Event ID 4698 at collection; it is not natural sensor failure or permanent loss of every telemetry source.",
            "This result measures persistent-state visibility and reconciliation under controlled event omission, not malicious-activity detection efficacy.",
            "No same-host wrong-object distractor condition was included in this cohort.",
            "The exact binomial interval is nominal for independent Bernoulli trials; repeated trials share one endpoint and environment.",
            "The 45-second latency bound is secondary engineering characterization, not a security-quality threshold.",
        ],
        "trials": trials,
    }
    ANALYSIS.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "analysis": str(ANALYSIS.relative_to(ROOT)),
                "primary_successes": f"{primary_successes}/{n}",
                "all_frozen_source_hashes_match": result["source_freeze_integrity"][
                    "all_frozen_source_hashes_match"
                ],
                "healthy_reconciliation_latency_median_seconds": result[
                    "secondary_latency"
                ]["median_seconds"],
                "within_45_seconds": result["secondary_latency"]["within_bound"],
            },
            indent=2,
        )
    )
    return 0 if primary_successes == n and result["source_freeze_integrity"]["all_frozen_source_hashes_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
