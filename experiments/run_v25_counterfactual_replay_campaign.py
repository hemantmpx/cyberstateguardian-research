"""Prepare and run a frozen, parent-linked v25 counterfactual replay cohort."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from experiments.replay_target_event_drop_with_distractor import replay

CAMPAIGN_ID = "scheduled-task-same-window-complete-distractor-campaign-v25"
RUN_ID = "scheduled-task-distractor-counterfactual-replay-v25"
RAW_RUN_DIR = (
    "windows/raw/research-campaign-20261013-"
    "scheduled-task-same-window-complete-distractor-v25"
)
SCENARIO_FILENAME = "trial-01-scheduled-task-persistence.json"
EXPECTED_TRIALS = 10
GRACE_SECONDS = 60


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def canonicalize_replay_input(
    source_path: Path,
    output_path: Path,
    target_event_ids: list[str],
    distractor_event_ids: list[str],
) -> tuple[str, str]:
    source = read_json(source_path)
    if not target_event_ids or not distractor_event_ids:
        raise ValueError("Canonical replay requires target and distractor event IDs")
    target_id = sorted(target_event_ids)[0]
    distractor_id = sorted(distractor_event_ids)[0]
    if target_id == distractor_id:
        raise ValueError("Target and distractor representative IDs must differ")

    exact_matches = source.get("event_plane", {}).get("exact_matches", [])
    provider_events = (source.get("distractor_evidence") or {}).get("provider_events", [])
    target_representatives = [item for item in exact_matches if item.get("event_id") == target_id]
    distractor_representatives = [
        item for item in provider_events if item.get("event_id") == distractor_id
    ]
    if len(target_representatives) != 1 or len(distractor_representatives) != 1:
        raise ValueError("Frozen representative event ID is absent or ambiguous in parent input")

    source["event_plane"]["exact_matches"] = target_representatives
    source["distractor_evidence"]["provider_events"] = distractor_representatives
    write_json(output_path, source)
    return target_id, distractor_id


def _identity_map(audit: dict[str, Any]) -> dict[str, dict[str, Any]]:
    mapped: dict[str, dict[str, Any]] = {}
    for group in audit.get("stable_identity_groups", []):
        for document in group.get("documents", []):
            event_id = str(document.get("event_id") or "")
            if not event_id:
                continue
            identity = {
                "identity": group.get("identity"),
                "event_record_id": str(document.get("event_record_id") or ""),
                "event_id_raw": str(document.get("event_id_raw") or ""),
                "provider": group.get("identity", [None] * 5)[4]
                if len(group.get("identity", [])) == 5
                else None,
                "raw_task_name": document.get("raw_task_name"),
            }
            previous = mapped.get(event_id)
            if previous is not None and previous["identity"] != identity["identity"]:
                raise ValueError(f"Wazuh event ID maps to conflicting physical identities: {event_id}")
            mapped[event_id] = identity
    return mapped


def prepare_input_manifest(parent_dir: Path, output_dir: Path, repo_root: Path) -> dict[str, Any]:
    parent_dir = parent_dir.resolve()
    output_dir = output_dir.resolve()
    parent_analysis = read_json(parent_dir / "analysis.json")
    primary = parent_analysis.get("primary_outcome", {})
    execution = parent_analysis.get("execution", {})
    if (
        parent_analysis.get("campaign_id") != CAMPAIGN_ID
        or primary.get("successes") != EXPECTED_TRIALS
        or primary.get("denominator") != EXPECTED_TRIALS
        or execution.get("strict_raw_audit_successes") != EXPECTED_TRIALS
        or execution.get("strict_raw_audit_failures") != []
        or parent_analysis.get("environment_integrity", {}).get("campaign_integrity_pass") is not True
    ):
        raise ValueError("Parent campaign did not pass its strict 10-trial integrity audit")

    assignments = read_json(parent_dir / "assignments.json").get("trials", [])
    if len(assignments) != EXPECTED_TRIALS:
        raise ValueError(f"Expected {EXPECTED_TRIALS} frozen parent assignments")

    raw_root = parent_dir / RAW_RUN_DIR
    entries: list[dict[str, Any]] = []
    for assignment in assignments:
        number = int(assignment["trial"])
        trial_dir = raw_root / f"trial-{number:02d}"
        scenario_path = trial_dir / "trials" / SCENARIO_FILENAME
        audit_path = trial_dir / "raw-indexer-identity-audit.json"
        if not scenario_path.is_file() or not audit_path.is_file():
            raise FileNotFoundError(f"Missing raw evidence for parent trial {number:02d}")

        scenario = read_json(scenario_path)
        additions = [
            delta
            for delta in scenario.get("deltas", [])
            if delta.get("category") == "scheduled_task" and delta.get("delta_type") == "ADD"
        ]
        if len(additions) != 1:
            raise ValueError(f"Parent trial {number:02d} has {len(additions)} scheduled-task ADDs")
        delta = additions[0]
        target_key = str(delta.get("object_key") or "").casefold()
        target_events = [
            event
            for event in scenario.get("event_plane", {}).get("exact_matches", [])
            if event.get("normalized_type") == "scheduled_task_created"
            and str((event.get("target") or {}).get("key") or "").casefold() == target_key
            and event.get("host_id") == delta.get("host_id")
        ]
        distractor_events = [
            event
            for event in scenario.get("distractor_evidence", {}).get("provider_events", [])
            if event.get("normalized_type") == "scheduled_task_created"
            and event.get("host_id") == delta.get("host_id")
            and str((event.get("target") or {}).get("key") or "").casefold() != target_key
        ]
        if not target_events or not distractor_events:
            raise ValueError(f"Parent trial {number:02d} lacks target/distractor event evidence")

        target_name = str(assignment["target"])
        distractor_name = str(assignment["distractor"])
        if target_name.casefold() not in target_key or distractor_name.casefold() not in str(
            (distractor_events[0].get("target") or {}).get("key") or ""
        ).casefold():
            raise ValueError(f"Parent trial {number:02d} event identities disagree with assignment")

        audit = read_json(audit_path)
        identities = _identity_map(audit)
        target_event_ids = sorted({str(event.get("event_id") or "") for event in target_events})
        distractor_event_ids = sorted(
            {str(event.get("event_id") or "") for event in distractor_events}
        )
        target_identities = [identities.get(event_id) for event_id in target_event_ids]
        distractor_identities = [identities.get(event_id) for event_id in distractor_event_ids]
        if not target_event_ids or not distractor_event_ids or any(
            identity is None for identity in [*target_identities, *distractor_identities]
        ):
            raise ValueError(f"Parent trial {number:02d} lacks raw Indexer identity for all events")
        target_physical_identities = {
            json.dumps(identity["identity"], sort_keys=True) for identity in target_identities
        }
        distractor_physical_identities = {
            json.dumps(identity["identity"], sort_keys=True)
            for identity in distractor_identities
        }
        if len(target_physical_identities) != 1 or len(distractor_physical_identities) != 1:
            raise ValueError(
                f"Parent trial {number:02d} has event aliases spanning physical events"
            )
        if target_physical_identities == distractor_physical_identities:
            raise ValueError(f"Parent trial {number:02d} target and distractor share physical identity")
        if any(
            target_name.casefold() not in str(identity["raw_task_name"] or "").casefold()
            for identity in target_identities
        ):
            raise ValueError(f"Parent trial {number:02d} target raw task name does not match assignment")
        if any(
            distractor_name.casefold() not in str(identity["raw_task_name"] or "").casefold()
            for identity in distractor_identities
        ):
            raise ValueError(f"Parent trial {number:02d} distractor raw task name does not match assignment")

        try:
            input_rel = scenario_path.resolve().relative_to(repo_root.resolve()).as_posix()
            audit_rel = audit_path.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError as exc:
            raise ValueError("Parent raw evidence must reside under the repository root") from exc
        entries.append(
            {
                "parent_trial": number,
                "target_name": target_name,
                "distractor_name": distractor_name,
                "input_path": input_rel,
                "input_sha256": sha256_file(scenario_path),
                "raw_identity_audit_path": audit_rel,
                "raw_identity_audit_sha256": sha256_file(audit_path),
                "host_id": delta["host_id"],
                "delta_id": delta["delta_id"],
                "target_object_key": delta["object_key"],
                "target_wazuh_event_ids": target_event_ids,
                "target_event_record_ids": sorted(
                    {identity["event_record_id"] for identity in target_identities}
                ),
                "target_physical_identity": next(iter(target_physical_identities)),
                "distractor_wazuh_event_ids": distractor_event_ids,
                "distractor_event_record_ids": sorted(
                    {identity["event_record_id"] for identity in distractor_identities}
                ),
                "distractor_physical_identity": next(iter(distractor_physical_identities)),
            }
        )

    manifest = {
        "schema_version": "csg-v25-counterfactual-replay-inputs-v1",
        "replay_id": RUN_ID,
        "parent_campaign_id": CAMPAIGN_ID,
        "parent_analysis_strict_raw_audit_successes": EXPECTED_TRIALS,
        "trial_count": len(entries),
        "entries": entries,
    }
    write_json(output_dir / "input-manifest.json", manifest)
    return manifest


def _verify_source_freeze(output_dir: Path, repo_root: Path) -> dict[str, Any]:
    freeze = read_json(output_dir / "source-freeze.json")
    checks: dict[str, bool] = {}
    files = {
        "protocol": output_dir / "PROTOCOL.md",
        "input_manifest": output_dir / "input-manifest.json",
        "runner": Path(__file__).resolve(),
        "replay_tool": repo_root / "experiments/replay_target_event_drop_with_distractor.py",
    }
    for key, path in files.items():
        expected = freeze.get("sha256", {}).get(key)
        actual = sha256_file(path)
        checks[key] = bool(expected) and actual == expected
    for relative_path, expected in freeze.get("parent_artifacts", {}).items():
        actual = sha256_file(repo_root / relative_path)
        checks[f"parent:{relative_path}"] = actual == expected
    if not all(checks.values()):
        raise ValueError(f"Frozen source/input hash mismatch: {checks}")
    return freeze


def run_campaign(output_dir: Path, repo_root: Path) -> dict[str, Any]:
    output_dir = output_dir.resolve()
    freeze = _verify_source_freeze(output_dir, repo_root)
    manifest = read_json(output_dir / "input-manifest.json")
    if manifest.get("trial_count") != EXPECTED_TRIALS or len(manifest.get("entries", [])) != EXPECTED_TRIALS:
        raise ValueError("Frozen replay manifest must contain exactly ten parent inputs")
    if manifest.get("parent_campaign_id") != CAMPAIGN_ID:
        raise ValueError("Replay input manifest references an unexpected parent campaign")

    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for entry in manifest["entries"]:
        input_path = repo_root / entry["input_path"]
        audit_path = repo_root / entry["raw_identity_audit_path"]
        if sha256_file(input_path) != entry["input_sha256"]:
            raise ValueError(f"Input changed after freeze: {entry['input_path']}")
        if sha256_file(audit_path) != entry["raw_identity_audit_sha256"]:
            raise ValueError(f"Raw identity audit changed after freeze: {entry['raw_identity_audit_path']}")

        trial_output = output_dir / "trials" / f"trial-{entry['parent_trial']:02d}"
        canonical_input = trial_output / "canonicalized-replay-input.json"
        target_id, distractor_id = canonicalize_replay_input(
            input_path,
            canonical_input,
            entry["target_wazuh_event_ids"],
            entry["distractor_wazuh_event_ids"],
        )
        replay_result = replay(canonical_input, trial_output, grace_seconds=GRACE_SECONDS)
        if (
            target_id != replay_result["input"]["target_event_id"]
            or distractor_id != replay_result["input"]["distractor_event_id"]
        ):
            raise ValueError(f"Replay event IDs disagree with frozen manifest for trial {entry['parent_trial']}")
        replay_result["input"]["path"] = canonical_input.relative_to(repo_root).as_posix()
        write_json(trial_output / "counterfactual-replay.json", replay_result)
        if not replay_result["all_checks_passed"]:
            failures.append(
                {"parent_trial": entry["parent_trial"], "checks": replay_result["checks"]}
            )
        provenance = {
            "parent_trial": entry["parent_trial"],
            "target_name": entry["target_name"],
            "distractor_name": entry["distractor_name"],
            "target_wazuh_event_ids": entry["target_wazuh_event_ids"],
            "target_event_record_ids": entry["target_event_record_ids"],
            "target_physical_identity": entry["target_physical_identity"],
            "canonical_target_wazuh_event_id": target_id,
            "distractor_wazuh_event_ids": entry["distractor_wazuh_event_ids"],
            "distractor_event_record_ids": entry["distractor_event_record_ids"],
            "distractor_physical_identity": entry["distractor_physical_identity"],
            "canonical_distractor_wazuh_event_id": distractor_id,
            "raw_identity_audit_path": entry["raw_identity_audit_path"],
            "raw_identity_audit_sha256": entry["raw_identity_audit_sha256"],
        }
        write_json(trial_output / "raw-identity-provenance.json", provenance)
        results.append(
            {
                "parent_trial": entry["parent_trial"],
                "target_name": entry["target_name"],
                "distractor_name": entry["distractor_name"],
                "target_event_record_ids": entry["target_event_record_ids"],
                "distractor_event_record_ids": entry["distractor_event_record_ids"],
                "target_wazuh_event_ids": entry["target_wazuh_event_ids"],
                "distractor_wazuh_event_ids": entry["distractor_wazuh_event_ids"],
                "canonical_target_wazuh_event_id": target_id,
                "canonical_distractor_wazuh_event_id": distractor_id,
                "all_checks_passed": replay_result["all_checks_passed"],
                "checks": replay_result["checks"],
                "complete_status": replay_result["conditions"][
                    "captured_complete_target_plus_distractor"
                ]["status"],
                "complete_matched_ids": replay_result["conditions"][
                    "captured_complete_target_plus_distractor"
                ]["matched_evidence_ids"],
                "target_removed_status": replay_result["conditions"][
                    "counterfactual_target_removed_distractor_retained"
                ]["status"],
                "target_removed_matched_ids": replay_result["conditions"][
                    "counterfactual_target_removed_distractor_retained"
                ]["matched_evidence_ids"],
                "naive_would_false_explain": replay_result["conditions"][
                    "naive_same_host_type_time_only_baseline"
                ]["would_label_target_explained"],
                "replay_result_path": (
                    trial_output / "counterfactual-replay.json"
                ).relative_to(output_dir).as_posix(),
                "provenance_path": (trial_output / "raw-identity-provenance.json")
                .relative_to(output_dir)
                .as_posix(),
            }
        )

    summary = {
        "schema_version": "csg-v25-counterfactual-replay-analysis-v1",
        "replay_id": RUN_ID,
        "parent_campaign_id": CAMPAIGN_ID,
        "analyzed_at_utc": datetime.now(UTC).isoformat(),
        "evidence_class": "post_hoc_deterministic_counterfactual_replay_not_live_trial",
        "protocol_sha256": sha256_file(output_dir / "PROTOCOL.md"),
        "input_manifest_sha256": sha256_file(output_dir / "input-manifest.json"),
        "source_freeze_sha256": sha256_file(output_dir / "source-freeze.json"),
        "frozen_sources": freeze.get("sha256"),
        "method": {
            "paired_parent_count": len(results),
            "lifecycle_grace_seconds": GRACE_SECONDS,
            "state_delta_held_constant_within_parent": True,
            "primary_intervention": "remove exact target event; retain captured distractor unchanged",
            "raw_windows_eventrecordid_provenance_required": True,
            "source_health_in_counterfactual": "assumed available and query complete",
            "inferential_confidence_interval": None,
            "interval_exclusion_reason": "Derived deterministic replays are not independent trials.",
        },
        "results": {
            "paired_replay_successes": sum(row["all_checks_passed"] for row in results),
            "target_alias_parents_canonicalized": sum(
                len(row["target_wazuh_event_ids"]) > 1 for row in results
            ),
            "distractor_alias_parents_canonicalized": sum(
                len(row["distractor_wazuh_event_ids"]) > 1 for row in results
            ),
            "captured_complete_exact_target_only": sum(
                row["complete_status"] == "CONSISTENT"
                and row["complete_matched_ids"] == [row["canonical_target_wazuh_event_id"]]
                for row in results
            ),
            "target_removed_distractor_only_finalized_unexplained": sum(
                row["target_removed_status"] == "UNEXPLAINED"
                and not row["target_removed_matched_ids"]
                for row in results
            ),
            "naive_baseline_false_explanations": sum(
                row["naive_would_false_explain"] for row in results
            ),
            "strict_failures": failures,
        },
        "trial_results": results,
        "limitations": [
            "This is a deterministic post-hoc replay of already-observed v25 live evidence, not a new live endpoint experiment.",
            "The target event is removed only from the replay input; physical Windows and Wazuh capture remain unchanged.",
        "The counterfactual labels event retrieval complete and the source healthy by assumption.",
            "The ten replays reuse ten trials from one Windows host and are not independent host replications.",
            "The naive comparator is a deliberately simple host/type/time rule, not a tuned Wazuh baseline.",
            "No malicious behavior or attack-detection outcome is tested.",
        ],
        "integrity_pass": not failures and len(results) == EXPECTED_TRIALS,
    }
    write_json(output_dir / "analysis.json", summary)
    write_results_markdown(output_dir / "RESULTS.md", summary)
    write_artifact_manifest(output_dir)
    return summary


def write_results_markdown(path: Path, summary: dict[str, Any]) -> None:
    rows = [
        "# v25 Parent-Linked Counterfactual Replay Results",
        "",
        f"**Evidence class:** `{summary['evidence_class']}`  ",
        f"**Paired replay outcomes:** {summary['results']['paired_replay_successes']}/{summary['method']['paired_parent_count']}  ",
        "**Inferential confidence interval:** not calculated; these are deterministic derived replays.",
        "",
        "## Trial-level outcomes",
        "",
            "| Parent | Target EventRecordID | Distractor EventRecordID | Complete | Target removed, distractor retained | Naive host/type/time baseline | Strict |",
        "|---:|---:|---:|---|---|---|---|",
    ]
    for row in summary["trial_results"]:
        rows.append(
            f"| {row['parent_trial']} | {', '.join(row['target_event_record_ids'])} | "
            f"{', '.join(row['distractor_event_record_ids'])} | {row['complete_status']} | "
            f"{row['target_removed_status']} / no matched IDs: "
            f"{'YES' if not row['target_removed_matched_ids'] else 'NO'} | "
            f"{'FALSE_SUPPORT' if row['naive_would_false_explain'] else 'NO_FALSE_SUPPORT'} | "
            f"{'PASS' if row['all_checks_passed'] else 'FAIL'} |"
        )
    result = summary["results"]
    rows.extend(
        [
            "",
            "## Aggregate",
            "",
            f"- Captured complete condition exact-target-only: {result['captured_complete_exact_target_only']}/{summary['method']['paired_parent_count']}",
            f"- Target removed, distractor retained, finalized `UNEXPLAINED` with no evidence IDs: {result['target_removed_distractor_only_finalized_unexplained']}/{summary['method']['paired_parent_count']}",
            f"- Naive host/type/time comparator would falsely explain the target: {result['naive_baseline_false_explanations']}/{summary['method']['paired_parent_count']}",
            f"- Target physical events with multiple Wazuh document IDs canonicalized from raw identity: {result['target_alias_parents_canonicalized']}; all aliases are retained in the input manifest and per-trial provenance.",
            f"- Strict paired replays passing every frozen check: {result['paired_replay_successes']}/{summary['method']['paired_parent_count']}",
            "",
            "## Interpretation",
            "",
            "On these captured examples, the deterministic reconciler distinguishes the intended task from a same-host, same-type event using object identity. With the target event removed in a replay copy, the reconciler returns `UNEXPLAINED`; the deliberately naive host/type/time comparator would accept the retained distractor. This is paired logic evidence derived from the v25 campaign, not evidence that a live Wazuh event was lost or that CSG detects attacks more effectively.",
            "",
            "## Limitations",
            "",
        ]
    )
    rows.extend(f"- {limitation}" for limitation in summary["limitations"])
    rows.append("")
    path.write_text("\n".join(rows), encoding="utf-8")


def write_artifact_manifest(output_dir: Path) -> None:
    files = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file() or path.name == "artifact-sha256.json":
            continue
        files.append(
            {
                "path": path.relative_to(output_dir).as_posix(),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    write_json(
        output_dir / "artifact-sha256.json",
        {"schema_version": "csg-artifact-sha256-catalog-v1", "files": files},
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare", help="freeze the ten v25 replay input identities")
    prepare.add_argument("--parent-campaign", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    execute = subparsers.add_parser("run", help="execute the frozen paired replay cohort")
    execute.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    repo_root = Path(__file__).resolve().parents[1]

    if args.command == "prepare":
        result = prepare_input_manifest(args.parent_campaign, args.output_dir, repo_root)
        print(json.dumps({"prepared_inputs": result["trial_count"]}, indent=2))
        return 0

    summary = run_campaign(args.output_dir, repo_root)
    print(
        json.dumps(
            {
                "paired_replay_successes": summary["results"]["paired_replay_successes"],
                "strict_failures": summary["results"]["strict_failures"],
                "integrity_pass": summary["integrity_pass"],
            },
            indent=2,
        )
    )
    return 0 if summary["integrity_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
