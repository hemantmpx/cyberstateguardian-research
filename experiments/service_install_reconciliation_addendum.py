"""Audit V16 service-install evidence as a supplemental cross-category result."""

from __future__ import annotations

import csv
import hashlib
import json
import textwrap
from collections import Counter
from pathlib import Path
from typing import Any

CONDITIONS = {
    "complete": "complete_collection_with_distractor",
    "target_event_drop": "target_event_drop_with_distractor",
    "target_no_change_with_wrong_object_event": "no_change_with_distractor",
}
V16_REL = Path("experiments/results/runs/20261016/service-install-randomized-three-arm-v16")
PRIOR_SYNTHESIS_REL = Path("experiments/results/runs/20261015/multi-category-stratified-synthesis")


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_artifact_manifest(root: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = _read(manifest_path)
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise ValueError(f"invalid artifact manifest: {manifest_path}")
    missing: list[str] = []
    mismatched: list[str] = []
    for entry in entries:
        rel = entry.get("path")
        target = root / rel if isinstance(rel, str) else None
        if target is None or not target.is_file():
            missing.append(str(rel))
            continue
        if target.stat().st_size != entry.get("bytes") or _sha256(target) != entry.get("sha256"):
            mismatched.append(rel)
    if missing or mismatched:
        raise ValueError(
            f"artifact manifest failed: missing={missing[:5]}, mismatched={mismatched[:5]}"
        )
    return {"entries": len(entries), "verified": len(entries), "missing": 0, "mismatched": 0}


def summarize_trials(
    rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if len(rows) != 30 or len({row.get("trial_id") for row in rows}) != 30:
        raise ValueError("V16 must contain 30 unique assigned trials")

    ids_by_object: dict[str, set[str]] = {}
    normalized: list[dict[str, Any]] = []
    target_names: set[str] = set()
    distractor_names: set[str] = set()
    for row in rows:
        condition = row.get("condition")
        if condition not in CONDITIONS:
            raise ValueError(f"unknown V16 condition: {condition}")
        if not row.get("trial_pass") or row.get("failure_reasons"):
            raise ValueError(f"trial did not pass its frozen gates: {row.get('trial_id')}")
        if not row.get("cleanup_verified") or not row.get("baseline_configuration_restored"):
            raise ValueError(f"trial cleanup/configuration gate failed: {row.get('trial_id')}")

        target_name = row.get("target_service_name")
        distractor_name = row.get("distractor_service_name")
        if not target_name or not distractor_name or target_name == distractor_name:
            raise ValueError(f"target/distractor identity invalid: {row.get('trial_id')}")
        target_names.add(target_name)
        distractor_names.add(distractor_name)
        raw_target_ids = row.get("target_evidence_ids") or []
        raw_distractor_ids = row.get("distractor_evidence_ids") or []
        target_ids = set(raw_target_ids)
        distractor_ids = set(raw_distractor_ids)
        if len(target_ids) != len(raw_target_ids) or len(distractor_ids) != len(raw_distractor_ids):
            raise ValueError(f"duplicate evidence ID within trial: {row.get('trial_id')}")
        matched_ids = set(row.get("matched_evidence_ids") or [])
        if target_ids & distractor_ids:
            raise ValueError(f"target and distractor share evidence IDs: {row.get('trial_id')}")
        if matched_ids - target_ids:
            raise ValueError(f"reconciliation cited non-target evidence: {row.get('trial_id')}")
        if row.get("distractor_exact_wazuh_event_count") != 1:
            raise ValueError(f"expected one exact distractor event: {row.get('trial_id')}")
        if len(distractor_ids) != 1 or not row.get("distractor_event_record_id_linked"):
            raise ValueError(
                f"distractor is not linked to its local Windows event: {row.get('trial_id')}"
            )

        if condition == "complete":
            expected_target = (
                row.get("target_state_add_observed")
                and row.get("target_exact_wazuh_event_count") == 1
                and len(target_ids) == 1
                and row.get("target_event_record_id_linked")
                and row.get("reconciliation_finalized")
                and row.get("reconciliation_status") == "CONSISTENT"
                and matched_ids == target_ids
                and row.get("matched_only_target_evidence")
            )
            if not expected_target:
                raise ValueError(
                    f"complete target did not reconcile to its exact event: {row.get('trial_id')}"
                )
        elif condition == "target_event_drop":
            expected_drop = (
                row.get("target_state_add_observed")
                and row.get("target_exact_wazuh_event_count") == 0
                and not target_ids
                and row.get("target_local_event_record_id") is not None
                and not row.get("target_event_record_id_linked")
                and row.get("reconciliation_finalized")
                and row.get("reconciliation_status") == "UNEXPLAINED"
                and not matched_ids
            )
            if not expected_drop:
                raise ValueError(
                    f"invalid filtered-target outcome: {row.get('trial_id')}"
                )
        else:
            expected_no_change = (
                row.get("target_absent_no_change_control")
                and not row.get("target_state_add_observed")
                and row.get("target_exact_wazuh_event_count") == 0
                and not target_ids
                and row.get("target_local_event_record_id") is None
                and row.get("reconciliation_status") == "NO_FINDING_EXPECTED"
                and not matched_ids
            )
            if not expected_no_change:
                raise ValueError(
                    f"invalid distractor-only control: {row.get('trial_id')}"
                )

        for object_name, evidence_ids in (
            (target_name, target_ids),
            (distractor_name, distractor_ids),
        ):
            for evidence_id in evidence_ids:
                prior_object = ids_by_object.setdefault(evidence_id, set())
                prior_object.add(f"{row['trial_id']}:{object_name}")

        normalized.append(
            {
                "trial_id": row["trial_id"],
                "condition": condition,
                "arm": CONDITIONS[condition],
                "target_service": target_name,
                "distractor_service": distractor_name,
                "state_add_observed": bool(row.get("target_state_add_observed")),
                "target_exact_event_count": int(row.get("target_exact_wazuh_event_count") or 0),
                "distractor_exact_event_count": int(
                    row.get("distractor_exact_wazuh_event_count") or 0
                ),
                "matched_evidence_ids": sorted(matched_ids),
                "target_evidence_ids": sorted(target_ids),
                "distractor_evidence_ids": sorted(distractor_ids),
                "matched_only_target_evidence": bool(row.get("matched_only_target_evidence")),
                "reconciliation_status": row.get("reconciliation_status"),
                "trial_pass": True,
            }
        )

    reused_ids = {
        event_id: objects for event_id, objects in ids_by_object.items() if len(objects) > 1
    }
    if reused_ids:
        raise ValueError(f"Wazuh evidence IDs reused across objects: {reused_ids}")
    if len(ids_by_object) != 40:
        raise ValueError(
            f"expected 40 distinct target/distractor Wazuh IDs, found {len(ids_by_object)}"
        )
    if len(target_names) != 30 or len(distractor_names) != 30 or target_names & distractor_names:
        raise ValueError("service names were reused across target and distractor assignments")

    summaries: list[dict[str, Any]] = []
    for condition, arm in CONDITIONS.items():
        trials = [trial for trial in normalized if trial["condition"] == condition]
        if len(trials) != 10:
            raise ValueError(f"expected 10 trials in {condition}, found {len(trials)}")
        statuses = Counter(trial["reconciliation_status"] for trial in trials)
        summary = {
            "arm": arm,
            "assigned": len(trials),
            "passed": sum(trial["trial_pass"] for trial in trials),
            "state_add_observed": sum(trial["state_add_observed"] for trial in trials),
            "exact_target_event": sum(trial["target_exact_event_count"] > 0 for trial in trials),
            "wrong_object_event": sum(
                trial["distractor_exact_event_count"] > 0 for trial in trials
            ),
            "target_only_citation": sum(trial["matched_only_target_evidence"] for trial in trials),
            "final_status_counts": dict(sorted(statuses.items())),
        }
        expected = {
            "complete_collection_with_distractor": (10, 10, 10, 10, {"CONSISTENT": 10}),
            "target_event_drop_with_distractor": (10, 0, 10, 0, {"UNEXPLAINED": 10}),
            "no_change_with_distractor": (0, 0, 10, 0, {"NO_FINDING_EXPECTED": 10}),
        }[arm]
        actual = (
            summary["state_add_observed"],
            summary["exact_target_event"],
            summary["wrong_object_event"],
            summary["target_only_citation"],
            summary["final_status_counts"],
        )
        if actual != expected or summary["passed"] != 10:
            raise ValueError(f"unexpected V16 outcomes in {arm}: {actual}")
        summaries.append(summary)
    return normalized, summaries


def build_addendum(repo_root: Path) -> dict[str, Any]:
    v16_root = repo_root / V16_REL
    manifest_path = v16_root / "analysis/artifact-manifest.json"
    analysis_path = v16_root / "analysis/analysis.json"
    service_audit_path = v16_root / "analysis/service-control-audit.json"
    prior_analysis_path = repo_root / PRIOR_SYNTHESIS_REL / "analysis/analysis.json"

    manifest_check = verify_artifact_manifest(v16_root, manifest_path)
    analysis = _read(analysis_path)
    service_audit = _read(service_audit_path)
    prior_analysis = _read(prior_analysis_path)
    if analysis.get("audit_status") != "PASS" or analysis.get("analyzed_raw_trials") != 30:
        raise ValueError("V16 raw-artifact audit is not a complete pass")
    if analysis.get("duplicate_evidence_id_cross_object_conflicts") != []:
        raise ValueError("V16 reports cross-object evidence-ID conflicts")
    if not service_audit.get("audit_pass") or service_audit.get("failures"):
        raise ValueError("V16 service-control transition audit failed")
    if (
        service_audit.get("passed_trials") != 30
        or service_audit.get("drop_trials") != 10
        or service_audit.get("recorded_service_transitions") != 40
    ):
        raise ValueError("V16 service-control audit denominator changed")
    if (
        prior_analysis.get("analysis_classification")
        != "POST_HOC_STRATIFIED_SYNTHESIS_NOT_A_NEW_EXPERIMENT"
    ):
        raise ValueError("prior three-category synthesis identity changed")

    trial_rows, arm_summaries = summarize_trials(analysis.get("trial_results", []))
    return {
        "schema_version": "csg-service-install-reconciliation-addendum-v1",
        "classification": "SUPPLEMENTAL_POST_HOC_ANALYSIS_NOT_A_NEW_EXPERIMENT",
        "host_scope": "Single Windows 11 ARM64 VM; same host as the prior three-category synthesis",
        "behavior_scope": "Benign inert service registration; service was never started",
        "prior_synthesis_path": PRIOR_SYNTHESIS_REL.as_posix(),
        "prior_synthesis_sha256": _sha256(prior_analysis_path),
        "v16_experiment_id": analysis.get("experiment_id"),
        "v16_randomization_seed": analysis.get("assignment_seed"),
        "v16_independent_audit": analysis.get("audit_status"),
        "v16_service_control_audit": {
            "passed": service_audit.get("audit_pass"),
            "passed_trials": service_audit.get("passed_trials"),
            "drop_trials": service_audit.get("drop_trials"),
            "recorded_service_transitions": service_audit.get("recorded_service_transitions"),
            "failures": service_audit.get("failures"),
        },
        "artifact_manifest_verification": manifest_check,
        "arm_summaries": arm_summaries,
        "trials": trial_rows,
        "evidence_id_uniqueness": {
            "distinct_exact_wazuh_evidence_ids": len(
                {
                    event_id
                    for trial in trial_rows
                    for event_id in trial["target_evidence_ids"] + trial["distractor_evidence_ids"]
                }
            ),
            "cross_object_reuse_detected": False,
        },
        "input_sha256": {
            "v16_analysis": _sha256(analysis_path),
            "v16_artifact_manifest": _sha256(manifest_path),
            "v16_service_control_audit": _sha256(service_audit_path),
            "prior_three_category_analysis": _sha256(prior_analysis_path),
        },
        "interpretation_limit": (
            "This adds a service-install distractor test to the existing stratified evidence. "
            "It is not a fourth behavior category, independent host, attack-efficacy result, or "
            "proof of natural or permanent telemetry loss."
        ),
    }


def write_outputs(repo_root: Path, output_dir: Path) -> None:
    result = build_addendum(repo_root)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "analysis.json"
    csv_path = output_dir / "trial-level.csv"
    report_path = output_dir / "RESULTS.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        fields = [
            "trial_id",
            "arm",
            "target_service",
            "distractor_service",
            "state_add_observed",
            "target_exact_event_count",
            "distractor_exact_event_count",
            "matched_evidence_ids",
            "reconciliation_status",
            "trial_pass",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for trial in result["trials"]:
            writer.writerow(
                {
                    field: (
                        ";".join(trial[field]) if field == "matched_evidence_ids" else trial[field]
                    )
                    for field in fields
                }
            )

    lines = [
        "# Service-Install Reconciliation Addendum",
        "",
        "**Classification:** Supplemental post-hoc analysis; no new endpoint experiment was run.  ",
        "**Endpoint:** One Windows 11 ARM64 VM (`win11-arm-lab`).  ",
        "**Behavior:** Benign inert service registration; test services were never started.",
        "",
        "## Why This Addendum",
        "",
    ]
    lines.extend(
        textwrap.fill(
            "The October 15 three-category synthesis already reports scheduled-task, "
            "service-modification, and Registry behavior. This addendum preserves that synthesis "
            "and adds the later V16 service-install cohort as a distinct service behavior subtype. "
            "Unlike the earlier synthesis arms, V16 placed a verified same-host wrong-object "
            "service event in every arm, including the no-change arm.",
            width=96,
        ).splitlines()
    )
    lines.extend(
        [
            "",
            "## Results",
            "",
            "| Arm | n | State | Target event | Distractor | Target-only cite | Result |",
            "|---|---:|---:|---:|---:|---:|---|",
        ]
    )
    for arm in result["arm_summaries"]:
        status = ", ".join(f"{key} {value}/10" for key, value in arm["final_status_counts"].items())
        lines.append(
            f"| `{arm['arm']}` | {arm['passed']}/10 | {arm['state_add_observed']}/10 | "
            f"{arm['exact_target_event']}/10 | {arm['wrong_object_event']}/10 | "
            f"{arm['target_only_citation']}/10 | {status} |"
        )
    paragraphs = (
        "Every arm passed its frozen trial gates (30/30). The V16 artifact manifest verifies "
        "49/49 files. The separate service-control audit passed all ten filtered-arm trials and "
        "recorded 40 Wazuh service transitions. Forty exact Wazuh evidence IDs were distinct "
        "across target and distractor objects; no cross-object reuse was detected.",
        "For these controlled benign registrations, the direct CSG probe observed each target "
        "service add even when the target-specific Wazuh collection path was filtered. With a "
        "same-host distractor event present, reconciliation was `UNEXPLAINED` and cited no event. "
        "Under complete collection, CSG reached `CONSISTENT` and cited target evidence only. "
        "When the assigned target remained absent and only a different service generated an "
        "event, CSG produced no target finding.",
        "This is evidence for exact-object reconciliation and a bounded state-visibility "
        "mechanism on one host. It is not malicious-activity detection efficacy, natural or "
        "permanent telemetry-loss evidence, a Wazuh superiority claim, or independent-host "
        "validation. The suppression arm is a controlled target-specific collection filter. Do "
        "not pool these trials with the earlier service-modification cohort or report them as a "
        "new behavior category.",
    )
    for paragraph in paragraphs:
        lines.extend(["", *textwrap.fill(paragraph, width=96).splitlines()])
    lines.extend(
        [
            "",
            "## Reproduction",
            "",
            "Run from the repository root:",
            "",
            "```shell",
            "python3 experiments/service_install_reconciliation_addendum.py",
            "```",
            "",
        ]
    )
    reproduction_links = (
        "The input hashes, validation gates, and trial rows are in [analysis.json](analysis.json); "
        "one-row-per-trial data are in [trial-level.csv](trial-level.csv). The original [V16 "
        "frozen protocol](../../20261016/service-install-randomized-three-arm-v16/PROTOCOL.md), "
        "[V16 analysis](../../20261016/"
        "service-install-randomized-three-arm-v16/analysis/analysis.md), "
        "and [October 15 synthesis](../../20261015/multi-category-stratified-synthesis/RESULTS.md) "
        "remain the primary records."
    )
    lines.extend(textwrap.fill(reproduction_links, width=96).splitlines())
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    files = []
    for path in (json_path, csv_path, report_path):
        files.append(
            {
                "path": path.name,
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    manifest = {
        "schema_version": "csg-service-install-addendum-artifact-manifest-v1",
        "source_script_sha256": _sha256(Path(__file__).resolve()),
        "input_sha256": result["input_sha256"],
        "files": files,
    }
    (output_dir / "artifact-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    destination = (
        project_root / "experiments/results/runs/20261016/service-install-cross-category-addendum"
    )
    write_outputs(project_root, destination)
    print(f"Wrote service-install reconciliation addendum to {destination}")
