"""Audit a post-hoc host/type/time-only ablation against V90/V91 raw trials."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
RUN_ROOT = ROOT / "experiments/results/runs/20261016"
COHORTS = {
    "V90": RUN_ROOT / "service-rule-event-only-baseline-v90-retry-aware",
    "V91": RUN_ROOT / "service-rule-event-only-baseline-v91-within-host-replication",
}
DEFAULT_OUTPUT = RUN_ROOT / "service-rule-event-only-v90-v91-identity-ablation"
EXPECTED_ARMS = 10
EVENT_TOLERANCE_SECONDS = 20
Z_95 = 1.959963984540054


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def as_json_list(value: str, field: str) -> list[str]:
    parsed = json.loads(value or "[]")
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise ValueError(f"{field} must be a JSON list of strings")
    return parsed


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise ValueError(f"timestamp lacks a UTC offset: {value}")
    return parsed


def wilson(successes: int, total: int) -> list[float] | None:
    if total == 0:
        return None
    rate = successes / total
    z2 = Z_95**2
    denominator = 1 + z2 / total
    center = (rate + z2 / (2 * total)) / denominator
    margin = Z_95 * math.sqrt(rate * (1 - rate) / total + z2 / (4 * total**2)) / denominator
    return [round(center - margin, 4), round(center + margin, 4)]


def physical_event_identity(event: dict[str, Any]) -> tuple[str, ...]:
    identity = (event.get("metadata") or {}).get("windows_event_identity") or {}
    fields = ("agent_id", "channel", "event_record_id", "event_code", "provider_name")
    values = tuple(str(identity.get(field, "")).casefold() for field in fields)
    if not all(values):
        raise ValueError(f"event {event.get('event_id')} lacks Windows physical-event identity")
    return values


def qualifies_for_naive_match(
    event: dict[str, Any],
    *,
    host_id: str,
    window_start: datetime,
    window_end: datetime,
    tolerance_seconds: int = EVENT_TOLERANCE_SECONDS,
) -> bool:
    """Apply host + event type + rule + time, deliberately ignoring object identity."""
    if event.get("host_id") != host_id or event.get("normalized_type") != "service_modified":
        return False
    attributes = event.get("attributes") or {}
    if str(attributes.get("event_code")) != "7040" or str(attributes.get("rule_id")) != "61104":
        return False
    timestamp = parse_utc(str(event.get("event_time", "")))
    return (
        window_start - timedelta(seconds=tolerance_seconds)
        <= timestamp
        <= window_end + timedelta(seconds=tolerance_seconds)
    )


def audit_trial(
    cohort: str, row: dict[str, str], run_path: Path, validation_path: Path
) -> dict[str, Any]:
    run = json.loads(run_path.read_text(encoding="utf-8-sig"))
    if sha256(run_path) != row["run_artifact_sha256"]:
        raise ValueError(
            f"{cohort}/{row['trial_id']}: raw run hash differs from frozen analysis row"
        )
    if sha256(validation_path) != row["validation_artifact_sha256"]:
        raise ValueError(
            f"{cohort}/{row['trial_id']}: validation hash differs from frozen analysis row"
        )
    if row["condition"] != "target_selective_drop" or row["host_id"] != "win11-arm-lab":
        raise ValueError(f"{cohort}/{row['trial_id']}: unexpected cohort or host")
    if run.get("trial_id") != row["trial_id"] or run.get("service_name") != row["service_name"]:
        raise ValueError(f"{cohort}/{row['trial_id']}: raw and analyzed identities disagree")

    if row["native_state_detected"].lower() != "true":
        raise ValueError(f"{cohort}/{row['trial_id']}: target state transition was not observed")
    if row["target_wazuh_61104_exact_event_detected"].lower() != "false":
        raise ValueError(f"{cohort}/{row['trial_id']}: target Wazuh event was not absent")
    target_event_ids = as_json_list(row["target_wazuh_61104_exact_event_ids"], "target event IDs")
    matched_ids = as_json_list(row["matched_evidence_ids"], "matched evidence IDs")
    declared_distractor_ids = set(
        as_json_list(row["distractor_event_ids_same_host"], "distractor event IDs")
    )
    if target_event_ids or matched_ids or row["reconciliation_status"] != "UNEXPLAINED":
        raise ValueError(f"{cohort}/{row['trial_id']}: expected target absence and UNEXPLAINED")

    details = run["same_host_distractor_proof"]["details"]
    target_name = details["target_service_name"]
    distractor_name = details["distractor_service_name"]
    if details["modify"].get("host_id") != row["host_id"]:
        raise ValueError(f"{cohort}/{row['trial_id']}: local mutation host mismatch")
    if target_name.casefold() != row["service_name"].casefold():
        raise ValueError(f"{cohort}/{row['trial_id']}: target identity mismatch")
    if target_name.casefold() == distractor_name.casefold():
        raise ValueError(f"{cohort}/{row['trial_id']}: distractor is not a distinct object")

    transitions = [
        delta
        for delta in run.get("target_state_deltas", [])
        if delta.get("category") == "service"
        and delta.get("delta_type") == "MODIFY"
        and delta.get("object_key", "").casefold() == f"service:{target_name}".casefold()
    ]
    if len(transitions) != 1:
        raise ValueError(f"{cohort}/{row['trial_id']}: expected one exact target MODIFY delta")
    transition = transitions[0]
    before = transition["before"]["attributes"].get("start_mode", "").casefold()
    after = transition["after"]["attributes"].get("start_mode", "").casefold()
    if (before, after) != ("manual", "auto"):
        raise ValueError(
            f"{cohort}/{row['trial_id']}: unexpected state transition {before!r}->{after!r}"
        )
    observation_window = transition["observation_window"]
    window_start = parse_utc(observation_window["start"])
    window_end = parse_utc(observation_window["end"])

    exact_events = details["modify"]["exact_wazuh_events"]
    candidates = [
        event
        for event in exact_events
        if qualifies_for_naive_match(
            event,
            host_id=row["host_id"],
            window_start=window_start,
            window_end=window_end,
        )
    ]
    if not candidates:
        raise ValueError(
            f"{cohort}/{row['trial_id']}: no host/type/time candidate in target window"
        )

    # All qualifying Wazuh documents must belong to the intentionally different service.
    if any(
        event.get("service_name", "").casefold() != distractor_name.casefold()
        or event.get("target_key", "").casefold() != f"service:{distractor_name}".casefold()
        for event in candidates
    ):
        raise ValueError(f"{cohort}/{row['trial_id']}: candidate identity is not distractor-only")
    physical_events = {physical_event_identity(event): event for event in candidates}
    raw_candidate_ids = {str(event["event_id"]) for event in candidates}
    provider_candidate_ids = set(details["modify_sync"]["exact_distractor_event_ids"])
    if provider_candidate_ids != declared_distractor_ids:
        raise ValueError(
            f"{cohort}/{row['trial_id']}: provider and analyzed distractor IDs disagree"
        )
    if not raw_candidate_ids or not raw_candidate_ids <= declared_distractor_ids:
        raise ValueError(f"{cohort}/{row['trial_id']}: raw event and provider IDs disagree")
    if len(physical_events) != 1:
        raise ValueError(
            f"{cohort}/{row['trial_id']}: expected duplicate documents for one OS event"
        )

    representative = next(iter(physical_events.values()))
    local_proof = details["modify"]["local_windows_events"]
    if local_proof.get("query_status") != "SUCCEEDED":
        raise ValueError(f"{cohort}/{row['trial_id']}: local Windows event query was not complete")
    local_matches = []
    namespace = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    for event in local_proof.get("events", []):
        if (
            event.get("event_id") != 7040
            or str(event.get("record_id")) != physical_event_identity(representative)[2]
            or event.get("provider", "").casefold() != "service control manager"
            or event.get("log_name", "").casefold() != "system"
        ):
            continue
        xml = ElementTree.fromstring(event["raw_xml"])
        event_data = {
            node.get("Name", ""): node.text or ""
            for node in xml.findall(f".//{namespace}EventData/{namespace}Data")
        }
        if event_data.get("param1", "").casefold() == distractor_name.casefold():
            local_matches.append(event)
    if len(local_matches) != 1:
        raise ValueError(
            f"{cohort}/{row['trial_id']}: Wazuh event lacks exact local EventRecordID proof"
        )
    event_time = parse_utc(representative["event_time"])
    nearest_window_edge_seconds = min(
        abs((event_time - window_start).total_seconds()),
        abs((event_time - window_end).total_seconds()),
    )
    return {
        "cohort": cohort,
        "trial_id": row["trial_id"],
        "host_id": row["host_id"],
        "target_service": target_name,
        "distractor_service": distractor_name,
        "target_transition": f"{before}->{after}",
        "target_delta_id": transition["delta_id"],
        "target_observation_start": observation_window["start"],
        "target_observation_end": observation_window["end"],
        "distractor_event_ids": sorted(declared_distractor_ids),
        "raw_event_object_ids": sorted(raw_candidate_ids),
        "local_windows_event_record_id": local_matches[0]["record_id"],
        "distractor_physical_event_identity": list(next(iter(physical_events))),
        "distractor_event_time": representative["event_time"],
        "seconds_to_nearest_observation_window_edge": round(nearest_window_edge_seconds, 3),
        "distractor_normalized_type": representative["normalized_type"],
        "distractor_rule_id": representative["attributes"]["rule_id"],
        "distractor_event_code": representative["attributes"]["event_code"],
        "naive_host_type_time_result": "FALSE_CORROBORATION",
        "exact_object_reconciliation_result": row["reconciliation_status"],
        "exact_reconciler_matched_evidence_ids": matched_ids,
        "raw_run_sha256": row["run_artifact_sha256"],
        "source_validation_artifact_sha256": row["validation_artifact_sha256"],
    }


def load_cohort(name: str, root: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    csv_path = root / "analysis" / f"{name.lower()}-results" / "trial-level.csv"
    raw_root = root / "campaign" / "remote-copy"
    with csv_path.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    selected = [row for row in rows if row.get("condition") == "target_selective_drop"]
    if len(selected) != EXPECTED_ARMS:
        raise ValueError(f"{name}: expected {EXPECTED_ARMS} target-selective-drop rows")
    audits = []
    for row in selected:
        run_path = raw_root / row["trial_id"] / "run.json"
        validation_path = raw_root / row["trial_id"] / "validation.json"
        if not run_path.is_file():
            raise FileNotFoundError(run_path)
        if not validation_path.is_file():
            raise FileNotFoundError(validation_path)
        audits.append(audit_trial(name, row, run_path, validation_path))
    return audits, rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = args.output_dir if args.output_dir.is_absolute() else ROOT / args.output_dir

    trials: list[dict[str, Any]] = []
    inputs: list[dict[str, str]] = []
    for cohort, root in COHORTS.items():
        cohort_trials, all_rows = load_cohort(cohort, root)
        trials.extend(cohort_trials)
        csv_path = root / "analysis" / f"{cohort.lower()}-results" / "trial-level.csv"
        inputs.append({"path": str(csv_path.relative_to(ROOT)), "sha256": sha256(csv_path)})
        for row in all_rows:
            if row.get("condition") != "target_selective_drop":
                continue
            trial_root = root / "campaign/remote-copy" / row["trial_id"]
            inputs.extend(
                [
                    {
                        "path": str((trial_root / "run.json").relative_to(ROOT)),
                        "sha256": row["run_artifact_sha256"],
                    },
                    {
                        "path": str((trial_root / "validation.json").relative_to(ROOT)),
                        "sha256": row["validation_artifact_sha256"],
                    },
                ]
            )

    if len(trials) != 2 * EXPECTED_ARMS:
        raise ValueError("unexpected total number of audited trials")
    if len({(trial["cohort"], trial["trial_id"]) for trial in trials}) != len(trials):
        raise ValueError("duplicate trial identity")
    if any(trial["naive_host_type_time_result"] != "FALSE_CORROBORATION" for trial in trials):
        raise ValueError("counterfactual result is not uniformly false corroboration")
    if any(trial["exact_object_reconciliation_result"] != "UNEXPLAINED" for trial in trials):
        raise ValueError("exact-object reconciliation result is not uniformly UNEXPLAINED")

    n = len(trials)
    result = {
        "schema_version": "csg-v90-v91-posthoc-identity-ablation-v1",
        "analysis_type": "post_hoc_counterfactual_method_ablation",
        "cohorts": ["V90", "V91"],
        "same_endpoint": "win11-arm-lab",
        "trial_count": n,
        "estimand": (
            "False corroboration conditional on an assigned target-selective-drop trial with a "
            "verified same-host, same-event-type, in-window wrong-object event."
        ),
        "naive_host_type_rule_time": {
            "false_corroborations": n,
            "eligible_trials": n,
            "rate": 1.0,
            "wilson_95_ci": wilson(n, n),
        },
        "exact_object_reconciliation": {
            "false_corroborations": 0,
            "eligible_trials": n,
            "rate": 0.0,
            "wilson_95_ci": wilson(0, n),
            "correct_unexplained_outcomes": n,
        },
        "limitations": [
            (
                "This is post-hoc replay over existing raw trials, not a separately "
                "executed or prospectively registered live baseline."
            ),
            (
                "The challenge set deliberately supplies an in-window same-host service_modified "
                "event for another service. The rate is conditional on that challenge, not a "
                "general false-positive rate."
            ),
            (
                "The event was a benign service configuration change; its target event was "
                "deliberately filtered from CSG's evidence view while Wazuh remained operational."
            ),
            (
                "Both cohorts used one Windows 11 ARM64 VM and one Wazuh setup; trial-level "
                "intervals do not represent independent hosts."
            ),
            (
                "This does not establish attack-detection efficacy, natural telemetry loss, or "
                "product-wide superiority over Wazuh."
            ),
        ],
        "input_artifacts": inputs,
        "trials": trials,
    }

    output.mkdir(parents=True, exist_ok=True)
    csv_path = output / "trial-level.csv"
    json_path = output / "identity-ablation.json"
    report_path = output / "RESULTS.md"
    fields = list(trials[0])
    with csv_path.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=fields)
        writer.writeheader()
        writer.writerows(trials)
    json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    report = (
        "# V90/V91 Post-Hoc Identity Ablation\n\n"
        "## Question\n\n"
        "When the exact target event is absent, would host, event type, rule, and time matching "
        "without object identity falsely accept another service's event?\n\n"
        "## Method\n\n"
        "This analysis re-opened the 20 raw `target_selective_drop` trials from frozen V90 and "
        "V91. Each trial was checked for the native target `Manual -> Auto` delta, absence of its "
        "exact rule-61104 event, and a distinct distractor service. The distractor had to produce "
        "a same-host Event 7040 / rule 61104 `service_modified` event within the target "
        "window plus the frozen 20-second tolerance. Its service name and EventRecordID were "
        "matched to the local Windows System log. Alert/archive documents were deduplicated by "
        "agent, channel, EventRecordID, event code, and provider. The counterfactual matcher then "
        "applied host, type, rule, and time while ignoring the target object.\n\n"
        "## Result\n\n"
        "| Method | False corroborations | Eligible trials | Conditional rate (95% Wilson CI) |\n"
        "|---|---:|---:|---:|\n"
        f"| Host + type + rule + time; identity ignored | {n}/{n} | {n} | "
        f"1.000 [{wilson(n, n)[0]:.4f}, {wilson(n, n)[1]:.4f}] |\n"
        f"| Exact-object CSG reconciliation | 0/{n} | {n} | "
        f"0.000 [{wilson(0, n)[0]:.4f}, {wilson(0, n)[1]:.4f}] |\n\n"
        "In every eligible trial, the counterfactual matcher would corroborate the target using "
        "the other service's event. CSG finalized the target as `UNEXPLAINED` without a matched "
        "evidence ID. Per-trial output retains object identities, observation windows, physical "
        "Windows event identity, evidence IDs, delta IDs, and source hashes.\n\n"
        "## Interpretation Limits\n\n"
        "This post-hoc ablation is not a separately executed Wazuh baseline. Its denominator "
        "contains only deliberately assigned wrong-object challenges, so 20/20 is not a general "
        "false-positive estimate. V90 and V91 repeat on one Windows VM; the trials are not "
        "independent host samples. Mutations were benign, and the target event was selectively "
        "filtered while Wazuh remained operational. The result supports only the bounded claim "
        "that exact object identity prevented false corroboration in this service-change test. It "
        "does not establish attack-detection efficacy, natural event loss, or product-wide "
        "superiority to Wazuh.\n\n"
        "## Reproduction\n\n"
        "From the repository root, run `python3 experiments/analyze_v90_v91_identity_ablation.py`. "
        "The script validates raw `run.json` and `validation.json` hashes against the frozen trial "
        "CSV, then writes the per-trial CSV, JSON, report, frozen sources, and artifact manifest.\n"
    )
    report_path.write_text(report, encoding="utf-8")

    frozen_sources = output / "frozen-sources"
    frozen_sources.mkdir(exist_ok=True)
    source_files = [
        Path(__file__),
        Path(__file__).with_name("test_analyze_v90_v91_identity_ablation.py"),
    ]
    frozen_source_paths = []
    for source_path in source_files:
        frozen_path = frozen_sources / source_path.name
        frozen_path.write_bytes(source_path.read_bytes())
        frozen_source_paths.append(frozen_path)
    manifest = {
        "schema_version": "csg-artifact-manifest-v1",
        "artifact_scope": "post-hoc identity ablation outputs",
        "files": [
            {"path": str(p.relative_to(output)), "sha256": sha256(p)}
            for p in [*frozen_source_paths, csv_path, json_path, report_path]
            if p.is_file()
        ],
        "input_artifact_count": len(inputs),
        "input_artifacts": inputs,
    }
    (output / "artifact-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"IDENTITY_ABLATION=PASS; TRIALS={n}; "
        f"NAIVE_FALSE_CORROBORATION={n}/{n}; CSG_FALSE_CORROBORATION=0/{n}; OUTPUT={output}"
    )


if __name__ == "__main__":
    main()
