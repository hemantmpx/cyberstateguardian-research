"""Build a detailed human-readable report from immutable experiment artifacts."""

# Markdown table rows intentionally contain long, readable columns.
# ruff: noqa: E501

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "experiments/results"
PUBLISHED = RESULTS / "published"
RUNS = RESULTS / "runs"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def md(value: Any) -> str:
    return str(value if value not in (None, "") else "N/A").replace("|", "\\|").replace("\n", " ")


def reconciliation_rows(record: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for histories in (record.get("reconciliation_histories") or {}).values():
        for wrapper in histories:
            rows.extend(wrapper.get("value", []))
    return rows


def finding_rows(record: dict[str, Any]) -> list[str]:
    reconciliations = reconciliation_rows(record)
    by_finding: dict[str, list[dict[str, Any]]] = {}
    for item in reconciliations:
        by_finding.setdefault(str(item.get("finding_id")), []).append(item)
    rows = []
    for finding in record.get("findings", []):
        finding_id = str(finding.get("finding_id"))
        histories = by_finding.get(finding_id, [])
        statuses = "; ".join(
            f"v{item.get('version')}: {item.get('status')} ({'final' if item.get('finalized') else 'provisional'})"
            for item in histories
        )
        evidence = sorted(
            {
                evidence_id
                for item in histories
                for evidence_id in item.get("matched_evidence_ids", [])
            }
        )
        rows.append(
            "| {id} | {category} | `{object_key}` | {risk} / {severity} | {auth} | {statuses} | {evidence} |".format(
                id=md(finding_id),
                category=md(finding.get("category")),
                object_key=md(finding.get("object_key")),
                risk=md((finding.get("risk") or {}).get("total")),
                severity=md((finding.get("risk") or {}).get("severity")),
                auth=md(finding.get("authorization_status")),
                statuses=md(statuses),
                evidence=md(", ".join(evidence)),
            )
        )
    return rows


def build_report() -> str:
    dataset = read_json(PUBLISHED / "windows-apt-2025-import-summary-20260923.json")
    campaign = read_json(PUBLISHED / "live-telemetry-campaign-summary-20260923.json")
    correlation = read_json(PUBLISHED / "incident-correlation-expanded-20260923.json")
    adversarial_correlation = read_json(
        PUBLISHED / "incident-correlation-adversarial-20260923.json"
    )
    authorization = read_json(PUBLISHED / "authorization-study-20260923.json")
    apt_evaluation = read_json(PUBLISHED / "windows-apt-2025-evaluation-20260923.json")
    ai_path = RUNS / "20260923/reviewer-hardening/ai-context-ollama-v4/study.json"
    ai = read_json(ai_path if ai_path.exists() else RUNS / "20260923/ai-context-legacy/study.json")
    review_path = RUNS / "20260923/reviewer-hardening/ai-context-ollama-v4/review_items.blinded.json"
    review = read_json(
        review_path
        if review_path.exists()
        else RUNS / "20260923/ai-context-ollama/blinded-review.json"
    )
    freeze = read_json(PUBLISHED / "research-freeze-20260923.json")
    audit = read_json(PUBLISHED / "reconciliation-evidence-audit-20260923.json")
    verified_live_paths = [
        RUNS / "20260923/reviewer-hardening/service-complete-control-v4/run.json",
        RUNS / "20260923/live-reconciliation/complete-verified/run.json",
        RUNS / "20260923/live-reconciliation/capture-drop-finalized/run.json",
    ]
    verified_live = [read_json(path) for path in verified_live_paths if path.exists()]
    capture_record = next(
        (record for record in verified_live if record.get("telemetry_condition") == "capture_drop"),
        None,
    )
    capture_proof_recorded = bool((capture_record or {}).get("capture_drop_proof"))
    live_files = {
        Path(item["file"]).name: read_json(ROOT / item["file"]) for item in campaign["conditions"]
    }

    lines = [
        "# CyberStateGuardian Detailed Research Results",
        "",
        f"Research version: `{md(freeze['research_version'])}`",
        f"Freeze timestamp: `{md(freeze['frozen_at'])}`",
        "",
        "## 1. Evidence Status",
        "",
        "This report is generated only from archived result artifacts. It distinguishes measured "
        "results from controlled fixtures and from research gates that are still pending.",
        "",
        "| Area | Status | Evidence |",
        "| --- | --- | --- |",
        f"| External event archive | Acquired and hashed | {dataset['event_count']:,} events, {dataset['scenario_count']} scenarios |",
        f"| Windows-APT normalization | Evaluated | {apt_evaluation['normalization']['semantic_normalization_rate']:.2%} semantic normalization; {apt_evaluation['normalization']['generic_event_rate']:.2%} retained as generic |",
        f"| Live telemetry | Corrected runs verified; historical matches superseded | {audit['invalid_match_count']} of {audit['match_count']} old stored matches fail strict identity; {len(verified_live)} corrected runs archived |",
        "| Live capture-drop tooling | Implemented | Bounded pre-restore result plus separate post-restore synchronization and validation |",
        f"| Authorization | Controlled study complete | {authorization['all_expected_statuses_observed']} approved/unknown/violation outcomes |",
        f"| Correlation | Controlled validation complete | {correlation['metrics']['finding_count']} labeled findings |",
        f"| Correlation stress test | Adversarial fixture complete | precision {adversarial_correlation['metrics']['pairwise_precision']}, recall {adversarial_correlation['metrics']['pairwise_recall']} |",
        f"| AI packages | Frozen and blinded | {review['items'].__len__()} review items |",
        f"| AI model/human scores | {'Model pilot archived; human scores pending' if ai_path.exists() else 'Pending'} | {'Ollama artifact available; independent human scoring remains required' if ai_path.exists() else 'No model output or human score was fabricated'} |",
        "",
        "## 2. Windows-APT 2025 Archive",
        "",
        "Source: [Mendeley Data revision 3](https://data.mendeley.com/datasets/b8fmtzvpy8/3)",
        f"\nArchive SHA-256: `{dataset['sha256']}`",
        f"\nTime range: `{dataset['event_time_range']['first']}` to `{dataset['event_time_range']['last']}`",
        f"\nObserved agents: {', '.join(f'`{agent}`' for agent in dataset['agents'])}",
        "",
        "### Event Distribution",
        "",
        "| Normalized event type | Count |",
        "| --- | ---: |",
    ]
    lines.extend(
        f"| `{md(event_type)}` | {count:,} |"
        for event_type, count in dataset["event_type_counts"].items()
    )
    capture_interpretation = (
        "The finalized `capture_drop` run kept Wazuh stopped through the observation window plus "
        "grace, stored the bounded result, restored Wazuh, and recorded a separate post-restore "
        "synchronization. The validator requires the pre-restore modification result to be "
        "`UNEXPLAINED` and the post-restore result to be `CONSISTENT` before calling recovery "
        "demonstrated."
        if capture_proof_recorded
        else "The archived `capture_drop` run kept Wazuh stopped through the observation window plus "
        "grace: the exact creation event was present, the exact modification event was absent, "
        "and the modification finding finalized as `UNEXPLAINED`. That archived run predates "
        "the new post-restore proof fields; rerun it before claiming recovery or permanent loss."
    )
    lines += [
        "",
        "### Normalization Evaluation",
        "",
        f"Semantic event types account for `{apt_evaluation['normalization']['semantic_events']:,}` of `{apt_evaluation['dataset']['event_count']:,}` records (`{apt_evaluation['normalization']['semantic_normalization_rate']:.2%}`). "
        f"The remaining `{apt_evaluation['normalization']['generic_dataset_events']:,}` records remain available as `dataset_event`; they are not silently discarded. "
        f"All recognized semantic events retained retrievable actor/target/attribute context in this evaluation (`{apt_evaluation['normalization']['semantic_context_retrieval_rate']:.2%}`).",
        "",
        "Interpretation: this archive is a Wazuh/Sysmon event-plane dataset. It contains no "
        "independent CSG probe snapshots, so it cannot by itself test state-plane resilience.",
        "",
        "## 3. Live Telemetry Trials",
        "",
        "Each trial created a unique Windows service, collected direct-probe state, changed the "
        "startup mode, synchronized CSG, recorded reconciliation revisions, and removed only its "
        "own service. The temporary source-unavailable condition restored `WazuhSvc` in cleanup.",
        "",
        "| Condition | Service | Findings | Finalized reconciliations | Recovery recorded |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for item in campaign["conditions"]:
        recovery = "yes" if item.get("event_source_restored_in_record") else "not applicable"
        if item.get("telemetry_condition") == "capture_drop":
            recovery = (
                "pre/post snapshots"
                if item.get("capture_drop_recovery_recorded")
                else "pre-restore only in archived run"
            )
        lines.append(
            f"| `{md(item['telemetry_condition'])}` | `{md(item['service_name'])}` | "
            f"{item['finding_count']} | {item['finalized_reconciliation_count']} | "
            f"{recovery} |"
        )
    for item in campaign["conditions"]:
        record = live_files[Path(item["file"]).name]
        lines += [
            "",
            f"### Trial: `{md(item['telemetry_condition'])}`",
            "",
            f"Run ID: `{md(record.get('run_id'))}`; started `{md(record.get('started_at'))}`; ended `{md(record.get('ended_at'))}`.",
            "",
            "Timeline: " + " -> ".join(f"`{md(phase)}`" for phase in item["timeline_phases"]),
            "",
            "| Finding ID | Category | Object | Risk / severity | Authorization | Reconciliation history | Matched evidence |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        lines.extend(finding_rows(record))
        lines += [
            "",
            "The raw JSON record contains complete API responses, state-plane/Wazuh provenance, "
            "observation windows, evidence IDs, and all reconciliation revisions.",
        ]
    lines += [
        "",
        "### Live-Trial Interpretation",
        "",
        "The delayed and temporarily unavailable trials recovered buffered Wazuh events and "
        "reached `CONSISTENT`. This demonstrates bounded latency/recovery handling. The corrected "
        "complete run then verified exact per-object matching for both service transitions. "
        + capture_interpretation,
        "",
        "### Strict Evidence Audit",
        "",
        f"The stored historical live records were audited against `{audit['audit_rule']}`. The audit found `{audit['invalid_match_count']}` invalid object-specific matches out of `{audit['match_count']}`, with `{len(audit['cross_object_reused_evidence_ids'])}` evidence IDs reused across different service object keys. The earlier `CONSISTENT` statuses therefore remain historical software output, not valid proof that the corresponding Wazuh event belonged to each service. The corrected matcher now rejects a display name alone; the two corrected runs above provide the replacement object-specific evidence.",
        "",
        "Audit artifact: `experiments/results/published/reconciliation-evidence-audit-20260923.json`.",
        "",
        "### Corrected Windows Service Runs",
        "",
        "These runs use the strict identity contract: same host, expected normalized event type, observation window, and exact internal service name or target key. A display name alone is not accepted.",
        "",
        "| Condition | Service | Exact create evidence | Exact modify evidence | Final create status | Final modify status |",
        "| --- | --- | ---: | ---: | --- | --- |",
    ]
    for record in verified_live:
        evidence = record.get("verified_exact_wazuh_evidence", {})
        finding_statuses = [
            finding.get("reconciliation", {}).get("status", "N/A")
            for finding in record.get("findings", [])
        ]
        lines.append(
            f"| `{md(record.get('telemetry_condition'))}` | `{md(record.get('service_name'))}` | "
            f"{evidence.get('exact_create_count', 0)} | {evidence.get('exact_modify_count', 0)} | "
            f"`{md(finding_statuses[-1] if finding_statuses else 'N/A')}` | "
            f"`{md(finding_statuses[0] if finding_statuses else 'N/A')}` |"
        )
    lines += [
        "",
        (
            "The complete run matched one exact Wazuh event for each service transition and finalized "
            "both findings as `CONSISTENT`. The capture-drop proof must be read as two observations: "
            "bounded pre-restore reconciliation, followed by a separate post-restore revision. It "
            "is a single live capture trial, not a population-level reliability estimate."
            if capture_proof_recorded
            else "The complete run matched one exact Wazuh event for each service transition and finalized "
            "both findings as `CONSISTENT`. The archived capture-drop run matched the exact creation "
            "event but no exact modification event and finalized the modification as `UNEXPLAINED`; "
            "its post-restore proof is not yet archived. It is not evidence of permanent event loss."
        ),
        "",
        "Complete-run artifact: `experiments/results/runs/20260923/live-reconciliation/complete-verified/run.json`.",
        "Latest reviewer-hardening complete artifact: `experiments/results/runs/20260923/reviewer-hardening/service-complete-control-v4/run.json`; it also archives timezone-safe state/event latency measurements.",
        "Capture-drop artifact: `experiments/results/runs/20260923/live-reconciliation/capture-drop-finalized/run.json`.",
        "",
        "## 4. Authorization Study",
        "",
        "The same service delta was evaluated against three policies. The state evidence was held constant; only authorization context changed.",
        "",
        "| Policy class | Status | Interpretation |",
        "| --- | --- | --- |",
    ]
    for label, observation in authorization["observations"].items():
        lines.append(f"| `{label}` | `{observation['status']}` | {md(observation['reason'])} |")
    lines += [
        "",
        "This supports the distinction between technical explanation and authorization: the same observed state can be approved, unknown, or prohibited without changing the underlying delta.",
        "",
        "## 5. Incident Correlation",
        "",
        f"The controlled labeled fixture contains `{correlation['metrics']['finding_count']}` findings across four known incident groups.",
        "",
        "| Metric | Result |",
        "| --- | ---: |",
    ]
    for key, value in correlation["metrics"].items():
        lines.append(f"| `{md(key)}` | `{md(value)}` |")
    lines += [
        "",
        "### Assignment Evidence",
        "",
        "| Label | Truth group | Incident ID | Score | Reasons |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for assignment in correlation["assignments"]:
        lines.append(
            f"| `{md(assignment['label'])}` | `{md(assignment['truth_group'])}` | "
            f"`{md(assignment['incident_id'])}` | {assignment['score']} | "
            f"{md('; '.join(assignment['reasons']))} |"
        )
    lines += [
        "",
        "Interpretation: precision and recall are perfect for this controlled fixture only. They "
        "are not estimates of real-world correlation performance.",
        "",
        "### Adversarial Correlation Stress Test",
        "",
        f"The stress fixture contains `{adversarial_correlation['metrics']['finding_count']}` findings and deliberately tests same-host simultaneous activity, longer gaps, and reused executable names. It produced pairwise precision `{adversarial_correlation['metrics']['pairwise_precision']}` and recall `{adversarial_correlation['metrics']['pairwise_recall']}`, with `{adversarial_correlation['metrics']['false_merge_pairs']}` false merge pairs and `{adversarial_correlation['metrics']['false_split_pairs']}` false split pairs. These failures are retained as algorithm limitations rather than hidden.",
        "",
        "## 6. AI Context Study",
        "",
        f"Study ID: `{md(ai['study_id'])}`; subject finding: `{md(ai['subject']['finding_id'])}`; repetitions: `{ai['repetitions']}`; provider/model: `{md((ai.get('execution_configuration') or {}).get('ai_provider', 'not run'))}` / `{md((ai.get('execution_configuration') or {}).get('model', 'not run'))}`.",
        "",
        "| Condition | Context mode | Package hash | Approx. input tokens | Evidence items | State deltas | Findings | Model analyses | Grounded analyses |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for condition, payload in ai["conditions"].items():
        analyses = sum(1 for trial in payload["trials"] if trial.get("analysis") is not None)
        grounded = sum(
            1
            for trial in payload["trials"]
            if trial.get("analysis", {}).get("metadata", {}).get("grounding_valid") is True
        )
        metrics = payload["input_metrics"]
        lines.append(
            f"| `{condition}` | `{md(payload['mode'])}` | `{md(payload['package_hash'])}` | "
            f"{metrics['approximate_input_tokens']:,} | {metrics['evidence_items']} | "
            f"{metrics['state_deltas']} | {metrics['findings']} | {analyses} | {grounded} |"
        )
    lines += [
        "",
        f"The blinded review package contains `{len(review['items'])}` randomized items. Model analyses completed: `{sum(1 for payload in ai['conditions'].values() for trial in payload['trials'] if trial.get('analysis') is not None)}`; citation-grounded analyses: `{sum(1 for payload in ai['conditions'].values() for trial in payload['trials'] if trial.get('analysis', {}).get('metadata', {}).get('grounding_valid') is True)}`; human scores completed: `{sum(1 for item in review['items'] if item.get('human_evaluation', {}).get('evidence_grounding_accuracy_0_to_5') is not None)}`. Model output, when present, is a pilot interpretation only; it is not a research-effect claim until independent human scores and paired statistics exist.",
        "",
        "## 7. Reproducibility Freeze",
        "",
        f"The freeze contains `{freeze['source_file_count']}` source/config/result file hashes and `{len(freeze['dependencies'])}` dependency records.",
        f"\nDataset hash repeated in freeze: `{freeze['dataset_archives']['windows_apt_2025_revision_3']['sha256']}`",
        "\nSecrets are excluded from source hashes; the raw archive is excluded from source hashes but its SHA-256 is recorded.",
        "",
        "## 8. Remaining Evidence Gates",
        "",
        "1. Repeat the corrected Windows complete and capture-drop service trials enough times to report variance, latency, and capture-loss rates; extend live trials to selected non-service categories.",
        "2. Have independent reviewers complete the blinded AI score forms; no human scores are fabricated by the system or by this agent.",
        "3. Run paired statistics only after valid reviewer files exist, then repeat Ollama A/B/C/D trials for stable comparisons.",
        "4. Validate correlation using larger human-labeled mixed benign/attack sequences and investigate the retained adversarial false merge/split cases.",
        "5. Link Windows-APT rows to trusted scenario labels or treat the normalization result as coverage characterization only.",
        "",
        "## 9. Artifact Directory",
        "",
        "Published summaries are under `experiments/results/published/`; raw machine-readable evidence is under `experiments/results/runs/`. The raw archive is under "
        "`experiments/datasets/windows_apt_2025/raw/`. The corresponding implementation history is in "
        "`change-records/2026-09-23-01-empirical-campaign-and-freeze.md`.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=PUBLISHED / "RESEARCH_RESULTS_DETAILED-20260923.md",
    )
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(build_report(), encoding="utf-8")
    print(f"wrote detailed results report to {args.output}")


if __name__ == "__main__":
    main()
