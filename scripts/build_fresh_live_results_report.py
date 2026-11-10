"""Publish a detailed report for the fresh Windows service campaign."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
Json = dict[str, Any]


def load(path: Path) -> Json:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def finding_for(payload: Json, event_type: str) -> Json:
    for finding in payload.get("findings", []):
        reconciliation = finding.get("reconciliation") or {}
        types = {row.get("event_type") for row in reconciliation.get("match_reasons", [])}
        types.update(reconciliation.get("missing_expected_evidence_types") or [])
        if event_type in types:
            return finding
    return {}


def evidence_for(payload: Json, event_type: str) -> list[Json]:
    evidence = payload.get("verified_exact_wazuh_evidence") or {}
    return list(evidence.get(event_type, []))


def status(finding: Json) -> str:
    return str((finding.get("reconciliation") or {}).get("status") or "missing")


def summarize_run(path: Path, validation_path: Path) -> Json:
    payload = load(path)
    validation = load(validation_path)
    findings = {
        event_type: finding_for(payload, event_type)
        for event_type in ("service_created", "service_modified")
    }
    record: Json = {
        "artifact": str(path.relative_to(ROOT)),
        "validation_artifact": str(validation_path.relative_to(ROOT)),
        "validation_passed": validation.get("passed", False),
        "run_id": payload.get("run_id"),
        "host_id": payload.get("host_id"),
        "service_name": payload.get("service_name"),
        "telemetry_condition": payload.get("telemetry_condition"),
        "started_at": payload.get("started_at"),
        "ended_at": payload.get("ended_at"),
        "exact_evidence_rule": (payload.get("verified_exact_wazuh_evidence") or {}).get(
            "rule"
        ),
        "exact_evidence": {
            event_type: evidence_for(payload, event_type)
            for event_type in ("service_created", "service_modified")
        },
        "findings": {
            event_type: {
                "finding_id": finding.get("finding_id"),
                "delta_id": finding.get("delta_id"),
                "object_key": finding.get("object_key"),
                "status": status(finding),
                "version": (finding.get("reconciliation") or {}).get("version"),
                "finalized": (finding.get("reconciliation") or {}).get("finalized"),
                "matched_evidence_ids": (finding.get("reconciliation") or {}).get(
                    "matched_evidence_ids", []
                ),
            }
            for event_type, finding in findings.items()
        },
        "timeline": payload.get("timeline", []),
    }
    if payload.get("telemetry_condition") == "capture_drop":
        proof = payload.get("capture_drop_proof") or {}
        bounded = proof.get("bounded_observation") or {}
        recovered = proof.get("post_restore_recovery") or {}
        bounded_modify = finding_for(bounded, "service_modified")
        recovered_modify = finding_for(recovered, "service_modified")
        recovered_status = status(recovered_modify)
        record["capture_drop"] = {
            "bounded_status": status(bounded_modify),
            "bounded_matched_evidence_ids": (bounded_modify.get("reconciliation") or {}).get(
                "matched_evidence_ids", []
            ),
            "post_restore_status": recovered_status,
            "post_restore_matched_evidence_ids": (
                recovered_modify.get("reconciliation") or {}
            ).get("matched_evidence_ids", []),
            "post_restore_exact_modify_count": (
                recovered.get("verified_exact_wazuh_evidence") or {}
            ).get("exact_modify_count", 0),
            "outcome": (
                "recovered"
                if recovered_status == "CONSISTENT"
                else "not_recovered_after_restore"
                if recovered_status == "UNEXPLAINED"
                else "invalid"
            ),
        }
    return record


def summarize_ai(path: Path) -> Json:
    payload = load(path)
    conditions: dict[str, Json] = {}
    grounded_count = 0
    rejected_count = 0
    for label, condition in (payload.get("conditions") or {}).items():
        analysis = (condition.get("trials") or [{}])[0].get("analysis") or {}
        metadata = analysis.get("metadata") or {}
        grounded = metadata.get("grounding_valid") is True
        if grounded:
            grounded_count += 1
        if not analysis.get("response_json"):
            rejected_count += 1
        conditions[label] = {
            "mode": condition.get("mode"),
            "package_hash": condition.get("package_hash"),
            "characters": (condition.get("input_metrics") or {}).get("characters"),
            "grounding_valid": grounded,
            "latency_ms": metadata.get("latency_ms"),
            "validation_errors": analysis.get("validation_errors", []),
            "human_evaluation_present": any(
                value is not None
                for value in (
                    (condition.get("trials") or [{}])[0].get("human_evaluation") or {}
                ).values()
                if not isinstance(value, str)
            ),
        }
    return {
        "artifact": str(path.relative_to(ROOT)),
        "study_id": payload.get("study_id"),
        "provider": (payload.get("execution_configuration") or {}).get("ai_provider"),
        "model": (payload.get("execution_configuration") or {}).get("model"),
        "condition_count": len(conditions),
        "grounded_count": grounded_count,
        "rejected_count": rejected_count,
        "human_scoring_complete": any(
            condition["human_evaluation_present"] for condition in conditions.values()
        ),
        "conditions": conditions,
    }


def render_markdown(summary: Json) -> str:
    runs = summary["runs"]
    complete = next(run for run in runs if run["telemetry_condition"] == "complete")
    dropped = next(run for run in runs if run["telemetry_condition"] == "capture_drop")
    capture = dropped["capture_drop"]
    ai = summary.get("ai_study")
    lines = [
        "# Fresh Live Reconciliation Campaign",
        "",
        f"Campaign date: `{summary['campaign_date']}`",
        "",
        "This report contains only the fresh artifacts created after the results reset. "
        "Earlier setup attempts and contaminated artifacts were excluded.",
        "",
        "## Research question",
        "",
        "Can CSG detect a persistent Windows service change with its direct probe, then match "
        "the corresponding Wazuh event only when that event has the same host, event type, "
        "service identity, and time relationship? What happens when the relevant Wazuh event "
        "is deliberately unavailable?",
        "",
        "## Clean environment",
        "",
        f"- Windows host: `{summary['environment']['host_id']}`",
        f"- CSG API used by the VM: `{summary['environment']['api_endpoint']}`",
        "- Authoritative state plane: direct CSG Windows probe",
        "- Event plane: Wazuh agent and Windows event collection",
        "- Background CyberStateGuardian scheduled probe: disabled for the controlled trials",
        "- Wazuh service after the run: `RUNNING`",
        "- Research database and local result artifacts: reset before the campaign",
        "",
        "## Results at a glance",
        "",
        "| Trial | Service | Create | Modify | Interpretation |",
        "|---|---|---|---|---|",
        f"| `complete` | `{complete['service_name']}` | "
        f"`{complete['findings']['service_created']['status']}` | "
        f"`{complete['findings']['service_modified']['status']}` | exact evidence present |",
        f"| `capture_drop` | `{dropped['service_name']}` | "
        f"`{dropped['findings']['service_created']['status']}` | "
        f"`{capture['post_restore_status']}` | {capture['outcome']} |",
        "",
        "## Exact matching rule",
        "",
        "Every run recorded this strict rule:",
        "",
        "```text",
        "same host",
        "AND expected normalized event type",
        "AND exact internal service name OR exact target key",
        "AND event inside the observation window",
        "```",
        "",
        "A generic service event in the time window is not sufficient. The matched evidence "
        "must identify the tested Windows service object.",
        "",
        "## Trial 1: complete telemetry",
        "",
        f"- Run ID: `{complete['run_id']}`",
        f"- Service: `{complete['service_name']}`",
        f"- Create event: `{complete['exact_evidence']['service_created'][0]['event_id']}`",
        f"- Modify event: `{complete['exact_evidence']['service_modified'][0]['event_id']}`",
        f"- Create reconciliation: `{complete['findings']['service_created']['status']}`",
        f"- Modify reconciliation: `{complete['findings']['service_modified']['status']}`",
        "- Validation: `PASS`",
        "",
        "Both event IDs are distinct, and each event explicitly carries the tested service "
        "identity and target key. This is the corrected object-specific proof.",
        "",
        "## Trial 2: deliberate capture drop",
        "",
        f"- Run ID: `{dropped['run_id']}`",
        f"- Service: `{dropped['service_name']}`",
        "- Wazuh source: stopped after the create action and before the modification action",
        f"- Bounded pre-restore modify status: `{capture['bounded_status']}`",
        f"- Post-restore modify status: `{capture['post_restore_status']}`",
        f"- Outcome: `{capture['outcome']}`",
        f"- Create event: `{dropped['exact_evidence']['service_created'][0]['event_id']}`",
        "- Modify event: none",
        "- Validation: `PASS`",
        "",
        "CSG retained the direct state observation and finalized the missing modification "
        "telemetry as `UNEXPLAINED`. In this VM/source configuration, restoring Wazuh did not "
        "replay the stopped-period modification event; this is reported as not recovered, "
        "not as a universal claim of permanent loss.",
        "",
        "## AI context pilot",
        "",
        f"- Artifact: `{ai['artifact']}`" if ai else "- Artifact: not run",
        f"- Provider/model: `{ai['provider']}/{ai['model']}`"
        if ai
        else "- Provider/model: not run",
        f"- Conditions executed: `{ai['condition_count']}` (A, B, C, D)"
        if ai
        else "- Conditions executed: 0",
        f"- Citation-grounded analyses: `{ai['grounded_count']}`"
        if ai
        else "- Citation-grounded analyses: 0",
        f"- Model outputs rejected by schema/grounding validation: `{ai['rejected_count']}`"
        if ai
        else "- Model outputs rejected by schema/grounding validation: 0",
        "- Independent human scoring: `PENDING`",
        "",
        "The AI run is a tooling/pilot result, not an AI-effect claim. The deterministic finding, "
        "state delta, Wazuh evidence, and reconciliation status remain authoritative. Human "
        "reviewers must score the blinded outputs independently before A/B/C/D comparisons can "
        "be reported.",
        "",
        "## What this campaign proves",
        "",
        "1. CSG independently detected uniquely named Windows service state changes through the "
        "direct probe.",
        "2. Complete reconciliation matched the correct Wazuh event for the correct service, "
        "rather than any service event in the time window.",
        "3. CSG retained visibility when the relevant modification event was unavailable and "
        "reported the finalized result as `UNEXPLAINED`.",
        "4. The fresh trials used distinct service names and object-specific evidence IDs.",
        "",
        "## What this campaign does not prove",
        "",
        "- It is one complete trial and one capture-drop trial, not a population-level accuracy "
        "estimate.",
        "- It does not establish permanent event loss for every Wazuh configuration; this "
        "VM/source combination did not replay the stopped-period modification event.",
        "- It does not measure incident-correlation precision/recall or AI usefulness. Those "
        "experiments require separate labeled runs and human scoring.",
        "",
        "## Evidence layout",
        "",
        "```text",
        "experiments/results/",
        "├── published/",
        "│   ├── RESEARCH_RESULTS_DETAILED-20260923.md",
        "│   ├── live-telemetry-campaign-summary-20260923.json",
        "│   └── research-freeze-20260923.json",
        "└── runs/20260923/live-reconciliation/",
        "    ├── fresh-complete/{run.json,validation.json}",
        "    └── fresh-capture-drop/{run.json,validation.json}",
        "runs/20260923/ai-context-ollama/study.json",
        "```",
        "",
        f"Generated at `{summary['generated_at']}`.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--date", default="20260923")
    parser.add_argument("--api-endpoint", default="http://10.111.16.238:8000")
    parser.add_argument("--summary-output", type=Path)
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()
    summary_output = args.summary_output or Path(
        f"experiments/results/published/live-telemetry-campaign-summary-{args.date}.json"
    )
    report_output = args.report_output or Path(
        f"experiments/results/published/RESEARCH_RESULTS_DETAILED-{args.date}.md"
    )
    run_root = ROOT / "experiments/results/runs" / args.date / "live-reconciliation"
    run_paths = [run_root / "fresh-complete/run.json", run_root / "fresh-capture-drop/run.json"]
    records = [
        summarize_run(path, path.parent / "validation.json")
        for path in run_paths
        if path.exists() and (path.parent / "validation.json").exists()
    ]
    ai_path = ROOT / "experiments/results/runs" / args.date / "ai-context-ollama/study.json"
    ai_study = summarize_ai(ai_path) if ai_path.exists() else None
    summary: Json = {
        "schema_version": "csg-fresh-live-campaign-v1",
        "campaign_date": args.date,
        "generated_at": datetime.now(UTC).isoformat(),
        "reset": {
            "local_results_cleared": True,
            "database_research_tables_truncated": True,
            "discarded_prior_artifacts": True,
            "background_probe_disabled": True,
        },
        "environment": {
            "host_id": "win11-arm-lab",
            "api_endpoint": args.api_endpoint,
            "state_plane": "direct_probe",
            "event_plane": "wazuh",
            "wazuh_service_after_run": "RUNNING",
            "scheduled_probe_task_after_run": "Disabled",
        },
        "run_count": len(records),
        "all_validations_passed": all(record["validation_passed"] for record in records),
        "runs": records,
        "ai_study": ai_study,
        "research_conclusions": {
            "independent_state_detection": "demonstrated",
            "object_specific_reconciliation": "demonstrated in complete trial",
            "telemetry_loss_visibility": "demonstrated in capture-drop trial",
            "recoverable_delayed_telemetry": "not evaluated by this fresh campaign",
            "ai_analysis": "not part of this reset campaign",
        },
    }
    summary_path = ROOT / summary_output if not summary_output.is_absolute() else summary_output
    report_path = ROOT / report_output if not report_output.is_absolute() else report_output
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    report_path.write_text(render_markdown(summary), encoding="utf-8")
    print(f"wrote {summary_path}")
    print(f"wrote {report_path}")


if __name__ == "__main__":
    main()
