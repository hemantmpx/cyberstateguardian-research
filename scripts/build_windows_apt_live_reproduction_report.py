"""Build the human-readable report for Windows-APT-inspired live validation."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
Json = dict[str, Any]


def load(path: Path) -> Json:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def status_list(scenario: Json) -> list[str]:
    return sorted(
        {
            str((finding.get("reconciliation") or {}).get("status"))
            for finding in scenario.get("findings") or []
        }
    )


def final_status(scenario: Json) -> str:
    finding = (scenario.get("post_campaign_finalization") or {}).get("finding") or {}
    return str((finding.get("reconciliation") or {}).get("status") or "not captured")


def summary(payload: Json, validation: Json, raw_path: Path) -> Json:
    raw_path = raw_path.resolve()
    scenarios = payload.get("scenarios") or []
    return {
        "schema_version": "csg-windows-apt-inspired-live-validation-summary-v2",
        "generated_at": datetime.now(UTC).isoformat(),
        "campaign_id": payload.get("campaign_id"),
        "dataset_reference": payload.get("dataset_reference"),
        "exact_replication": False,
        "validation_passed": validation.get("passed", False),
        "raw_artifact": str(raw_path.relative_to(ROOT)),
        "raw_sha256": sha256(raw_path),
        "environment": payload.get("environment", {}),
        "scenario_count": len(scenarios),
        "state_objects_observed": sum(
            bool((scenario.get("state_plane") or {}).get("after_action_observed"))
            for scenario in scenarios
        ),
        "exact_wazuh_event_matches": sum(
            len((scenario.get("event_plane") or {}).get("exact_matches") or [])
            for scenario in scenarios
        ),
        "cleanups_completed": sum(
            scenario.get("action", {}).get("cleanup_completed") is True for scenario in scenarios
        ),
        "scenarios": [
            {
                "scenario_id": scenario.get("scenario_id"),
                "behavior_family": scenario.get("kind"),
                "object_name": scenario.get("object_name"),
                "object_key": scenario.get("expected_object_key"),
                "state_observed": bool(
                    (scenario.get("state_plane") or {}).get("after_action_observed")
                ),
                "exact_wazuh_event_count": len(
                    (scenario.get("event_plane") or {}).get("exact_matches") or []
                ),
                "wazuh_event_ids": [
                    event.get("event_id")
                    for event in (scenario.get("event_plane") or {}).get("exact_matches") or []
                ],
                "finding_count": len(scenario.get("findings") or []),
                "reconciliation_statuses": status_list(scenario),
                "final_reconciliation_status": final_status(scenario),
                "cleanup_completed": scenario.get("action", {}).get("cleanup_completed") is True,
            }
            for scenario in scenarios
        ],
        "limitations": payload.get("limitations", []),
    }


def render(payload: Json, validation: Json, result: Json, raw_path: Path) -> str:
    raw_path = raw_path.resolve()
    env = payload.get("environment", {})
    lines = [
        "# Windows-APT-Inspired Behavior-Family Live Validation",
        "",
        f"Campaign: `{payload.get('campaign_id')}`",
        f"Generated: `{result['generated_at']}`",
        "",
        "## Scope",
        "",
        "This is a controlled live validation of selected Windows-APT-inspired behavior families "
        "using the CyberStateGuardian native Windows probe and Wazuh event collection. It is "
        "not an exact replay, copy, or accuracy claim about the Windows-APT 2025 public archive.",
        "",
        f"- Dataset reference: `{payload.get('dataset_reference')}`",
        "- Exact replication: `false`",
        f"- Windows host: `{env.get('host_id')}`",
        "- Authoritative state plane: native CSG Windows probe",
        "- Event plane: Wazuh agent plus Windows/Sysmon collection",
        f"- Baseline probe observation: `{env.get('probe_observation_id')}`",
        f"- Raw artifact SHA-256: `{result['raw_sha256']}`",
        "",
        "## What was tested",
        "",
        "Each action used a unique temporary object and a benign command that exits immediately "
        "or times out briefly. The runner probed after creation, waited 35 seconds for event "
        "delivery, synchronized the Wazuh event plane, then removed the object and probed again.",
        "",
        "| Scenario | CSG state observed | Exact Wazuh match | Final status | Findings | Cleanup |",
        "|---|---:|---:|---|---:|---:|",
    ]
    for item in result["scenarios"]:
        lines.append(
            f"| `{item['scenario_id']}` | "
            f"{'yes' if item['state_observed'] else 'no'} | "
            f"{item['exact_wazuh_event_count']} | `{item['final_reconciliation_status']}` | "
            f"{item['finding_count']} | "
            f"{'yes' if item['cleanup_completed'] else 'no'} |"
        )
    lines += [
        "",
        "The strict Wazuh match rule was:",
        "",
        "```text",
        "same host",
        "AND expected normalized event type",
        "AND exact target object identity",
        "AND event timestamp inside the bounded action window",
        "```",
        "",
        "## Results by scenario",
        "",
    ]
    for scenario, item in zip(payload.get("scenarios") or [], result["scenarios"], strict=True):
        state = scenario.get("state_plane") or {}
        after_action_id = state.get("after_action_observation_id")
        after_cleanup_id = state.get("after_cleanup_observation_id")
        retained_statuses = ", ".join(item["reconciliation_statuses"]) or "none"
        lines += [
            f"### {item['scenario_id']}",
            "",
            f"- Object: `{item['object_name']}`",
            f"- Expected CSG object key: `{item['object_key']}`",
            f"- Expected normalized event type: `{scenario.get('expected_event_type')}`",
            f"- Direct-probe observation ID after action: `{after_action_id}`",
            f"- Direct-probe observation ID after cleanup: `{after_cleanup_id}`",
            f"- Direct-probe object record: `{item['state_observed']}`",
            f"- Cleanup removed object from probe: `{item['cleanup_completed']}`",
            f"- Reconciliation statuses retained: `{retained_statuses}`",
            f"- Final post-window reconciliation: `{item['final_reconciliation_status']}`",
            "",
        ]
        events = (scenario.get("event_plane") or {}).get("exact_matches") or []
        if events:
            lines += ["Exact Wazuh evidence:", ""]
            for event in events:
                attrs = event.get("attributes") or {}
                identity_value = (
                    attrs.get("service_name")
                    or attrs.get("task_name")
                    or attrs.get("target_object")
                )
                document_id = (event.get("source_reference") or {}).get("document_id")
                lines += [
                    f"- `{event.get('event_id')}` at `{event.get('event_time')}`",
                    f"  - type: `{event.get('normalized_type')}`",
                    f"  - target: `{(event.get('target') or {}).get('key')}`",
                    f"  - event code: `{attrs.get('event_code')}`",
                    f"  - service/task/registry identity: `{identity_value}`",
                    f"  - source document: `{document_id}`",
                ]
        else:
            lines += [
                "Exact Wazuh evidence: none returned in the bounded retrieval window.",
                "This is a telemetry-coverage observation, not proof of permanent event loss.",
            ]
        lines += ["", "- Raw finding and reconciliation records are in the run artifact.", ""]

    unique_keys = next(
        (
            check["passed"]
            for check in validation.get("checks", [])
            if check["name"] == "unique_object_keys"
        ),
        "n/a",
    )
    unique_evidence = next(
        (
            check["passed"]
            for check in validation.get("checks", [])
            if check["name"] == "no_reused_exact_wazuh_ids"
        ),
        "n/a",
    )

    lines += [
        "## Interpretation",
        "",
        "The strongest live result is that the CSG state plane independently observed each "
        "persistent object before cleanup. The service action also produced a Wazuh event whose "
        "normalized type and target key identify the exact generated service. The other action "
        "families did not produce exact Wazuh matches in this run, so this campaign exposes a "
        "collection/configuration gap rather than silently treating generic events as proof. "
        "After the observation windows closed, the scheduled-task and registry action findings "
        "finalized UNEXPLAINED; that is evidence of absent matching telemetry in this trial, "
        "not proof of permanent event loss.",
        "",
        "This does not establish permanent telemetry-loss resistance, broad detection accuracy, "
        "or ATT&CK classification accuracy. It establishes a reproducible live test harness and "
        "a strict evidence comparison for the selected behavior families.",
        "",
        "## Validation",
        "",
        f"- Record validation: `{'PASS' if validation.get('passed') else 'FAIL'}`",
        f"- Unique object keys: `{unique_keys}`",
        f"- No reused exact Wazuh IDs across scenarios: `{unique_evidence}`",
        f"- Raw record: `{raw_path.relative_to(ROOT)}`",
        "- Validation record: same run folder as the raw record",
        "",
        "## Safety and limitations",
        "",
    ]
    lines.extend(f"- {limitation}" for limitation in payload.get("limitations", []))
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("raw_path", type=Path)
    parser.add_argument("validation_path", type=Path)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    args = parser.parse_args()
    raw_path = args.raw_path.resolve()
    validation_path = args.validation_path.resolve()
    payload = load(raw_path)
    validation = load(validation_path)
    result = summary(payload, validation, raw_path)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    args.markdown_output.write_text(render(payload, validation, result, raw_path), encoding="utf-8")
    print(f"wrote {args.json_output}")
    print(f"wrote {args.markdown_output}")


if __name__ == "__main__":
    main()
