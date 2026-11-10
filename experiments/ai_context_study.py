from __future__ import annotations

import argparse
import copy
import json
import random
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from csg.config import Settings, get_settings
from csg.db.repositories import CyberStateRepository
from csg.db.session import SessionLocal
from csg.domain.enums import AIContextMode
from csg.domain.models import AIAnalysisRecord, EvidencePackage
from csg.services.incident_context import IncidentContextBuilder
from csg.services.llm_analysis import AIAnalysisService, evidence_package_hash

CONDITIONS = (
    ("A", AIContextMode.FINDING_ONLY),
    ("B", AIContextMode.EVENT_HISTORY),
    ("C", AIContextMode.FULL_CONTEXT),
    ("D", AIContextMode.FULL_CONTEXT),
)


def build_study_export(
    repo: CyberStateRepository,
    settings: Settings,
    *,
    finding_id: str | None = None,
    incident_id: str | None = None,
    run_ai: bool = False,
    repetitions: int = 1,
    ground_truth: dict[str, Any] | None = None,
    seed: int = 530,
) -> dict[str, Any]:
    if bool(finding_id) == bool(incident_id):
        raise ValueError("provide exactly one finding_id or incident_id")
    if repetitions < 1:
        raise ValueError("repetitions must be positive")

    builder = IncidentContextBuilder(settings)
    incident = repo.get_incident(incident_id) if incident_id else None
    finding = repo.get_finding(finding_id) if finding_id else None
    if incident_id and incident is None:
        raise ValueError(f"incident {incident_id} was not found")
    if finding_id and finding is None:
        raise ValueError(f"finding {finding_id} was not found")

    study_id = str(uuid4())
    conditions: dict[str, Any] = {}
    packages: dict[str, EvidencePackage] = {}
    # Freeze every condition before model calls and exclude prior model interpretations.
    for label, mode in CONDITIONS[:3]:
        package = (
            builder.build_for_incident(repo, incident, mode=mode)
            if incident
            else builder.build_for_finding(repo, finding, mode=mode)
        )
        package = package.model_copy(
            update={
                "interpretive_memory": None,
                "experiment_id": study_id,
                "trial_id": f"{study_id}:{label}",
            },
            deep=True,
        )
        package = _isolate_package_to_subject(package)
        packages[label] = package
        conditions[label] = {
            "mode": mode.value,
            "package_hash": evidence_package_hash(package),
            "input_metrics": _package_metrics(package),
            "package": package.model_dump(mode="json"),
            "analysis": None,
            "human_evaluation": _evaluation_template(),
            "trials": [
                {
                    "trial": index + 1,
                    "analysis": None,
                    "human_evaluation": _evaluation_template(),
                }
                for index in range(repetitions)
            ],
        }

    # D is a full-context control with the same serialized character budget as B. This
    # separates evidence type from the confound that C contains substantially more text.
    target_characters = conditions["B"]["input_metrics"]["characters"]
    matched_package = _fit_package_to_character_budget(packages["C"], target_characters)
    matched_package = matched_package.model_copy(
        update={"trial_id": f"{study_id}:D"},
        deep=True,
    )
    packages["D"] = matched_package
    conditions["D"] = {
        "mode": "full_context_token_matched",
        "package_hash": evidence_package_hash(matched_package),
        "input_metrics": _package_metrics(matched_package),
        "budget_target_characters": target_characters,
        "budget_match_ratio": round(
            _package_metrics(matched_package)["characters"] / target_characters, 4
        ),
        "package": matched_package.model_dump(mode="json"),
        "analysis": None,
        "human_evaluation": _evaluation_template(),
        "trials": [
            {
                "trial": index + 1,
                "analysis": None,
                "human_evaluation": _evaluation_template(),
            }
            for index in range(repetitions)
        ],
    }

    execution_conditions = (*CONDITIONS[:3], ("D", AIContextMode.FULL_CONTEXT))
    execution_order = [
        (label, trial) for trial in range(repetitions) for label, _ in execution_conditions
    ]
    random.Random(seed).shuffle(execution_order)
    if run_ai:
        for label, trial in execution_order:
            analysis = _run_analysis(repo, settings, packages[label]).model_dump(mode="json")
            conditions[label]["trials"][trial]["analysis"] = analysis
        for payload in conditions.values():
            payload["analysis"] = payload["trials"][0]["analysis"]

    return {
        "study_version": "csg-ai-context-study-v3-evidence-isolation",
        "study_id": study_id,
        "execution_seed": seed,
        "execution_order": [
            {"condition": label, "trial": trial + 1} for label, trial in execution_order
        ],
        "prior_ai_memory_excluded": True,
        "research_question": (
            "Does combining temporal event history, persistent host-state transitions, and "
            "authorization context improve LLM-assisted incident reconstruction compared with "
            "isolated-finding analysis?"
        ),
        "generated_at": datetime.now(UTC).isoformat(),
        "execution_configuration": {
            "ai_provider": settings.ai_provider,
            "model": (
                settings.ollama_model
                if settings.ai_provider == "ollama"
                else settings.openai_model
            ),
            "ollama_num_ctx": settings.ollama_num_ctx,
            "ollama_num_predict": settings.ollama_num_predict,
            "ai_context_max_events": settings.ai_context_max_events,
            "ai_context_related_limit": settings.ai_context_related_limit,
        },
        "subject": {
            "finding_id": finding_id,
            "incident_id": incident_id,
        },
        "ground_truth": ground_truth or {},
        "repetitions": max(1, repetitions),
        "conditions": conditions,
        "evaluation_rule": (
            "Score each condition against external scenario ground truth. Never use another AI "
            "answer as ground truth or primary evidence."
        ),
    }


def write_study_export(payload: dict[str, Any], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return output_path


def _run_analysis(
    repo: CyberStateRepository,
    settings: Settings,
    package: EvidencePackage,
) -> AIAnalysisRecord:
    analysis = AIAnalysisService(settings).explain(package)
    return repo.create_ai_analysis(analysis)


def _package_metrics(package: EvidencePackage) -> dict[str, int]:
    serialized = package.model_dump_json()
    return {
        "characters": len(serialized),
        "approximate_input_tokens": max(1, len(serialized) // 4),
        "evidence_items": len(package.evidence),
        "state_deltas": int(package.state_delta is not None) + len(package.related_deltas),
        "findings": 1 + len(package.related_findings),
    }


def _isolate_package_to_subject(package: EvidencePackage) -> EvidencePackage:
    """Prevent a same-host neighboring trial from contaminating an AI condition."""
    target_key = package.finding.object_key
    if not target_key:
        return package

    def keep_evidence(item: Any) -> bool:
        target = (item.content or {}).get("target") or {}
        target_key_value = target.get("key")
        return (
            target_key_value in {None, target_key}
            or item.evidence_type in {"process_start", "network_activity"}
        )

    filtered_context = copy.deepcopy(package.incident_context)
    deterministic = filtered_context.get("deterministic_results")
    if isinstance(deterministic, dict):
        deterministic["findings"] = [
            row
            for row in deterministic.get("findings", [])
            if row.get("finding_id") == package.finding_id
        ]
    transitions = filtered_context.get("state_transitions")
    if isinstance(transitions, list):
        filtered_context["state_transitions"] = [
            row for row in transitions if row.get("object_key") == target_key
        ]
    assignment = filtered_context.get("incident_assignment")
    if isinstance(assignment, dict):
        assignment["assignments"] = [
            row
            for row in assignment.get("assignments", [])
            if row.get("finding_id") == package.finding_id
        ]
    filtered_incident = package.incident
    if filtered_incident is not None:
        filtered_incident = filtered_incident.model_copy(
            update={
                "finding_ids": [package.finding_id],
                "object_keys": [target_key],
                "categories": [package.finding.category],
            }
        )
    return package.model_copy(
        update={
            "incident": filtered_incident,
            "evidence": [item for item in package.evidence if keep_evidence(item)],
            "related_deltas": [
                delta for delta in package.related_deltas if delta.object_key == target_key
            ],
            "related_findings": [
                finding
                for finding in package.related_findings
                if finding.object_key == target_key
            ],
            "incident_context": filtered_context,
        },
        deep=True,
    )


def _fit_package_to_character_budget(
    package: EvidencePackage, target_characters: int
) -> EvidencePackage:
    """Bound lower-priority context while retaining the trigger state and finding."""
    if target_characters < 1:
        raise ValueError("target character budget must be positive")
    candidate = package.model_copy(deep=True)
    while len(candidate.model_dump_json()) > target_characters:
        if candidate.related_findings:
            candidate = candidate.model_copy(
                update={"related_findings": candidate.related_findings[:-1]}
            )
        elif candidate.related_deltas:
            candidate = candidate.model_copy(
                update={"related_deltas": candidate.related_deltas[:-1]}
            )
        elif candidate.incident is not None:
            candidate = candidate.model_copy(update={"incident": None})
        elif candidate.incident_context:
            candidate = candidate.model_copy(update={"incident_context": {}})
        elif candidate.source_quality:
            candidate = candidate.model_copy(update={"source_quality": {}})
        elif candidate.attack_context is not None:
            candidate = candidate.model_copy(update={"attack_context": None})
        elif candidate.state_delta is not None and candidate.state_delta.metadata:
            compact_delta = candidate.state_delta.model_copy(update={"metadata": {}})
            candidate = candidate.model_copy(update={"state_delta": compact_delta})
        elif candidate.finding.metadata:
            candidate = candidate.model_copy(
                update={"finding": candidate.finding.model_copy(update={"metadata": {}})}
            )
        elif len(candidate.evidence) > 1:
            # Keep the trigger event when a token-matched package must lose lower-priority
            # evidence. For the service study, service_modified is the primary transition.
            removable_index = next(
                (
                    index
                    for index, item in enumerate(candidate.evidence)
                    if item.evidence_type != "service_modified"
                ),
                len(candidate.evidence) - 1,
            )
            evidence = list(candidate.evidence)
            evidence.pop(removable_index)
            candidate = candidate.model_copy(update={"evidence": evidence})
        else:
            break
    return candidate


def _evaluation_template() -> dict[str, Any]:
    return {
        "attack_chain_reconstruction_accuracy_0_to_5": None,
        "root_cause_identification_correct": None,
        "mitre_attack_mapping_accuracy_0_to_5": None,
        "evidence_grounding_accuracy_0_to_5": None,
        "unsupported_claim_count": None,
        "analyst_usefulness_0_to_5": None,
        "confidence_calibration_0_to_5": None,
        "reviewer_notes": "",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Export CSG AI context conditions A, B, C, and D")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--finding-id")
    target.add_argument("--incident-id")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("experiments/results/ai-context-study.json"),
    )
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--seed", type=int, default=530)
    parser.add_argument(
        "--ground-truth",
        type=Path,
        help="JSON ground-truth record created independently from the model output",
    )
    parser.add_argument(
        "--run-ai",
        action="store_true",
        help="Call the configured model for each condition and persist the analyses",
    )
    args = parser.parse_args()
    ground_truth = None
    if args.ground_truth:
        ground_truth = json.loads(args.ground_truth.read_text(encoding="utf-8"))

    settings = get_settings()
    with SessionLocal() as session:
        payload = build_study_export(
            CyberStateRepository(session),
            settings,
            finding_id=args.finding_id,
            incident_id=args.incident_id,
            run_ai=args.run_ai,
            repetitions=args.repetitions,
            ground_truth=ground_truth,
            seed=args.seed,
        )
    path = write_study_export(payload, args.output)
    print(f"wrote AI context study export to {path}")


if __name__ == "__main__":
    main()
