from __future__ import annotations

import argparse
import copy
import hashlib
import json
import random
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from csg.config import get_settings
from csg.db.repositories import CyberStateRepository
from csg.db.session import SessionLocal
from csg.domain.enums import AIContextMode
from csg.domain.models import (
    AIAnalystResponseDraft,
    AIResponseAction,
    AIResponseCitations,
    AIResponseConsequence,
    AIResponseEvidenceGap,
    AIResponseHypothesis,
    AIResponseOption,
    EvidencePackage,
)
from csg.services.ai_response_assistant import (
    PROMPT_VERSION,
    AIResponseAssistant,
    build_csg_determined_facts,
    derive_unresolved_questions,
)
from csg.services.incident_context import IncidentContextBuilder
from experiments.ai_response_evaluation import blank_scores

STUDY_VERSION = "csg-ai-response-assistance-v8"
RESEARCH_QUESTION = (
    "Does evidence-grounded AI response assistance provide measurable incremental "
    "investigative value after deterministic state-event reconciliation?"
)


def build_study(
    package: EvidencePackage,
    *,
    settings: Any,
    ground_truth: dict[str, Any] | None = None,
    seed: int = 530,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str], dict[str, Any]]:
    package = isolate_package_to_subject(package.model_copy(deep=True))
    package_hash = _package_hash(package)
    questions = derive_unresolved_questions(package)
    facts = [fact.model_dump(mode="json") for fact in build_csg_determined_facts(package)]
    static_plan = build_static_playbook(package, questions)
    ai_result = AIResponseAssistant(settings).analyze(package)
    ai_guidance = _guidance_from_ai_result(ai_result)
    subject_id = hashlib.sha256(f"{package.finding_id}:{package_hash}".encode()).hexdigest()[:16]
    conditions = {
        "csg_only": {"supplemental_guidance": None},
        "static_playbook": {"supplemental_guidance": static_plan.model_dump(mode="json")},
        "ai_response_assistant": {"supplemental_guidance": ai_guidance},
    }
    study_id = str(uuid4())
    seed_rng = random.Random(seed)
    condition_entries = list(conditions.items())
    seed_rng.shuffle(condition_entries)
    items = []
    condition_key: dict[str, str] = {}
    for condition, value in condition_entries:
        review_id = uuid4().hex[:16]
        condition_key[review_id] = condition
        items.append(
            {
                "review_id": review_id,
                "subject_id": subject_id,
                "deterministic_facts": facts,
                "supplemental_guidance": value["supplemental_guidance"],
                "scores": blank_scores(),
            }
        )
    seed_rng.shuffle(items)
    baseline = _deterministic_dossier(package, facts)
    study = {
        "schema_version": "csg-ai-response-assistance-study-v8",
        "study_version": STUDY_VERSION,
        "study_id": study_id,
        "review_eligible": ai_result.plan is not None,
        "generated_at": datetime.now(UTC).isoformat(),
        "research_question": RESEARCH_QUESTION,
        "design": {
            "conditions": list(conditions),
            "assignment": "randomized blinded response ordering within each case",
            "experimental_unit": "independent case/subject, not individual reviewer rating",
            "intended_analysis": "descriptive and paired by reviewer and case",
        },
        "subject": {"subject_id": subject_id, "finding_id": package.finding_id},
        "input": {
            "package_sha256": package_hash,
            "context_version": package.context_version,
            "evidence_item_count": len(package.evidence),
            "state_delta_count": int(package.state_delta is not None) + len(package.related_deltas),
            "deterministic_unresolved_questions": questions,
            "source_quality": package.source_quality,
        },
        "execution": {
            "provider": ai_result.metadata.get("provider"),
            "model": ai_result.metadata.get("model"),
            "prompt_version": PROMPT_VERSION,
            "prompt_sha256": _prompt_hash(),
            "output_schema_sha256": ai_result.metadata.get("output_schema_sha256"),
            "latency_ms": ai_result.metadata.get("latency_ms"),
            "usage": ai_result.metadata.get("usage", {}),
            "inference_parameters": ai_result.metadata.get("inference_parameters", {}),
            "normalizations": ai_result.metadata.get("normalizations", []),
            "validation_errors": ai_result.validation_errors,
            "response_validated": ai_result.plan is not None,
            "raw_response_sha256": ai_result.raw_response_sha256,
            "raw_response": ai_result.raw_response,
            "response_metadata": ai_result.metadata,
        },
        "deterministic_baseline": baseline,
        "conditions": conditions,
        "evidence_package": package.model_dump(mode="json", exclude={"interpretive_memory"}),
        "limitations": [
            "A single controlled case is a workflow/pilot example, not inferential evidence.",
            "Reviewers may infer a condition from output content despite hidden labels.",
            "The semantic review rubric requires independent human ratings.",
            "A model citation validator checks identifier membership, not whether every "
            "natural-language claim is true.",
        ],
    }
    packet = {
        "schema_version": "csg-ai-response-blinded-review-v8",
        "study_version": STUDY_VERSION,
        "review_eligible": ai_result.plan is not None,
        "review_instructions": (
            "For each anonymous item, first inspect the shared deterministic CSG dossier. "
            "Then score only the additional guidance shown for that item. Do not open the private "
            "condition key or answer key, and do not discuss ratings with another reviewer "
            "before submission. "
            "The same case can appear more than once in randomized order."
        ),
        "evidence_dossier": baseline,
        "items": items,
    }
    answer_key = {
        "study_id": study_id,
        "subject_id": subject_id,
        "ground_truth": ground_truth
        or {
            "status": "not_independently_supplied",
            "note": "Do not score factual correctness against model output.",
        },
        "known_csg_facts": facts,
        "unknowns_at_analysis_time": questions,
    }
    return study, packet, condition_key, answer_key


def build_static_playbook(
    package: EvidencePackage, questions: list[dict[str, str]]
) -> AIAnalystResponseDraft:
    finding = package.finding
    citations = AIResponseCitations(
        finding_ids=[finding.finding_id],
        delta_ids=[package.state_delta.delta_id] if package.state_delta else [],
    )
    category = finding.category.lower()
    if category == "service":
        hypotheses = [
            ("approved-change", "Approved administrative configuration change."),
            (
                "software-update",
                "An installer or software update changed the service configuration.",
            ),
            (
                "unexplained-persistence",
                "The configuration could support persistence if the executable or change was "
                "unauthorized.",
            ),
        ]
        action_specs = [
            (
                "Collect the service ImagePath, arguments, account, and start mode",
                "Service Control Manager configuration",
                "Determine the exact executable and privilege context configured by this change.",
            ),
            (
                "Collect SCM events 7040/7045 and Security event 4697 with adjacent process "
                "telemetry",
                "Windows event logs and matching host/time window",
                "Identify the initiating account/process and test whether the event describes "
                "this exact object.",
            ),
            (
                "Calculate the configured binary SHA-256 and verify its Authenticode signer",
                "Configured service binary on the endpoint",
                "Distinguish a known signed component from an unexpected or altered executable.",
            ),
            (
                "Compare service configuration with approved change records and the host-role "
                "baseline",
                "Change-management record and known-good service inventory",
                "Test whether the observed configuration was expected for this host.",
            ),
            (
                "Review process lineage and network connections attributable to the service binary",
                "Sysmon process/network events after the service transition",
                "Determine whether the binary executed and whether follow-on behavior changes "
                "risk.",
            ),
        ]
    elif category == "scheduled_task":
        hypotheses = [
            ("approved-change", "Approved administrative task creation or modification."),
            ("software-update", "A legitimate installer created or changed a scheduled task."),
            (
                "unexplained-persistence",
                "The task could provide persistence if its action or principal is unauthorized.",
            ),
        ]
        action_specs = [
            (
                "Export the task XML and inspect action, trigger, and principal",
                "Exact scheduled task object",
                "Determine what will run, when, and with what privilege.",
            ),
            (
                "Collect Task Scheduler operational events and initiating process telemetry",
                "Task registration time window",
                "Identify the process/account responsible for the task.",
            ),
            (
                "Hash and verify the signer of each executable referenced by the task",
                "Task action binary on endpoint",
                "Test whether the executable has expected provenance.",
            ),
            (
                "Compare the task definition with approved change records and host baseline",
                "Change-management record and task inventory",
                "Test whether the persistence configuration is expected.",
            ),
        ]
    elif category == "registry":
        hypotheses = [
            ("approved-change", "Approved application or administrator configuration change."),
            ("software-update", "An installer changed an autorun value as part of software setup."),
            (
                "unexplained-persistence",
                "The value could cause startup execution if its command is unauthorized.",
            ),
        ]
        action_specs = [
            (
                "Collect the exact registry key, value name, data, and modified time",
                "Observed autorun registry value",
                "Establish the configured command and startup scope.",
            ),
            (
                "Correlate registry-write events with process creation and account telemetry",
                "Registry write observation interval",
                "Identify the process/account that wrote the value.",
            ),
            (
                "Hash and verify the signer of the referenced executable",
                "Executable named by the registry data",
                "Test the command's provenance.",
            ),
            (
                "Check startup execution and compare against approved baseline/change records",
                "Subsequent logon/startup events and baseline",
                "Test whether the value is expected and was exercised.",
            ),
        ]
    else:
        questions_for_category = questions
        hypotheses = [
            (
                "approved-change",
                f"An approved administrative or software workflow produced the {category} change.",
            ),
            (
                "unexpected-change",
                f"The {category} change may be unintended or otherwise unexplained.",
            ),
        ]
        action_specs = [
            (question["question"], question["question"], question["why_it_matters"])
            for question in questions_for_category[:5]
        ]
    question_lookup = {question["question"]: question for question in questions}
    hyp_models = [
        AIResponseHypothesis(
            hypothesis_id=identifier,
            hypothesis=text,
            rationale=(
                "The deterministic CSG record establishes the state change but does not "
                "establish intent."
            ),
            supporting=citations,
            contradicting=AIResponseCitations(),
            evidence_needed_to_test=[
                question_lookup.get(
                    questions[min(index, len(questions) - 1)]["question"], questions[0]
                )["question"]
            ],
            confidence="low",
        )
        for index, (identifier, text) in enumerate(hypotheses)
    ]
    actions = []
    for index, (action, target, objective) in enumerate(action_specs, start=1):
        action_question = next(
            (item for item in questions if item["question"].lower() in action.lower()),
            questions[min(index - 1, len(questions) - 1)],
        )
        actions.append(
            AIResponseAction(
                priority=index,
                action=action,
                objective=objective,
                exact_target=str(finding.object_key or target),
                why_this_action=(
                    "The state change is deterministic; actor intent and binary provenance "
                    "remain unresolved."
                ),
                expected_information_gain=action_question["why_it_matters"],
                interpretation_if_positive=(
                    "A result consistent with the change record, known-good baseline, or "
                    "trusted binary "
                    "supports an expected administrative/software explanation."
                ),
                interpretation_if_negative=(
                    "An unrecognized actor, binary, configuration, or event mismatch leaves "
                    "the change unexplained "
                    "and warrants escalation for analyst review."
                ),
                evidence_basis=citations,
                action_type="investigation",
                disruptiveness="low",
                prerequisites=["Preserve the original CSG and Windows event artifacts."],
                safety_notes=(
                    "Collect and validate evidence before changing the endpoint configuration."
                ),
            )
        )
    questions_text = [item["question"] for item in questions]
    gaps = [
        AIResponseEvidenceGap(
            missing_information=question["question"],
            why_it_matters=question["why_it_matters"],
            how_to_collect_it=action_specs[min(index, len(action_specs) - 1)][0],
            hypotheses_discriminated=[item[0] for item in hypotheses],
        )
        for index, question in enumerate(questions[:6])
    ]
    options = [
        AIResponseOption(
            trigger_condition=(
                "Current evidence alone is insufficient to justify endpoint containment."
            ),
            recommended_response=(
                "Continue non-disruptive evidence collection and validate the change record."
            ),
            rationale=(
                "The CSG state change is established, but intent and binary provenance remain "
                "unresolved."
            ),
            impact="Preserves availability while reducing uncertainty.",
            reversibility="high",
            evidence_required_before_action=[
                "Initiating process/account attribution",
                "Binary hash and signer verification",
                "Corroborating change-management or malicious-behavior evidence",
            ],
            evidence_basis=citations,
            disruptiveness="low",
        ),
        AIResponseOption(
            trigger_condition=(
                "Independent evidence shows an untrusted binary or active harmful behavior "
                "attributable to the object."
            ),
            recommended_response=(
                "Consider containment under the organization's incident-response authority "
                "after preserving volatile evidence."
            ),
            rationale=(
                "Containment is conditional on additional evidence and an authorized response "
                "decision."
            ),
            impact=(
                "May interrupt malicious activity but can disrupt legitimate service availability."
            ),
            reversibility="medium",
            evidence_required_before_action=[
                "Verified binary/path and service dependency impact",
                "Evidence of active harmful behavior or confirmed unauthorized change",
                "Incident commander or policy authorization",
            ],
            evidence_basis=citations,
            disruptiveness="high",
        ),
    ]
    return AIAnalystResponseDraft(
        assessment_boundary_unknown=questions_text,
        investigative_hypotheses=hyp_models,
        general_security_knowledge=[
            f"A Windows {category} configuration can affect host execution or access; that "
            "general capability does not establish malicious intent in this case."
        ],
        priority_actions=actions,
        evidence_gaps=gaps,
        response_options=options,
        possible_consequences=[
            AIResponseConsequence(
                condition_if=(
                    "If the configured object is unauthorized and is exercised by the "
                    "operating system or a user."
                ),
                consequence=(
                    "It could provide persistence or alter host behavior, depending on its "
                    "configured target and privileges."
                ),
            )
        ],
        attack_technique_candidates=[],
        analyst_decision_summary=(
            "CSG establishes the state transition and its reconciliation result. First identify "
            "the responsible process/account and verify the configured binary against approved "
            "change records and host baseline; "
            "make a containment decision only after those results are available."
        ),
        confidence="low",
        uncertainty=(
            "The available deterministic finding does not establish intent, actor identity, "
            "or binary trust."
        ),
        citations=citations,
    )


def _guidance_from_ai_result(result: Any) -> dict[str, Any]:
    if result.plan is None:
        return {
            "generation_status": "rejected_or_unavailable",
            "message": "No validated supplemental guidance was available for this condition.",
        }
    payload = result.plan.model_dump(mode="json")
    for key in ("incident_anchor", "assessment_boundary_known", "csg_determined_facts"):
        payload.pop(key, None)
    return payload


def isolate_package_to_subject(package: EvidencePackage) -> EvidencePackage:
    """Keep target-object context and omit neighboring same-host trial objects."""
    target_key = package.finding.object_key
    if not target_key:
        return package

    def is_relevant_evidence(item: Any) -> bool:
        target = (item.content or {}).get("target") or {}
        target_key_value = target.get("key")
        return target_key_value in {None, target_key} or item.evidence_type in {
            "process_start",
            "network_activity",
        }

    incident_context = copy.deepcopy(package.incident_context)
    deterministic = incident_context.get("deterministic_results")
    if isinstance(deterministic, dict):
        deterministic["findings"] = [
            row
            for row in deterministic.get("findings", [])
            if row.get("finding_id") == package.finding_id
        ]
    transitions = incident_context.get("state_transitions")
    if isinstance(transitions, list):
        incident_context["state_transitions"] = [
            row for row in transitions if row.get("object_key") == target_key
        ]
    assignment = incident_context.get("incident_assignment")
    if isinstance(assignment, dict):
        assignment["assignments"] = [
            row
            for row in assignment.get("assignments", [])
            if row.get("finding_id") == package.finding_id
        ]
    incident = package.incident
    if incident:
        incident = incident.model_copy(
            update={
                "finding_ids": [package.finding_id],
                "object_keys": [target_key],
                "categories": [package.finding.category],
            }
        )
    return package.model_copy(
        update={
            "incident": incident,
            "evidence": [item for item in package.evidence if is_relevant_evidence(item)],
            "related_deltas": [
                item for item in package.related_deltas if item.object_key == target_key
            ],
            "related_findings": [
                item for item in package.related_findings if item.object_key == target_key
            ],
            "incident_context": incident_context,
        },
        deep=True,
    )


def _deterministic_dossier(package: EvidencePackage, facts: list[dict[str, Any]]) -> dict[str, Any]:
    finding = package.finding.model_dump(mode="json")
    delta = package.state_delta.model_dump(mode="json") if package.state_delta else None
    return {
        "host": package.host.model_dump(mode="json"),
        "finding": finding,
        "state_delta": delta,
        "deterministic_facts": facts,
        "reconciliation": finding["reconciliation"],
        "authorization": {
            "status": finding["authorization_status"],
            "reason": finding["authorization_reason"],
        },
        "risk": finding["risk"],
        "source_quality": package.source_quality,
        "evidence": [item.model_dump(mode="json") for item in package.evidence],
        "related_deltas": [item.model_dump(mode="json") for item in package.related_deltas],
        "related_findings": [item.model_dump(mode="json") for item in package.related_findings],
        "incident": package.incident.model_dump(mode="json") if package.incident else None,
        "note": "This deterministic CSG dossier is identical for every condition in the case.",
    }


def _package_hash(package: EvidencePackage) -> str:
    payload = package.model_dump(
        mode="json", exclude={"package_id", "created_at", "interpretive_memory"}
    )
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _prompt_hash() -> str:
    from csg.services.ai_response_assistant import _SYSTEM_PROMPT

    return hashlib.sha256(_SYSTEM_PROMPT.encode("utf-8")).hexdigest()


def write_study_files(
    output_dir: Path,
    study: dict[str, Any],
    packet: dict[str, Any],
    condition_key: dict[str, str],
    answer_key: dict[str, Any],
    package: EvidencePackage,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=False)
    # Persist exactly the isolated package used to generate the study and model prompt.
    archived_package = study.get("evidence_package")
    if not isinstance(archived_package, dict):
        archived_package = package.model_dump(mode="json", exclude={"interpretive_memory"})
    _write_json(output_dir / "study.json", study)
    _write_json(output_dir / "review_items.blinded.json", packet)
    _write_json(output_dir / "condition-key.private.json", condition_key)
    _write_json(output_dir / "answer-key.private.json", answer_key)
    _write_json(
        output_dir / "evidence-package.json",
        archived_package,
    )
    raw_response = study.get("execution", {}).get("raw_response")
    if raw_response:
        (output_dir / "model-response.raw.txt").write_text(raw_response, encoding="utf-8")
    (output_dir / "README.md").write_text(
        "# AI Response Assistance Pilot\n\n"
        "This is a single-case workflow demonstration, not a test of statistical effect or a "
        "publication-ready result. The same deterministic CSG dossier is shown in all three "
        "blinded conditions. Review condition labels and ground truth are kept in private files; "
        "do not provide those files to reviewers. At least two independent reviewers should score "
        "the packet in the CSG AI review UI before condition unblinding. A study with an invalid, "
        "rejected, or unavailable AI response is archived but is not eligible for content-quality "
        "review; report it separately as a generation/availability failure.\n",
        encoding="utf-8",
    )
    hashes = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(output_dir.iterdir())
        if path.is_file()
    }
    _write_json(
        output_dir / "artifact-sha256.json",
        {"schema_version": "csg-ai-response-pilot-sha256-v1", "sha256": hashes},
    )


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a blinded CSG AI response-assistance pilot"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--finding-id")
    source.add_argument(
        "--package-json",
        type=Path,
        help="Full-context EvidencePackage exported by the CSG API when the local DB is remote.",
    )
    parser.add_argument("--ground-truth", type=Path)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--seed", type=int, default=530)
    args = parser.parse_args()
    settings = get_settings()
    if args.package_json:
        package = EvidencePackage.model_validate(
            json.loads(args.package_json.read_text(encoding="utf-8"))
        )
    else:
        with SessionLocal() as session:
            repo = CyberStateRepository(session)
            finding = repo.get_finding(args.finding_id)
            if finding is None:
                raise SystemExit(f"finding not found: {args.finding_id}")
            package = IncidentContextBuilder(settings).build_for_finding(
                repo, finding, mode=AIContextMode.FULL_CONTEXT
            )
    ground_truth = (
        json.loads(args.ground_truth.read_text(encoding="utf-8")) if args.ground_truth else None
    )
    study, packet, key, answer = build_study(
        package, settings=settings, ground_truth=ground_truth, seed=args.seed
    )
    output_root = (
        args.output_root
        or Path("experiments/results/runs")
        / datetime.now(UTC).strftime("%Y%m%d")
        / "ai-response-assistance"
    )
    output_dir = output_root / study["study_id"]
    write_study_files(output_dir, study, packet, key, answer, package)
    print(
        json.dumps(
            {
                "study_id": study["study_id"],
                "output": str(output_dir),
                "response_validated": study["execution"]["response_validated"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
