from __future__ import annotations

import json

import pytest
from experiments.ai_response_assistance_study import (
    build_static_playbook,
    build_study,
    write_study_files,
)
from pydantic import ValidationError

from csg.config import Settings
from csg.domain.enums import (
    AIContextMode,
    AuthorizationStatus,
    DeltaType,
    ObservationKind,
    ReconciliationStatus,
    Severity,
)
from csg.domain.models import (
    AIAnalystResponseDraft,
    AIResponseAction,
    AIResponseCitations,
    AIResponseHypothesis,
    AIResponseOption,
    EvidenceItem,
    EvidencePackage,
    Finding,
    Host,
    ReconciliationResult,
    RiskScore,
    StateDelta,
    StateObject,
    TimeWindow,
    utc_now,
)
from csg.services.ai_response_assistant import (
    AIResponseAssistant,
    _build_prompt,
    _incident_anchor,
    _normalize_action_priorities,
    _response_schema,
    build_csg_determined_facts,
    derive_unresolved_questions,
    validate_response_draft,
)


def _package() -> EvidencePackage:
    now = utc_now()
    finding = Finding(
        finding_id="finding-service-1",
        host_id="host-1",
        observation_kind=ObservationKind.STATE_DELTA,
        delta_id="delta-service-1",
        category="service",
        object_key="service:UpdateAgent",
        reconciliation=ReconciliationResult(
            host_id="host-1",
            status=ReconciliationStatus.CONSISTENT,
            matched_evidence_ids=["event-service-1"],
            observation_window=TimeWindow(start=now, end=now),
        ),
        authorization_status=AuthorizationStatus.UNKNOWN,
        authorization_reason="No matching approval was supplied.",
        risk=RiskScore(total=42, severity=Severity.MEDIUM, rules_version="test"),
        created_at=now,
    )
    before = StateObject(
        category="service",
        object_key="service:UpdateAgent",
        attributes={"start_mode": "manual", "account": "LocalSystem"},
        source_timestamp=now,
    )
    after = before.model_copy(
        update={"attributes": {"start_mode": "auto", "account": "LocalSystem"}}
    )
    delta = StateDelta(
        delta_id="delta-service-1",
        host_id="host-1",
        category="service",
        object_key="service:UpdateAgent",
        delta_type=DeltaType.MODIFY,
        before=before,
        after=after,
        observation_window=TimeWindow(start=now, end=now),
    )
    return EvidencePackage(
        finding_id=finding.finding_id,
        context_mode=AIContextMode.FULL_CONTEXT,
        host=Host(
            host_id="host-1", hostname="host-1", role="test", os="Windows", architecture="arm64"
        ),
        finding=finding,
        state_delta=delta,
        evidence=[
            EvidenceItem(
                evidence_id="event-service-1",
                host_id="host-1",
                evidence_type="service_modified",
                timestamp=now,
                content={"target": {"key": "service:UpdateAgent"}},
                source_reference={"event_id": 7040},
            )
        ],
        source_quality={"status": "healthy"},
    )


def _draft(**updates: object) -> AIAnalystResponseDraft:
    citations = AIResponseCitations(
        finding_ids=["finding-service-1"], delta_ids=["delta-service-1"]
    )
    values = {
        "assessment_boundary_unknown": ["Which process changed the service?"],
        "investigative_hypotheses": [
            AIResponseHypothesis(
                hypothesis_id="admin-change",
                hypothesis="A legitimate administrator made the change.",
                rationale="The transition alone does not establish intent.",
                supporting=citations,
                evidence_needed_to_test=["Matching approved change record"],
                confidence="low",
            ),
            AIResponseHypothesis(
                hypothesis_id="installer",
                hypothesis="A software update changed the service.",
                rationale=(
                    "Installers can update service configuration; no installer evidence is "
                    "present here."
                ),
                supporting=citations,
                evidence_needed_to_test=["Initiating process and package installation log"],
                confidence="low",
            ),
        ],
        "general_security_knowledge": ["Windows services can run automatically at startup."],
        "priority_actions": [
            AIResponseAction(
                priority=1,
                action="Collect the service ImagePath and arguments from SCM configuration.",
                objective="Identify the executable configured for this service.",
                exact_target="service:UpdateAgent",
                why_this_action=(
                    "The observed start mode changed but the binary provenance is unknown."
                ),
                expected_information_gain=(
                    "A known-good path supports an update; an unexpected path raises a "
                    "different hypothesis."
                ),
                interpretation_if_positive=(
                    "A known signed binary supports expected software change."
                ),
                interpretation_if_negative="An unrecognized path keeps the change unexplained.",
                evidence_basis=citations,
                action_type="investigation",
                disruptiveness="low",
                safety_notes="Collect without modifying the service.",
            )
        ],
        "evidence_gaps": [
            {
                "missing_information": "Authenticode signer and SHA-256 of the service binary",
                "why_it_matters": "Tests software provenance.",
                "how_to_collect_it": (
                    "Resolve ImagePath, hash the binary, and verify its signature."
                ),
                "hypotheses_discriminated": ["admin-change", "installer"],
            }
        ],
        "response_options": [
            AIResponseOption(
                trigger_condition="Current evidence does not establish intent.",
                recommended_response="Continue non-disruptive evidence collection.",
                rationale=(
                    "The change is observed, but provenance and initiating actor remain unknown."
                ),
                impact="Preserves service availability while gathering evidence.",
                reversibility="high",
                evidence_required_before_action=["Approved change record", "Binary signature"],
                evidence_basis=citations,
                disruptiveness="low",
            )
        ],
        "possible_consequences": [],
        "attack_technique_candidates": [],
        "analyst_decision_summary": "First identify the configured binary and initiating process.",
        "confidence": "low",
        "uncertainty": "The actor and intent are not established.",
        "citations": citations,
    }
    values.update(updates)
    return AIAnalystResponseDraft.model_validate(values)


def test_facts_are_deterministically_populated_and_cite_csg_objects() -> None:
    package = _package()
    facts = build_csg_determined_facts(package)
    transition = next(fact for fact in facts if "before=" in fact.statement)

    assert "manual" in transition.statement
    assert "auto" in transition.statement
    assert transition.citations.delta_ids == ["delta-service-1"]
    assert all(fact.citations.finding_ids == ["finding-service-1"] for fact in facts)


def test_questions_are_deterministic_and_category_specific() -> None:
    questions = derive_unresolved_questions(_package())

    assert [item["question_id"] for item in questions] == [
        "service.binary",
        "service.actor",
        "service.provenance",
        "service.approval",
        "service.execution",
    ]


def test_model_schema_constrains_exact_target_to_canonical_object_key() -> None:
    schema = _response_schema(_package())
    properties = schema["properties"]

    assert schema["$defs"]["AIResponseAction"]["properties"]["exact_target"]["enum"] == [
        "service:UpdateAgent"
    ]
    assert schema["$defs"]["AIResponseHypothesis"]["properties"]["hypothesis_id"]["enum"] == [
        "H1",
        "H2",
    ]
    assert schema["$defs"]["AIResponseEvidenceGap"]["properties"][
        "hypotheses_discriminated"
    ]["items"]["enum"] == ["H1", "H2"]
    assert properties["investigative_hypotheses"]["maxItems"] == 2
    assert properties["priority_actions"]["maxItems"] == 3
    assert properties["evidence_gaps"]["minItems"] == 1
    assert {"evidence_gaps", "response_options"} <= set(schema["required"])


def test_provider_enforced_schema_is_not_duplicated_in_prompt() -> None:
    package = _package()
    prompt = _build_prompt(package, build_csg_determined_facts(package), [],)

    assert "complete_bounded_evidence_package" in prompt
    assert "output_contract" not in prompt


def test_server_owned_incident_anchor_respects_public_model_limit() -> None:
    package = _package()
    delta = package.state_delta.model_copy(
        update={
            "before": package.state_delta.before.model_copy(
                update={"attributes": {"large": "x" * 2000}}
            ),
            "after": package.state_delta.after.model_copy(
                update={"attributes": {"large": "y" * 2000}}
            ),
        }
    )

    anchor = _incident_anchor(package.model_copy(update={"state_delta": delta}))

    assert len(anchor) <= 500
    assert "reconciliation=CONSISTENT" in anchor
    assert "authorization=UNKNOWN" in anchor


def test_unknown_identifiers_rejected_but_future_artifact_request_is_allowed() -> None:
    draft = _draft()
    assert validate_response_draft(_package(), draft) == []

    action = draft.priority_actions[0].model_copy(
        update={"evidence_basis": AIResponseCitations(evidence_ids=["invented-event"])}
    )
    invalid = draft.model_copy(update={"priority_actions": [action]})
    assert any(
        "unknown evidence_ids" in error for error in validate_response_draft(_package(), invalid)
    )
    wrong_target = draft.priority_actions[0].model_copy(update={"exact_target": "UpdateAgent"})
    invalid_target = draft.model_copy(update={"priority_actions": [wrong_target]})
    assert any(
        "canonical object key" in error
        for error in validate_response_draft(_package(), invalid_target)
    )
    id_as_future_evidence = draft.investigative_hypotheses[0].model_copy(
        update={"evidence_needed_to_test": ["event-service-1"]}
    )
    invalid_question = draft.model_copy(
        update={
            "investigative_hypotheses": [
                id_as_future_evidence,
                *draft.investigative_hypotheses[1:],
            ]
        }
    )
    assert any(
        "must name an artifact or test" in error
        for error in validate_response_draft(_package(), invalid_question)
    )
    assert "Authenticode signer and SHA-256" not in " ".join(
        fact.statement for fact in build_csg_determined_facts(_package())
    )


def test_generic_action_and_unsupported_maliciousness_claim_are_rejected() -> None:
    draft = _draft()
    vague = draft.priority_actions[0].model_copy(
        update={
            "action": "Investigate further",
            "objective": "Investigate further",
            "expected_information_gain": "Investigate further",
        }
    )
    invalid = draft.model_copy(
        update={
            "priority_actions": [vague],
            "analyst_decision_summary": "The service is definitely malicious.",
        }
    )
    errors = validate_response_draft(_package(), invalid)
    assert any("generic action" in error for error in errors)
    assert any("unsupported maliciousness" in error for error in errors)


def test_action_priorities_are_rebased_from_ordered_list_positions() -> None:
    draft = _draft()
    action = draft.priority_actions[0].model_copy(update={"priority": 2})
    draft = draft.model_copy(update={"priority_actions": [action]})

    normalized, changed = _normalize_action_priorities(draft)

    assert changed is True
    assert [item.priority for item in normalized.priority_actions] == [1]
    assert validate_response_draft(_package(), normalized) == []


def test_action_priorities_reject_conflicting_rank_order() -> None:
    draft = _draft()
    first = draft.priority_actions[0].model_copy(update={"priority": 2})
    second = first.model_copy(update={"priority": 1})
    draft = draft.model_copy(update={"priority_actions": [first, second]})

    normalized, changed = _normalize_action_priorities(draft)

    assert changed is False
    assert [item.priority for item in normalized.priority_actions] == [2, 1]
    assert "priority values must follow action list order starting at 1" in (
        validate_response_draft(_package(), normalized)
    )


def test_containment_requires_trigger_evidence_and_disruption_label() -> None:
    draft = _draft()
    action = draft.priority_actions[0].model_copy(
        update={
            "action_type": "containment",
            "trigger_condition": "",
            "evidence_required_before_action": [],
        }
    )
    errors = validate_response_draft(
        _package(), draft.model_copy(update={"priority_actions": [action]})
    )
    assert any("containment requires a trigger" in error for error in errors)
    assert any("evidence prerequisites" in error for error in errors)


def test_model_cannot_supply_or_overwrite_csg_decisions() -> None:
    with pytest.raises(ValidationError):
        AIAnalystResponseDraft.model_validate({**_draft().model_dump(), "risk_score": 0})


def test_assistant_assembles_server_owned_fact_block(monkeypatch: pytest.MonkeyPatch) -> None:
    package = _package()
    settings = Settings(ai_enabled=True, ai_provider="ollama", ollama_model="test-model")
    assistant = AIResponseAssistant(settings)
    monkeypatch.setattr(
        assistant,
        "_request",
        lambda provider, prompt, schema: (
            json.dumps(_draft().model_dump(mode="json")),
            {"eval_count": 12},
        ),
    )

    result = assistant.analyze(package)

    assert result.plan is not None
    assert result.plan.csg_determined_facts == build_csg_determined_facts(package)
    assert result.plan.citations.finding_ids == [package.finding_id]
    assert result.metadata["valid"] is True
    assert result.metadata["inference_parameters"]["num_predict"] == 700


def test_invalid_model_json_is_preserved_for_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    assistant = AIResponseAssistant(
        Settings(ai_enabled=True, ai_provider="ollama", ollama_model="test-model")
    )
    raw = '{"truncated":'
    monkeypatch.setattr(
        assistant, "_request", lambda provider, prompt, schema: (raw, {"eval_count": 7})
    )

    result = assistant.analyze(_package())

    assert result.plan is None
    assert result.raw_response == raw
    assert result.raw_response_sha256 is not None
    assert result.metadata["usage"] == {"eval_count": 7}
    assert result.validation_errors


def test_three_condition_study_has_blinded_labels_and_identical_csg_facts() -> None:
    package = _package()
    study, packet, condition_key, answer_key = build_study(
        package, settings=Settings(ai_enabled=False), seed=530
    )

    assert set(study["conditions"]) == {
        "csg_only",
        "static_playbook",
        "ai_response_assistant",
    }
    assert "conditions" not in packet
    assert "ground_truth" not in packet
    assert set(condition_key.values()) == set(study["conditions"])
    assert answer_key["ground_truth"]["status"] == "not_independently_supplied"
    assert all(
        item["deterministic_facts"] == packet["items"][0]["deterministic_facts"]
        for item in packet["items"]
    )

    plan = build_static_playbook(package, derive_unresolved_questions(package))
    assert len(plan.priority_actions) >= 3
    assert all(action.expected_information_gain for action in plan.priority_actions)


def test_archived_package_is_the_same_isolated_package_used_by_the_study(tmp_path) -> None:
    package = _package()
    unrelated = package.evidence[0].model_copy(
        update={
            "evidence_id": "event-service-other-trial",
            "content": {"target": {"key": "service:OtherTrial"}},
        }
    )
    package = package.model_copy(update={"evidence": [*package.evidence, unrelated]})
    study, packet, condition_key, answer_key = build_study(
        package, settings=Settings(ai_enabled=False)
    )
    output_dir = tmp_path / "study"

    write_study_files(output_dir, study, packet, condition_key, answer_key, package)

    archived = json.loads((output_dir / "evidence-package.json").read_text())
    assert archived == study["evidence_package"]
    assert [item["evidence_id"] for item in archived["evidence"]] == ["event-service-1"]
