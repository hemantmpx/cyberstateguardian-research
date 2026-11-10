from __future__ import annotations

from csg.config import Settings
from csg.domain.enums import (
    AIContextMode,
    AuthorizationStatus,
    ObservationKind,
    ReconciliationStatus,
    Severity,
)
from csg.domain.models import (
    AIAnalystExplanation,
    EvidenceItem,
    EvidencePackage,
    Finding,
    Host,
    ReconciliationResult,
    RiskScore,
    TimeWindow,
    utc_now,
)
from csg.services.llm_analysis import (
    AIAnalysisService,
    _model_visible_package,
    evidence_package_hash,
    validate_citations,
)


def _package() -> EvidencePackage:
    now = utc_now()
    finding = Finding(
        finding_id="finding-1",
        host_id="host-1",
        observation_kind=ObservationKind.STATE_DELTA,
        category="service",
        object_key="service:test",
        reconciliation=ReconciliationResult(
            host_id="host-1",
            status=ReconciliationStatus.CONSISTENT,
            matched_evidence_ids=["event-1"],
            observation_window=TimeWindow(start=now, end=now),
        ),
        authorization_status=AuthorizationStatus.UNKNOWN,
        authorization_reason="not approved",
        risk=RiskScore(
            total=50,
            severity=Severity.HIGH,
            components=[],
            rules_version="test",
        ),
        created_at=now,
    )
    return EvidencePackage(
        finding_id=finding.finding_id,
        context_mode=AIContextMode.EVENT_HISTORY,
        host=Host(
            host_id="host-1",
            hostname="host-1",
            role="test",
            os="Windows",
            architecture="arm64",
        ),
        finding=finding,
        evidence=[
            EvidenceItem(
                evidence_id="event-1",
                host_id="host-1",
                evidence_type="service_created",
                timestamp=now,
                content={},
                source_reference={},
            )
        ],
    )


def _explanation(**updates) -> AIAnalystExplanation:
    values = {
        "summary": "A service was created.",
        "what_changed": "service:test appeared",
        "likely_cause": "unknown",
        "why_it_matters": "persistence is possible",
        "authorization_context": "not approved",
        "telemetry_consistency": "consistent",
        "attack_relevance": "possible persistence",
        "recommended_next_steps": ["review binary"],
        "confidence": "medium",
        "uncertainty": "actor intent is unknown",
        "evidence_ids": ["event-1"],
        "finding_ids": ["finding-1"],
    }
    values.update(updates)
    return AIAnalystExplanation.model_validate(values)


def test_citation_validation_accepts_only_package_ids() -> None:
    package = _package()

    assert validate_citations(package, _explanation()) == []
    errors = validate_citations(
        package,
        _explanation(evidence_ids=["invented-event"], finding_ids=["invented-finding"]),
    )

    assert errors == [
        "unknown evidence IDs: invented-event",
        "unknown finding IDs: invented-finding",
    ]


def test_package_hash_ignores_volatile_package_identity() -> None:
    package = _package()
    duplicate = package.model_copy(update={"package_id": "another-id", "created_at": utc_now()})

    assert evidence_package_hash(package) == evidence_package_hash(duplicate)


def test_event_history_model_payload_hides_state_and_condition_metadata() -> None:
    payload = _model_visible_package(_package())

    assert "context_mode" not in payload
    assert payload["state_delta"] is None
    assert payload["finding"] == {
        "finding_id": "finding-1",
        "host_id": "host-1",
        "observation_kind": "STATE_DELTA",
        "category": "service",
        "object_key": "service:test",
        "created_at": payload["finding"]["created_at"],
    }
    assert "deterministic_results" not in payload["incident_context"]


def test_citation_validation_rejects_evidence_from_another_object() -> None:
    package = _package().model_copy(
        update={
            "evidence": [
                EvidenceItem(
                    evidence_id="event-1",
                    host_id="host-1",
                    evidence_type="service_created",
                    timestamp=utc_now(),
                    content={"target": {"key": "service:other"}},
                )
            ]
        }
    )
    errors = validate_citations(package, _explanation())
    assert any("outside package object scope" in error for error in errors)


def test_citation_validation_rejects_unsupported_authorized_user_claim() -> None:
    package = _package()
    explanation = _explanation(
        authorization_context="The service was stopped by an authorized user."
    )
    errors = validate_citations(package, explanation)
    assert any("authorized user" in error for error in errors)


def test_ollama_provider_validates_structured_grounded_response(monkeypatch) -> None:
    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {
                "done": True,
                "prompt_eval_count": 10,
                "eval_count": 20,
                "message": {
                    "content": '{"summary":"A service was created.",'
                    '"what_changed":"service:test appeared",'
                    '"likely_cause":"unknown","why_it_matters":"persistence is possible",'
                    '"authorization_context":"not approved","telemetry_consistency":"consistent",'
                    '"attack_relevance":"possible persistence",'
                    '"recommended_next_steps":["review binary"],'
                    '"confidence":"medium","uncertainty":"actor intent is unknown",'
                    '"evidence_ids":["event-1"],"finding_ids":["finding-1"]}',
                },
            }

    monkeypatch.setattr(
        "csg.services.llm_analysis.httpx.post", lambda *args, **kwargs: FakeResponse()
    )
    settings = Settings(
        CSG_AI_ENABLED=True,
        CSG_AI_PROVIDER="ollama",
        CSG_OLLAMA_MODEL="llama3.2:latest",
    )
    record = AIAnalysisService(settings).explain(_package())

    assert record.enabled is True
    assert record.model == "llama3.2:latest"
    assert record.validation_errors == []
    assert record.metadata["ai_provider"] == "ollama"
    assert record.metadata["grounding_valid"] is True
