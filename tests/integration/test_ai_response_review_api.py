from __future__ import annotations

from datetime import UTC, datetime

from experiments.ai_response_assistance_study import (
    build_static_playbook,
    build_study,
    write_study_files,
)
from experiments.ai_response_evaluation import (
    BOOLEAN_FIELDS,
    COUNT_FIELDS,
    RATING_FIELDS,
    blank_scores,
)
from fastapi.testclient import TestClient

from csg.api.deps import settings_dependency
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
    EvidenceItem,
    EvidencePackage,
    Finding,
    Host,
    ReconciliationResult,
    RiskScore,
    StateDelta,
    StateObject,
    TimeWindow,
)
from csg.main import app
from csg.services.ai_response_assistant import AIResponseAnalysis, derive_unresolved_questions


def _package() -> EvidencePackage:
    at = datetime(2026, 10, 1, tzinfo=UTC)
    finding = Finding(
        finding_id="review-finding-1",
        host_id="review-host-1",
        observation_kind=ObservationKind.STATE_DELTA,
        delta_id="review-delta-1",
        category="service",
        object_key="service:UpdateAgent",
        reconciliation=ReconciliationResult(
            host_id="review-host-1",
            status=ReconciliationStatus.CONSISTENT,
            matched_evidence_ids=["review-event-1"],
            observation_window=TimeWindow(start=at, end=at),
        ),
        authorization_status=AuthorizationStatus.UNKNOWN,
        authorization_reason="No matching approval was supplied.",
        risk=RiskScore(total=35, severity=Severity.MEDIUM, rules_version="test"),
        created_at=at,
    )
    before = StateObject(
        category="service",
        object_key="service:UpdateAgent",
        attributes={"start_mode": "manual"},
        source_timestamp=at,
    )
    after = before.model_copy(update={"attributes": {"start_mode": "auto"}})
    delta = StateDelta(
        delta_id="review-delta-1",
        host_id="review-host-1",
        category="service",
        object_key="service:UpdateAgent",
        delta_type=DeltaType.MODIFY,
        before=before,
        after=after,
        observation_window=TimeWindow(start=at, end=at),
    )
    return EvidencePackage(
        finding_id=finding.finding_id,
        context_mode=AIContextMode.FULL_CONTEXT,
        host=Host(
            host_id="review-host-1",
            hostname="review-host-1",
            role="test",
            os="Windows",
            architecture="arm64",
        ),
        finding=finding,
        state_delta=delta,
        evidence=[
            EvidenceItem(
                evidence_id="review-event-1",
                host_id="review-host-1",
                evidence_type="service_modified",
                timestamp=at,
                content={"target": {"key": "service:UpdateAgent"}},
            )
        ],
    )


def _scores() -> dict[str, object]:
    scores = blank_scores()
    scores.update({field: 4 for field in RATING_FIELDS})
    scores.update({field: 0 for field in COUNT_FIELDS})
    scores.update({field: True for field in BOOLEAN_FIELDS})
    return scores


def test_blinded_response_review_save_lock_and_unblind(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(Settings, "resolve_path", lambda self, path: tmp_path / path)
    settings = Settings(ai_enabled=False)
    app.dependency_overrides[settings_dependency] = lambda: settings
    monkeypatch.setattr(
        "csg.services.ai_response_assistant.AIResponseAssistant.analyze",
        lambda self, package: AIResponseAnalysis(
            plan=build_static_playbook(package, derive_unresolved_questions(package)),
            metadata={"provider": "test", "model": "test-model"},
            validation_errors=[],
            raw_response_sha256="test-hash",
            raw_response="{}",
        ),
    )
    try:
        study, packet, key, answer = build_study(
            _package(), settings=settings, ground_truth={"transition": "manual_to_auto"}
        )
        output_dir = (
            tmp_path
            / "experiments/results/runs/20261001/ai-response-assistance"
            / study["study_id"]
        )
        write_study_files(output_dir, study, packet, key, answer, _package())
        study_path = f"20261001/ai-response-assistance/{study['study_id']}"
        client = TestClient(app)

        listed = client.get("/api/research/ai-response-review/studies")
        detail = client.get(f"/api/research/ai-response-review/studies/{study_path}")
        assert listed.status_code == 200
        assert detail.status_code == 200
        public_text = detail.text
        assert "csg_only" not in public_text
        assert "static_playbook" not in public_text
        assert "condition-key.private.json" not in public_text
        assert (
            detail.json()["packet"]["evidence_dossier"]["finding"]["finding_id"]
            == "review-finding-1"
        )

        canonical = detail.json()["packet"]["items"]
        for reviewer in ("reviewer-1", "reviewer-2"):
            scored = [
                {**item, "scores": _scores(), "supplemental_guidance": {"tampered": True}}
                for item in canonical
            ]
            saved = client.post(
                f"/api/research/ai-response-review/studies/{study_path}/drafts",
                json={"reviewer_id": reviewer, "items": scored, "submit": True},
            )
            assert saved.status_code == 200, saved.text
            assert saved.json()["status"] == "SUBMITTED"
            reread = client.get(
                f"/api/research/ai-response-review/studies/{study_path}/drafts/{reviewer}"
            )
            assert reread.status_code == 200
            assert "tampered" not in reread.text
            locked = client.post(
                f"/api/research/ai-response-review/studies/{study_path}/drafts",
                json={"reviewer_id": reviewer, "items": scored, "submit": True},
            )
            assert locked.status_code == 409

        aggregated = client.post(
            f"/api/research/ai-response-review/studies/{study_path}/aggregate",
            json={"reviewer_ids": ["reviewer-1", "reviewer-2"], "confirm_unblind": True},
        )
        assert aggregated.status_code == 200, aggregated.text
        assert aggregated.json()["aggregate"]["reviewer_count"] == 2
    finally:
        app.dependency_overrides.clear()


def test_failed_generation_is_archived_but_not_listed_for_content_review(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(Settings, "resolve_path", lambda self, path: tmp_path / path)
    settings = Settings(ai_enabled=False)
    app.dependency_overrides[settings_dependency] = lambda: settings
    try:
        study, packet, key, answer = build_study(_package(), settings=settings)
        assert study["review_eligible"] is False
        output_dir = (
            tmp_path
            / "experiments/results/runs/20261001/ai-response-assistance"
            / study["study_id"]
        )
        write_study_files(output_dir, study, packet, key, answer, _package())
        study_path = f"20261001/ai-response-assistance/{study['study_id']}"
        client = TestClient(app)

        listed = client.get("/api/research/ai-response-review/studies")
        detail = client.get(f"/api/research/ai-response-review/studies/{study_path}")

        assert listed.status_code == 200
        assert study_path not in {item["study_id"] for item in listed.json()["studies"]}
        assert detail.status_code == 404
        assert (output_dir / "study.json").is_file()
    finally:
        app.dependency_overrides.clear()
