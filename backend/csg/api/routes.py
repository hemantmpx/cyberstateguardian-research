from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from csg.api.deps import db_dependency, require_probe_token, settings_dependency
from csg.config import Settings
from csg.db.repositories import CyberStateRepository
from csg.domain.enums import AIContextMode, IncidentStatus
from csg.domain.models import (
    AIAnalysisRecord,
    EventObservationResult,
    EvidencePackage,
    ExperimentRun,
    ExperimentScenario,
    Finding,
    Host,
    Incident,
    IncidentFindingAssignment,
    NormalizedEvent,
    ProbeObservation,
    ProbeTransitionBatch,
    ReconciliationResult,
    StateDelta,
    StateSnapshot,
    StateTrajectory,
    StateTransitionRecord,
    TransitionReconciliationResult,
    TransitionTimelineItem,
    ensure_utc,
    utc_now,
)
from csg.providers.factory import build_event_provider, build_state_provider
from csg.services.incident_context import IncidentContextBuilder
from csg.services.incident_correlation import IncidentCorrelationService
from csg.services.live_pipeline import LivePipelineService
from csg.services.llm_analysis import AIAnalysisService
from csg.services.provider_sync import ProviderSyncService
from csg.services.reconciliation_lifecycle import ReconciliationLifecycleService
from csg.services.trajectories import StateTrajectoryBuilder
from csg.services.transition_reconciliation import TransitionReconciliationService
from csg.services.wazuh_status import WazuhStatusService

router = APIRouter(prefix="/api")


class ExperimentActionRequest(BaseModel):
    action: Literal[
        "run_fixture_suite",
        "sync_host",
        "process_backlog",
        "correlate_backlog",
    ]
    host_id: str | None = None
    scenario_id: str | None = None
    repetitions: int = Field(default=1, ge=1, le=10)


AI_REVIEW_SCORE_FIELDS = (
    "attack_chain_reconstruction_accuracy_0_to_5",
    "mitre_attack_mapping_accuracy_0_to_5",
    "evidence_grounding_accuracy_0_to_5",
    "analyst_usefulness_0_to_5",
    "confidence_calibration_0_to_5",
)
AI_REVIEW_SCORE_KEYS = (
    *AI_REVIEW_SCORE_FIELDS,
    "root_cause_identification_correct",
    "unsupported_claim_count",
    "reviewer_notes",
)


class AIReviewSaveRequest(BaseModel):
    reviewer_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    items: list[dict[str, Any]] = Field(min_length=1)
    submit: bool = False


class AIReviewAggregateRequest(BaseModel):
    reviewer_ids: list[str] = Field(min_length=1, max_length=10)
    confirm_unblind: bool = False


class AIResponseReviewSaveRequest(BaseModel):
    reviewer_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    items: list[dict[str, Any]] = Field(min_length=1)
    submit: bool = False


class AIResponseReviewAggregateRequest(BaseModel):
    reviewer_ids: list[str] = Field(min_length=2, max_length=10)
    confirm_unblind: bool = False


def _read_result_file(path: Path, *, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        if path.suffix == ".md":
            return path.read_text(encoding="utf-8")
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return default


def _ai_review_study_dirs(runs_dir: Path) -> list[tuple[str, Path]]:
    studies = []
    for packet_path in runs_dir.rglob("review_items.blinded.json"):
        study_dir = packet_path.parent
        study = _read_result_file(study_dir / "study.json", default={})
        if isinstance(study, dict) and str(study.get("schema_version", "")).startswith(
            "csg-ai-response-assistance-"
        ):
            continue
        study_id = study_dir.relative_to(runs_dir).as_posix()
        studies.append((study_id, study_dir))
    return sorted(studies, key=lambda item: item[0], reverse=True)


def _ai_review_study_dir(runs_dir: Path, study_id: str) -> Path:
    root = runs_dir.resolve()
    candidate = (runs_dir / study_id).resolve()
    if root not in candidate.parents or not (candidate / "review_items.blinded.json").exists():
        raise HTTPException(status_code=404, detail="AI review study not found")
    return candidate


def _ai_review_packet(study_dir: Path) -> dict[str, Any]:
    packet = _read_result_file(study_dir / "review_items.blinded.json", default={})
    if not isinstance(packet, dict) or not isinstance(packet.get("items"), list):
        raise HTTPException(status_code=422, detail="AI review packet is invalid")
    items = []
    for item in packet["items"]:
        if not isinstance(item, dict) or not item.get("review_id"):
            continue
        items.append(
            {
                "review_id": str(item["review_id"]),
                "subject": item.get("subject", {}),
                "analysis": item.get("analysis"),
                "scores": item.get("scores", {}),
            }
        )
    return {
        "schema_version": packet.get("schema_version"),
        "study_version": packet.get("study_version"),
        "review_instructions": packet.get("review_instructions", ""),
        "items": items,
    }


def _ai_neutral_evidence_dossier(study_dir: Path) -> dict[str, Any]:
    study = _read_result_file(study_dir / "study.json", default={})
    conditions = study.get("conditions", {}) if isinstance(study, dict) else {}
    packages = [
        value.get("package")
        for value in conditions.values()
        if isinstance(value, dict) and isinstance(value.get("package"), dict)
    ]
    package = max(packages, key=lambda item: len(item.get("evidence", [])), default={})
    return {
        "subject": study.get("subject", {}) if isinstance(study, dict) else {},
        "host": package.get("host"),
        "finding": package.get("finding"),
        "state_delta": package.get("state_delta"),
        "transient_observation": package.get("transient_observation"),
        "incident_context": package.get("incident_context"),
        "related_findings": package.get("related_findings", []),
        "evidence": package.get("evidence", []),
        "source_quality": package.get("source_quality"),
        "dossier_note": (
            "This dossier contains primary state and event evidence for scoring. "
            "It intentionally omits AI condition labels, private answer keys, and "
            "condition mappings."
        ),
    }


def _valid_ai_score(value: Any) -> bool:
    return type(value) in (int, float) and 0 <= value <= 5


def _valid_reviewer_id(value: str) -> bool:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    return bool(value) and all(character in allowed for character in value)


def _review_completion(items: list[dict[str, Any]]) -> dict[str, int | bool]:
    complete = 0
    for item in items:
        scores = item.get("scores") or {}
        if (
            all(_valid_ai_score(scores.get(field)) for field in AI_REVIEW_SCORE_FIELDS)
            and type(scores.get("root_cause_identification_correct")) is bool
            and type(scores.get("unsupported_claim_count")) is int
            and scores.get("unsupported_claim_count") >= 0
        ):
            complete += 1
    return {
        "completed_items": complete,
        "total_items": len(items),
        "complete": complete == len(items) and bool(items),
    }


def _partial_ai_response_score_errors(scores: dict[str, Any]) -> list[str]:
    from experiments.ai_response_evaluation import BOOLEAN_FIELDS, COUNT_FIELDS, RATING_FIELDS

    for field in RATING_FIELDS:
        value = scores.get(field)
        if value is not None and (type(value) not in (int, float) or not 0 <= value <= 5):
            return [f"{field} must be empty or a number from 0 to 5"]
    for field in COUNT_FIELDS:
        value = scores.get(field)
        if value is not None and (type(value) is not int or value < 0):
            return [f"{field} must be empty or a non-negative integer"]
    for field in BOOLEAN_FIELDS:
        value = scores.get(field)
        if value is not None and type(value) is not bool:
            return [f"{field} must be empty or boolean"]
    if not isinstance(scores.get("reviewer_notes", ""), str):
        return ["reviewer_notes must be text"]
    return []


def _ai_review_summary(study_id: str, study_dir: Path) -> dict[str, Any]:
    packet = _ai_review_packet(study_dir)
    study = _read_result_file(study_dir / "study.json", default={})
    conditions = study.get("conditions", {}) if isinstance(study, dict) else {}
    first_analysis = next(
        (
            value.get("analysis")
            for value in conditions.values()
            if isinstance(value, dict) and isinstance(value.get("analysis"), dict)
        ),
        {},
    )
    drafts = []
    review_dir = study_dir / "human-review"
    if review_dir.exists():
        for path in sorted(review_dir.glob("*.json")):
            draft = _read_result_file(path, default={})
            if isinstance(draft, dict):
                completion = _review_completion(draft.get("items", []))
                drafts.append(
                    {
                        "reviewer_id": draft.get("reviewer_id", path.stem),
                        "status": draft.get("status", "DRAFT"),
                        "submitted_at": draft.get("submitted_at"),
                        **completion,
                    }
                )
    return {
        "study_id": study_id,
        "study_version": packet.get("study_version"),
        "item_count": len(packet["items"]),
        "model": first_analysis.get("model"),
        "provider": (first_analysis.get("metadata") or {}).get("ai_provider"),
        "reviewer_drafts": drafts,
        "saved_results": (study_dir / "human-review-aggregate.json").exists(),
    }


def _ai_response_study_dirs(runs_dir: Path) -> list[tuple[str, Path]]:
    studies = []
    for packet_path in runs_dir.rglob("review_items.blinded.json"):
        study_dir = packet_path.parent
        study = _read_result_file(study_dir / "study.json", default={})
        if not isinstance(study, dict) or study.get("schema_version") != (
            "csg-ai-response-assistance-study-v8"
        ):
            continue
        if study.get("review_eligible") is not True:
            continue
        study_id = study_dir.relative_to(runs_dir).as_posix()
        studies.append((study_id, study_dir))
    return sorted(studies, key=lambda item: item[0], reverse=True)


def _ai_response_study_dir(runs_dir: Path, study_id: str) -> Path:
    root = runs_dir.resolve()
    candidate = (runs_dir / study_id).resolve()
    study = _read_result_file(candidate / "study.json", default={})
    if (
        root not in candidate.parents
        or not isinstance(study, dict)
        or study.get("schema_version") != "csg-ai-response-assistance-study-v8"
        or study.get("review_eligible") is not True
        or not (candidate / "review_items.blinded.json").exists()
    ):
        raise HTTPException(status_code=404, detail="AI response review study not found")
    return candidate


def _ai_response_review_packet(study_dir: Path) -> dict[str, Any]:
    packet = _read_result_file(study_dir / "review_items.blinded.json", default={})
    if (
        not isinstance(packet, dict)
        or packet.get("schema_version") != "csg-ai-response-blinded-review-v8"
        or not isinstance(packet.get("items"), list)
    ):
        raise HTTPException(status_code=422, detail="AI response review packet is invalid")
    canonical_items = []
    for item in packet["items"]:
        if not isinstance(item, dict) or not item.get("review_id"):
            continue
        canonical_items.append(
            {
                "review_id": str(item["review_id"]),
                "subject_id": str(item.get("subject_id", "")),
                "deterministic_facts": item.get("deterministic_facts", []),
                "supplemental_guidance": item.get("supplemental_guidance"),
                "scores": item.get("scores") or {},
            }
        )
    if not canonical_items:
        raise HTTPException(status_code=422, detail="AI response review packet has no items")
    return {
        "schema_version": packet["schema_version"],
        "study_version": packet.get("study_version"),
        "review_instructions": packet.get("review_instructions", ""),
        "evidence_dossier": packet.get("evidence_dossier", {}),
        "items": canonical_items,
    }


def _ai_response_review_summary(study_id: str, study_dir: Path) -> dict[str, Any]:
    packet = _ai_response_review_packet(study_dir)
    drafts = []
    review_dir = study_dir / "human-review"
    if review_dir.exists():
        from experiments.ai_response_evaluation import validate_scores

        for path in sorted(review_dir.glob("*.json")):
            review = _read_result_file(path, default={})
            if not isinstance(review, dict):
                continue
            complete = sum(
                not validate_scores(item.get("scores") or {}) for item in review.get("items", [])
            )
            drafts.append(
                {
                    "reviewer_id": review.get("reviewer_id", path.stem),
                    "status": review.get("status", "DRAFT"),
                    "completed_items": complete,
                    "total_items": len(packet["items"]),
                    "submitted_at": review.get("submitted_at"),
                }
            )
    return {
        "study_id": study_id,
        "study_version": packet.get("study_version"),
        "item_count": len(packet["items"]),
        "reviewer_drafts": drafts,
        "has_aggregate": (study_dir / "human-review-aggregate.json").exists(),
    }


def repository(session: Session) -> CyberStateRepository:
    return CyberStateRepository(session)


@router.get("/hosts", response_model=list[Host])
def list_hosts(session: Session = Depends(db_dependency)) -> list[Host]:
    return repository(session).list_hosts()


@router.post("/hosts", response_model=Host)
def upsert_host(host: Host, session: Session = Depends(db_dependency)) -> Host:
    return repository(session).upsert_host(host)


@router.get("/hosts/{host_id}", response_model=Host)
def get_host(host_id: str, session: Session = Depends(db_dependency)) -> Host:
    host = repository(session).get_host(host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    return host


@router.post(
    "/probe/observations",
    dependencies=[Depends(require_probe_token)],
)
def ingest_probe_observation(
    observation: ProbeObservation,
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> dict[str, object]:
    repo = repository(session)
    result = LivePipelineService(settings).ingest_probe_observation(repo, observation)
    return {
        "status": "accepted",
        "observation_id": result.observation_id,
        "snapshot_id": result.snapshot_id,
        "delta_count": len(result.deltas),
        "finding_count": len(result.findings),
        "incident_count": len({incident.incident_id for incident in result.incidents}),
        "ignored_delta_count": result.skipped_ignored_categories,
        "deltas": [delta.model_dump(mode="json") for delta in result.deltas],
        "findings": [finding.model_dump(mode="json") for finding in result.findings],
        "incidents": [incident.model_dump(mode="json") for incident in result.incidents],
    }


@router.post(
    "/probe/transitions",
    dependencies=[Depends(require_probe_token)],
)
def ingest_probe_transitions(
    batch: ProbeTransitionBatch,
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> dict[str, object]:
    if not settings.transition_capture_enabled:
        raise HTTPException(status_code=409, detail="transition capture is disabled")
    enabled_categories = settings.transition_enabled_category_set
    submitted_categories = {item.category for item in batch.records} | {
        item.category for item in batch.monitor_health
    }
    disabled = submitted_categories - enabled_categories
    if disabled:
        raise HTTPException(
            status_code=409,
            detail=f"transition capture is disabled for categories: {', '.join(sorted(disabled))}",
        )
    if any(item.source != "direct_probe" for item in batch.records):
        raise HTTPException(
            status_code=422, detail="transition records must use direct_probe source"
        )

    repo = repository(session)
    received_records = [
        item.model_copy(update={"received_at": utc_now()}) for item in batch.records
    ]
    try:
        stored, created_count = repo.create_transition_records(received_records, commit=False)
        health = repo.create_transition_monitor_health(batch.monitor_health, commit=False)
        session.commit()
    except Exception:
        session.rollback()
        raise
    return {
        "status": "accepted",
        "host_id": batch.host_id,
        "received_count": len(batch.records),
        "created_count": created_count,
        "duplicate_count": max(0, len(batch.records) - created_count),
        "stored_transition_ids": [item.transition_id for item in stored],
        "monitor_health_count": len(health),
    }


@router.get("/transition-capture/status")
def transition_capture_status(
    host_id: str | None = None,
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> dict[str, object]:
    latest_health = repository(session).latest_transition_monitor_health(host_id) if host_id else []
    health_by_category = {item.category: item.model_dump(mode="json") for item in latest_health}
    category_flags = {
        "process": settings.transition_processes_enabled,
        "service": settings.transition_services_enabled,
        "registry": settings.transition_registry_enabled,
        "scheduled_task": settings.transition_tasks_enabled,
        "privileged_group": settings.transition_privileged_groups_enabled,
        "listener": settings.transition_listeners_enabled,
    }
    return {
        "enabled": settings.transition_capture_enabled,
        "host_id": host_id,
        "enabled_categories": sorted(settings.transition_enabled_category_set),
        "categories": {
            category: {
                "enabled": settings.transition_capture_enabled and configured,
                "monitor_health": health_by_category.get(category),
            }
            for category, configured in category_flags.items()
        },
    }


@router.get("/hosts/{host_id}/transitions", response_model=list[StateTransitionRecord])
def list_host_transitions(
    host_id: str,
    start: datetime | None = None,
    end: datetime | None = None,
    category: str | None = None,
    object_key: str | None = None,
    reconciliation_status: str | None = None,
    limit: int = Query(default=200, ge=1, le=500),
    session: Session = Depends(db_dependency),
) -> list[StateTransitionRecord]:
    if start and end and end < start:
        raise HTTPException(status_code=422, detail="end must not precede start")
    return repository(session).list_transition_records(
        host_id,
        start=start,
        end=end,
        category=category,
        object_key=object_key,
        reconciliation_status=reconciliation_status,
        limit=limit,
    )


@router.get(
    "/hosts/{host_id}/transition-timeline",
    response_model=list[TransitionTimelineItem],
)
def list_host_transition_timeline(
    host_id: str,
    start: datetime | None = None,
    end: datetime | None = None,
    category: str | None = None,
    object_key: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(db_dependency),
) -> list[TransitionTimelineItem]:
    if start and end and end < start:
        raise HTTPException(status_code=422, detail="end must not precede start")
    repo = repository(session)
    transitions = repo.list_transition_records(
        host_id,
        start=start,
        end=end,
        category=category,
        object_key=object_key,
        limit=limit,
    )
    latest = repo.latest_transition_reconciliations(item.transition_id for item in transitions)
    return [
        TransitionTimelineItem(
            transition=item,
            latest_reconciliation=latest.get(item.transition_id),
        )
        for item in transitions
    ]


@router.get("/transitions/{transition_id}", response_model=StateTransitionRecord)
def get_transition(
    transition_id: str,
    session: Session = Depends(db_dependency),
) -> StateTransitionRecord:
    transition = repository(session).get_transition_record(transition_id)
    if transition is None:
        raise HTTPException(status_code=404, detail="transition not found")
    return transition


@router.get(
    "/transitions/{transition_id}/reconciliations",
    response_model=list[TransitionReconciliationResult],
)
def get_transition_reconciliations(
    transition_id: str,
    session: Session = Depends(db_dependency),
) -> list[TransitionReconciliationResult]:
    repo = repository(session)
    if repo.get_transition_record(transition_id) is None:
        raise HTTPException(status_code=404, detail="transition not found")
    return repo.transition_reconciliation_history(transition_id)


@router.post(
    "/transitions/{transition_id}/reconcile",
    response_model=TransitionReconciliationResult,
)
async def reconcile_transition(
    transition_id: str,
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> TransitionReconciliationResult:
    transition = repository(session).get_transition_record(transition_id)
    if transition is None:
        raise HTTPException(status_code=404, detail="transition not found")
    if transition.category not in settings.transition_enabled_category_set:
        raise HTTPException(
            status_code=409, detail="transition capture is disabled for this category"
        )
    return await TransitionReconciliationService(settings).reconcile(
        repository(session), transition
    )


@router.get("/hosts/{host_id}/trajectories", response_model=list[StateTrajectory])
def list_host_trajectories(
    host_id: str,
    start: datetime | None = None,
    end: datetime | None = None,
    category: str | None = None,
    object_key: str | None = None,
    trajectory_type: str | None = None,
    include_stable: bool = False,
    limit: int = Query(default=50, ge=1, le=200),
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> list[StateTrajectory]:
    end = end or utc_now()
    start = start or end - timedelta(hours=24)
    if end < start:
        raise HTTPException(status_code=422, detail="end must not precede start")
    repo = repository(session)
    snapshots = repo.snapshots_for_trajectory_interval(host_id, start, end, limit=limit)
    snapshots = snapshots[: limit + 1]
    if len(snapshots) < 2:
        return []
    records = repo.list_transition_records(
        host_id,
        start=snapshots[0].built_at,
        end=snapshots[-1].built_at,
        category=category,
        limit=5001,
    )
    if len(records) > 5000:
        raise HTTPException(
            status_code=413,
            detail="transition interval contains more than 5000 records; narrow the time range",
        )

    builder = StateTrajectoryBuilder()
    trajectories: list[StateTrajectory] = []
    for before, after in zip(snapshots, snapshots[1:], strict=False):
        enabled = settings.transition_enabled_category_set
        coverage_by_category = {
            item.category: ("UNKNOWN" if item.category in enabled else "OFFLINE")
            for item in after.category_statuses
        }
        for health in repo.transition_monitor_health_at(host_id, after.built_at):
            coverage_by_category[health.category] = health.status
        trajectories.extend(
            builder.build_interval(
                before,
                after,
                records,
                coverage_by_category=coverage_by_category,
                category=category,
                object_key=object_key,
                include_stable=include_stable,
            )
        )
    if trajectory_type:
        trajectories = [
            item for item in trajectories if item.trajectory_type.value == trajectory_type
        ]
    return trajectories[:limit]


@router.post("/pipeline/process-backlog")
def process_pipeline_backlog(
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> dict[str, object]:
    result = LivePipelineService(settings).process_backlog(repository(session))
    return {
        "status": "processed",
        "delta_count": len(result.deltas),
        "finding_count": len(result.findings),
        "incident_count": len({incident.incident_id for incident in result.incidents}),
        "skipped_existing_findings": result.skipped_existing_findings,
        "ignored_delta_count": result.skipped_ignored_categories,
        "reconciliation_updates": result.reconciliation_updates,
    }


@router.get("/hosts/{host_id}/observations/latest", response_model=ProbeObservation | None)
def latest_observation(
    host_id: str, session: Session = Depends(db_dependency)
) -> ProbeObservation | None:
    return repository(session).latest_source_observation(host_id)


@router.get("/hosts/{host_id}/state/latest", response_model=StateSnapshot | None)
def latest_state(host_id: str, session: Session = Depends(db_dependency)) -> StateSnapshot | None:
    return repository(session).latest_snapshot(host_id)


@router.get("/hosts/{host_id}/deltas", response_model=list[StateDelta])
def list_deltas(
    host_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    object_key: str | None = Query(default=None, min_length=1, max_length=2048),
    created_after: datetime | None = None,
    category: str | None = Query(default=None, max_length=128),
    session: Session = Depends(db_dependency),
) -> list[StateDelta]:
    return repository(session).list_deltas(
        host_id,
        limit=limit,
        object_key=object_key,
        created_after=created_after,
        category=category,
    )


@router.post("/events", response_model=list[NormalizedEvent])
def create_events(
    events: list[NormalizedEvent],
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> list[NormalizedEvent]:
    repo = repository(session)
    saved = repo.create_events(events)
    lifecycle = ReconciliationLifecycleService(settings)
    for host_id in sorted({event.host_id for event in saved}):
        lifecycle.reevaluate_pending(
            repo, host_id=host_id, events=[event for event in saved if event.host_id == host_id]
        )
    return saved


@router.post("/hosts/{host_id}/event-observations")
def ingest_event_observation(
    host_id: str,
    observation: EventObservationResult,
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> dict[str, object]:
    if len(observation.events) > 5000:
        raise HTTPException(status_code=413, detail="observation contains too many events")
    if any(event.host_id != host_id for event in observation.events):
        raise HTTPException(status_code=422, detail="all events must belong to the path host")
    start_value = observation.metadata.get("query_start")
    end_value = observation.metadata.get("query_end")
    if not start_value or not end_value:
        raise HTTPException(status_code=422, detail="query_start and query_end are required")
    try:
        start = ensure_utc(datetime.fromisoformat(str(start_value).replace("Z", "+00:00")))
        end = ensure_utc(datetime.fromisoformat(str(end_value).replace("Z", "+00:00")))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="query bounds must be ISO timestamps") from exc
    if end <= start or end - start > timedelta(minutes=30):
        raise HTTPException(
            status_code=422,
            detail="query window must be positive and at most 30 minutes",
        )

    repo = repository(session)
    saved = repo.create_events(observation.events)
    scoped_observation = observation.model_copy(update={"events": saved})
    updates = ReconciliationLifecycleService(settings).reevaluate_pending(
        repo,
        host_id=host_id,
        events=saved,
        event_observation=scoped_observation,
    )
    return {
        "host_id": host_id,
        "query_complete": observation.query_complete,
        "coverage_status": observation.coverage_status,
        "endpoint_collection_status": observation.endpoint_collection_status,
        "transport_status": observation.transport_status,
        "index_status": observation.index_status,
        "received_event_count": len(observation.events),
        "stored_event_count": len(saved),
        "reconciliation_updates": len(updates.updated_findings),
        "updated_findings": [
            {
                "finding_id": finding.finding_id,
                "status": finding.reconciliation.status.value,
                "finalized": finding.reconciliation.finalized,
                "reconciliation_semantics": finding.reconciliation.metadata.get(
                    "reconciliation_semantics"
                ),
            }
            for finding in updates.updated_findings
        ],
    }


@router.get("/hosts/{host_id}/events", response_model=list[NormalizedEvent])
def list_events(
    host_id: str,
    start: datetime | None = None,
    end: datetime | None = None,
    normalized_type: str | None = Query(default=None, max_length=128),
    source: str | None = Query(default=None, max_length=128),
    object_key: str | None = Query(default=None, max_length=512),
    object_name: str | None = Query(default=None, max_length=256),
    limit: int = Query(default=1000, ge=1, le=5000),
    session: Session = Depends(db_dependency),
) -> list[NormalizedEvent]:
    now = datetime.now(UTC)
    start = start or now - timedelta(hours=24)
    end = end or now + timedelta(minutes=5)
    return repository(session).get_events(
        host_id,
        start=start,
        end=end,
        normalized_type=normalized_type,
        source=source,
        object_key=object_key,
        object_name=object_name,
        limit=limit,
    )


@router.get("/hosts/{host_id}/provider-events", response_model=list[NormalizedEvent])
async def list_provider_events(
    host_id: str,
    start: datetime,
    end: datetime,
    settings: Settings = Depends(settings_dependency),
) -> list[NormalizedEvent]:
    provider = build_event_provider(settings)
    result = await provider.get_events(host_id, start=start, end=end)
    return result.events if hasattr(result, "events") else result


@router.get(
    "/hosts/{host_id}/provider-event-observation",
    response_model=EventObservationResult,
)
async def provider_event_observation(
    host_id: str,
    start: datetime,
    end: datetime,
    settings: Settings = Depends(settings_dependency),
) -> EventObservationResult:
    if end <= start:
        raise HTTPException(status_code=422, detail="end must be later than start")
    if end - start > timedelta(minutes=30):
        raise HTTPException(
            status_code=422,
            detail="provider event window cannot exceed 30 minutes",
        )
    provider = build_event_provider(settings)
    result = await provider.get_events(host_id, start=start, end=end)
    if isinstance(result, EventObservationResult):
        return result
    return EventObservationResult(
        events=result,
        query_complete=True,
        endpoint_collection_status="UNKNOWN",
        transport_status="AVAILABLE",
        index_status="AVAILABLE",
        coverage_status="COMPLETE",
        retrieved_count=len(result),
    )


@router.get("/wazuh/status")
async def wazuh_status(
    settings: Settings = Depends(settings_dependency),
) -> dict[str, object]:
    return await WazuhStatusService(settings).status()


@router.get("/hosts/{host_id}/provider-state", response_model=StateSnapshot)
async def get_provider_state(
    host_id: str,
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> StateSnapshot:
    if settings.state_provider == "probe":
        snapshot = repository(session).latest_snapshot_by_source(host_id, "direct_probe")
        if snapshot is None:
            raise HTTPException(status_code=404, detail="direct probe state not found")
        return snapshot
    provider = build_state_provider(settings)
    return await provider.get_snapshot(host_id)


@router.post("/hosts/{host_id}/provider-sync")
async def sync_provider_host(
    host_id: str,
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> dict[str, object]:
    repo = repository(session)
    if (
        settings.state_provider == "probe"
        and repo.latest_snapshot_by_source(host_id, "direct_probe") is None
    ):
        raise HTTPException(
            status_code=409, detail="Run the native probe before synchronizing events"
        )
    result = await ProviderSyncService(settings).sync_host(repo, host_id)
    return {
        "status": "synced",
        "host_id": result.host_id,
        "snapshot_id": result.snapshot.snapshot_id,
        "snapshot_created": result.snapshot_created,
        "state_plane_source": result.state_plane_source,
        "event_plane_source": result.event_plane_source,
        "cross_validation": result.cross_validation,
        "event_count": len(result.events),
        "delta_count": len(result.pipeline.deltas),
        "finding_count": len(result.pipeline.findings),
        "reconciliation_updates": result.pipeline.reconciliation_updates,
        "incident_count": len({incident.incident_id for incident in result.pipeline.incidents}),
        "category_statuses": [
            status.model_dump(mode="json") for status in result.snapshot.category_statuses
        ],
    }


@router.get("/findings", response_model=list[Finding])
def list_findings(
    host_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    object_key: str | None = Query(default=None, min_length=1, max_length=2048),
    created_after: datetime | None = None,
    category: str | None = Query(default=None, max_length=128),
    session: Session = Depends(db_dependency),
) -> list[Finding]:
    return repository(session).list_findings(
        host_id=host_id,
        limit=limit,
        object_key=object_key,
        created_after=created_after,
        category=category,
    )


@router.get(
    "/findings/{finding_id}/reconciliations",
    response_model=list[ReconciliationResult],
)
def list_finding_reconciliations(
    finding_id: str,
    session: Session = Depends(db_dependency),
) -> list[ReconciliationResult]:
    repo = repository(session)
    finding = repo.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return repo.list_reconciliations(
        finding_id=finding_id,
        delta_id=finding.delta_id,
    )


@router.post("/incidents/correlate-backlog", response_model=list[Incident])
def correlate_incident_backlog(
    limit: int = Query(default=100, ge=1, le=500),
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> list[Incident]:
    return IncidentCorrelationService(settings).correlate_backlog(repository(session), limit=limit)


@router.get("/incidents", response_model=list[Incident])
def list_incidents(
    host_id: str | None = None,
    status: IncidentStatus | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(db_dependency),
) -> list[Incident]:
    return repository(session).list_incidents(
        host_id=host_id,
        status=status.value if status else None,
        limit=limit,
    )


@router.get("/incidents/{incident_id}", response_model=Incident)
def get_incident(
    incident_id: str,
    session: Session = Depends(db_dependency),
) -> Incident:
    incident = repository(session).get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@router.get("/incidents/{incident_id}/findings", response_model=list[Finding])
def get_incident_findings(
    incident_id: str,
    session: Session = Depends(db_dependency),
) -> list[Finding]:
    repo = repository(session)
    if repo.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return repo.list_incident_findings(incident_id)


@router.get(
    "/incidents/{incident_id}/assignments",
    response_model=list[IncidentFindingAssignment],
)
def get_incident_assignments(
    incident_id: str,
    session: Session = Depends(db_dependency),
) -> list[IncidentFindingAssignment]:
    repo = repository(session)
    if repo.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return repo.list_incident_assignments(incident_id)


@router.patch("/incidents/{incident_id}/status", response_model=Incident)
def update_incident_status(
    incident_id: str,
    status: IncidentStatus,
    session: Session = Depends(db_dependency),
) -> Incident:
    repo = repository(session)
    incident = repo.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return repo.save_incident(
        incident.model_copy(
            update={"status": status, "updated_at": datetime.now(UTC)},
        )
    )


@router.get("/findings/{finding_id}/ai-context", response_model=EvidencePackage)
def get_finding_ai_context(
    finding_id: str,
    mode: AIContextMode = AIContextMode.FULL_CONTEXT,
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> EvidencePackage:
    repo = repository(session)
    finding = repo.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    try:
        return IncidentContextBuilder(settings).build_for_finding(repo, finding, mode=mode)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/incidents/{incident_id}/ai-context", response_model=EvidencePackage)
def get_incident_ai_context(
    incident_id: str,
    mode: AIContextMode = AIContextMode.FULL_CONTEXT,
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> EvidencePackage:
    repo = repository(session)
    incident = repo.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    try:
        return IncidentContextBuilder(settings).build_for_incident(repo, incident, mode=mode)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/experiments/runs", response_model=list[ExperimentRun])
def list_experiment_runs(
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(db_dependency),
) -> list[ExperimentRun]:
    return repository(session).list_experiment_runs(limit=limit)


@router.get("/experiments/scenarios", response_model=list[ExperimentScenario])
def list_scenarios(settings: Settings = Depends(settings_dependency)) -> list[ExperimentScenario]:
    scenario_dir = settings.resolve_path(Path("experiments/scenarios"))
    scenarios: list[ExperimentScenario] = []
    for path in sorted(scenario_dir.glob("*.json")):
        with path.open("r", encoding="utf-8") as handle:
            scenarios.append(ExperimentScenario.model_validate(json.load(handle)))
    return scenarios


@router.post("/experiments/actions")
async def execute_experiment_action(
    request: ExperimentActionRequest,
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> dict[str, object]:
    """Execute only allow-listed research operations exposed by the control console."""
    repo = repository(session)
    if request.action == "sync_host":
        if not request.host_id:
            raise HTTPException(status_code=422, detail="host_id is required for sync_host")
        if (
            settings.state_provider == "probe"
            and repo.latest_snapshot_by_source(request.host_id, "direct_probe") is None
        ):
            raise HTTPException(
                status_code=409,
                detail="Run the native Windows probe before synchronizing this host",
            )
        result = await ProviderSyncService(settings).sync_host(repo, request.host_id)
        return {
            "action": request.action,
            "status": "completed",
            "host_id": request.host_id,
            "state_plane_source": result.state_plane_source,
            "event_plane_source": result.event_plane_source,
            "event_count": len(result.events),
            "delta_count": len(result.pipeline.deltas),
            "finding_count": len(result.pipeline.findings),
            "reconciliation_updates": result.pipeline.reconciliation_updates,
            "incident_count": len({incident.incident_id for incident in result.pipeline.incidents}),
        }

    if request.action == "process_backlog":
        result = LivePipelineService(settings).process_backlog(repo)
        return {
            "action": request.action,
            "status": "completed",
            "delta_count": len(result.deltas),
            "finding_count": len(result.findings),
            "reconciliation_updates": result.reconciliation_updates,
            "incident_count": len({incident.incident_id for incident in result.incidents}),
        }

    if request.action == "correlate_backlog":
        incidents = IncidentCorrelationService(settings).correlate_backlog(repo)
        return {
            "action": request.action,
            "status": "completed",
            "incident_count": len(incidents),
            "incident_ids": [incident.incident_id for incident in incidents],
        }

    from experiments.runner.run_scenarios import ROOT, run_all, run_scenario

    results_dir = settings.resolve_path(
        Path("experiments/results/runs/ui") / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    )
    results_dir.mkdir(parents=True, exist_ok=True)
    scenario_root = settings.resolve_path(Path("experiments/scenarios"))
    if request.scenario_id:
        scenario_path = scenario_root / f"{request.scenario_id}.json"
        if not scenario_path.exists():
            raise HTTPException(status_code=404, detail="scenario not found")
        runs = [run_scenario(scenario_path, root=ROOT) for _ in range(request.repetitions)]
    else:
        runs = run_all(root=ROOT, output_dir=results_dir, repetitions=request.repetitions)
    if request.scenario_id:
        from experiments.runner.run_scenarios import write_run_json

        for run in runs:
            write_run_json(run, results_dir)
    for run in runs:
        repo.create_experiment_run(run)
    return {
        "action": request.action,
        "status": "completed",
        "scenario_id": request.scenario_id,
        "repetitions": request.repetitions,
        "run_count": len(runs),
        "success_count": sum(run.success for run in runs),
        "failure_count": sum(not run.success for run in runs),
        "run_ids": [run.run_id for run in runs],
        "results_directory": str(results_dir.relative_to(settings.resolve_path(Path(".")))),
    }


@router.get("/research/ai-review/studies")
def list_ai_review_studies(settings: Settings = Depends(settings_dependency)) -> dict[str, Any]:
    runs_dir = settings.resolve_path(Path("experiments/results/runs"))
    return {
        "studies": [
            _ai_review_summary(study_id, path) for study_id, path in _ai_review_study_dirs(runs_dir)
        ]
    }


@router.get("/research/ai-review/studies/{study_id:path}/drafts/{reviewer_id}")
def get_ai_review_draft(
    study_id: str,
    reviewer_id: str,
    settings: Settings = Depends(settings_dependency),
) -> dict[str, Any]:
    if not _valid_reviewer_id(reviewer_id):
        raise HTTPException(status_code=400, detail="invalid reviewer id")
    runs_dir = settings.resolve_path(Path("experiments/results/runs"))
    study_dir = _ai_review_study_dir(runs_dir, study_id)
    draft_path = study_dir / "human-review" / f"{reviewer_id}.json"
    if not draft_path.exists():
        raise HTTPException(status_code=404, detail="reviewer draft not found")
    return _read_result_file(draft_path, default={})


@router.post("/research/ai-review/studies/{study_id:path}/drafts")
def save_ai_review_draft(
    study_id: str,
    request: AIReviewSaveRequest,
    settings: Settings = Depends(settings_dependency),
) -> dict[str, Any]:
    runs_dir = settings.resolve_path(Path("experiments/results/runs"))
    study_dir = _ai_review_study_dir(runs_dir, study_id)
    packet = _ai_review_packet(study_dir)
    canonical = {item["review_id"]: item for item in packet["items"]}
    incoming = {str(item.get("review_id")): item for item in request.items if item.get("review_id")}
    if set(incoming) != set(canonical):
        raise HTTPException(
            status_code=422,
            detail="review must contain exactly the supplied review items",
        )
    saved_items = []
    for review_id, original in canonical.items():
        scores = incoming[review_id].get("scores") or {}
        clean_scores = {key: scores.get(key) for key in AI_REVIEW_SCORE_KEYS}
        for field in AI_REVIEW_SCORE_FIELDS:
            value = clean_scores[field]
            if value is not None and not _valid_ai_score(value):
                raise HTTPException(
                    status_code=422,
                    detail=f"{field} must be null or a number from 0 to 5",
                )
        unsupported = clean_scores["unsupported_claim_count"]
        if unsupported is not None and (type(unsupported) is not int or unsupported < 0):
            raise HTTPException(
                status_code=422,
                detail="unsupported_claim_count must be a non-negative integer",
            )
        root_correct = clean_scores["root_cause_identification_correct"]
        if root_correct is not None and type(root_correct) is not bool:
            raise HTTPException(
                status_code=422,
                detail="root_cause_identification_correct must be boolean or null",
            )
        saved_items.append({**original, "scores": clean_scores})
    completion = _review_completion(saved_items)
    output_path = study_dir / "human-review" / f"{request.reviewer_id}.json"
    existing = _read_result_file(output_path, default={})
    if isinstance(existing, dict) and existing.get("status") == "SUBMITTED":
        raise HTTPException(
            status_code=409,
            detail="this review has already been submitted and is locked",
        )
    if request.submit and not completion["complete"]:
        raise HTTPException(
            status_code=422,
            detail=(
                f"complete every review item before submitting "
                f"({completion['completed_items']}/{completion['total_items']} complete)"
            ),
        )
    submitted_at = datetime.now(UTC).isoformat() if request.submit else None
    payload = {
        "schema_version": packet["schema_version"],
        "study_id": study_id,
        "reviewer_id": request.reviewer_id,
        "status": "SUBMITTED" if request.submit else "DRAFT",
        "saved_at": datetime.now(UTC).isoformat(),
        "submitted_at": submitted_at,
        "items": saved_items,
    }
    review_dir = study_dir / "human-review"
    review_dir.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_suffix(".json.tmp")
    temporary_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temporary_path.replace(output_path)
    return {
        "status": "submitted" if request.submit else "saved",
        "review_status": payload["status"],
        "study_id": study_id,
        **completion,
    }


@router.post("/research/ai-review/studies/{study_id:path}/aggregate")
def aggregate_ai_review(
    study_id: str,
    request: AIReviewAggregateRequest,
    settings: Settings = Depends(settings_dependency),
) -> dict[str, Any]:
    if not request.confirm_unblind:
        raise HTTPException(
            status_code=400,
            detail="confirm_unblind is required for operator aggregation",
        )
    runs_dir = settings.resolve_path(Path("experiments/results/runs"))
    study_dir = _ai_review_study_dir(runs_dir, study_id)
    key_path = study_dir / "condition-key.private.json"
    if not key_path.exists():
        raise HTTPException(status_code=404, detail="private condition key is not available")
    reviews = []
    if len(set(request.reviewer_ids)) != len(request.reviewer_ids):
        raise HTTPException(status_code=422, detail="reviewer IDs must be unique")
    for reviewer_id in request.reviewer_ids:
        if not _valid_reviewer_id(reviewer_id):
            raise HTTPException(status_code=400, detail="invalid reviewer id")
        path = study_dir / "human-review" / f"{reviewer_id}.json"
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"reviewer draft not found: {reviewer_id}")
        review = _read_result_file(path, default={})
        if not isinstance(review, dict) or review.get("status") != "SUBMITTED":
            raise HTTPException(
                status_code=409,
                detail=f"reviewer has not submitted a complete review: {reviewer_id}",
            )
        completion = _review_completion(review.get("items", []))
        if not completion["complete"]:
            raise HTTPException(
                status_code=409,
                detail=f"reviewer submission is incomplete: {reviewer_id}",
            )
        reviews.append(review)
    from experiments.ai_context_evaluation import aggregate_completed_reviews

    aggregate = aggregate_completed_reviews(reviews, _read_result_file(key_path, default={}))
    aggregate["study_id"] = study_id
    aggregate["reviewer_ids"] = request.reviewer_ids
    output_path = study_dir / "human-review-aggregate.json"
    output_path.write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
    return {"status": "aggregated", "output": "human-review-aggregate.json", "aggregate": aggregate}


@router.get("/research/ai-review/studies/{study_id:path}")
def get_ai_review_study(
    study_id: str,
    settings: Settings = Depends(settings_dependency),
) -> dict[str, Any]:
    runs_dir = settings.resolve_path(Path("experiments/results/runs"))
    study_dir = _ai_review_study_dir(runs_dir, study_id)
    return {
        **_ai_review_summary(study_id, study_dir),
        "packet": _ai_review_packet(study_dir),
        "evidence_dossier": _ai_neutral_evidence_dossier(study_dir),
    }


@router.get("/research/ai-response-review/studies")
def list_ai_response_review_studies(
    settings: Settings = Depends(settings_dependency),
) -> dict[str, Any]:
    runs_dir = settings.resolve_path(Path("experiments/results/runs"))
    return {
        "studies": [
            _ai_response_review_summary(study_id, path)
            for study_id, path in _ai_response_study_dirs(runs_dir)
        ]
    }


@router.get("/research/ai-response-review/studies/{study_id:path}/drafts/{reviewer_id}")
def get_ai_response_review_draft(
    study_id: str,
    reviewer_id: str,
    settings: Settings = Depends(settings_dependency),
) -> dict[str, Any]:
    if not _valid_reviewer_id(reviewer_id):
        raise HTTPException(status_code=400, detail="invalid reviewer id")
    runs_dir = settings.resolve_path(Path("experiments/results/runs"))
    study_dir = _ai_response_study_dir(runs_dir, study_id)
    path = study_dir / "human-review" / f"{reviewer_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="reviewer draft not found")
    return _read_result_file(path, default={})


@router.post("/research/ai-response-review/studies/{study_id:path}/drafts")
def save_ai_response_review_draft(
    study_id: str,
    request: AIResponseReviewSaveRequest,
    settings: Settings = Depends(settings_dependency),
) -> dict[str, Any]:
    from experiments.ai_response_evaluation import ALL_SCORE_FIELDS, validate_scores

    runs_dir = settings.resolve_path(Path("experiments/results/runs"))
    study_dir = _ai_response_study_dir(runs_dir, study_id)
    packet = _ai_response_review_packet(study_dir)
    canonical = {item["review_id"]: item for item in packet["items"]}
    incoming = {str(item.get("review_id")): item for item in request.items if item.get("review_id")}
    if set(incoming) != set(canonical):
        raise HTTPException(
            status_code=422, detail="review must contain exactly the supplied items"
        )

    saved_items = []
    for review_id, original in canonical.items():
        scores = incoming[review_id].get("scores") or {}
        clean_scores = {field: scores.get(field) for field in ALL_SCORE_FIELDS}
        validation_errors = _partial_ai_response_score_errors(clean_scores)
        if validation_errors:
            raise HTTPException(status_code=422, detail=validation_errors[0])
        saved_items.append({**original, "scores": clean_scores})
    completed = sum(not validate_scores(item["scores"]) for item in saved_items)
    is_complete = completed == len(saved_items)
    if request.submit and not is_complete:
        raise HTTPException(
            status_code=422,
            detail=f"complete every score before submitting ({completed}/{len(saved_items)})",
        )
    output = study_dir / "human-review" / f"{request.reviewer_id}.json"
    existing = _read_result_file(output, default={})
    if isinstance(existing, dict) and existing.get("status") == "SUBMITTED":
        raise HTTPException(status_code=409, detail="submitted reviews are locked")
    payload = {
        "schema_version": packet["schema_version"],
        "study_id": study_id,
        "reviewer_id": request.reviewer_id,
        "status": "SUBMITTED" if request.submit else "DRAFT",
        "saved_at": datetime.now(UTC).isoformat(),
        "submitted_at": datetime.now(UTC).isoformat() if request.submit else None,
        "items": saved_items,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temporary.replace(output)
    return {
        "status": payload["status"],
        "completed_items": completed,
        "total_items": len(saved_items),
    }


@router.post("/research/ai-response-review/studies/{study_id:path}/aggregate")
def aggregate_ai_response_reviews(
    study_id: str,
    request: AIResponseReviewAggregateRequest,
    settings: Settings = Depends(settings_dependency),
) -> dict[str, Any]:
    if not request.confirm_unblind:
        raise HTTPException(status_code=400, detail="confirm_unblind is required")
    if len(set(request.reviewer_ids)) != len(request.reviewer_ids):
        raise HTTPException(status_code=422, detail="reviewer IDs must be distinct")
    runs_dir = settings.resolve_path(Path("experiments/results/runs"))
    study_dir = _ai_response_study_dir(runs_dir, study_id)
    key_path = study_dir / "condition-key.private.json"
    if not key_path.is_file():
        raise HTTPException(status_code=404, detail="private condition key is unavailable")
    reviews = []
    from experiments.ai_response_evaluation import validate_scores

    for reviewer_id in request.reviewer_ids:
        if not _valid_reviewer_id(reviewer_id):
            raise HTTPException(status_code=400, detail="invalid reviewer id")
        path = study_dir / "human-review" / f"{reviewer_id}.json"
        review = _read_result_file(path, default={})
        if not isinstance(review, dict) or review.get("status") != "SUBMITTED":
            raise HTTPException(status_code=409, detail=f"reviewer {reviewer_id} has not submitted")
        if any(validate_scores(item.get("scores") or {}) for item in review.get("items", [])):
            raise HTTPException(
                status_code=409, detail=f"reviewer {reviewer_id} has incomplete scores"
            )
        reviews.append(review)
    from experiments.ai_response_evaluation import aggregate_completed_reviews

    try:
        aggregate = aggregate_completed_reviews(reviews, _read_result_file(key_path, default={}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    aggregate["study_id"] = study_id
    aggregate["reviewer_ids"] = request.reviewer_ids
    output = study_dir / "human-review-aggregate.json"
    output.write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
    return {"status": "aggregated", "output": output.name, "aggregate": aggregate}


@router.get("/research/ai-response-review/studies/{study_id:path}")
def get_ai_response_review_study(
    study_id: str,
    settings: Settings = Depends(settings_dependency),
) -> dict[str, Any]:
    runs_dir = settings.resolve_path(Path("experiments/results/runs"))
    study_dir = _ai_response_study_dir(runs_dir, study_id)
    return {
        **_ai_response_review_summary(study_id, study_dir),
        "packet": _ai_response_review_packet(study_dir),
    }


@router.get("/research/results")
def research_results(settings: Settings = Depends(settings_dependency)) -> dict[str, object]:
    results_root = settings.resolve_path(Path("experiments/results"))
    published_dir = results_root / "published"
    runs_dir = results_root / "runs"
    report_path = published_dir / "RESEARCH_RESULTS_DETAILED-20260923.md"
    campaign_path = published_dir / "live-telemetry-campaign-summary-20260923.json"
    freeze_path = published_dir / "research-freeze-20260923.json"
    ai_study_path = runs_dir / "20260923/ai-context-ollama/study.json"
    reviewer_complete_path = (
        runs_dir / "20260923/reviewer-hardening/service-complete-control-v4/run.json"
    )
    reviewer_no_change_path = (
        runs_dir / "20260923/reviewer-hardening/service-no-change-control-v2/run.json"
    )
    reviewer_ai_path = runs_dir / "20260923/reviewer-hardening/ai-context-ollama-v4/study.json"
    reviewer_blinded_path = (
        runs_dir / "20260923/reviewer-hardening/ai-context-ollama-v4/review_items.blinded.json"
    )
    windows_apt_reproduction_path = published_dir / "windows-apt-live-reproduction-20260923.json"
    windows_apt_reproduction_report_path = (
        published_dir / "windows-apt-live-reproduction-20260923.md"
    )
    live_run_paths = [
        runs_dir / "20260923/live-reconciliation/fresh-complete/run.json",
        runs_dir / "20260923/live-reconciliation/fresh-capture-drop/run.json",
    ]
    artifact_names = [
        "README.md",
        "catalog.json",
        "published/RESEARCH_RESULTS_DETAILED-20260923.md",
        "published/live-telemetry-campaign-summary-20260923.json",
        "runs/20260923/live-reconciliation/fresh-complete/run.json",
        "runs/20260923/live-reconciliation/fresh-complete/validation.json",
        "runs/20260923/live-reconciliation/fresh-capture-drop/run.json",
        "runs/20260923/live-reconciliation/fresh-capture-drop/validation.json",
        "runs/20260923/ai-context-ollama/study.json",
        "runs/20260923/reviewer-hardening/service-complete-control/run.json",
        "runs/20260923/reviewer-hardening/service-complete-control/validation.json",
        "runs/20260923/reviewer-hardening/service-complete-control-v4/run.json",
        "runs/20260923/reviewer-hardening/service-complete-control-v4/validation.json",
        "runs/20260923/reviewer-hardening/service-no-change-control/run.json",
        "runs/20260923/reviewer-hardening/service-no-change-control-v2/run.json",
        "runs/20260923/reviewer-hardening/service-no-change-control-v2/validation.json",
        "runs/20260923/reviewer-hardening/ai-context-ollama/study.json",
        "runs/20260923/reviewer-hardening/ai-context-ollama/blinded-review.json",
        "runs/20260923/reviewer-hardening/ai-context-ollama/review_items.blinded.json",
        "runs/20260923/reviewer-hardening/ai-context-ollama-v2/study.json",
        "runs/20260923/reviewer-hardening/ai-context-ollama-v2/review_items.blinded.json",
        "runs/20260923/reviewer-hardening/ai-context-ollama-v2/answer-key.private.json",
        "runs/20260923/reviewer-hardening/ai-context-ollama-v2/condition-key.private.json",
        "runs/20260923/reviewer-hardening/ai-context-ollama-v4/study.json",
        "runs/20260923/reviewer-hardening/ai-context-ollama-v4/review_items.blinded.json",
        "runs/20260923/reviewer-hardening/ai-context-ollama-v4/answer-key.private.json",
        "runs/20260923/reviewer-hardening/ai-context-ollama-v4/condition-key.private.json",
        "runs/20260923/windows-apt-live-reproduction/raw/windows-apt-live-reproduction.json",
        "runs/20260923/windows-apt-live-reproduction/validation.json",
        "published/windows-apt-live-reproduction-20260923.md",
        "published/windows-apt-live-reproduction-20260923.json",
        "published/research-freeze-20260923.json",
    ]
    campaign = _read_result_file(campaign_path, default={})
    campaign["trial_count"] = campaign.get("run_count", 0)
    campaign["conditions"] = []
    return {
        "status": "available",
        "artifact_directory": "experiments/results",
        "published_directory": "experiments/results/published",
        "runs_directory": "experiments/results/runs",
        "artifacts": [
            {"name": name, "available": (results_root / name).exists()} for name in artifact_names
        ],
        "detailed_report": _read_result_file(report_path, default=""),
        "dataset": {},
        "dataset_evaluation": {},
        "campaign": campaign,
        "correlation": {},
        "adversarial_correlation": {},
        "authorization": {},
        "ai_study": _read_result_file(ai_study_path, default={}),
        "reviewer_hardening": {
            "complete_control": _read_result_file(reviewer_complete_path, default={}),
            "no_change_control": _read_result_file(reviewer_no_change_path, default={}),
            "ai_study": _read_result_file(reviewer_ai_path, default={}),
            "blinded_review": _read_result_file(reviewer_blinded_path, default={}),
        },
        "windows_apt_live_reproduction": _read_result_file(
            windows_apt_reproduction_path, default={}
        ),
        "windows_apt_live_reproduction_report": _read_result_file(
            windows_apt_reproduction_report_path, default=""
        ),
        "reconciliation_audit": {},
        "corrected_live_runs": [
            _read_result_file(path, default={}) for path in live_run_paths if path.exists()
        ],
        "freeze": _read_result_file(freeze_path, default={}),
    }


@router.post("/findings/{finding_id}/ai-analysis")
def explain_finding(
    finding_id: str,
    mode: AIContextMode = AIContextMode.FULL_CONTEXT,
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> dict[str, object]:
    repo = repository(session)
    finding = repo.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    try:
        package = IncidentContextBuilder(settings).build_for_finding(repo, finding, mode=mode)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    analysis = AIAnalysisService(settings).explain(package)
    repo.create_ai_analysis(analysis)
    return analysis.model_dump(mode="json")


@router.post("/incidents/{incident_id}/ai-analysis", response_model=AIAnalysisRecord)
def explain_incident(
    incident_id: str,
    mode: AIContextMode = AIContextMode.FULL_CONTEXT,
    settings: Settings = Depends(settings_dependency),
    session: Session = Depends(db_dependency),
) -> AIAnalysisRecord:
    repo = repository(session)
    incident = repo.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    try:
        package = IncidentContextBuilder(settings).build_for_incident(repo, incident, mode=mode)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    analysis = AIAnalysisService(settings).explain(package)
    return repo.create_ai_analysis(analysis)


@router.get("/ai-analyses", response_model=list[AIAnalysisRecord])
def list_ai_analyses(
    finding_id: str | None = None,
    incident_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(db_dependency),
) -> list[AIAnalysisRecord]:
    return repository(session).list_ai_analyses(
        finding_id=finding_id,
        incident_id=incident_id,
        limit=limit,
    )
