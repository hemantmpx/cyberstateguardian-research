"""Compare registered methods on the same trial evidence and preserve assignment denominators.

Input is a JSON object with ``campaign_id``, ``config``, ``assignments``, and ``observations``.
Ground-truth labels live in each observation and are used only after method predictions are built.
For exact alert/archive deduplication, provide an adjudicated ``occurrence_id`` derived from the
original computer/channel/record identity; otherwise each evidence document remains distinct.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import UTC, datetime, timedelta
from itertools import combinations
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

METHODS = (
    "configured_wazuh_alert_fim",
    "raw_event_only",
    "native_probe_only",
    "strong_identity_matcher",
    "loose_host_type_time_matcher",
    "full_csg",
)
ALERT_KINDS = {"alert", "wazuh_alert"}
FIM_KINDS = {"fim", "fim_alert", "wazuh_fim"}
Z95 = 1.959963984540054


class ComparisonConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    wazuh_alert_rule_ids: list[str] = Field(default_factory=list)
    wazuh_fim_rule_ids: list[str] = Field(default_factory=list)


class Assignment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trial_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    family: str = Field(min_length=1)
    condition: str = Field(min_length=1)
    status: str = Field(min_length=1)
    target_changed: StrictBool


class EventRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    occurrence_id: str | None = None
    host_id: str = Field(min_length=1)
    object_key: str | None = None
    normalized_type: str = Field(min_length=1)
    source: str = Field(min_length=1)
    source_kind: str = Field(min_length=1)
    event_time: datetime
    first_observed_at: datetime
    rule_id: str | None = None
    source_document_id: str | None = None
    synthetic: StrictBool = False

    @field_validator("event_time", "first_observed_at")
    @classmethod
    def require_aware_timestamps(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event and first-observed timestamps must include a timezone")
        return value.astimezone(UTC)


class CSGDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(min_length=1)
    finalized: StrictBool
    finding_present: StrictBool
    matched_event_ids: list[str] = Field(default_factory=list)
    source_coverage_status: str | None = None


class TrialObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trial_id: str = Field(min_length=1)
    host_id: str = Field(min_length=1)
    target_object_key: str = Field(min_length=1)
    expected_event_types: list[str] = Field(min_length=1)
    window_start: datetime
    window_end: datetime
    cutoff_at: datetime
    time_tolerance_seconds: int = Field(ge=0, le=86_400)
    event_query_complete: StrictBool
    action_verified: StrictBool | None = None
    condition_attained: StrictBool | None = None
    cleanup_verified: StrictBool | None = None
    state_observed: StrictBool | None = None
    expected_reconciliation_status: str | None = None
    truth_supporting_occurrence_ids: list[str] = Field(default_factory=list)
    events: list[EventRecord] = Field(default_factory=list)
    full_csg: CSGDecision | None = None

    @field_validator("window_start", "window_end", "cutoff_at")
    @classmethod
    def require_aware_trial_timestamps(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("trial timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def check_window_and_event_ids(self) -> TrialObservation:
        if self.window_start > self.window_end:
            raise ValueError("window_start must be no later than window_end")
        event_ids = [event.event_id for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("event_id must be unique within a trial observation")
        return self


class CampaignInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    campaign_id: str = Field(min_length=1)
    config: ComparisonConfig
    assignments: list[Assignment] = Field(min_length=1)
    observations: list[TrialObservation] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_trial_accounting(self) -> CampaignInput:
        assigned = [row.trial_id for row in self.assignments]
        observed = [row.trial_id for row in self.observations]
        if len(assigned) != len(set(assigned)):
            raise ValueError("duplicate assignment trial_id")
        if len(observed) != len(set(observed)):
            raise ValueError("duplicate observation trial_id")
        unknown = sorted(set(observed) - set(assigned))
        if unknown:
            raise ValueError(f"observations have no assignment: {unknown}")
        if not (self.config.wazuh_alert_rule_ids or self.config.wazuh_fim_rule_ids):
            raise ValueError("pre-register at least one Wazuh alert or FIM rule ID")
        return self


def _occurrence_id(event: EventRecord) -> str:
    # Do not merge alert/archive copies unless their original source occurrence was adjudicated.
    return event.occurrence_id or f"document:{event.event_id}"


def _event_visible_by_cutoff(event: EventRecord, observation: TrialObservation) -> bool:
    return event.first_observed_at <= observation.cutoff_at


def _event_in_window(event: EventRecord, observation: TrialObservation) -> bool:
    start = observation.window_start - timedelta(seconds=observation.time_tolerance_seconds)
    end = observation.window_end + timedelta(seconds=observation.time_tolerance_seconds)
    return start <= event.event_time <= end


def _common_events(observation: TrialObservation) -> list[EventRecord]:
    return [
        event
        for event in observation.events
        if event.source.casefold() == "wazuh"
        and not event.synthetic
        and event.host_id == observation.host_id
        and _event_in_window(event, observation)
        and _event_visible_by_cutoff(event, observation)
    ]


def _predict_methods(
    observation: TrialObservation, config: ComparisonConfig
) -> dict[str, dict[str, Any]]:
    events = _common_events(observation)
    expected_types = set(observation.expected_event_types)
    object_key = observation.target_object_key.casefold()

    def exact_identity(event: EventRecord) -> bool:
        return (event.object_key or "").casefold() == object_key

    def typed(event: EventRecord) -> bool:
        return event.normalized_type in expected_types

    alert_rules = set(config.wazuh_alert_rule_ids)
    fim_rules = set(config.wazuh_fim_rule_ids)
    configured_alerts = [
        event
        for event in events
        if (
            event.source_kind.casefold() in ALERT_KINDS and event.rule_id in alert_rules
            and event.source_document_id
        )
        or (
            event.source_kind.casefold() in FIM_KINDS
            and event.rule_id in fim_rules
            and event.source_document_id
        )
    ]
    exact_alerts = [event for event in configured_alerts if exact_identity(event) and typed(event)]
    raw_exact_object = [event for event in events if exact_identity(event)]
    strong = [event for event in raw_exact_object if typed(event)]
    loose = [event for event in events if typed(event)]

    def ids(rows: list[EventRecord]) -> list[str]:
        return sorted({event.event_id for event in rows})

    predicted = {
        "configured_wazuh_alert_fim": ids(exact_alerts),
        "raw_event_only": ids(raw_exact_object),
        "native_probe_only": [],
        "strong_identity_matcher": ids(strong),
        "loose_host_type_time_matcher": ids(loose),
        "full_csg": list(observation.full_csg.matched_event_ids)
        if observation.full_csg
        else [],
    }
    result: dict[str, dict[str, Any]] = {}
    by_id = {event.event_id: event for event in observation.events}
    for method, event_ids in predicted.items():
        selected = [by_id[event_id] for event_id in event_ids if event_id in by_id]
        if method == "native_probe_only":
            signal = observation.state_observed
        elif method == "full_csg":
            signal = observation.full_csg.finding_present if observation.full_csg else None
        else:
            signal = bool(event_ids)
        if method == "full_csg":
            asserted = bool(
                observation.full_csg
                and (
                    observation.full_csg.status == "CONSISTENT"
                    or observation.full_csg.matched_event_ids
                )
            )
        elif method == "native_probe_only":
            asserted = None
        else:
            asserted = bool(event_ids)
        if method == "native_probe_only":
            available = []
        elif method == "configured_wazuh_alert_fim":
            available = configured_alerts
        elif method == "raw_event_only":
            available = raw_exact_object
        elif method == "strong_identity_matcher":
            available = strong
        elif method == "loose_host_type_time_matcher":
            available = loose
        else:
            available = events
        result[method] = {
            "selected_event_ids": sorted(set(event_ids)),
            "unresolved_event_ids": sorted(set(event_ids) - set(by_id)),
            "selected_occurrence_ids": sorted({_occurrence_id(event) for event in selected})
            + [f"unresolved:{event_id}" for event_id in sorted(set(event_ids) - set(by_id))],
            "available_event_ids": sorted({event.event_id for event in available}),
            "available_occurrence_ids": sorted({_occurrence_id(event) for event in available}),
            "target_change_signal": signal,
            "asserted_target_corroboration": asserted,
            "unscoped_alert_ids": sorted(
                event.event_id
                for event in configured_alerts
                if event.object_key is None and event.event_id not in event_ids
            )
            if method == "configured_wazuh_alert_fim"
            else [],
        }
    return result


def _rate(successes: int, denominator: int) -> dict[str, Any]:
    if denominator == 0:
        return {"successes": successes, "denominator": 0, "estimate": None, "wilson_95": None}
    estimate = successes / denominator
    z2 = Z95 * Z95
    scale = 1 + z2 / denominator
    center = (estimate + z2 / (2 * denominator)) / scale
    margin = Z95 * math.sqrt(
        estimate * (1 - estimate) / denominator + z2 / (4 * denominator**2)
    ) / scale
    return {
        "successes": successes,
        "denominator": denominator,
        "estimate": estimate,
        "wilson_95": [max(0.0, center - margin), min(1.0, center + margin)],
    }


def _score_method(
    method: str,
    prediction: dict[str, Any],
    assignment: Assignment,
    observation: TrialObservation,
) -> dict[str, Any]:
    truth = set(observation.truth_supporting_occurrence_ids)
    selected = set(prediction["selected_occurrence_ids"])
    available = set(prediction["available_occurrence_ids"])
    available_truth = truth & available
    linked_truth = truth & selected
    base_eligible = observation.action_verified is True and observation.condition_attained is True
    event_method = method != "native_probe_only"
    if method in {"native_probe_only", "full_csg"}:
        query_eligible = True
    else:
        query_eligible = (
            observation.event_query_complete or prediction["target_change_signal"] is True
        )
    target_eligible = (
        base_eligible
        and query_eligible
        and prediction["target_change_signal"] is not None
    )
    link_eligible = (
        base_eligible
        and observation.event_query_complete
        and event_method
        and (method != "full_csg" or observation.full_csg is not None)
    )
    signal = prediction["target_change_signal"]
    target_correct = (
        signal == assignment.target_changed if target_eligible and signal is not None else None
    )
    asserted = prediction["asserted_target_corroboration"]
    false_corroboration = (
        bool(asserted) and not linked_truth if link_eligible and asserted is not None else None
    )
    status_correct = None
    pending = None
    if method == "full_csg" and observation.full_csg is not None:
        decision = observation.full_csg
        pending = not decision.finalized or decision.status.startswith("PENDING")
        if (
            observation.event_query_complete
            and observation.expected_reconciliation_status is not None
            and decision.finalized
        ):
            status_correct = decision.status == observation.expected_reconciliation_status
    selected_count = len(selected)
    correct_count = len(linked_truth)
    return {
        "trial_id": assignment.trial_id,
        "session_id": assignment.session_id,
        "family": assignment.family,
        "condition": assignment.condition,
        "method": method,
        "target_change_signal": signal,
        "target_change_detection_correct": target_correct,
        "target_outcome_evaluable": target_eligible,
        "event_query_complete": observation.event_query_complete,
        "action_verified": observation.action_verified,
        "condition_attained": observation.condition_attained,
        "cleanup_verified": observation.cleanup_verified,
        "selected_event_ids": prediction["selected_event_ids"],
        "selected_occurrence_ids": sorted(selected),
        "unresolved_event_ids": prediction["unresolved_event_ids"],
        "unscoped_alert_ids": prediction["unscoped_alert_ids"],
        "asserted_target_corroboration": asserted,
        "link_task_evaluable": link_eligible,
        "supporting_occurrences_available": sorted(available_truth) if link_eligible else [],
        "correct_supporting_occurrences_linked": sorted(linked_truth) if link_eligible else [],
        "link_precision": (
            correct_count / selected_count if link_eligible and selected_count else None
        ),
        "link_recall": len(linked_truth) / len(available_truth)
        if link_eligible and observation.event_query_complete and available_truth
        else None,
        "false_corroboration": false_corroboration,
        "complete_evidence_missed": (
            not linked_truth if link_eligible and available_truth else None
        ),
        "reconciliation_status": observation.full_csg.status
        if method == "full_csg" and observation.full_csg
        else None,
        "reconciliation_status_correct": status_correct,
        "pending_at_cutoff": pending,
    }


def _paired_comparisons(outcomes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_trial: dict[str, dict[str, dict[str, Any]]] = {}
    for row in outcomes:
        by_trial.setdefault(row["trial_id"], {})[row["method"]] = row
    scopes: dict[tuple[str, str | None, str | None, str | None], set[str]] = {
        ("all", None, None, None): set(by_trial)
    }
    for trial_id, method_rows in by_trial.items():
        sample = next(iter(method_rows.values()))
        scopes.setdefault(
            ("family_condition", sample["family"], sample["condition"], None), set()
        ).add(trial_id)
        scopes.setdefault(
            ("session", sample["family"], sample["condition"], sample["session_id"]), set()
        ).add(trial_id)

    comparisons = []
    for (scope, family, condition, session_id), trial_ids in sorted(
        scopes.items(), key=lambda item: tuple(value or "" for value in item[0])
    ):
        for left, right in combinations(METHODS, 2):
            pairs = [
                (by_trial[trial_id][left], by_trial[trial_id][right])
                for trial_id in sorted(trial_ids)
                if left in by_trial[trial_id] and right in by_trial[trial_id]
            ]
            target_pairs = [
                (a, b)
                for a, b in pairs
                if a["target_change_detection_correct"] is not None
                and b["target_change_detection_correct"] is not None
            ]
            link_pairs = [
                (a, b)
                for a, b in pairs
                if a["false_corroboration"] is not None
                and b["false_corroboration"] is not None
            ]
            # These are descriptive paired counts, not an independent-trial significance test.
            comparisons.append(
                {
                    "scope": scope,
                    "family": family,
                    "condition": condition,
                    "session_id": session_id,
                    "method_a": left,
                    "method_b": right,
                    "target_outcome_pairs": len(target_pairs),
                    "a_correct_b_incorrect": sum(
                        a["target_change_detection_correct"] is True
                        and b["target_change_detection_correct"] is False
                        for a, b in target_pairs
                    ),
                    "a_incorrect_b_correct": sum(
                        a["target_change_detection_correct"] is False
                        and b["target_change_detection_correct"] is True
                        for a, b in target_pairs
                    ),
                    "false_corroboration_pairs": len(link_pairs),
                    "a_false_b_not_false": sum(
                        a["false_corroboration"] is True
                        and b["false_corroboration"] is False
                        for a, b in link_pairs
                    ),
                    "a_not_false_b_false": sum(
                        a["false_corroboration"] is False
                        and b["false_corroboration"] is True
                        for a, b in link_pairs
                    ),
                    "warning": "Descriptive paired outcomes; not a significance test.",
                }
            )
    return comparisons


def evaluate_campaign(campaign: CampaignInput) -> dict[str, Any]:
    assignments = {row.trial_id: row for row in campaign.assignments}
    observations = {row.trial_id: row for row in campaign.observations}
    ledger: list[dict[str, Any]] = []
    outcomes: list[dict[str, Any]] = []
    for assignment in campaign.assignments:
        observation = observations.get(assignment.trial_id)
        if observation is None:
            ledger.append(
                {
                    **assignment.model_dump(mode="json"),
                    "artifact_present": False,
                    "action_verified": None,
                    "condition_attained": None,
                    "cleanup_verified": None,
                    "outcome_status": "MISSING_OBSERVATION",
                }
            )
            continue
        ledger.append(
            {
                **assignment.model_dump(mode="json"),
                "artifact_present": True,
                "action_verified": observation.action_verified,
                "condition_attained": observation.condition_attained,
                "cleanup_verified": observation.cleanup_verified,
                "event_query_complete": observation.event_query_complete,
                "outcome_status": "OBSERVED",
            }
        )
        predictions = _predict_methods(observation, campaign.config)
        outcomes.extend(
            _score_method(method, predictions[method], assignment, observation)
            for method in METHODS
        )

    groups = {
        (assignment.family, assignment.condition, None)
        for assignment in campaign.assignments
    }
    groups.update(
        (assignment.family, assignment.condition, assignment.session_id)
        for assignment in campaign.assignments
    )
    summaries = []
    for family, condition, session_id in sorted(
        groups, key=lambda item: (item[0], item[1], item[2] or "")
    ):
        group_assignments = [
            assignment
            for assignment in campaign.assignments
            if assignment.family == family
            and assignment.condition == condition
            and (session_id is None or assignment.session_id == session_id)
        ]
        group_trial_ids = {assignment.trial_id for assignment in group_assignments}
        rows = [row for row in outcomes if row["trial_id"] in group_trial_ids]
        for method in METHODS:
            method_rows = [row for row in rows if row["method"] == method]
            evaluated = [
                row
                for row in method_rows
                if row["target_change_detection_correct"] is not None
            ]
            link_rows = [row for row in method_rows if row["link_task_evaluable"]]
            corroboration_rows = [
                row for row in link_rows if row["false_corroboration"] is not None
            ]
            summary = {
                "family": family,
                "condition": condition,
                "session_id": session_id,
                "method": method,
                "assigned": len(group_assignments),
                "observations_found": len({row["trial_id"] for row in method_rows}),
                "missing_observations": len(group_assignments)
                - len({row["trial_id"] for row in method_rows}),
                "action_verified": sum(row["action_verified"] is True for row in method_rows),
                "condition_attained": sum(row["condition_attained"] is True for row in method_rows),
                "cleanup_verified": sum(row["cleanup_verified"] is True for row in method_rows),
                "target_detection_correct": _rate(
                    sum(row["target_change_detection_correct"] is True for row in evaluated),
                    len(evaluated),
                ),
                "no_change_false_target_findings": _rate(
                    sum(
                        row["target_change_signal"] is True
                        for row in evaluated
                        if not assignments[row["trial_id"]].target_changed
                    ),
                    sum(not assignments[row["trial_id"]].target_changed for row in evaluated),
                ),
                "link_precision_counts": {
                    "correct_occurrences": sum(
                        len(row["correct_supporting_occurrences_linked"]) for row in link_rows
                    ),
                    "selected_occurrences": sum(
                        len(row["selected_occurrence_ids"]) for row in link_rows
                    ),
                },
                "link_recall_counts": {
                    "correct_occurrences": sum(
                        len(row["correct_supporting_occurrences_linked"]) for row in link_rows
                    ),
                    "available_supporting_occurrences": sum(
                        len(row["supporting_occurrences_available"]) for row in link_rows
                    ),
                },
                "false_corroboration": _rate(
                    sum(row["false_corroboration"] is True for row in corroboration_rows),
                    len(corroboration_rows),
                ),
                "complete_evidence_missed": _rate(
                    sum(row["complete_evidence_missed"] is True for row in link_rows),
                    sum(row["complete_evidence_missed"] is not None for row in link_rows),
                ),
                "correct_reconciliation_status": _rate(
                    sum(row["reconciliation_status_correct"] is True for row in method_rows),
                    sum(row["reconciliation_status_correct"] is not None for row in method_rows),
                ),
                "pending_at_cutoff": sum(row["pending_at_cutoff"] is True for row in method_rows),
            }
            summaries.append(summary)

    reused_ids: dict[str, list[str]] = {}
    for observation in campaign.observations:
        for event in observation.events:
            reused_ids.setdefault(event.event_id, []).append(observation.trial_id)
    reused_ids = {
        event_id: sorted(trial_ids)
        for event_id, trial_ids in reused_ids.items()
        if len(set(trial_ids)) > 1
    }
    return {
        "schema_version": "csg-reconciliation-method-comparison-v1",
        "campaign_id": campaign.campaign_id,
        "assignment_count": len(campaign.assignments),
        "observations_found": len(campaign.observations),
        "missing_observation_count": len(campaign.assignments) - len(campaign.observations),
        "configuration": campaign.config.model_dump(mode="json"),
        "methods": list(METHODS),
        "method_summaries": summaries,
        "paired_target_outcome_comparisons": _paired_comparisons(outcomes),
        "reused_event_ids_across_trials": reused_ids,
        "interpretation_limits": [
            "Predictions are built before private ground-truth labels are scored.",
            "Trials are paired by trial ID; method rows are not independent samples.",
            "Unresolved alert/archive equivalence is not merged; supply occurrence_id only when "
            "original source identity proves equivalence.",
            "The loose host/type/time method is an intentionally weak ablation, not a Wazuh "
            "product baseline.",
            "The evaluator does not establish malicious intent or cross-host generalization.",
            "A completed query is required before absence is interpreted; event_time is distinct "
            "from first_observed_at.",
        ],
        "trial_ledger": ledger,
        "method_outcomes": outcomes,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    content = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    path.write_text(content, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Compare registered methods on common trial evidence without losing assignments."
        )
    )
    parser.add_argument(
        "campaign",
        type=Path,
        help="Canonical campaign JSON with assignments and observations",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    payload = json.loads(args.campaign.read_text(encoding="utf-8"))
    campaign = CampaignInput.model_validate(payload)
    result = evaluate_campaign(campaign)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "trial-ledger.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in result.pop("trial_ledger")),
        encoding="utf-8",
    )
    (args.output_dir / "method-outcomes.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in result.pop("method_outcomes")),
        encoding="utf-8",
    )
    result["input_sha256"] = _sha256(args.campaign)
    result["analysis_script_sha256"] = _sha256(Path(__file__))
    (args.output_dir / "aggregate.json").write_text(
        json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
