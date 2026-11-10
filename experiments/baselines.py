"""Explicit target/time baselines; never infer ground truth from detector output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from csg.domain.models import Finding, NormalizedEvent, TimeWindow

EVENT_TYPES = {
    ("service", "ADD"): "service_created",
    ("service", "MODIFY"): "service_modified",
    ("scheduled_task", "ADD"): "scheduled_task_created",
    ("scheduled_task", "MODIFY"): "scheduled_task_modified",
    ("privileged_group", "ADD"): "privileged_group_member_added",
    ("registry", "ADD"): "registry_value_modified",
    ("registry", "MODIFY"): "registry_value_modified",
    ("listener", "ADD"): "listener_created",
    ("process", "ADD"): "process_start",
}


def matching_events(events, *, host_id, object_key, window, event_types):
    return [
        event
        for event in events
        if event.host_id == host_id
        and event.target.get("key") == object_key
        and window.start <= event.event_time <= window.end
        and event.normalized_type in event_types
    ]


def fixture_event_detection(events, expected_deltas, *, host_id, window):
    return any(
        matching_events(
            events,
            host_id=host_id,
            object_key=expected["object_key"],
            window=window,
            event_types={EVENT_TYPES.get((expected["category"], expected["delta_type"]))},
        )
        for expected in expected_deltas
    )


class Trial(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trial_id: str = Field(min_length=1)
    host_id: str = Field(min_length=1)
    object_key: str = Field(min_length=1)
    window: TimeWindow
    positive: StrictBool
    event_types: list[str] = Field(min_length=1)
    condition: str


def confusion_metrics(labels: list[bool], predictions: list[bool]) -> dict:
    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must have equal length")
    counts = {key: 0 for key in ("tp", "fp", "fn", "tn")}
    for label, prediction in zip(labels, predictions, strict=True):
        counts[("tp" if prediction else "fn") if label else ("fp" if prediction else "tn")] += 1
    tp, fp, fn, tn = (counts[key] for key in ("tp", "fp", "fn", "tn"))

    def rate(n, d):
        return n / d if d else None

    return {
        **counts,
        "n": len(labels),
        "precision": rate(tp, tp + fp),
        "recall": rate(tp, tp + fn),
        "false_positive_rate": rate(fp, fp + tn),
        "specificity": rate(tn, tn + fp),
        "accuracy": rate(tp + tn, len(labels)),
    }


def evaluate_trials(
    trials: list[Trial],
    events: list[NormalizedEvent],
    findings: list[Finding],
    *,
    wazuh_rule_ids: set[str],
    wazuh_min_level: int = 7,
    csg_min_risk: float = 40,
) -> dict:
    if len({trial.trial_id for trial in trials}) != len(trials):
        raise ValueError("duplicate trial IDs")
    if not wazuh_rule_ids:
        raise ValueError("pre-register nonempty Wazuh rule IDs")
    if not 0 <= wazuh_min_level <= 16 or not 0 <= csg_min_risk <= 100:
        raise ValueError("invalid detector thresholds")
    # Overlapping same-target windows would count one signal in multiple trials.
    for i, left in enumerate(trials):
        for right in trials[i + 1 :]:
            if (left.host_id, left.object_key) == (right.host_id, right.object_key) and (
                max(left.window.start, right.window.start) <= min(left.window.end, right.window.end)
            ):
                raise ValueError("overlapping same-target trial windows")
    rows = []
    for trial in trials:
        matched = matching_events(
            events,
            host_id=trial.host_id,
            object_key=trial.object_key,
            window=trial.window,
            event_types=set(trial.event_types),
        )
        wazuh = [
            event
            for event in matched
            if event.source == "wazuh"
            and not event.synthetic
            and str(event.metadata.get("rule", {}).get("id")) in wazuh_rule_ids
            and int(event.metadata.get("rule", {}).get("level", 0)) >= wazuh_min_level
        ]
        csg = [
            finding
            for finding in findings
            if finding.host_id == trial.host_id
            and finding.object_key == trial.object_key
            and trial.window.start <= finding.created_at <= trial.window.end
            and finding.risk.total >= csg_min_risk
        ]
        rows.append(
            {
                "trial_id": trial.trial_id,
                "condition": trial.condition,
                "positive": trial.positive,
                "event_only": bool(matched),
                "wazuh": bool(wazuh),
                "csg": bool(csg),
                "event_ids": sorted({e.event_id for e in matched}),
                "wazuh_event_ids": sorted({e.event_id for e in wazuh}),
                "finding_ids": sorted({f.finding_id for f in csg}),
            }
        )
    return {
        "schema_version": "csg-baseline-comparison-v1",
        "trials": rows,
        "configuration": {
            "wazuh_rule_ids": sorted(wazuh_rule_ids),
            "wazuh_min_level": wazuh_min_level,
            "csg_min_risk": csg_min_risk,
        },
        "metrics": {
            detector: confusion_metrics([r["positive"] for r in rows], [r[detector] for r in rows])
            for detector in ("event_only", "wazuh", "csg")
        },
        "warning": "Window-level signals, not proof of causation. Wazuh results cover only the "
        "specified rules and supplied normalized alert export, not all Wazuh capabilities.",
    }


def main():
    parser = argparse.ArgumentParser(description="Score labeled trials against exported evidence")
    parser.add_argument("trials", type=Path, help="JSON array of independent Trial labels")
    parser.add_argument("bundle", type=Path, help="Live export with events and findings arrays")
    parser.add_argument("--wazuh-rule-id", action="append", required=True)
    parser.add_argument("--wazuh-min-level", type=int, default=7)
    parser.add_argument("--csg-min-risk", type=float, default=40)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bundle = json.loads(args.bundle.read_text())
    result = evaluate_trials(
        [Trial.model_validate(row) for row in json.loads(args.trials.read_text())],
        [NormalizedEvent.model_validate(row) for row in bundle["events"]],
        [Finding.model_validate(row) for row in bundle["findings"]],
        wazuh_rule_ids=set(args.wazuh_rule_id),
        wazuh_min_level=args.wazuh_min_level,
        csg_min_risk=args.csg_min_risk,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
