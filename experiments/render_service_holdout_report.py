"""Render an auditable Markdown report from a frozen service holdout."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

Json = dict[str, Any]


def _load(path: Path) -> Json:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _rate(metric: Json) -> str:
    lo, hi = metric["ci95"]
    return f"{metric['successes']}/{metric['total']} ({metric['rate']:.0%}; {lo:.1%}-{hi:.1%})"


def _ids(values: list[str]) -> str:
    return ", ".join(f"`{value}`" for value in values) or "-"


def _trial_row(trial: Json, raw: Json) -> str:
    condition = trial["condition"]
    deltas = trial["target_delta_counts"]
    add = trial["transition_reconciliation"]["ADD"]
    modify = trial["transition_reconciliation"]["MODIFY"]
    local = trial["local_windows_source_events"]
    if condition == "complete":
        detail = (
            f"ADD {add['status']} {_ids(add['exact_evidence_ids'])}; "
            f"MODIFY {modify['status']} {_ids(modify['exact_evidence_ids'])}; "
            f"System 7045/7040 {','.join(local['service_created_7045_record_ids'])}/"
            f"{','.join(local['service_modified_7040_record_ids'])}"
        )
    elif condition == "same_host_distractor":
        bounded = trial["bounded_distractor"]
        detail = (
            f"bounded ADD {bounded['target_add_status']} (no target citation); "
            f"wrong-object event {_ids(bounded['wrong_object_event_ids'])}; "
            f"later MODIFY {modify['status']} {_ids(modify['exact_evidence_ids'])}"
        )
    else:
        control = trial["no_change_control"]
        unchanged = (
            control["attributes_unchanged"] and control["independent_os_attributes_unchanged"]
        )
        detail = (
            f"unchanged={unchanged}; "
            f"new deltas={control['new_delta_count']}; findings={control['new_finding_count']}"
        )
    failed = trial["legacy_validator_failed_checks"]
    legacy = ",".join(failed) or "pass"
    state_seconds = trial["timing"].get("state_detection_seconds")
    state_seconds_text = f"{state_seconds:.2f}" if state_seconds is not None else "-"
    return (
        f"| {condition} | `{trial['trial_id']}` | `{raw.get('service_name', '-')}` | "
        f"{deltas['ADD']}/{deltas['MODIFY']} | {detail} | "
        f"{state_seconds_text} | "
        f"{legacy} |"
    )


def render(campaign: Path, analysis_path: Path, protocol_path: Path) -> str:
    analysis = _load(analysis_path)
    manifest = _load(campaign / "campaign-manifest.json")
    protocol_hash = hashlib.sha256(protocol_path.read_bytes()).hexdigest()
    if protocol_hash != analysis["protocol_sha256"] or protocol_hash != manifest["protocol_sha256"]:
        raise ValueError("Protocol SHA-256 does not match the analyzer and campaign manifest")
    rows: list[str] = []
    trials_by_condition: dict[str, list[Json]] = {}
    for trial in analysis["trials"]:
        trials_by_condition.setdefault(trial["condition"], []).append(trial)
    for condition in ("complete", "same_host_distractor", "no_change"):
        for trial in sorted(
            trials_by_condition.get(condition, []), key=lambda item: item["trial_id"]
        ):
            raw_path = campaign / trial["trial_id"] / "run.json"
            rows.append(_trial_row(trial, _load(raw_path)))

    complete_trials = trials_by_condition["complete"]
    state_detection = sorted(
        trial["timing"]["state_detection_seconds"]
        for trial in complete_trials
        if trial["timing"].get("state_detection_seconds") is not None
    )
    event_offsets = sorted(
        trial["timing"]["event_occurrence_offset_from_action_end_seconds"]
        for trial in complete_trials
        if trial["timing"].get("event_occurrence_offset_from_action_end_seconds") is not None
    )
    multi_index_copies = [
        trial["trial_id"]
        for trial in complete_trials
        if any(
            transition["evidence_record_count"] > transition["unique_event_occurrence_count"]
            for transition in trial["transition_reconciliation"].values()
        )
    ]

    metrics = []
    for condition in ("complete", "same_host_distractor", "no_change"):
        condition_analysis = analysis["conditions"][condition]
        metric = condition_analysis["metrics"]["protocol_trial_pass"]
        metrics.append(f"| `{condition}` | {metric['total']} | {_rate(metric)} |")

    add_metric = analysis["conditions"]["complete"]["metrics"][
        "csg_exact_consistent_add_and_modify"
    ]
    distractor_metric = analysis["conditions"]["same_host_distractor"]["metrics"][
        "distractor_false_consistent"
    ]
    nochange_metric = analysis["conditions"]["no_change"]["metrics"][
        "no_change_false_delta_or_finding"
    ]
    alert_add = analysis["conditions"]["complete"]["metrics"]["add_has_wazuh_alert_exact_record"]
    alert_modify = analysis["conditions"]["complete"]["metrics"][
        "modify_has_wazuh_alert_exact_record"
    ]
    archive_add = analysis["conditions"]["complete"]["metrics"][
        "add_has_wazuh_archive_exact_record"
    ]
    archive_modify = analysis["conditions"]["complete"]["metrics"][
        "modify_has_wazuh_archive_exact_record"
    ]

    def range_text(values: list[float]) -> str:
        return f"{values[0]:.3f}-{values[-1]:.3f} s" if values else "not available"

    assigned = len(manifest["runs"])
    completed = sum(item.get("status") == "COMPLETED" for item in manifest["runs"])
    failed = sum(item.get("status") == "FAILED" for item in manifest["runs"])

    return f"""# Service Reconciliation Confirmatory Holdout v3: Results

**Campaign:** `{analysis["campaign_id"]}`  
**Execution status:** {manifest["status"]}; {assigned} assigned, {completed} completed,
{failed} failed  
**Protocol:** [PROTOCOL.md](PROTOCOL.md), SHA-256 `{protocol_hash}`  
**Machine analysis:** [analysis.json](analysis.json)  
**Raw endpoint campaign:** [windows-campaign](windows-campaign/)  
**Analysis implementation:** `experiments/analyze_service_reconciliation_holdout.py`  

## Result In Brief

All 30 assigned trials have raw artifacts: 10 complete, 10 same-host wrong-object distractor,
and 10 no-change controls. The frozen holdout scorer classifies all 30/30 as protocol passes.
Across complete trials, CSG produced one target ADD and one target MODIFY delta and finalized
both as `CONSISTENT` with exact target Wazuh event IDs in 10/10 trials. Across distractor trials,
the bounded target ADD was finalized `UNEXPLAINED` without citing the deliberately indexed
same-host, same-type event for another service in 10/10; none was falsely `CONSISTENT`. The
no-change control produced no target transition finding in 10/10.

This supports a narrow mechanism claim: under this one Windows 11 ARM64 VM and one Wazuh
deployment, exact host/type/object reconciliation distinguished the controlled target service
from a same-host service distractor, while the native probe observed the controlled state change.
It does **not** establish malicious-activity detection, improved attack detection, generalization
to other hosts, or production efficacy.

## Outcomes

| Condition | Assigned | Protocol passes, two-sided 95% Wilson interval |
|---|---:|---:|
{chr(10).join(metrics)}

| Endpoint outcome | Result, two-sided 95% Wilson interval |
|---|---:|
| Complete: ADD and MODIFY exact CSG-to-Wazuh linkage | {_rate(add_metric)} |
| Complete: exact ADD present in Wazuh alert index | {_rate(alert_add)} |
| Complete: exact MODIFY present in Wazuh alert index | {_rate(alert_modify)} |
| Complete: exact ADD present in Wazuh archive index | {_rate(archive_add)} |
| Complete: exact MODIFY present in Wazuh archive index | {_rate(archive_modify)} |
| Distractor: false `CONSISTENT` for target ADD | {_rate(distractor_metric)} |
| No-change: false target delta/finding | {_rate(nochange_metric)} |

The 95% intervals are exact descriptions of binomial uncertainty for these small trial counts; they
are not between-host population estimates. For 10/10 and 0/10, the interval remains wide
(approximately 72.2%-100% and 0%-27.8%, respectively).

## Trial Audit Table

`ADD/MODIFY` counts are target-object CSG deltas. `state seconds` is action-to-response time for a
manually triggered one-shot probe, not autonomous or steady-state probe latency. A
`complete_final_evidence` entry in the legacy column means that validator counted index rows
differently; see the audit note below. Raw event IDs and record IDs are retained per trial.

| Condition | Trial | Target | ADD/MODIFY | Evidence / controls | Probe s | Legacy |
|---|---|---|---:|---|---:|---|
{chr(10).join(rows)}

## Timing And Duplicate-Record Audit

- The CSG event-time tolerance was 10 seconds and Wazuh retrieval lookback was 300 seconds, both
  frozen before this campaign. The tolerance had been chosen from prior same-host calibration; this
  campaign validates it on new randomized trial instances on that same endpoint, not on an
  independent host or an independently calibrated deployment.
- For complete trials, manual action-to-probe-response observations ranged from
  {range_text(state_detection)}. This is operator-triggered observation timing, not a sensor-latency
  percentile and not continuous autonomous detection latency.
- The event timestamp offset from the action completion timestamp ranged from
  {range_text(event_offsets)}. This is an event-time offset, not event-delivery latency.
- No P95/P99 claims are made. `event_to_query_seconds` measures when the later query completed,
  not when the event first became available, and is not used as an ingestion-latency estimate.
- Some raw evidence packages contain both an alert-index row and an archive-index row for the same
  underlying event occurrence: {", ".join(f"`{item}`" for item in multi_index_copies) or "none"}.
  The frozen primary analyzer counts unique `(host, type, target, event time, event code)`
  occurrences and verifies that CSG cites an exact target event ID; it does not inflate event counts
  from mirrored index documents.
- The older generic validator reports `complete_final_evidence` failures for `complete-5`,
  `complete-6`, and `complete-8`, because it requires exactly one raw evidence row per transition.
  The raw rows in those cases are cross-index copies of one event occurrence, not two Windows
  actions. The protocol-specific holdout analyzer, frozen before the campaign, passes the exact-ID
  and unique-occurrence rules for all three. Both outputs are retained; this report does not rewrite
  the generic validator's artifacts.
- After this frozen analysis, the generic validator was corrected to deduplicate mirrored index rows
  by event occurrence while requiring an exact cited record ID. Regression tests cover both mirrored
  alert/archive copies and a missing event citation. The historical `validation.json` and
  `analysis.json` files remain unchanged; the correction applies to future validation runs.

## Provenance And Reproduction

- The protocol SHA-256 is `{protocol_hash}`; the analyzed campaign manifest embeds the same value.
- Randomization seed: `{manifest["random_seed"]}`. Per-condition assignments and execution order
  are preserved in `windows-campaign/campaign-manifest.json`.
- All 30 trial folders contain the raw `run.json` and independent `validation.json`. The raw records
  preserve state before/after values, observation IDs, Windows System event record IDs, Wazuh exact
  event IDs and index references, reconciliation versions, task/service state, and cleanup evidence.
- CSG's periodic probe task was disabled during each trial, explicit one-shot captures were used,
  and the task was re-enabled afterward in all 30 trials.
- The campaign manifest does not include the standalone pretrial environment capture prescribed in
  the protocol. Per-trial artifacts do contain host ID, API/Wazuh/indexer status and endpoint source
  evidence, but this missing pretrial file is a provenance deviation and is not reconstructed
  after the fact.
- The experiment used the repository's frozen drill/controller/analyzer hashes listed in
  `PROTOCOL.md`. The protocol states no repository Git commit was available. Container image
  digests, database migration revision, and a separately frozen Windows environment inventory
  are not captured in this campaign package.

## Limitations And Claim Boundary

1. **Not attacks.** The positive action created a stopped service configured with the inert
   `cmd.exe /c exit 0` image and changed its startup mode. It was not run and carries no malicious
   intent label. Findings establish change observation and event association only.
2. **One host and one stack.** All trial replications are repeated operations on the same VM, not
   30 independent Windows systems. Windows 11 ARM64, one Wazuh manager/indexer, and one agent
   configuration were used.
3. **Tolerance prior calibration.** The ten-second tolerance is not an independently selected
   universal parameter. It was fixed before these trials but selected using earlier observations.
4. **Small control samples.** The confidence intervals are wide; 0/10 false matches does not prove
   a zero false-match probability.
5. **Capture drop not tested here.** The distractor design tests rejection of an available
   wrong-object event. It does not demonstrate permanent event loss; Wazuh may buffer and recover
   events after a temporary outage.
6. **No claim of superiority.** No labeled malicious-versus-benign classifier comparison, analyst
   outcome study, independent AI scoring, or operational SOC baseline is part of this campaign.

The appropriate paper language is: “In a preregistered, single-host controlled service experiment,
CSG observed the target service state transitions and exact-object reconciliation associated each
transition with its corresponding Wazuh evidence; same-host wrong-object events were rejected in the
tested distractor condition.” Do not rewrite this as “CSG detects attacks better than Wazuh.”
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("analysis", type=Path)
    parser.add_argument("protocol", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    report = render(args.campaign, args.analysis, args.protocol)
    args.output.write_text(report, encoding="utf-8")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
