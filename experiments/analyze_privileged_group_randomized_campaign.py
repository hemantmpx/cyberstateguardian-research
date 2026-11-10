"""Independently audit the frozen privileged-group live campaign artifacts."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import math
import textwrap
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

STUDY_ID = "csg-privileged-group-randomized-v9"
CONDITIONS = (
    "complete_with_distractor",
    "target_audit_omission_with_distractor",
    "no_target_change_with_distractor",
)
WINDOW_TOLERANCE_SECONDS = 20


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def report_lines(text: str) -> list[str]:
    return textwrap.wrap(text, width=96, break_long_words=False)


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def xml_event_identity(event: dict[str, Any]) -> dict[str, str] | None:
    raw = event.get("xml")
    if not raw:
        return None
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None
    system = root.find("{*}System")
    if system is None:
        return None
    event_id = system.findtext("{*}EventID")
    record_id = system.findtext("{*}EventRecordID")
    data = {
        item.get("Name", ""): item.text or "" for item in root.findall(".//{*}EventData/{*}Data")
    }
    return {
        "event_id": event_id or "",
        "record_id": record_id or "",
        "member_sid": data.get("MemberSid", ""),
        "group": data.get("TargetUserName", ""),
        "channel": system.findtext("{*}Channel") or "",
        "computer": system.findtext("{*}Computer") or "",
        "provider": (
            system.find("{*}Provider").get("Name", "")
            if system.find("{*}Provider") is not None
            else ""
        ),
    }


def within_transition_window(event: dict[str, Any], transition: dict[str, Any] | None) -> bool:
    if not transition:
        return False
    start, end = transition.get("window_start"), transition.get("window_end")
    if not start or not end:
        return False
    event_time = parse_utc(event["event_time"])
    return (
        parse_utc(start) - timedelta(seconds=WINDOW_TOLERANCE_SECONDS)
        <= event_time
        <= parse_utc(end) + timedelta(seconds=WINDOW_TOLERANCE_SECONDS)
    )


def exact_wazuh_events(run: dict[str, Any], sid: str) -> list[dict[str, Any]]:
    query = run.get("wazuh_query") or {}
    matching = [
        event
        for event in query.get("exact_events", [])
        if event.get("host_id") == run.get("host_id")
        and event.get("source") == "wazuh"
        and event.get("synthetic") is False
        and event.get("normalized_type") == "privileged_group_member_added"
        and event.get("attributes", {}).get("event_code") == "4732"
        and event.get("attributes", {}).get("group") == "Administrators"
        and event.get("attributes", {}).get("member_sid") == sid
        and str(event.get("metadata", {}).get("windows_event_identity", {}).get("event_code"))
        == "4732"
        and str(
            event.get("metadata", {}).get("windows_event_identity", {}).get("channel", "")
        ).lower()
        == "security"
        and str(event.get("metadata", {}).get("agent", {}).get("id"))
        == str(run.get("wazuh_preflight", {}).get("agent_id"))
    ]
    logical: dict[tuple[str, ...], dict[str, Any]] = {}
    for event in matching:
        identity = event.get("metadata", {}).get("windows_event_identity", {})
        key = (
            str(event.get("host_id")),
            str(event.get("metadata", {}).get("agent", {}).get("id")),
            str(identity.get("channel", "")).lower(),
            str(identity.get("event_code")),
            str(identity.get("event_record_id")),
            str(event.get("attributes", {}).get("member_sid")),
            str(event.get("attributes", {}).get("group")),
        )
        prior = logical.get(key)
        if prior is None or (
            event.get("metadata", {}).get("source_kind") == "wazuh_alert"
            and prior.get("metadata", {}).get("source_kind") != "wazuh_alert"
        ):
            logical[key] = event
    return list(logical.values())


def cited_windows_identity_matches(
    run: dict[str, Any],
    evidence_ids: list[str],
    sid: str,
    local_identity: dict[str, str] | None,
    transition: dict[str, Any] | None,
) -> bool:
    ids = list(dict.fromkeys(item for item in evidence_ids if item))
    if not ids or not local_identity or not transition:
        return False
    candidates = (run.get("citation_resolution_query") or {}).get("exact_events", [])
    by_id: dict[str, list[dict[str, Any]]] = {}
    for event in candidates:
        by_id.setdefault(str(event.get("event_id")), []).append(event)
    rows = [by_id.get(event_id, []) for event_id in ids]
    if any(len(matches) != 1 for matches in rows):
        return False
    cited = [matches[0] for matches in rows]
    for event in cited:
        attributes = event.get("attributes", {})
        metadata = event.get("metadata", {})
        windows = metadata.get("windows_event_identity", {})
        if not (
            event.get("host_id") == run.get("host_id")
            and event.get("source") == "wazuh"
            and event.get("synthetic") is False
            and event.get("normalized_type") == "privileged_group_member_added"
            and attributes.get("event_code") == "4732"
            and attributes.get("group") == "Administrators"
            and attributes.get("member_sid") == sid
            and str(windows.get("event_code")) == "4732"
            and str(windows.get("event_record_id")) == local_identity.get("record_id")
            and str(windows.get("channel", "")).lower() == "security"
            and str(windows.get("provider_name", "")).lower()
            == "microsoft-windows-security-auditing"
            and str(metadata.get("agent", {}).get("id"))
            == str(run.get("wazuh_preflight", {}).get("agent_id"))
            and within_transition_window(event, transition)
        ):
            return False
    return True


def audit_trial(
    assigned: dict[str, Any], run: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    condition = assigned["condition"]
    target_sid = run.get("target", {}).get("sid")
    distractor_sid = run.get("distractor", {}).get("sid")
    target_change = condition != "no_target_change_with_distractor"
    target_event_expected = condition == "complete_with_distractor"
    target_status = "CORROBORATED" if target_event_expected else "UNEXPLAINED_BY_EVENT_PLANE"
    target_local = run.get("local_target_events", [])
    distractor_local = run.get("local_distractor_events", [])
    target_wazuh = exact_wazuh_events(run, target_sid or "")
    distractor_wazuh = exact_wazuh_events(run, distractor_sid or "")
    target_transition = run.get("target_transition")
    distractor_transition = run.get("distractor_transition")
    target_recon = run.get("target_reconciliation") or {}
    distractor_recon = run.get("distractor_reconciliation") or {}
    target_recon_ids = target_recon.get("matched_evidence_ids", [])
    target_key = run.get("target", {}).get("object_key")
    distractor_key = run.get("distractor", {}).get("object_key")
    after = run.get("snapshot_after") or {}
    after_keys = {item.get("object_key") for item in after.get("present_objects", [])}

    local_target_identity = xml_event_identity(target_local[0]) if len(target_local) == 1 else None
    local_distractor_identity = (
        xml_event_identity(distractor_local[0]) if len(distractor_local) == 1 else None
    )
    target_event = target_wazuh[0] if len(target_wazuh) == 1 else None
    distractor_event = distractor_wazuh[0] if len(distractor_wazuh) == 1 else None
    target_windows_record = (
        str(
            target_event.get("metadata", {})
            .get("windows_event_identity", {})
            .get("event_record_id")
        )
        if target_event
        else None
    )
    distractor_windows_record = (
        str(
            distractor_event.get("metadata", {})
            .get("windows_event_identity", {})
            .get("event_record_id")
        )
        if distractor_event
        else None
    )
    audit = run.get("audit_policy") or {}
    baseline = audit.get("baseline") or {}
    after_restore = audit.get("after_restore") or {}
    citation_query = run.get("citation_resolution_query") or {}
    target_citation_identity = cited_windows_identity_matches(
        run, target_recon_ids, target_sid or "", local_target_identity, target_transition
    )
    distractor_citation_identity = cited_windows_identity_matches(
        run,
        distractor_recon.get("matched_evidence_ids", []),
        distractor_sid or "",
        local_distractor_identity,
        distractor_transition,
    )

    checks = {
        "assignment_matches": run.get("trial_id") == assigned["trial_id"]
        and run.get("condition") == condition
        and run.get("target", {}).get("username") == assigned["target_username"]
        and run.get("distractor", {}).get("username") == assigned["distractor_username"],
        "fresh_distinct_sids": bool(target_sid and distractor_sid and target_sid != distractor_sid),
        "direct_probe_snapshot_source": after.get("source") == "direct_probe",
        "target_state_matches_assignment": (target_key in after_keys) == target_change,
        "distractor_state_present": distractor_key in after_keys,
        "target_transition_matches_assignment": (target_transition is not None) == target_change,
        "no_target_finding_in_no_change": condition != "no_target_change_with_distractor"
        or len(run.get("target_findings") or []) == 0,
        "target_transition_identity": not target_change
        or (
            target_transition.get("object_key") == target_key
            and target_transition.get("transition_type") == "PRIVILEGED_MEMBER_ADDED"
            and target_transition.get("source") == "direct_probe"
        ),
        "distractor_transition_identity": bool(distractor_transition)
        and distractor_transition.get("object_key") == distractor_key
        and distractor_transition.get("transition_type") == "PRIVILEGED_MEMBER_ADDED"
        and distractor_transition.get("source") == "direct_probe",
        "target_local_event_count": len(target_local) == int(target_event_expected),
        "distractor_local_event_count": len(distractor_local) == 1,
        "target_local_event_identity": not target_event_expected
        or bool(local_target_identity)
        and local_target_identity.get("event_id") == "4732"
        and local_target_identity.get("member_sid") == target_sid
        and local_target_identity.get("group") == "Administrators"
        and local_target_identity.get("channel").lower() == "security"
        and local_target_identity.get("computer").lower()
        == run.get("environment", {}).get("windows_computer_name", "").lower()
        and local_target_identity.get("provider").lower() == "microsoft-windows-security-auditing",
        "distractor_local_event_identity": bool(local_distractor_identity)
        and local_distractor_identity.get("event_id") == "4732"
        and local_distractor_identity.get("member_sid") == distractor_sid
        and local_distractor_identity.get("group") == "Administrators"
        and local_distractor_identity.get("channel").lower() == "security"
        and local_distractor_identity.get("computer").lower()
        == run.get("environment", {}).get("windows_computer_name", "").lower()
        and local_distractor_identity.get("provider").lower()
        == "microsoft-windows-security-auditing",
        "target_wazuh_event_count": len(target_wazuh) == int(target_event_expected),
        "distractor_wazuh_event_count": len(distractor_wazuh) == 1,
        "target_wazuh_record_matches_local": not target_event_expected
        or (bool(target_event) and bool(local_target_identity))
        and target_windows_record == str(local_target_identity.get("record_id")),
        "distractor_wazuh_record_matches_local": bool(distractor_event)
        and bool(local_distractor_identity)
        and distractor_windows_record == str(local_distractor_identity.get("record_id")),
        "reconciliation_citation_ids_resolved": citation_query.get("expected_ids_observed") is True,
        "target_reconciliation_status": not target_change
        or target_recon.get("status") == target_status,
        "target_cites_exact_windows_event": not target_event_expected or target_citation_identity,
        "omitted_target_has_no_citations": condition != "target_audit_omission_with_distractor"
        or len(target_recon_ids) == 0,
        "distractor_reconciles_to_own_event": bool(distractor_event)
        and distractor_recon.get("status") == "CORROBORATED"
        and distractor_citation_identity,
        "distractor_inside_target_transition_window": not target_change
        or (
            bool(distractor_event) and within_transition_window(distractor_event, target_transition)
        ),
        "paired_actions_within_five_seconds": action_gap_seconds(run) <= 5.0,
        "audit_baseline_success_only": baseline.get("success") is True
        and baseline.get("failure") is False,
        "audit_omission_condition_restored": condition != "target_audit_omission_with_distractor"
        or (
            audit.get("target_omission_applied") is True
            and audit.get("restore_verified") is True
            and after_restore.get("success") is True
            and after_restore.get("failure") is False
        ),
        "runner_reported_success": run.get("success") is True,
        "cleanup_probe_refresh_succeeded": (run.get("cleanup") or {}).get("probe_refresh_exit_code")
        == 0,
        "cleanup_complete": (run.get("cleanup") or {}).get("complete") is True,
    }
    row = {
        "trial_id": assigned["trial_id"],
        "block": assigned["block"],
        "condition": condition,
        "gate_pass": all(checks.values()),
        "target_sid": target_sid,
        "distractor_sid": distractor_sid,
        "target_local_record_id": local_target_identity.get("record_id")
        if local_target_identity
        else None,
        "target_wazuh_event_id": target_event.get("event_id") if target_event else None,
        "distractor_local_record_id": local_distractor_identity.get("record_id")
        if local_distractor_identity
        else None,
        "distractor_wazuh_event_id": distractor_event.get("event_id") if distractor_event else None,
        "target_transition_id": (target_transition or {}).get("transition_id"),
        "target_reconciliation_status": target_recon.get("status"),
        "target_reconciliation_evidence_ids": target_recon_ids,
        "distractor_reconciliation_status": distractor_recon.get("status"),
        "failed_checks": [name for name, passed in checks.items() if not passed],
        "checks": checks,
    }
    return row, checks


def action_gap_seconds(run: dict[str, Any]) -> float:
    phases = {item.get("phase"): item.get("at_utc") for item in run.get("action_timeline", [])}
    target = phases.get("target_membership_add_started")
    if not target:
        return 0.0 if phases.get("target_no_change_assigned") else math.inf
    distractor = phases.get("distractor_membership_add_started")
    if not distractor:
        return math.inf
    return abs((parse_utc(distractor) - parse_utc(target)).total_seconds())


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total <= 0:
        return None
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denom
    return [max(0.0, center - margin), min(1.0, center + margin)]


def verify_freeze(campaign_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    freeze = load(campaign_dir / "campaign-freeze.json")
    schedule = load(campaign_dir / "schedule.json")["trials"]
    frozen = campaign_dir / "frozen-source"
    expected = freeze["source_hashes"]
    paths = {
        "controller_sha256": frozen / "run_privileged_group_randomized_campaign.py",
        "windows_runner_sha256": frozen / "run_privileged_group_trial_windows_v9.ps1",
        "analyzer_sha256": frozen / Path(__file__).name,
        "protocol_sha256": frozen / "privileged-group-randomized-campaign-protocol-v9.md",
        "protocol_copy_sha256": campaign_dir / "PROTOCOL.md",
        "schedule_sha256": campaign_dir / "schedule.json",
    }
    actual = {key: digest(path) for key, path in paths.items()}
    if actual != expected:
        raise RuntimeError(f"Frozen-source verification failed: {actual}")
    if len(schedule) != 30:
        raise RuntimeError("The frozen schedule does not contain 30 trials.")
    return freeze, schedule


def analyze(campaign_dir: Path) -> dict[str, Any]:
    freeze, schedule = verify_freeze(campaign_dir)
    trial_rows: list[dict[str, Any]] = []
    audit_bundles: dict[str, Any] = {}
    for assigned in schedule:
        path = campaign_dir / "trials" / assigned["trial_id"] / "raw-windows" / "run.json"
        sums = path.with_name("SHA256SUMS.txt")
        if not path.is_file() or not sums.is_file():
            raise RuntimeError(f"Missing assigned raw run or checksum file: {assigned['trial_id']}")
        expected_line = sums.read_text(encoding="utf-8").splitlines()[0].split()
        if expected_line[0].lower() != digest(path) or expected_line[1] != "run.json":
            raise RuntimeError(f"Raw run checksum failed: {assigned['trial_id']}")
        run = load(path)
        if run.get("campaign_id") != STUDY_ID or run.get("host_id") != freeze["endpoint_id"]:
            raise RuntimeError(f"Run identity/host mismatch: {assigned['trial_id']}")
        row, checks = audit_trial(assigned, run)
        trial_rows.append(row)
        audit_bundles[row["trial_id"]] = {
            "run_path": str(path.relative_to(campaign_dir)),
            "checks": checks,
        }

    assignments = Counter(row["condition"] for row in schedule)
    summaries: dict[str, Any] = {}
    for condition in CONDITIONS:
        rows = [row for row in trial_rows if row["condition"] == condition]
        passes = sum(row["gate_pass"] for row in rows)
        summaries[condition] = {
            "assigned": assignments[condition],
            "audited": len(rows),
            "all_gate_pass": passes,
            "all_gate_pass_rate": passes / len(rows) if rows else None,
            "descriptive_wilson_95_interval": wilson(passes, len(rows)),
            "failed_trial_ids": [row["trial_id"] for row in rows if not row["gate_pass"]],
        }

    target_sids = [row["target_sid"] for row in trial_rows]
    distractor_sids = [row["distractor_sid"] for row in trial_rows]
    windows_ids = [
        value
        for row in trial_rows
        for value in (row["target_local_record_id"], row["distractor_local_record_id"])
        if value is not None
    ]
    wazuh_ids = [
        value
        for row in trial_rows
        for value in (row["target_wazuh_event_id"], row["distractor_wazuh_event_id"])
        if value is not None
    ]
    result = {
        "study_id": STUDY_ID,
        "classification": "prospective_randomized_within_host_benign_mechanism_study",
        "freeze_timestamp_utc": freeze["frozen_at_utc"],
        "endpoint_count": 1,
        "assigned_trials": len(schedule),
        "trials_audited": len(trial_rows),
        "all_trials_pass": len(trial_rows) == 30 and all(row["gate_pass"] for row in trial_rows),
        "condition_summaries": summaries,
        "identity_uniqueness": {
            "target_sid_count": len(target_sids),
            "target_sid_unique": len(set(target_sids)) == len(target_sids),
            "distractor_sid_count": len(distractor_sids),
            "distractor_sid_unique": len(set(distractor_sids)) == len(distractor_sids),
            "local_event_record_count": len(windows_ids),
            "local_event_records_unique": len(set(windows_ids)) == len(windows_ids),
            "wazuh_evidence_count": len(wazuh_ids),
            "wazuh_evidence_ids_unique": len(set(wazuh_ids)) == len(wazuh_ids),
        },
        "interpretation_boundary": [
            (
                "The audit-omission condition disables local Security Group Management success "
                "auditing only for the target action; it is not a claim of Wazuh network loss or "
                "permanent event loss."
            ),
            (
                "All mutations are benign disabled-account membership changes; no attacker "
                "behavior or malicious intent is evaluated."
            ),
            (
                "All repeated trials share one Windows endpoint; intervals are descriptive and "
                "do not provide independent-host replication."
            ),
            (
                "The result evaluates exact reconciliation and retained state observation, not "
                "whether CSG detects attacks or outperforms all Wazuh features."
            ),
        ],
        "trials": trial_rows,
        "raw_audit": audit_bundles,
    }
    return result


def write_outputs(campaign_dir: Path, result: dict[str, Any]) -> None:
    (campaign_dir / "analysis").mkdir(exist_ok=True)
    analysis_path = campaign_dir / "analysis" / "analysis.json"
    analysis_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    csv_path = campaign_dir / "analysis" / "trial-summary.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        fields = [
            "trial_id",
            "block",
            "condition",
            "gate_pass",
            "target_sid",
            "distractor_sid",
            "target_local_record_id",
            "target_wazuh_event_id",
            "distractor_local_record_id",
            "distractor_wazuh_event_id",
            "target_transition_id",
            "target_reconciliation_status",
            "distractor_reconciliation_status",
            "failed_checks",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in result["trials"]:
            writer.writerow({**row, "failed_checks": ";".join(row["failed_checks"])})

    titles = {
        "complete_with_distractor": "Complete target evidence + wrong-member distractor",
        "target_audit_omission_with_distractor": (
            "Target audit omission + wrong-member event visible"
        ),
        "no_target_change_with_distractor": "No target change + wrong-member distractor",
    }
    lines = [
        "# Privileged-Group Randomized Reconciliation Campaign v9",
        "",
        f"Campaign ID: `{STUDY_ID}`  ",
        f"Frozen: `{result['freeze_timestamp_utc']}`  ",
        "Endpoint: one Windows 11 ARM64 VM (`win11-arm-lab`)  ",
        "Ground truth: benign authorized lab operations; maliciousness was not tested.",
        "",
        "## Research question",
        "",
        *report_lines(
            "Does CSG reconcile a native persistent privileged-group membership transition only "
            "with the exact same member's Windows/Wazuh event, reject a same-host/same-event-class "
            "wrong-member distractor, and retain state visibility when local success auditing is "
            "intentionally omitted for the target action?"
        ),
        "",
        "## Results by condition",
        "",
        "| Condition | n | All gates passed | Rate | Descriptive Wilson 95% interval |",
        "|---|---:|---:|---:|---:|",
    ]
    for condition in CONDITIONS:
        summary = result["condition_summaries"][condition]
        interval = summary["descriptive_wilson_95_interval"]
        interval_text = (
            "not available" if interval is None else f"[{interval[0]:.3f}, {interval[1]:.3f}]"
        )
        rate = (
            "not available"
            if summary["all_gate_pass_rate"] is None
            else f"{summary['all_gate_pass_rate']:.3f}"
        )
        lines.append(
            f"| {titles[condition]} | {summary['assigned']} | "
            f"{summary['all_gate_pass']} | {rate} | {interval_text} |"
        )
    lines += [
        "",
        *report_lines(
            f"Overall independent raw-artifact audit: "
            f"**{'PASS' if result['all_trials_pass'] else 'NOT PASS'}** "
            f"({result['trials_audited']}/30 assigned slots audited)."
        ),
        "",
        "## How to read this",
        "",
        *report_lines(
            "The complete arm challenges identity matching with a different account's Security "
            "Event 4732 in the same bounded action interval. A correct target reconciliation "
            "must cite the target SID's event and not the distractor. The audit-omission arm "
            "turns off only local Security Group Management success auditing for the target "
            "membership action, restores the recorded Success-only baseline, and then generates "
            "a visible wrong-member event. The expected result is target state observed but no "
            "target event and an `UNEXPLAINED_BY_EVENT_PLANE` reconciliation with no cited "
            "event. The no-change arm performs only the distractor membership operation; the "
            "target must remain absent from probe state with no target transition."
        ),
        "",
        *report_lines(
            "The audit-omission arm is **not** evidence of Wazuh dropping or losing a Windows "
            "event: Windows is configured not to emit the target success event. Wazuh remains "
            "running and the different-member event checks that the event pathway is available. "
            "This is an explicit telemetry-coverage intervention."
        ),
        "",
        "## Identity and artifact audit",
        "",
        *report_lines(
            f"- Target SIDs unique: {result['identity_uniqueness']['target_sid_unique']} "
            f"({result['identity_uniqueness']['target_sid_count']})."
        ),
        *report_lines(
            f"- Distractor SIDs unique: {result['identity_uniqueness']['distractor_sid_unique']} "
            f"({result['identity_uniqueness']['distractor_sid_count']})."
        ),
        *report_lines(
            f"- Local Windows EventRecordIDs unique: "
            f"{result['identity_uniqueness']['local_event_records_unique']} "
            f"({result['identity_uniqueness']['local_event_record_count']})."
        ),
        *report_lines(
            f"- Wazuh evidence IDs unique: "
            f"{result['identity_uniqueness']['wazuh_evidence_ids_unique']} "
            f"({result['identity_uniqueness']['wazuh_evidence_count']})."
        ),
        *report_lines(
            "- Trial-level identities, reconciliation statuses, citations, and failed checks are "
            "in `analysis/trial-summary.csv` and `analysis/analysis.json`."
        ),
        *report_lines(
            "- Every run has a raw Windows JSON bundle and a SHA-256 checksum. The freeze binds "
            "the schedule, controller, runner, analyzer, and protocol."
        ),
        "",
        "## Limits",
        "",
        *report_lines(
            "This is repeated benign mechanism evidence from one Windows VM. Its intervals are "
            "descriptive binomial summaries; ten repetitions per arm on one host do not establish "
            "independent endpoint reliability. It does not measure malicious detection, attack "
            "recall, natural/permanent telemetry failure, cross-host generalization, or "
            "superiority to Wazuh. A second endpoint is unavailable in the current setup."
        ),
        "",
        "## Reproduction",
        "",
        *report_lines(
            "The immutable assignment and hashes are in `campaign-freeze.json`, `schedule.json`, "
            "and `frozen-source/`. Raw bundles are under `trials/`. Re-run the independent audit "
            "with:"
        ),
        "",
        "```sh",
        "uv run python experiments/analyze_privileged_group_randomized_campaign.py "
        f"--campaign-dir {campaign_dir}",
        "```",
        "",
    ]
    (campaign_dir / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")

    entries = {}
    for path in sorted(campaign_dir.rglob("*")):
        if path.is_file() and path.name != "artifact-manifest.json":
            entries[path.relative_to(campaign_dir).as_posix()] = digest(path)
    (campaign_dir / "artifact-manifest.json").write_text(
        json.dumps(
            {"algorithm": "sha256", "manifest_excludes_self": True, "files": entries},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def synthetic_trial(
    condition: str, target_event_expected: bool, target_change: bool
) -> tuple[dict[str, Any], dict[str, Any]]:
    target_sid = "S-1-5-21-1-1001"
    distractor_sid = "S-1-5-21-1-1002"
    target_key = "privileged_group:administrators:winlab/csgt000000000001"
    distractor_key = "privileged_group:administrators:winlab/csgd000000000002"

    def local_event(record: str, sid: str) -> dict[str, Any]:
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
            f"<EventID>4732</EventID><EventRecordID>{record}</EventRecordID>"
            "<Channel>Security</Channel><Computer>WINLAB</Computer></System>"
            "<EventData><Data Name='MemberSid'>"
            f"{sid}</Data><Data Name='TargetUserName'>Administrators</Data>"
            "</EventData></Event>"
        )
        return {"event_id": 4732, "event_record_id": int(record), "xml": xml}

    def wazuh_event(event_id: str, record: str, sid: str) -> dict[str, Any]:
        return {
            "event_id": event_id,
            "host_id": "win11-arm-lab",
            "event_time": "2026-10-16T12:00:01Z",
            "normalized_type": "privileged_group_member_added",
            "source": "wazuh",
            "synthetic": False,
            "attributes": {"event_code": "4732", "group": "Administrators", "member_sid": sid},
            "metadata": {
                "source_kind": "wazuh_archive",
                "agent": {"id": "001"},
                "windows_event_identity": {
                    "event_code": "4732",
                    "channel": "security",
                    "provider_name": "microsoft-windows-security-auditing",
                    "event_record_id": record,
                },
            },
        }

    target_wazuh = wazuh_event("wazuh-target", "501", target_sid) if target_event_expected else None
    distractor_wazuh = wazuh_event("wazuh-distractor", "502", distractor_sid)
    target_citation = dict(target_wazuh) if target_wazuh else None
    if target_citation:
        target_citation["event_id"] = "wazuh-target-alert-copy"
        target_citation["metadata"] = {
            **target_citation["metadata"],
            "source_kind": "wazuh_alert",
        }
    distractor_citation = dict(distractor_wazuh)
    distractor_citation["event_id"] = "wazuh-distractor-alert-copy"
    distractor_citation["metadata"] = {
        **distractor_citation["metadata"],
        "source_kind": "wazuh_alert",
    }
    target_transition = (
        {
            "transition_id": "transition-target",
            "object_key": target_key,
            "transition_type": "PRIVILEGED_MEMBER_ADDED",
            "source": "direct_probe",
            "window_start": "2026-10-16T12:00:00Z",
            "window_end": "2026-10-16T12:00:03Z",
        }
        if target_change
        else None
    )
    distractor_transition = {
        "transition_id": "transition-distractor",
        "object_key": distractor_key,
        "transition_type": "PRIVILEGED_MEMBER_ADDED",
        "source": "direct_probe",
        "window_start": "2026-10-16T12:00:00Z",
        "window_end": "2026-10-16T12:00:03Z",
    }
    target_recon = (
        {
            "status": "CORROBORATED" if target_event_expected else "UNEXPLAINED_BY_EVENT_PLANE",
            "matched_evidence_ids": [target_citation["event_id"]] if target_citation else [],
        }
        if target_change
        else None
    )
    distractor_recon = {
        "status": "CORROBORATED",
        "matched_evidence_ids": [distractor_citation["event_id"]],
    }
    run = {
        "trial_id": "PG-001",
        "condition": condition,
        "host_id": "win11-arm-lab",
        "environment": {"windows_computer_name": "WINLAB"},
        "wazuh_preflight": {"agent_id": "001"},
        "target": {
            "sid": target_sid,
            "username": target_key.rsplit("/", 1)[-1],
            "object_key": target_key,
        },
        "distractor": {
            "sid": distractor_sid,
            "username": distractor_key.rsplit("/", 1)[-1],
            "object_key": distractor_key,
        },
        "snapshot_after": {
            "source": "direct_probe",
            "present_objects": ([{"object_key": target_key}] if target_change else [])
            + [{"object_key": distractor_key}],
        },
        "target_transition": target_transition,
        "distractor_transition": distractor_transition,
        "local_target_events": [local_event("501", target_sid)] if target_event_expected else [],
        "local_distractor_events": [local_event("502", distractor_sid)],
        "wazuh_query": {
            "exact_events": ([target_wazuh] if target_wazuh else []) + [distractor_wazuh]
        },
        "citation_resolution_query": {
            "exact_events": ([target_citation] if target_citation else []) + [distractor_citation],
            "expected_ids_observed": True,
        },
        "target_reconciliation": target_recon,
        "distractor_reconciliation": distractor_recon,
        "target_findings": [],
        "action_timeline": (
            [
                {"phase": "target_membership_add_started", "at_utc": "2026-10-16T12:00:00Z"},
                {"phase": "distractor_membership_add_started", "at_utc": "2026-10-16T12:00:01Z"},
            ]
            if target_change
            else [{"phase": "target_no_change_assigned", "at_utc": "2026-10-16T12:00:00Z"}]
            + [{"phase": "distractor_membership_add_started", "at_utc": "2026-10-16T12:00:01Z"}]
        ),
        "audit_policy": {
            "baseline": {"success": True, "failure": False},
            "target_omission_applied": condition == "target_audit_omission_with_distractor",
            "restore_verified": condition == "target_audit_omission_with_distractor",
            "after_restore": {"success": True, "failure": False},
        },
        "success": True,
        "cleanup": {"complete": True, "probe_refresh_exit_code": 0},
    }
    assigned = {
        "trial_id": "PG-001",
        "block": 1,
        "condition": condition,
        "target_username": run["target"]["username"],
        "distractor_username": run["distractor"]["username"],
    }
    return assigned, run


def self_test() -> int:
    sample = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><EventID>4732</EventID><EventRecordID>5</EventRecordID></System>"
        "<EventData><Data Name='MemberSid'>S-1-5-21-1</Data>"
        "<Data Name='TargetUserName'>Administrators</Data></EventData></Event>"
    )
    parsed = xml_event_identity({"xml": sample})
    assert parsed == {
        "event_id": "4732",
        "record_id": "5",
        "member_sid": "S-1-5-21-1",
        "group": "Administrators",
        "channel": "",
        "computer": "",
        "provider": "",
    }
    assert within_transition_window(
        {"event_time": "2026-10-16T12:00:00Z"},
        {"window_start": "2026-10-16T12:00:19Z", "window_end": "2026-10-16T12:00:30Z"},
    )
    assert not within_transition_window(
        {"event_time": "2026-10-16T12:00:00Z"},
        {"window_start": "2026-10-16T12:00:21Z", "window_end": "2026-10-16T12:00:30Z"},
    )
    assert wilson(10, 10)[0] > 0.70 and abs(wilson(10, 10)[1] - 1.0) < 1e-9
    fixtures = [
        ("complete_with_distractor", True, True),
        ("target_audit_omission_with_distractor", False, True),
        ("no_target_change_with_distractor", False, False),
    ]
    audited = []
    for condition, event_present, state_change in fixtures:
        assignment, run = synthetic_trial(condition, event_present, state_change)
        row, _ = audit_trial(assignment, run)
        assert row["gate_pass"], row["failed_checks"]
        audited.append((assignment, run))
    wrong_assignment, wrong_run = audited[1]
    wrong_run["target_reconciliation"]["matched_evidence_ids"] = ["wazuh-distractor"]
    wrong_row, _ = audit_trial(wrong_assignment, wrong_run)
    assert not wrong_row["gate_pass"]
    assert "omitted_target_has_no_citations" in wrong_row["failed_checks"]
    no_change_assignment, no_change_run = audited[2]
    no_change_run["target_findings"] = None
    null_findings_row, _ = audit_trial(no_change_assignment, no_change_run)
    assert null_findings_row["gate_pass"], null_findings_row["failed_checks"]
    no_change_run["target_findings"] = [{"finding_id": "unexpected"}]
    no_change_row, _ = audit_trial(no_change_assignment, no_change_run)
    assert not no_change_row["gate_pass"]
    assert "no_target_finding_in_no_change" in no_change_row["failed_checks"]
    complete_assignment, complete_run = audited[0]
    wrong_object_run = copy.deepcopy(complete_run)
    wrong_object_run["citation_resolution_query"]["exact_events"][0]["attributes"]["member_sid"] = (
        wrong_object_run["distractor"]["sid"]
    )
    wrong_object_row, _ = audit_trial(complete_assignment, wrong_object_run)
    assert not wrong_object_row["gate_pass"]
    assert "target_cites_exact_windows_event" in wrong_object_row["failed_checks"]
    print("Self-test passed: XML identity, frozen event-window tolerance, Wilson interval.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-dir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.campaign_dir:
        parser.error("--campaign-dir is required unless --self-test is used")
    campaign_dir = args.campaign_dir.resolve()
    result = analyze(campaign_dir)
    write_outputs(campaign_dir, result)
    print(
        json.dumps(
            {
                "study_id": STUDY_ID,
                "all_trials_pass": result["all_trials_pass"],
                "audited": result["trials_audited"],
                "conditions": result["condition_summaries"],
            },
            indent=2,
        )
    )
    return 0 if result["all_trials_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
