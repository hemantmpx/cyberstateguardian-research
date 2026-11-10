"""Prepare and execute a frozen, single-host WFP listener reconciliation campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

STUDY_ID = "listener-wfp5154-randomized-three-arm-v1"
HOST_ID = "win11-arm-lab"
CONDITIONS = (
    "complete_exact",
    "target_event_absent_with_distractor",
    "no_change_with_distractor",
)
ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "experiments" / "run_listener_wfp5154_trial_windows.ps1"
ANALYZER = ROOT / "experiments" / "analyze_listener_wfp5154_campaign.py"
PROTOCOL_TEMPLATE = ROOT / "experiments" / "listener-wfp5154-campaign-protocol.md"


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def create_schedule(seed: int, repetitions: int) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    ports = rng.sample(range(52000, 62000), repetitions * len(CONDITIONS) * 2)
    schedule: list[dict[str, Any]] = []
    port_index = 0
    for block in range(1, repetitions + 1):
        conditions = list(CONDITIONS)
        rng.shuffle(conditions)
        for condition in conditions:
            slot = len(schedule) + 1
            schedule.append(
                {
                    "slot": slot,
                    "block": block,
                    "trial_id": f"LWF-{slot:03d}",
                    "condition": condition,
                    "target_port": ports[port_index],
                    "distractor_port": ports[port_index + 1],
                }
            )
            port_index += 2
    return schedule


def prepare(args: argparse.Namespace) -> int:
    if args.repetitions != 10:
        raise SystemExit("The frozen protocol specifies exactly 10 randomized blocks (30 trials).")
    out = args.campaign_dir.resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"Refusing to overwrite nonempty campaign directory: {out}")
    out.mkdir(parents=True, exist_ok=True)
    frozen = out / "frozen-source"
    frozen.mkdir(exist_ok=True)
    frozen_controller = frozen / Path(__file__).name
    frozen_controller.write_bytes(Path(__file__).resolve().read_bytes())
    frozen_runner = frozen / RUNNER.name
    frozen_runner.write_bytes(RUNNER.read_bytes())
    frozen_analyzer = frozen / ANALYZER.name
    frozen_analyzer.write_bytes(ANALYZER.read_bytes())
    frozen_protocol = frozen / PROTOCOL_TEMPLATE.name
    frozen_protocol.write_bytes(PROTOCOL_TEMPLATE.read_bytes())
    schedule = create_schedule(args.seed, args.repetitions)
    (out / "PROTOCOL.md").write_bytes(frozen_protocol.read_bytes())
    write_json(
        out / "schedule.json", {"seed": args.seed, "blocks": args.repetitions, "trials": schedule}
    )
    freeze = {
        "study_id": STUDY_ID,
        "frozen_at_utc": iso(utc_now()),
        "endpoint_id": HOST_ID,
        "endpoint_count": 1,
        "random_seed": args.seed,
        "repetitions_per_condition": args.repetitions,
        "assigned_trial_count": len(schedule),
        "source_hashes": {
            "controller_sha256": digest(frozen_controller),
            "windows_runner_sha256": digest(frozen_runner),
            "analyzer_sha256": digest(frozen_analyzer),
            "protocol_template_sha256": digest(frozen_protocol),
            "protocol_sha256": digest(out / "PROTOCOL.md"),
            "schedule_sha256": digest(out / "schedule.json"),
        },
        "git_metadata_available": (ROOT / ".git").exists(),
        "execution_status": "FROZEN_NOT_STARTED",
        "interpretation_boundary": (
            "single-host benign listener mechanism; no attack-efficacy or permanent-loss claim"
        ),
    }
    write_json(out / "campaign-freeze.json", freeze)
    print(
        json.dumps(
            {
                "campaign_dir": str(out),
                "trial_count": len(schedule),
                "seed": args.seed,
                "freeze": freeze,
            },
            indent=2,
        )
    )
    return 0


def verify_freeze(campaign_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    freeze = read_json(campaign_dir / "campaign-freeze.json")
    schedule_data = read_json(campaign_dir / "schedule.json")
    expected = freeze["source_hashes"]
    actual = {
        "controller_sha256": digest(campaign_dir / "frozen-source" / Path(__file__).name),
        "windows_runner_sha256": digest(campaign_dir / "frozen-source" / RUNNER.name),
        "analyzer_sha256": digest(campaign_dir / "frozen-source" / ANALYZER.name),
        "protocol_template_sha256": digest(campaign_dir / "frozen-source" / PROTOCOL_TEMPLATE.name),
        "protocol_sha256": digest(campaign_dir / "PROTOCOL.md"),
        "schedule_sha256": digest(campaign_dir / "schedule.json"),
    }
    if actual != expected or digest(Path(__file__).resolve()) != expected["controller_sha256"]:
        raise RuntimeError(f"Frozen source/schedule hash mismatch: {actual}")
    trials = schedule_data["trials"]
    if len(trials) != freeze["assigned_trial_count"]:
        raise RuntimeError("Assigned schedule length does not match the freeze.")
    if (
        len({item["target_port"] for item in trials} | {item["distractor_port"] for item in trials})
        != len(trials) * 2
    ):
        raise RuntimeError("Port identities are not unique across the frozen schedule.")
    for block in range(1, freeze["repetitions_per_condition"] + 1):
        block_conditions = {item["condition"] for item in trials if item["block"] == block}
        if block_conditions != set(CONDITIONS):
            raise RuntimeError(f"Block {block} is incomplete or duplicates an arm.")
    return freeze, trials


def api_json(
    base_url: str, path: str, *, method: str = "GET", payload: Any = None, timeout: int = 45
) -> Any:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        f"{base_url.rstrip('/')}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except (HTTPError, URLError) as exc:
        raise RuntimeError(f"CSG API {method} {path} failed: {exc}") from exc


def run_command(command: list[str], *, timeout: int = 45) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)


def remote_state(control_socket: str, target: str, out_path: Path) -> dict[str, Any]:
    powershell = (
        "$os=Get-CimInstance Win32_OperatingSystem; "
        "$svc=Get-Service WazuhSvc; "
        "$task=Get-ScheduledTask -TaskName 'CyberStateGuardian Probe'; "
        "$audit=auditpol /get /subcategory:'Filtering Platform Connection'; "
        "[pscustomobject]@{ComputerName=$env:COMPUTERNAME;Caption=$os.Caption; "
        "Version=$os.Version;BuildNumber=$os.BuildNumber;WazuhService=$svc.Status.ToString(); "
        "ProbeTask=$task.State.ToString();AuditPolicy=($audit -join ' ')} | "
        "ConvertTo-Json -Compress"
    )
    command = [
        "ssh",
        "-T",
        "-S",
        control_socket,
        "-o",
        "ConnectTimeout=8",
        target,
        f'powershell.exe -NoLogo -NoProfile -Command "{powershell}"',
    ]
    result = run_command(command, timeout=20)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(result.stdout + result.stderr, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(
            f"Windows read-only preflight failed ({result.returncode}). See {out_path}"
        )
    start = result.stdout.find("{")
    if start < 0:
        raise RuntimeError(f"Windows preflight did not return JSON. See {out_path}")
    value, _ = json.JSONDecoder().raw_decode(result.stdout[start:])
    return value


def compact_state(snapshot: dict[str, Any], object_key: str) -> dict[str, Any]:
    return {
        "snapshot_id": snapshot.get("snapshot_id"),
        "host_id": snapshot.get("host_id"),
        "built_at": snapshot.get("built_at"),
        "source": snapshot.get("source"),
        "category_statuses": [
            status
            for status in snapshot.get("category_statuses", [])
            if status.get("category") == "listener"
        ],
        "objects": [
            obj for obj in snapshot.get("objects", []) if obj.get("object_key") == object_key
        ],
    }


def get_state(base_url: str, object_key: str) -> dict[str, Any]:
    snapshot = api_json(base_url, f"/api/hosts/{HOST_ID}/state/latest", timeout=60)
    if snapshot is None:
        raise RuntimeError("CSG has no latest probe snapshot.")
    return compact_state(snapshot, object_key)


def query_api_items(base_url: str, endpoint: str, params: dict[str, Any]) -> Any:
    return api_json(base_url, f"{endpoint}?{urlencode(params)}", timeout=60)


def events_for_key(events: list[dict[str, Any]], object_key: str) -> list[dict[str, Any]]:
    return [
        event
        for event in events
        if event.get("normalized_type") == "listener_created"
        and (event.get("target") or {}).get("key") == object_key
    ]


def local_events_for_port(runner: dict[str, Any], port: int) -> list[dict[str, Any]]:
    return [
        event
        for event in runner.get("local_5154_events", [])
        if event.get("fields", {}).get("SourceAddress") == "127.0.0.1"
        and event.get("fields", {}).get("SourcePort") == str(port)
        and event.get("fields", {}).get("Protocol") == "6"
    ]


def windows_identity(event: dict[str, Any]) -> dict[str, Any]:
    return (event.get("metadata") or {}).get("windows_event_identity") or {}


def query_keys(
    campaign_dir: Path, trial: dict[str, Any], base_url: str, runner: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = campaign_dir / "slots" / f"slot-{trial['slot']:03d}" / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    start = datetime.fromisoformat(runner["started_utc"].replace("Z", "+00:00")) - timedelta(
        seconds=5
    )
    cutoff = datetime.fromisoformat(runner["completed_utc"].replace("Z", "+00:00")) + timedelta(
        seconds=60
    )
    attempts: list[dict[str, Any]] = []
    latest: dict[str, Any] | None = None
    number = 0
    while True:
        number += 1
        end = utc_now()
        params = {"start": iso(start), "end": iso(end)}
        latest = query_api_items(
            base_url, f"/api/hosts/{HOST_ID}/provider-event-observation", params
        )
        events = latest.get("events", [])
        target_key = f"listener:tcp:127.0.0.1:{trial['target_port']}"
        distractor_key = f"listener:tcp:127.0.0.1:{trial['distractor_port']}"
        target_count = len(events_for_key(events, target_key))
        distractor_count = len(events_for_key(events, distractor_key))
        attempts.append(
            {
                "attempt": number,
                "query_started_after_action_utc": iso(end),
                "query_complete": latest.get("query_complete"),
                "coverage_status": latest.get("coverage_status"),
                "endpoint_collection_status": latest.get("endpoint_collection_status"),
                "transport_status": latest.get("transport_status"),
                "index_status": latest.get("index_status"),
                "retrieved_count": latest.get("retrieved_count"),
                "total_hits": latest.get("total_hits"),
                "target_exact_event_count": target_count,
                "distractor_exact_event_count": distractor_count,
            }
        )
        now = utc_now()
        if now >= cutoff:
            break
        time.sleep(min(10, max(0.1, (cutoff - now).total_seconds())))

    assert latest is not None
    write_json(raw / "wazuh-observation-final.json", latest)
    (raw / "wazuh-query-attempts.jsonl").write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in attempts), encoding="utf-8"
    )
    submitted = dict(latest)
    submitted["metadata"] = {
        **(latest.get("metadata") or {}),
        "query_start": iso(start),
        "query_end": iso(utc_now()),
        "study_id": STUDY_ID,
        "trial_id": trial["trial_id"],
        "condition": trial["condition"],
        "post_action_grace_seconds": 60,
    }
    write_json(raw / "csg-event-observation-submitted.json", submitted)
    ingest = api_json(
        base_url,
        f"/api/hosts/{HOST_ID}/event-observations",
        method="POST",
        payload=submitted,
        timeout=90,
    )
    write_json(raw / "csg-event-observation-ingest.json", ingest)
    return latest, ingest


def fetch_trial_pipeline(
    campaign_dir: Path,
    trial: dict[str, Any],
    base_url: str,
    started_at: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    raw = campaign_dir / "slots" / f"slot-{trial['slot']:03d}" / "raw"
    key = f"listener:tcp:127.0.0.1:{trial['target_port']}"
    params = {"object_key": key, "category": "listener", "limit": 500}
    deltas = query_api_items(base_url, f"/api/hosts/{HOST_ID}/deltas", params)
    findings = query_api_items(
        base_url,
        "/api/findings",
        {
            "host_id": HOST_ID,
            "object_key": key,
            "category": "listener",
            "created_after": started_at,
            "limit": 500,
        },
    )
    write_json(raw / "csg-target-deltas.json", deltas)
    write_json(raw / "csg-target-findings.json", findings)
    return deltas, findings


def stored_events_for_key(
    campaign_dir: Path,
    trial: dict[str, Any],
    base_url: str,
    object_key: str,
    query_start: str,
    query_end: str,
    filename: str,
) -> list[dict[str, Any]]:
    events = query_api_items(
        base_url,
        f"/api/hosts/{HOST_ID}/events",
        {
            "object_key": object_key,
            "normalized_type": "listener_created",
            "start": query_start,
            "end": query_end,
            "limit": 5000,
        },
    )
    write_json(campaign_dir / "slots" / f"slot-{trial['slot']:03d}" / "raw" / filename, events)
    return events


def run_trial(
    campaign_dir: Path,
    trial: dict[str, Any],
    base_url: str,
    target: str,
    control_socket: str,
    remote_runner: str,
    expected_agent_id: str,
) -> dict[str, Any]:
    slot_dir = campaign_dir / "slots" / f"slot-{trial['slot']:03d}"
    raw_dir = slot_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    target_key = f"listener:tcp:127.0.0.1:{trial['target_port']}"
    distractor_key = f"listener:tcp:127.0.0.1:{trial['distractor_port']}"
    before = get_state(base_url, target_key)
    write_json(raw_dir / "csg-state-before.json", before)
    if before["objects"]:
        raise RuntimeError(f"Assigned target port exists in baseline snapshot: {target_key}")

    local_started = iso(utc_now())
    remote_output = f"C:\\CSG\\results\\{STUDY_ID}-{trial['trial_id']}.json"
    command = [
        "ssh",
        "-T",
        "-S",
        control_socket,
        "-o",
        "ConnectTimeout=8",
        target,
        f"powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File {remote_runner} "
        f"-TrialId {trial['trial_id']} -Condition {trial['condition']} "
        f"-TargetPort {trial['target_port']} -DistractorPort {trial['distractor_port']} "
        f"-OutputPath {remote_output} -ObservationSeconds 75 -DistractorSeconds 2",
    ]
    result = run_command(command, timeout=240)
    (raw_dir / "windows-runner-stdout.txt").write_text(result.stdout, encoding="utf-8")
    (raw_dir / "windows-runner-stderr.txt").write_text(result.stderr, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(
            f"Windows trial {trial['trial_id']} failed with exit {result.returncode}; "
            "raw output preserved."
        )
    json_start = result.stdout.find("{")
    if json_start < 0:
        raise RuntimeError(f"Windows trial {trial['trial_id']} returned no result JSON.")
    runner, _ = json.JSONDecoder().raw_decode(result.stdout[json_start:])
    write_json(raw_dir / "windows-runner.json", runner)
    if runner.get("failure"):
        raise RuntimeError(f"Windows trial {trial['trial_id']} reported failure.")
    if not runner.get("audit_restored_to_baseline"):
        raise RuntimeError(f"WFP audit restore gate failed for {trial['trial_id']}.")
    postflight = runner.get("postflight", {})
    if any(postflight.get(name) != "Running" for name in ("wazuh_service", "probe_task")):
        raise RuntimeError(f"Source health postflight failed for {trial['trial_id']}.")
    if not postflight.get("target_port_absent") or not postflight.get("distractor_port_absent"):
        raise RuntimeError(f"Socket cleanup gate failed for {trial['trial_id']}.")

    observation, ingest = query_keys(campaign_dir, trial, base_url, runner)
    after = get_state(base_url, target_key)
    write_json(raw_dir / "csg-state-after.json", after)
    start_query = iso(
        datetime.fromisoformat(runner["started_utc"].replace("Z", "+00:00")) - timedelta(seconds=5)
    )
    deltas, findings = fetch_trial_pipeline(campaign_dir, trial, base_url, start_query)
    add_deltas = [delta for delta in deltas if str(delta.get("delta_type", "")).upper() == "ADD"]
    add_delta_ids = {delta.get("delta_id") for delta in add_deltas}
    add_findings = [finding for finding in findings if finding.get("delta_id") in add_delta_ids]
    if trial["condition"] != "no_change_with_distractor":
        deadline = time.monotonic() + 180
        while not add_deltas and time.monotonic() < deadline:
            time.sleep(5)
            deltas, findings = fetch_trial_pipeline(campaign_dir, trial, base_url, start_query)
            add_deltas = [
                delta for delta in deltas if str(delta.get("delta_type", "")).upper() == "ADD"
            ]
            add_delta_ids = {delta.get("delta_id") for delta in add_deltas}
            add_findings = [
                finding for finding in findings if finding.get("delta_id") in add_delta_ids
            ]
        deadline = time.monotonic() + 240
        while (
            add_findings
            and not any(
                (item.get("reconciliation") or {}).get("finalized") for item in add_findings
            )
            and time.monotonic() < deadline
        ):
            time.sleep(5)
            deltas, findings = fetch_trial_pipeline(campaign_dir, trial, base_url, start_query)
            add_deltas = [
                delta for delta in deltas if str(delta.get("delta_type", "")).upper() == "ADD"
            ]
            add_delta_ids = {delta.get("delta_id") for delta in add_deltas}
            add_findings = [
                finding for finding in findings if finding.get("delta_id") in add_delta_ids
            ]

    target_local = local_events_for_port(runner, trial["target_port"])
    distractor_local = local_events_for_port(runner, trial["distractor_port"])
    observed_events = observation.get("events", [])
    target_wazuh = events_for_key(observed_events, target_key)
    distractor_wazuh = events_for_key(observed_events, distractor_key)
    query_end = (observation.get("metadata", {}).get("retrieval", {}) or {}).get("end") or iso(
        utc_now()
    )
    stored_target = stored_events_for_key(
        campaign_dir,
        trial,
        base_url,
        target_key,
        start_query,
        query_end,
        "csg-stored-target-events.json",
    )
    stored_distractor = stored_events_for_key(
        campaign_dir,
        trial,
        base_url,
        distractor_key,
        start_query,
        query_end,
        "csg-stored-distractor-events.json",
    )
    add_finding = next(
        (item for item in add_findings if (item.get("reconciliation") or {}).get("finalized")),
        add_findings[-1] if add_findings else None,
    )
    reconciliation = (add_finding or {}).get("reconciliation") or {}
    expected_target_local = 1 if trial["condition"] == "complete_exact" else 0
    expected_target_wazuh = expected_target_local
    target_record_ids = {str(item.get("event_record_id")) for item in target_local}
    distractor_record_ids = {str(item.get("event_record_id")) for item in distractor_local}

    def joined_event_ids(events: list[dict[str, Any]], record_ids: set[str]) -> set[str]:
        return {
            str(event.get("event_id"))
            for event in events
            if event.get("host_id") == HOST_ID
            if str(windows_identity(event).get("event_record_id")) in record_ids
            and str(windows_identity(event).get("agent_id")) == expected_agent_id
            and windows_identity(event).get("event_code") == "5154"
            and windows_identity(event).get("channel", "").lower() == "security"
            and (event.get("source_reference") or {}).get("document_id")
        }

    joined_target_ids = joined_event_ids(target_wazuh, target_record_ids)
    joined_distractor_ids = joined_event_ids(distractor_wazuh, distractor_record_ids)
    joined_stored_target_ids = joined_event_ids(stored_target, target_record_ids)
    joined_stored_distractor_ids = joined_event_ids(stored_distractor, distractor_record_ids)
    matched_ids = set(reconciliation.get("matched_evidence_ids", []))
    summary = {
        **trial,
        "target_object_key": target_key,
        "distractor_object_key": distractor_key,
        "driver_started_utc": local_started,
        "windows_runner_exit_code": result.returncode,
        "local_target_5154_count": len(target_local),
        "local_distractor_5154_count": len(distractor_local),
        "local_target_event_record_ids": sorted(target_record_ids),
        "local_distractor_event_record_ids": sorted(distractor_record_ids),
        "wazuh_target_event_count": len(target_wazuh),
        "wazuh_distractor_event_count": len(distractor_wazuh),
        "target_wazuh_ids_linked_to_local_event": sorted(joined_target_ids),
        "distractor_wazuh_ids_linked_to_local_event": sorted(joined_distractor_ids),
        "target_csg_stored_ids_linked_to_local_event": sorted(joined_stored_target_ids),
        "distractor_csg_stored_ids_linked_to_local_event": sorted(joined_stored_distractor_ids),
        "stored_csg_target_event_count": len(stored_target),
        "stored_csg_distractor_event_count": len(stored_distractor),
        "wazuh_query_complete": observation.get("query_complete"),
        "wazuh_coverage_status": observation.get("coverage_status"),
        "wazuh_endpoint_collection_status": observation.get("endpoint_collection_status"),
        "wazuh_transport_status": observation.get("transport_status"),
        "wazuh_index_status": observation.get("index_status"),
        "csg_state_add_count": len(add_deltas),
        "csg_state_add_observed": bool(add_deltas),
        "csg_target_finding_count": len(add_findings),
        "csg_target_reconciliation_status": reconciliation.get("status"),
        "csg_target_reconciliation_finalized": reconciliation.get("finalized"),
        "csg_target_matched_evidence_ids": reconciliation.get("matched_evidence_ids", []),
        "csg_ingest_reconciliation_updates": ingest.get("reconciliation_updates"),
        "target_absent_from_latest_snapshot_after_cleanup": not after["objects"],
        "target_state_after_attributes": add_deltas[0].get("after") if add_deltas else None,
        "target_delta_ids": [delta.get("delta_id") for delta in deltas],
        "target_finding_ids": [finding.get("finding_id") for finding in findings],
        "assigned_gate_status": "unvalidated",
    }
    summary["assigned_gate_status"] = (
        "passed"
        if (
            runner.get("target_event_count") == expected_target_local
            and len(target_local) == expected_target_local
            and len(distractor_local) == 1
            and len(joined_target_ids) >= expected_target_wazuh
            and len(joined_distractor_ids) >= 1
            and len(joined_stored_target_ids) >= expected_target_wazuh
            and len(joined_stored_distractor_ids) >= 1
            and observation.get("query_complete") is True
            and observation.get("coverage_status") == "COMPLETE"
            and observation.get("endpoint_collection_status") == "AVAILABLE"
            and observation.get("transport_status") == "AVAILABLE"
            and observation.get("index_status") == "AVAILABLE"
            and runner.get("local_event_query_status")
            in ("COMPLETE_WITH_EVENTS", "COMPLETE_NO_MATCHES")
            and (
                trial["condition"] == "complete_exact"
                and "Success" in (runner.get("target_audit_policy") or "")
                or trial["condition"] != "complete_exact"
                and "No Auditing" in (runner.get("target_audit_policy") or "")
            )
            and summary["target_absent_from_latest_snapshot_after_cleanup"]
            and (
                trial["condition"] == "no_change_with_distractor"
                and not deltas
                and not findings
                or trial["condition"] == "complete_exact"
                and bool(add_deltas)
                and reconciliation.get("status") == "CONSISTENT"
                and reconciliation.get("finalized") is True
                and bool(matched_ids)
                and matched_ids <= joined_target_ids
                and not (matched_ids & joined_distractor_ids)
                or trial["condition"] == "target_event_absent_with_distractor"
                and bool(add_deltas)
                and reconciliation.get("status") == "UNEXPLAINED"
                and reconciliation.get("finalized") is True
                and not reconciliation.get("matched_evidence_ids")
            )
        )
        else "failed"
    )
    write_json(raw_dir / "trial-summary.json", summary)
    return summary


def run_campaign(args: argparse.Namespace) -> int:
    campaign_dir = args.campaign_dir.resolve()
    freeze, trials = verify_freeze(campaign_dir)
    if (campaign_dir / "campaign-progress.json").exists():
        raise SystemExit("Campaign already has progress; refusing to start or restart it.")
    health = api_json(args.api_url, "/health")
    wazuh = api_json(args.api_url, "/api/wazuh/status")
    if health.get("status") != "ok":
        raise RuntimeError(f"CSG API health check is not ok: {health}")
    if not wazuh.get("enabled") or not wazuh.get("ok"):
        raise RuntimeError(f"Wazuh integration is not healthy: {wazuh.get('warnings')}")
    endpoint_agent = next(
        (
            agent
            for agent in wazuh.get("agents", [])
            if agent.get("name") == HOST_ID and not agent.get("manager")
        ),
        None,
    )
    if not endpoint_agent or endpoint_agent.get("status") != "active":
        raise RuntimeError("The expected active Windows Wazuh agent is unavailable.")
    expected_agent_id = str(endpoint_agent["id"])
    socket_check = run_command(
        ["ssh", "-S", args.ssh_control_socket, "-O", "check", args.ssh_target], timeout=10
    )
    if socket_check.returncode:
        raise RuntimeError(
            "The existing SSH control connection is not available; no trial was started."
        )
    remote = remote_state(
        args.ssh_control_socket,
        args.ssh_target,
        campaign_dir / "preflight" / "windows-preflight.txt",
    )
    if remote.get("WazuhService") != "Running" or remote.get("ProbeTask") != "Running":
        raise RuntimeError(f"Windows source preflight is unhealthy: {remote}")
    if "No Auditing" not in remote.get("AuditPolicy", ""):
        raise RuntimeError(f"WFP audit baseline is not No Auditing: {remote}")
    write_json(campaign_dir / "preflight" / "csg-health.json", health)
    write_json(campaign_dir / "preflight" / "wazuh-status.json", wazuh)
    inspect = run_command(
        ["docker", "inspect", "--format={{.Name}} {{.Image}}", "csg-api", "csg-worker"], timeout=10
    )
    (campaign_dir / "preflight" / "container-images.txt").write_text(
        inspect.stdout + inspect.stderr, encoding="utf-8"
    )
    source = campaign_dir / "frozen-source" / RUNNER.name
    remote_runner = "C:\\CSG\\run_listener_wfp5154_trial_windows.ps1"
    copy = run_command(
        [
            "scp",
            "-o",
            f"ControlPath={args.ssh_control_socket}",
            "-o",
            "ConnectTimeout=8",
            str(source),
            f"{args.ssh_target}:C:/CSG/{RUNNER.name}",
        ],
        timeout=30,
    )
    (campaign_dir / "preflight" / "runner-upload.txt").write_text(
        copy.stdout + copy.stderr, encoding="utf-8"
    )
    if copy.returncode:
        raise RuntimeError("Could not upload the frozen Windows runner; no trial was started.")
    progress = {
        "study_id": STUDY_ID,
        "started_at_utc": iso(utc_now()),
        "completed_slots": [],
        "status": "RUNNING",
    }
    write_json(campaign_dir / "campaign-progress.json", progress)
    summaries: list[dict[str, Any]] = []
    for trial in trials:
        print(
            f"START {trial['trial_id']} block={trial['block']} "
            f"condition={trial['condition']} target={trial['target_port']} "
            f"distractor={trial['distractor_port']}",
            flush=True,
        )
        try:
            summary = run_trial(
                campaign_dir,
                trial,
                args.api_url,
                args.ssh_target,
                args.ssh_control_socket,
                remote_runner,
                expected_agent_id,
            )
        except Exception as exc:
            progress.update(
                {
                    "status": "STOPPED_ON_SAFETY_OR_CAPTURE_FAILURE",
                    "stopped_at_trial": trial["trial_id"],
                    "error": str(exc),
                }
            )
            write_json(campaign_dir / "campaign-progress.json", progress)
            print(f"STOP {trial['trial_id']}: {exc}", flush=True)
            raise
        summaries.append(summary)
        progress["completed_slots"].append(trial["trial_id"])
        progress["last_gate_status"] = summary["assigned_gate_status"]
        write_json(campaign_dir / "campaign-progress.json", progress)
        print(
            f"DONE {trial['trial_id']} gate={summary['assigned_gate_status']} "
            f"CSG={summary['csg_target_reconciliation_status']} "
            f"target_events={summary['wazuh_target_event_count']} "
            f"distractor_events={summary['wazuh_distractor_event_count']}",
            flush=True,
        )
    progress.update({"status": "EXECUTION_COMPLETE", "completed_at_utc": iso(utc_now())})
    write_json(campaign_dir / "campaign-progress.json", progress)
    write_json(campaign_dir / "trial-summaries.json", summaries)
    print(
        f"EXECUTION_COMPLETE {len(summaries)}/{len(trials)} assigned slots; "
        "run the independent analyzer next.",
        flush=True,
    )
    return 0


def self_test() -> int:
    schedule = create_schedule(53020261016, 10)
    assert len(schedule) == 30
    assert (
        len({row["target_port"] for row in schedule} | {row["distractor_port"] for row in schedule})
        == 60
    )
    assert all(
        {row["condition"] for row in schedule if row["block"] == block} == set(CONDITIONS)
        for block in range(1, 11)
    )
    assert events_for_key([{"normalized_type": "listener_created", "target": {"key": "x"}}], "x")
    assert not events_for_key(
        [{"normalized_type": "listener_created", "target": {"key": "y"}}], "x"
    )
    print("Self-test passed: 30 assignments, randomized blocks, unique ports, exact-key selector.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--campaign-dir", type=Path, required=True)
    prepare_parser.add_argument("--seed", type=int, default=53020261016)
    prepare_parser.add_argument("--repetitions", type=int, default=10)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--campaign-dir", type=Path, required=True)
    run_parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    run_parser.add_argument("--ssh-target", default="Hemant@192.168.64.5")
    run_parser.add_argument("--ssh-control-socket", required=True)
    subparsers.add_parser("self-test")
    args = parser.parse_args()
    if args.command == "prepare":
        return prepare(args)
    if args.command == "run":
        return run_campaign(args)
    return self_test()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(
            "Interrupted; current assigned slot and cleanup state must be inspected before resume.",
            file=sys.stderr,
        )
        raise SystemExit(130) from None
