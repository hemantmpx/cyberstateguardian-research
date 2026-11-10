from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER = REPO_ROOT / "scripts" / "verify_wazuh_active_eventchannel_query.py"
CONFIG_SHA256 = "0e2eec247d4e645112f5dedc6f80e1713e2377f08ec2bbf7dc5e9cd4059ec3c1"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def encoded_powershell(command: str) -> str:
    return base64.b64encode(command.encode("utf-16le")).decode("ascii")


def run_ssh(
    args: argparse.Namespace, command: str, *, capture: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "ssh",
            "-S",
            str(args.control_path),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            "-T",
            args.ssh_target,
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
            f"{encoded_powershell(command)}",
        ],
        check=False,
        capture_output=capture,
        text=True,
    )


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def verify_active_query(
    args: argparse.Namespace, expected_b64: str, output_path: Path
) -> dict[str, Any]:
    environment = os.environ.copy()
    python_path = [str(REPO_ROOT / "backend")]
    if environment.get("PYTHONPATH"):
        python_path.append(environment["PYTHONPATH"])
    environment["PYTHONPATH"] = os.pathsep.join(python_path)
    completed = subprocess.run(
        [
            sys.executable,
            str(VERIFIER),
            "--api-url",
            args.wazuh_api_url,
            "--expected-query-base64",
            expected_b64,
            "--output",
            str(output_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    if not output_path.is_file():
        raise RuntimeError(
            f"Wazuh query verifier produced no audit file: {completed.stderr[-500:]}"
        )
    audit = json.loads(output_path.read_text(encoding="utf-8"))
    if (
        completed.returncode != 0
        or audit.get("schema_version") != "csg-wazuh-active-eventchannel-query-v1"
        or audit.get("agent_id") != "001"
        or audit.get("channel") != "Security"
        or audit.get("api_error") != 0
        or audit.get("security_localfile_block_count") != 1
        or audit.get("matches_expected_query") is not True
    ):
        raise RuntimeError(
            f"Live Wazuh active-query check rejected: {audit.get('error', 'hash/schema mismatch')}"
        )
    return audit


def write_remote_approval(
    args: argparse.Namespace, remote_path: str, audit: dict[str, Any]
) -> None:
    payload_b64 = base64.b64encode(
        (json.dumps(audit, indent=2, sort_keys=True) + "\n").encode("utf-8")
    ).decode("ascii")
    command = (
        f"$bytes=[Convert]::FromBase64String('{payload_b64}');"
        f"[IO.File]::WriteAllBytes({ps_quote(remote_path)},$bytes)"
    )
    result = run_ssh(args, command)
    if result.returncode:
        raise RuntimeError(f"Could not transfer active-query approval: {result.stderr[-500:]}")


def assess_controller_result(result_path: Path) -> dict[str, Any]:
    if not result_path.is_file():
        return {"result_present": False, "strict_trial_pass": False, "safe_to_continue": False}
    result = json.loads(result_path.read_text(encoding="utf-8-sig"))
    reconciliation = result.get("final_target_reconciliation") or {}
    metadata = reconciliation.get("metadata") or {}
    event_plane = metadata.get("event_plane") or {}
    restoration = result.get("restoration") or {}
    health = restoration.get("endpoint_health") or {}
    strict = all(
        [
            result.get("capture_gates_passed") is True,
            result.get("paired_wrong_object_trial_passed") is True,
            result.get("direct_probe_state_sequence_passed") is True,
            result.get("target_absent_from_csg_event_store_during_filter") is True,
            result.get("query_complete_during_filter") is True,
            result.get("distractor_inside_final_reconciliation_window") is True,
            reconciliation.get("status") == "UNEXPLAINED",
            reconciliation.get("finalized") is True,
            reconciliation.get("matched_evidence_ids") == [],
            event_plane.get("query_complete") is True,
            event_plane.get("coverage_status") == "COMPLETE",
            event_plane.get("endpoint_collection_status") == "AVAILABLE",
            event_plane.get("transport_status") == "AVAILABLE",
            event_plane.get("index_status") == "AVAILABLE",
        ]
    )
    safe = all(
        [
            result.get("cleanup_verified") is True,
            result.get("restored_hash_matches_original") is True,
            restoration.get("hash_restored") is True,
            health.get("csg_api_healthy") is True,
            health.get("wazuh_server_api_healthy") is True,
            health.get("wazuh_indexer_healthy") is True,
            health.get("endpoint_agent_status") == "active",
            any(
                service.get("name") == "WazuhSvc" and service.get("state") == "Running"
                for service in health.get("services", [])
            ),
        ]
    )
    return {
        "result_present": True,
        "controller_status": result.get("status"),
        "strict_trial_pass": strict,
        "safe_to_continue": safe,
        "cleanup_verified": result.get("cleanup_verified"),
        "config_restored": restoration.get("hash_restored"),
        "final_reconciliation_status": reconciliation.get("status"),
        "final_reconciliation_version": reconciliation.get("version"),
        "matched_evidence_ids": reconciliation.get("matched_evidence_ids"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run frozen v50 capture-drop/distractor assignments."
    )
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--ssh-target", default="Hemant@192.168.64.5")
    parser.add_argument("--control-path", type=Path, default=Path("/tmp/csg-v41-ssh.sock"))
    parser.add_argument("--wazuh-api-url", default="https://localhost:55000")
    parser.add_argument(
        "--windows-controller",
        default="C:/CSG/research-v50/run_scheduled_task_eventid_filter_diagnostic_v15_windows.ps1",
    )
    parser.add_argument(
        "--windows-runner",
        default="C:/CSG/research-v50/run_windows_category_same_window_distractor_v15.ps1",
    )
    parser.add_argument("--windows-output-root", default="C:/CSG/results/research-v50")
    parser.add_argument("--csg-api-base", default="http://192.168.64.1:8000")
    parser.add_argument(
        "--trial-id", action="append", help="Run only listed frozen trial(s); repeatable."
    )
    parser.add_argument(
        "--resume-after-pre-mutation-failure",
        action="store_true",
        help=(
            "Resume remaining assignments after validating pre-mutation failure "
            "and clean endpoint state."
        ),
    )
    parser.add_argument(
        "--resume-after-v50-verified-gate-abort",
        action="store_true",
        help="Resume only the remaining v50 assignments after its verified pre-action gate abort.",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_dir = args.run_dir.resolve()
    schedule = json.loads((run_dir / "schedule.json").read_text(encoding="utf-8"))
    trials = schedule["trials"]
    campaign_path = run_dir / "campaign-summary.json"
    prior = (
        json.loads(campaign_path.read_text(encoding="utf-8")) if campaign_path.exists() else None
    )
    prior_attempts = prior.get("attempts", []) if prior else []
    prior_ids = {attempt["trial_id"] for attempt in prior_attempts}
    if prior and prior.get("status") == "STOPPED_FOR_SAFETY_OR_EXECUTION_FAILURE":
        if args.resume_after_v50_verified_gate_abort:
            trial_dir = run_dir / "trial-01"
            controller_path = trial_dir / "windows-raw" / "trial-01" / "result.json"
            safety_path = trial_dir / "post-launch-safety-check.json"
            query_path = trial_dir / "baseline-query-after-abort.json"
            filtered_query_path = (
                trial_dir / "preflight" / "active-query-filtered-readonly-diagnostic.json"
            )
            controller = json.loads(controller_path.read_text(encoding="utf-8-sig"))
            safety = json.loads(safety_path.read_text(encoding="utf-8"))
            query = json.loads(query_path.read_text(encoding="utf-8"))
            filtered_query = json.loads(filtered_query_path.read_text(encoding="utf-8"))
            failed = next(
                (item for item in prior_attempts if item["trial_id"] == "trial-01"), None
            )
            health = controller.get("restoration", {}).get("endpoint_health", {})
            remaining_ids = {
                trial["trial_id"]
                for trial in schedule["trials"]
                if trial["trial_id"] not in prior_ids
            }
            selected_ids = set(args.trial_id or [])
            if not (
                len(prior_attempts) == 1
                and failed
                and failed.get("controller_exit_code") == 0
                and failed.get("active_query_gate_seen") is True
                and failed.get("active_query_approved") is False
                and not failed.get("assessment", {}).get("safe_to_continue")
                and controller.get("status") == "INCOMPLETE_OR_INVALID"
                and controller.get("active_query_gate", {}).get("status")
                == "ABORTED_BEFORE_TASK_ACTION_APPROVAL_TIMEOUT"
                and controller.get("target_task_name") is None
                and controller.get("distractor_task_name") is None
                and controller.get("residual_study_tasks") == []
                and controller.get("restoration", {}).get("hash_restored") is True
                and controller.get("restoration", {}).get("restored_config_sha256") == CONFIG_SHA256
                and controller.get("restoration", {}).get("service_restart", {}).get("status")
                == "RESTART_CONFIRMED"
                and health.get("csg_api_healthy") is True
                and health.get("wazuh_server_api_healthy") is True
                and health.get("wazuh_indexer_healthy") is True
                and health.get("endpoint_agent_status") == "active"
                and safety.get("agent_config_sha256") == CONFIG_SHA256
                and safety.get("study_task_names") == []
                and safety.get("probe_state") == "Ready"
                and safety.get("probe_enabled") is True
                and {item["name"]: item["state"] for item in safety.get("services", [])}
                == {"WazuhSvc": "Running", "Sysmon64a": "Running"}
                and query.get("active_query_sha256_normalized")
                == "cc9a4c11bde78e37b451ed918fd66d299f0f0d0369383f8878845f31d4c9ce37"
                and query.get("matches_expected_query") is True
                and query.get("api_error") == 0
                and filtered_query.get("matches_expected_query") is True
                and filtered_query.get("expected_query_sha256_normalized")
                == controller.get("active_query_gate", {}).get("expected_query_sha256")
                and selected_ids == remaining_ids
            ):
                raise SystemExit(
                    "Recorded gate-abort and fresh safety evidence do not authorize resume."
                )
        elif args.resume_after_pre_mutation_failure:
            safety_path = run_dir / "trial-01" / "post-launch-safety-check.json"
            query_path = run_dir / "trial-01" / "baseline-query-after-launch-failure.json"
            log_path = run_dir / "trial-01" / "controller-console.txt"
            safety = json.loads(safety_path.read_text(encoding="utf-8"))
            query = json.loads(query_path.read_text(encoding="utf-8"))
            failed = next((item for item in prior_attempts if item["trial_id"] == "trial-01"), None)
            if not (
                failed
                and failed.get("controller_exit_code") == 1
                and not failed.get("active_query_gate_seen")
                and not failed.get("assessment", {}).get("result_present")
                and log_path.exists()
                and "running scripts is disabled" in log_path.read_text(encoding="utf-8").lower()
                and safety.get("agent_config_sha256") == CONFIG_SHA256
                and safety.get("study_task_count") == 0
                and safety.get("probe_state") == "Ready"
                and safety.get("probe_enabled") is True
                and {item["name"]: item["state"] for item in safety.get("services", [])}
                == {"WazuhSvc": "Running", "Sysmon64a": "Running"}
                and query.get("active_query_sha256_normalized")
                == "cc9a4c11bde78e37b451ed918fd66d299f0f0d0369383f8878845f31d4c9ce37"
                and query.get("api_error") == 0
            ):
                raise SystemExit(
                    "Post-failure safety evidence does not authorize resuming the cohort."
                )
        else:
            raise SystemExit("Campaign stopped; explicit verified-resume flag is required.")

    if args.trial_id:
        selected = set(args.trial_id)
        assigned = {trial["trial_id"] for trial in trials}
        if not selected <= assigned:
            raise SystemExit("Unknown or duplicate trial id in --trial-id")
        if selected & prior_ids:
            raise SystemExit("Refusing to rerun an already attempted assigned trial")
        if args.resume_after_v50_verified_gate_abort and selected != {
            trial["trial_id"] for trial in schedule["trials"] if trial["trial_id"] not in prior_ids
        }:
            raise SystemExit("Verified v50 resume must include every remaining frozen assignment.")
        trials = [trial for trial in trials if trial["trial_id"] in selected]
    else:
        trials = [trial for trial in trials if trial["trial_id"] not in prior_ids]
    if not trials:
        raise SystemExit("No assigned trials selected")

    campaign = prior or {
        "schema_version": "csg-live-campaign-execution-v1",
        "experiment_id": schedule["experiment_id"],
        "started_at_utc": utc_now(),
        "assigned_count": len(schedule["trials"]),
        "attempts": [],
    }
    campaign["selected_trial_ids"] = list(
        dict.fromkeys(
            campaign.get("selected_trial_ids", []) + [trial["trial_id"] for trial in trials]
        )
    )
    campaign["status"] = "DRY_RUN" if args.dry_run else "RUNNING"
    if args.dry_run:
        for trial in trials:
            print(
                json.dumps(
                    {
                        "trial_id": trial["trial_id"],
                        "target": trial["target_task_name"],
                        "distractor": trial["distractor_task_name"],
                        "remote_output": f"{args.windows_output_root}/{trial['trial_id']}",
                    }
                )
            )
        return 0

    expected_config_hash = CONFIG_SHA256
    for trial in trials:
        trial_id = trial["trial_id"]
        trial_dir = run_dir / trial_id
        raw_dir = trial_dir / "windows-raw"
        trial_dir.mkdir(parents=True, exist_ok=False)
        raw_dir.mkdir()
        remote_output = f"{args.windows_output_root}/{trial_id}"
        remote_approval = f"{remote_output}/active-query-approval.json"
        approval_seen = False
        approval_ok = False
        started = utc_now()

        ps_command = " ".join(
            [
                f"& {ps_quote(args.windows_controller)}",
                f"-ExpectedAgentConfigSha256 {ps_quote(expected_config_hash)}",
                f"-OutputDirectory {ps_quote(remote_output)}",
                f"-CsgApiBase {ps_quote(args.csg_api_base)}",
                "-HostId 'win11-arm-lab'",
                f"-ScheduledTaskName {ps_quote(trial['target_task_name'])}",
                f"-DistractorTaskName {ps_quote(trial['distractor_task_name'])}",
                f"-RunnerPath {ps_quote(args.windows_runner)}",
                "-FilterMode event_id -WaitSeconds 60 -PostRestoreQuerySeconds 90",
                "-ReconciliationWaitSeconds 240 -ActiveQueryGateTimeoutSeconds 180",
                f"-ActiveQueryApprovalFile {ps_quote(remote_approval)}",
                "-DistractorAfterSuppressedTarget -HoldForActiveQueryVerification",
            ]
        )
        ssh_command = [
            "ssh",
            "-S",
            str(args.control_path),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            "-T",
            args.ssh_target,
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
            f"{encoded_powershell(ps_command)}",
        ]
        log_path = trial_dir / "controller-console.txt"
        exit_code: int | None = None
        errors: list[str] = []
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                ssh_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert process.stdout is not None
            for line in process.stdout:
                log.write(line)
                log.flush()
                if "CSG_ACTIVE_QUERY_GATE_READY|" not in line:
                    continue
                if approval_seen:
                    errors.append("controller emitted more than one active-query gate")
                    continue
                approval_seen = True
                parts = line.strip().split("|", 2)
                if len(parts) != 3:
                    errors.append("malformed active-query gate marker")
                    continue
                expected_b64 = parts[2]
                audit_path = trial_dir / "preflight" / "active-query-filtered-verified.json"
                audit_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    audit = verify_active_query(args, expected_b64, audit_path)
                    write_remote_approval(args, remote_approval, audit)
                    approval_ok = True
                except Exception as exc:  # retain failure and let controller restore/abort
                    errors.append(f"active-query approval rejected: {type(exc).__name__}: {exc}")
            exit_code = process.wait()

        remote_windows_path = remote_output.replace("\\", "/")
        copy = subprocess.run(
            [
                "scp",
                "-o",
                f"ControlPath={args.control_path}",
                "-o",
                "BatchMode=yes",
                "-r",
                f"{args.ssh_target}:{remote_windows_path}",
                str(raw_dir),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if copy.returncode:
            errors.append(f"raw Windows output transfer failed: {copy.stderr[-500:]}")

        copied_result = raw_dir / trial_id / "result.json"
        if not copied_result.exists():
            copied_result = raw_dir / "result.json"
        assessment = assess_controller_result(copied_result)
        record = {
            "schema_version": "csg-live-trial-execution-record-v1",
            "experiment_id": schedule["experiment_id"],
            "trial_id": trial_id,
            "target_task_name": trial["target_task_name"],
            "distractor_task_name": trial["distractor_task_name"],
            "started_at_utc": started,
            "completed_at_utc": utc_now(),
            "controller_exit_code": exit_code,
            "active_query_gate_seen": approval_seen,
            "active_query_approved": approval_ok,
            "raw_transfer_exit_code": copy.returncode,
            "errors": errors,
            "assessment": assessment,
        }
        (trial_dir / "execution-record.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        campaign["attempts"].append(record)
        campaign["updated_at_utc"] = utc_now()
        campaign["strict_pass_count"] = sum(
            item["assessment"].get("strict_trial_pass", False) for item in campaign["attempts"]
        )
        campaign["safe_to_continue"] = assessment.get("safe_to_continue", False)
        campaign["status"] = "RUNNING"
        campaign_path.write_text(
            json.dumps(campaign, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(json.dumps({"trial_id": trial_id, **assessment, "errors": errors}), flush=True)

        if not assessment.get("safe_to_continue") or exit_code != 0 or copy.returncode != 0:
            campaign["status"] = "STOPPED_FOR_SAFETY_OR_EXECUTION_FAILURE"
            break

    accounted_ids = {attempt["trial_id"] for attempt in campaign["attempts"]}
    assigned_ids = {item["trial_id"] for item in schedule["trials"]}
    if accounted_ids == assigned_ids:
        campaign["status"] = "ALL_ASSIGNED_TRIALS_ACCOUNTED"
    elif campaign["status"] != "STOPPED_FOR_SAFETY_OR_EXECUTION_FAILURE":
        campaign["status"] = "PARTIAL_ASSIGNMENTS_COMPLETED"
    campaign["completed_at_utc"] = utc_now()
    campaign["unattempted_assigned_trial_ids"] = [
        item["trial_id"]
        for item in schedule["trials"]
        if item["trial_id"] not in {attempt["trial_id"] for attempt in campaign["attempts"]}
    ]
    campaign_path.write_text(
        json.dumps(campaign, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0 if campaign["status"] == "ALL_ASSIGNED_TRIALS_ACCOUNTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
