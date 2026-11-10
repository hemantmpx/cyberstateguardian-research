"""Freeze, execute, and supervise the privileged-group reconciliation campaign."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
STUDY_ID = "csg-privileged-group-randomized-v11"
HOST_ID = "win11-arm-lab"
CONDITIONS = (
    "complete_with_distractor",
    "target_audit_omission_with_distractor",
    "no_target_change_with_distractor",
)
RUNNER = ROOT / "scripts" / "run_privileged_group_trial_windows_v11.ps1"
ANALYZER = ROOT / "experiments" / "analyze_privileged_group_randomized_campaign_v11.py"
PROTOCOL = ROOT / "experiments" / "privileged-group-randomized-campaign-protocol-v11.md"


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checksum_matches(path: Path, checksum_path: Path) -> bool:
    values = checksum_path.read_text(encoding="utf-8").split()
    return bool(values) and digest(path) == values[0].lower()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def create_schedule(seed: int, blocks: int = 10) -> list[dict[str, Any]]:
    if blocks != 10:
        raise ValueError("Protocol v11 assigns exactly ten randomized blocks.")
    rng = random.Random(seed)
    schedule: list[dict[str, Any]] = []
    for block in range(1, blocks + 1):
        conditions = list(CONDITIONS)
        rng.shuffle(conditions)
        for condition in conditions:
            slot = len(schedule) + 1
            schedule.append(
                {
                    "slot": slot,
                    "block": block,
                    "trial_id": f"PG-{slot:03d}",
                    "condition": condition,
                    "target_username": f"csgt{rng.getrandbits(48):012x}",
                    "distractor_username": f"csgd{rng.getrandbits(48):012x}",
                }
            )
    return schedule


def self_test() -> int:
    schedule = create_schedule(20261016)
    assert len(schedule) == 30
    assert len({row["trial_id"] for row in schedule}) == 30
    names = [row[key] for row in schedule for key in ("target_username", "distractor_username")]
    assert len(set(names)) == 60
    sample_script = (
        "& 'C:\\CSG\\runner.ps1' -TrialId 'PG-001' -Condition 'complete_with_distractor'"
    )
    command = encoded_powershell_command(sample_script)
    assert "-ExecutionPolicy Bypass -EncodedCommand " in command
    payload = command.rsplit(" ", 1)[1]
    decoded = base64.b64decode(payload).decode("utf-16le")
    assert decoded == sample_script
    with tempfile.TemporaryDirectory() as temp_dir:
        raw_path = Path(temp_dir) / "run.json"
        checksum_path = Path(temp_dir) / "SHA256SUMS.txt"
        raw_path.write_bytes(b"checksum-case-regression")
        uppercase_digest = hashlib.sha256(raw_path.read_bytes()).hexdigest().upper()
        checksum_path.write_text(f"{uppercase_digest}  run.json\n", encoding="utf-8")
        assert checksum_matches(raw_path, checksum_path)
    for block in range(1, 11):
        assert {row["condition"] for row in schedule if row["block"] == block} == set(CONDITIONS)
    assert all(len(row["target_username"]) <= 20 for row in schedule)
    print("Self-test passed: 10 randomized blocks, 30 slots, 60 unique account identities.")
    return 0


def prepare(args: argparse.Namespace) -> int:
    out = args.campaign_dir.resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"Refusing to overwrite a nonempty campaign directory: {out}")
    out.mkdir(parents=True, exist_ok=True)
    frozen = out / "frozen-source"
    frozen.mkdir()
    sources = {
        "controller_sha256": Path(__file__).resolve(),
        "windows_runner_sha256": RUNNER,
        "analyzer_sha256": ANALYZER,
        "protocol_sha256": PROTOCOL,
    }
    for source in sources.values():
        (frozen / source.name).write_bytes(source.read_bytes())
    schedule = create_schedule(args.seed)
    schedule_path = out / "schedule.json"
    write_json(schedule_path, {"seed": args.seed, "blocks": 10, "trials": schedule})
    (out / "PROTOCOL.md").write_bytes(PROTOCOL.read_bytes())
    hashes = {key: digest(frozen / path.name) for key, path in sources.items()}
    hashes["protocol_copy_sha256"] = digest(out / "PROTOCOL.md")
    hashes["schedule_sha256"] = digest(schedule_path)
    freeze = {
        "study_id": STUDY_ID,
        "frozen_at_utc": utc_now(),
        "status": "FROZEN_BEFORE_FIRST_TRIAL",
        "endpoint_id": HOST_ID,
        "endpoint_count": 1,
        "random_seed": args.seed,
        "blocks": 10,
        "trials_per_condition": 10,
        "assigned_trial_count": len(schedule),
        "source_hashes": hashes,
        "git_metadata_available": (ROOT / ".git").exists(),
        "study_scope": "single Windows 11 endpoint; benign privileged-group mechanism only",
        "omission_intervention": (
            "temporarily disable Security Group Management success auditing for target action; "
            "restore exact Success-only baseline before distractor"
        ),
        "execution_status": "FROZEN_NOT_STARTED",
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
    schedule = read_json(campaign_dir / "schedule.json")["trials"]
    frozen = campaign_dir / "frozen-source"
    mapping = {
        "controller_sha256": frozen / Path(__file__).name,
        "windows_runner_sha256": frozen / RUNNER.name,
        "analyzer_sha256": frozen / ANALYZER.name,
        "protocol_sha256": frozen / PROTOCOL.name,
        "protocol_copy_sha256": campaign_dir / "PROTOCOL.md",
        "schedule_sha256": campaign_dir / "schedule.json",
    }
    actual = {key: digest(path) for key, path in mapping.items()}
    if actual != freeze["source_hashes"]:
        raise RuntimeError(f"Campaign freeze hash mismatch: {actual}")
    if digest(Path(__file__).resolve()) != actual["controller_sha256"]:
        raise RuntimeError("Current controller differs from the frozen controller.")
    if freeze.get("study_id") != STUDY_ID:
        raise RuntimeError("Campaign study ID differs from the current protocol revision.")
    if len(schedule) != 30 or freeze["assigned_trial_count"] != 30:
        raise RuntimeError("Frozen schedule must contain exactly 30 assigned slots.")
    for block in range(1, 11):
        if {row["condition"] for row in schedule if row["block"] == block} != set(CONDITIONS):
            raise RuntimeError(f"Block {block} does not contain each assigned condition once.")
    usernames = [row[key] for row in schedule for key in ("target_username", "distractor_username")]
    if len(usernames) != 60 or len(set(usernames)) != 60:
        raise RuntimeError("Frozen target/distractor usernames are not globally unique.")
    return freeze, schedule


def run_command(command: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)


def api_json(base_url: str, path: str, timeout: int = 45) -> Any:
    request = Request(f"{base_url.rstrip('/')}{path}", headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except (HTTPError, URLError) as exc:
        raise RuntimeError(f"CSG API GET {path} failed: {exc}") from exc


def parse_json_output(output: str) -> Any:
    start = output.rfind("{")
    if start < 0:
        raise ValueError("Remote PowerShell did not return a JSON object.")
    value, _ = json.JSONDecoder().raw_decode(output[start:])
    return value


def encoded_powershell_command(script: str) -> str:
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return f"powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}"


def execute(args: argparse.Namespace) -> int:
    campaign_dir = args.campaign_dir.resolve()
    freeze, schedule = verify_freeze(campaign_dir)
    if args.max_trials is not None and not 1 <= args.max_trials <= len(schedule):
        raise ValueError(f"--max-trials must be from 1 through {len(schedule)}.")
    progress_path = campaign_dir / "campaign-progress.json"
    progress = None
    completed_ids: set[str] = set()
    if progress_path.exists():
        progress = read_json(progress_path)
        if progress.get("status") != "PAUSED_BY_EXECUTION_LIMIT":
            raise SystemExit("Campaign is not in a resumable paused state; refusing replay.")
        assigned_by_id = {row["trial_id"]: row for row in schedule}
        completed = progress.get("completed_trials", [])
        for record in completed:
            trial_id = record.get("trial_id")
            if trial_id not in assigned_by_id:
                raise RuntimeError(f"Progress contains an unassigned trial: {trial_id}")
            if record.get("condition") != assigned_by_id[trial_id]["condition"]:
                raise RuntimeError(
                    f"Progress condition differs from the frozen assignment: {trial_id}"
                )
            if (
                record.get("runner_success") is not True
                or record.get("cleanup_complete") is not True
            ):
                raise RuntimeError(f"A completed slot did not pass all gates: {trial_id}")
            raw_path = campaign_dir / "trials" / trial_id / "raw-windows" / "run.json"
            checksum_path = raw_path.with_name("SHA256SUMS.txt")
            if not checksum_matches(raw_path, checksum_path):
                raise RuntimeError(f"A prior raw run checksum failed: {trial_id}")
            completed_ids.add(trial_id)
        if len(completed_ids) != len(completed):
            raise RuntimeError("Progress repeats a trial assignment.")
    api_root = args.api_url.rstrip("/")
    health_url = api_root.removesuffix("/api") + "/health"
    health = api_json(health_url, "")
    if health.get("status") != "ok":
        raise RuntimeError("CSG API health is not ok.")
    wazuh = api_json(api_root, "/wazuh/status")
    agent = next(
        (
            item
            for item in wazuh.get("agents", [])
            if item.get("name") == HOST_ID and not item.get("manager")
        ),
        None,
    )
    if (
        not wazuh.get("ok")
        or not wazuh.get("indexer", {}).get("ok")
        or not agent
        or agent.get("status") != "active"
    ):
        raise RuntimeError(
            "Wazuh server/indexer or the expected Windows endpoint agent is unhealthy."
        )
    ssh_check = run_command(
        ["ssh", "-S", args.ssh_socket, "-O", "check", args.ssh_target], timeout=12
    )
    if ssh_check.returncode:
        raise RuntimeError(
            "Authenticated SSH control connection is not available; no trial was started."
        )

    preflight_script = (
        "$ErrorActionPreference='Stop'; $os=Get-CimInstance Win32_OperatingSystem; "
        "$svc=Get-Service WazuhSvc; $task=Get-ScheduledTask -TaskName 'CyberStateGuardian Probe'; "
        "$audit=auditpol /get /subcategory:'Security Group Management' | Out-String; "
        '$line=($audit -split "`n" | Where-Object '
        "{$_ -match 'Security Group Management'} | Select-Object -Last 1).Trim(); "
        "[pscustomobject]@{ComputerName=$env:COMPUTERNAME;Caption=$os.Caption;Build=$os.BuildNumber;"
        "Architecture=$env:PROCESSOR_ARCHITECTURE;WazuhService=$svc.Status.ToString();"
        "ProbeTask=$task.State.ToString();AuditRaw=$audit;AuditLine=$line;"
        "AuditSuccess=($line -match 'Success');AuditFailure=($line -match 'Failure')} | "
        "ConvertTo-Json -Compress"
    )
    remote_preflight = run_command(
        [
            "ssh",
            "-S",
            args.ssh_socket,
            "-T",
            args.ssh_target,
            encoded_powershell_command(preflight_script),
        ],
        timeout=30,
    )
    (campaign_dir / "windows-preflight.txt").write_text(
        remote_preflight.stdout + remote_preflight.stderr, encoding="utf-8"
    )
    if remote_preflight.returncode:
        raise RuntimeError("Windows read-only preflight failed; no mutation was started.")
    windows = parse_json_output(remote_preflight.stdout)
    if windows.get("WazuhService") != "Running" or windows.get("ProbeTask") != "Running":
        raise RuntimeError(f"Windows services are not healthy: {windows}")
    if windows.get("AuditSuccess") is not True or windows.get("AuditFailure") is not False:
        raise RuntimeError(
            "Expected Security Group Management Success-only audit baseline: "
            f"{windows.get('AuditLine')}"
        )
    if str(windows.get("Build")) != "26200" or windows.get("Architecture") != "ARM64":
        raise RuntimeError(f"Unexpected endpoint build/architecture: {windows}")
    write_json(
        campaign_dir / "preflight.json",
        {
            "captured_at_utc": utc_now(),
            "api_health": health,
            "wazuh_status": wazuh,
            "windows": windows,
        },
    )
    inspect = run_command(
        ["docker", "inspect", "--format={{.Name}} {{.Image}} {{.Id}}", "csg-api", "csg-worker"],
        timeout=15,
    )
    (campaign_dir / "container-images.txt").write_text(
        inspect.stdout + inspect.stderr, encoding="utf-8"
    )

    upload_files = [
        campaign_dir / "frozen-source" / RUNNER.name,
        campaign_dir / "frozen-source" / PROTOCOL.name,
        campaign_dir / "campaign-freeze.json",
        campaign_dir / "schedule.json",
    ]
    for source in upload_files:
        uploaded = run_command(
            [
                "scp",
                "-o",
                f"ControlPath={args.ssh_socket}",
                str(source),
                f"{args.ssh_target}:C:/CSG/{source.name}",
            ],
            timeout=60,
        )
        if uploaded.returncode:
            raise RuntimeError(f"Could not upload frozen file {source.name}; no trial started.")

    remote_hashes = [
        (f"C:\\CSG\\{RUNNER.name}", freeze["source_hashes"]["windows_runner_sha256"]),
        (f"C:\\CSG\\{PROTOCOL.name}", freeze["source_hashes"]["protocol_sha256"]),
        ("C:\\CSG\\campaign-freeze.json", digest(campaign_dir / "campaign-freeze.json")),
        ("C:\\CSG\\schedule.json", freeze["source_hashes"]["schedule_sha256"]),
    ]
    checks = ",".join(
        "@{path='" + path + "';sha256='" + expected + "'}" for path, expected in remote_hashes
    )
    parse_path = f"C:\\CSG\\{RUNNER.name}"
    parse_check = (
        f"[void][System.Management.Automation.Language.Parser]::ParseFile('{parse_path}',"
        "[ref]$tokens,[ref]$parseErrors); "
    )
    verify_script = (
        "$checks=@(" + checks + "); foreach($item in $checks){ "
        "if(-not(Test-Path -LiteralPath $item.path)){throw ('Missing frozen file: '+$item.path)}; "
        "$actual=(Get-FileHash -LiteralPath $item.path -Algorithm SHA256).Hash.ToLowerInvariant(); "
        "if($actual -ne $item.sha256){throw ('Frozen file hash mismatch: '+$item.path)} }; "
        "$tokens=$null; $parseErrors=$null; "
        + parse_check
        + "if($parseErrors.Count -gt 0){throw 'Windows runner has PowerShell parse errors.'}; "
        "$nullFindings=$null; "
        "if(@($nullFindings | ? { $_ }).Count){throw 'Null findings regression failed.'}; "
        "'REMOTE_FROZEN_FILES_OK'"
    )
    remote_verify = run_command(
        [
            "ssh",
            "-S",
            args.ssh_socket,
            "-T",
            args.ssh_target,
            encoded_powershell_command(verify_script),
        ],
        timeout=30,
    )
    (campaign_dir / "windows-upload-verification.txt").write_text(
        remote_verify.stdout + remote_verify.stderr, encoding="utf-8"
    )
    if remote_verify.returncode or "REMOTE_FROZEN_FILES_OK" not in remote_verify.stdout:
        raise RuntimeError("Remote frozen-file verification failed; no trial was started.")

    if progress is None:
        progress = {
            "study_id": STUDY_ID,
            "started_at_utc": utc_now(),
            "status": "RUNNING",
            "completed_trials": [],
        }
    else:
        progress["status"] = "RUNNING"
        progress["resumed_at_utc"] = utc_now()
    write_json(progress_path, progress)
    trial_root = campaign_dir / "trials"
    for trial in schedule:
        tid = trial["trial_id"]
        if tid in completed_ids:
            continue
        if args.max_trials is not None and len(completed_ids) >= args.max_trials:
            progress.update({"status": "PAUSED_BY_EXECUTION_LIMIT", "paused_at_utc": utc_now()})
            write_json(progress_path, progress)
            print(f"PAUSED after {len(completed_ids)} passing assigned slots.")
            return 0
        print(f"START {tid} block={trial['block']} condition={trial['condition']}", flush=True)
        script = (
            f"& 'C:\\CSG\\{RUNNER.name}' "
            f"-CampaignId '{STUDY_ID}' -TrialId '{tid}' "
            f"-Condition '{trial['condition']}' "
            f"-TargetUsername '{trial['target_username']}' "
            f"-DistractorUsername '{trial['distractor_username']}' "
            f"-ProtocolPath 'C:\\CSG\\{PROTOCOL.name}' "
            "-FreezeManifestPath 'C:\\CSG\\campaign-freeze.json' "
            "-SchedulePath 'C:\\CSG\\schedule.json'"
        )
        result = run_command(
            [
                "ssh",
                "-S",
                args.ssh_socket,
                "-T",
                args.ssh_target,
                encoded_powershell_command(script),
            ],
            timeout=1200,
        )
        trial_dir = trial_root / tid
        trial_dir.mkdir(parents=True, exist_ok=False)
        (trial_dir / "windows-stdout.txt").write_text(result.stdout, encoding="utf-8")
        (trial_dir / "windows-stderr.txt").write_text(result.stderr, encoding="utf-8")
        remote_dir = (
            f"C:/ProgramData/CyberStateGuardian/Research/privileged-group-campaign/{STUDY_ID}/{tid}"
        )
        raw_dir = trial_dir / "raw-windows"
        raw_dir.mkdir()
        for filename in ("run.json", "SHA256SUMS.txt"):
            copied = run_command(
                [
                    "scp",
                    "-o",
                    f"ControlPath={args.ssh_socket}",
                    f"{args.ssh_target}:{remote_dir}/{filename}",
                    str(raw_dir / filename),
                ],
                timeout=60,
            )
            if copied.returncode:
                progress.update(
                    {
                        "status": "STOPPED_ARTIFACT_CAPTURE_FAILURE",
                        "stopped_trial": tid,
                        "reason": f"Could not retrieve {filename}",
                    }
                )
                write_json(progress_path, progress)
                raise RuntimeError(f"Failed to retrieve {tid} raw artifact {filename}.")
        record = read_json(raw_dir / "run.json")
        row = {
            "trial_id": tid,
            "condition": trial["condition"],
            "runner_exit_code": result.returncode,
            "runner_success": record.get("success"),
            "cleanup_complete": record.get("cleanup", {}).get("complete"),
            "target_status": (record.get("target_reconciliation") or {}).get("status"),
        }
        progress["completed_trials"].append(row)
        completed_ids.add(tid)
        progress["last_trial_finished_at_utc"] = utc_now()
        write_json(progress_path, progress)
        print(
            f"DONE {tid} success={row['runner_success']} "
            f"cleanup={row['cleanup_complete']} target={row['target_status']}",
            flush=True,
        )
        if (
            result.returncode != 0
            or row["runner_success"] is not True
            or row["cleanup_complete"] is not True
        ):
            progress.update({"status": "STOPPED_ON_FROZEN_GATE_FAILURE", "stopped_trial": tid})
            write_json(progress_path, progress)
            raise RuntimeError(
                f"Frozen pass/cleanup gate failed at {tid}; raw data retained and "
                "no later trial was started."
            )

    if len(completed_ids) != len(schedule):
        progress.update({"status": "PAUSED_BY_EXECUTION_LIMIT", "paused_at_utc": utc_now()})
        write_json(progress_path, progress)
        print(f"PAUSED after {len(completed_ids)} passing assigned slots.")
        return 0
    progress.update({"status": "EXECUTION_COMPLETE", "completed_at_utc": utc_now()})
    write_json(progress_path, progress)
    analysis = run_command(
        [sys.executable, str(ANALYZER), "--campaign-dir", str(campaign_dir)], timeout=300
    )
    if analysis.returncode:
        print(analysis.stdout, file=sys.stdout)
        print(analysis.stderr, file=sys.stderr)
        raise RuntimeError("Independent campaign analyzer failed. Raw campaign remains preserved.")
    print(analysis.stdout)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    test_parser = sub.add_parser("self-test")
    test_parser.set_defaults(func=lambda _args: self_test())
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--campaign-dir", type=Path, required=True)
    prepare_parser.add_argument("--seed", type=int, required=True)
    prepare_parser.set_defaults(func=prepare)
    run_parser = sub.add_parser("execute")
    run_parser.add_argument("--campaign-dir", type=Path, required=True)
    run_parser.add_argument("--api-url", default="http://127.0.0.1:8000/api")
    run_parser.add_argument("--ssh-target", required=True)
    run_parser.add_argument("--ssh-socket", required=True)
    run_parser.add_argument("--max-trials", type=int)
    run_parser.set_defaults(func=execute)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
