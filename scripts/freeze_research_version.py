"""Create a content-addressed research version manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_files(exclude: Path | None = None) -> list[Path]:
    roots = [
        ROOT / name
        for name in ("backend", "probe", "experiments", "scripts", "config", "docker")
    ]
    files: list[Path] = []
    for directory in roots:
        if not directory.exists():
            continue
        for path in directory.rglob("*"):
            if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
                continue
            if path.name == "catalog.json":
                continue
            if path.name.startswith("RESEARCH_RESULTS_DETAILED"):
                continue
            if "raw" in path.parts and path.suffix.lower() not in {".json", ".md", ".gitignore"}:
                continue
            if path.suffix.lower() in {
                ".py", ".ps1", ".yaml", ".yml", ".json", ".toml", ".md", ".gitignore"
            }:
                files.append(path)
    for name in (
        ".dockerignore",
        "alembic.ini",
        "compose.yaml",
        "pyproject.toml",
        "README.md",
        "BUILD_STATUS.md",
        "RESEARCH_VERSION",
        "config/sysmon-csg-lab.xml",
        "config/wazuh/csg_research_rules.xml",
        ".wazuh-lab/wazuh-docker/single-node/docker-compose.yml",
        ".wazuh-lab/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf",
    ):
        path = ROOT / name
        if path.exists():
            files.append(path)
    excluded = exclude.resolve() if exclude else None
    return sorted(path for path in set(files) if path.resolve() != excluded)


def dependency_snapshot() -> list[str]:
    python = ROOT / ".venv/bin/python"
    if not python.exists():
        return []
    result = subprocess.run(
        [str(python), "-m", "pip", "freeze"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return sorted(line for line in result.stdout.splitlines() if line.strip())


def run_command(args: list[str]) -> tuple[int, str]:
    result = subprocess.run(
        args,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, result.stdout.strip()


def repository_snapshot() -> dict[str, object]:
    code, commit = run_command(["git", "rev-parse", "HEAD"])
    if code != 0:
        return {
            "available": False,
            "commit": None,
            "branch": None,
            "dirty_worktree": None,
            "reason": "repository root is not a Git work tree",
        }
    branch_code, branch = run_command(["git", "branch", "--show-current"])
    status_code, status = run_command(["git", "status", "--porcelain"])
    return {
        "available": True,
        "commit": commit,
        "branch": branch if branch_code == 0 else None,
        "dirty_worktree": bool(status) if status_code == 0 else None,
    }


def docker_snapshot() -> dict[str, object]:
    projects = {
        "csg": {
            "project": None,
            "compose_file": ROOT / "compose.yaml",
        },
        "wazuh": {
            "project": "csg-wazuh",
            "compose_file": ROOT / ".wazuh-lab/wazuh-docker/single-node/docker-compose.yml",
        },
    }
    results: dict[str, dict[str, object]] = {}
    for name, project in projects.items():
        compose_file = project["compose_file"]
        if not isinstance(compose_file, Path) or not compose_file.exists():
            results[name] = {
                "available": False,
                "image_ids": [],
                "image_digests": {},
                "reason": "Compose file unavailable",
            }
            continue
        command = ["docker", "compose"]
        if project["project"]:
            command.extend(["-p", str(project["project"])])
        command.extend(["-f", str(compose_file), "images", "-q"])
        code, image_ids_output = run_command(command)
        image_ids = sorted(set(image_ids_output.splitlines()))
        if code != 0 or not image_ids:
            results[name] = {
                "available": False,
                "image_ids": image_ids,
                "image_digests": {},
                "reason": "Docker Compose returned no image IDs",
            }
            continue
        digests: dict[str, str] = {}
        for image_id in image_ids:
            inspect_code, raw = run_command(
                ["docker", "image", "inspect", image_id, "--format", "{{json .RepoDigests}}"]
            )
            if inspect_code == 0:
                digests[image_id] = raw
        results[name] = {
            "available": True,
            "image_ids": image_ids,
            "image_digests": digests,
        }

    wazuh = results["wazuh"]
    return {
        "available": all(result["available"] for result in results.values()),
        "projects": results,
        # Retain the original Wazuh keys for readers of earlier freeze manifests.
        "image_digests": wazuh["image_digests"],
        "csg_image_ids": results["csg"]["image_ids"],
        "csg_image_digests": results["csg"]["image_digests"],
    }


def migration_snapshot() -> dict[str, object]:
    versions = ROOT / "backend/csg/db/migrations/versions"
    revisions: list[str] = []
    for path in sorted(versions.glob("*.py")) if versions.exists() else []:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("revision") and "=" in line:
                revisions.append(line.split("=", 1)[1].strip().strip('"\''))
    return {
        "known_revision_files": revisions,
        "latest_known_revision": revisions[-1] if revisions else None,
    }


def external_lab_snapshot(path: Path | None) -> dict[str, object]:
    if path is None or not path.exists():
        return {
            "windows_build": None,
            "wazuh_agent_version": None,
            "wazuh_server_version": None,
            "wazuh_indexer_version": None,
            "sysmon_version": None,
            "sysmon_config_sha256": None,
            "wazuh_agent_config_sha256": None,
            "status": "not_supplied_for_this_freeze",
        }
    captured = json.loads(path.read_text(encoding="utf-8-sig"))
    wazuh_status = captured.get("csg_wazuh_status") or {}
    server_api = wazuh_status.get("server_api") or {}
    manager = next(
        (agent for agent in server_api.get("agents", []) if agent.get("manager")),
        None,
    )
    files = captured.get("config_sha256") or {}
    runner_hashes = captured.get("windows_runner_sha256") or {}
    architecture = captured.get("windows_architecture")
    architecture_label = {12: "ARM64", 9: "x64", 0: "x86"}.get(
        architecture, architecture
    )
    source_path = path.resolve()
    try:
        source_path_text = str(source_path.relative_to(ROOT))
    except ValueError:
        source_path_text = str(source_path)
    return {
        "windows_build": captured.get("windows_build") or captured.get("windows_version"),
        "wazuh_agent_version": captured.get("wazuh_agent_version"),
        "wazuh_server_version": captured.get("wazuh_server_version")
        or (manager or {}).get("version"),
        "wazuh_indexer_version": captured.get("wazuh_indexer_version")
        or (wazuh_status.get("indexer") or {}).get("version"),
        "sysmon_version": captured.get("sysmon_version"),
        "sysmon_config_sha256": captured.get("sysmon_config_sha256")
        or files.get("sysmon_value"),
        "wazuh_agent_config_sha256": captured.get("wazuh_agent_config_sha256")
        or files.get("wazuh_agent_value"),
        "windows_architecture": architecture_label,
        "windows_os_caption": captured.get("windows_os_caption"),
        "experiment_script_sha256": captured.get("experiment_script_sha256")
        or runner_hashes,
        "captured_at": captured.get("captured_at"),
        "source_path": source_path_text,
        "source_sha256": file_hash(source_path),
        "status": "captured_from_live_lab",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--lab-environment",
        type=Path,
        help="Fresh JSON captured from the endpoint and Wazuh environment for this freeze.",
    )
    args = parser.parse_args()
    files = source_files(args.output)
    manifest = {
        "schema_version": "csg-research-freeze-v1",
        "research_version": args.version,
        "frozen_at": datetime.now(UTC).isoformat(),
        "repository_root": str(ROOT),
        "source_file_count": len(files),
        "source_sha256": {str(path.relative_to(ROOT)): file_hash(path) for path in files},
        "dependencies": dependency_snapshot(),
        "dataset_archives": {
            "windows_apt_2025_revision_3": {
                "path": "experiments/datasets/windows_apt_2025/raw/windows-apt-2025-v3.zip",
                "sha256": "0dfd0270ea41788fb5e9d24045f4314fe2682cc327d9d6da537b2d908d29c5c5",
            }
        },
        "reproducibility": {
            "git": repository_snapshot(),
            "docker": docker_snapshot(),
            "database_migrations": migration_snapshot(),
            "external_lab_versions": external_lab_snapshot(args.lab_environment),
            "raw_archive_excluded_from_source_hashes": True,
            "secrets_excluded": True,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote research freeze {args.version} to {args.output}")


if __name__ == "__main__":
    main()
