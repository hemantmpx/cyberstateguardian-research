from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LAB_DIR = ROOT / ".wazuh-lab"
WAZUH_DOCKER_REPO = "https://github.com/wazuh/wazuh-docker.git"
DEFAULT_TAG = "v4.14.7"
PROJECT_NAME = "csg-wazuh"


def run(command: list[str], cwd: Path, timeout: int = 1800) -> None:
    printable = " ".join(command)
    print(f"+ {printable}")
    completed = subprocess.run(command, cwd=cwd, text=True, timeout=timeout, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def prepare_repo(lab_dir: Path, tag: str, force_reclone: bool) -> Path:
    repo_dir = lab_dir / "wazuh-docker"
    if force_reclone and repo_dir.exists():
        shutil.rmtree(repo_dir)

    if not repo_dir.exists():
        lab_dir.mkdir(parents=True, exist_ok=True)
        run(
            ["git", "clone", "--depth", "1", "--branch", tag, WAZUH_DOCKER_REPO, str(repo_dir)],
            cwd=lab_dir,
        )
    elif not (repo_dir / ".git").exists():
        raise SystemExit(
            f"{repo_dir} exists but is not a git checkout. Move it or use --force-reclone."
        )
    else:
        run(["git", "fetch", "--depth", "1", "origin", tag], cwd=repo_dir)
        run(["git", "checkout", tag], cwd=repo_dir)

    return repo_dir


def single_node_dir(repo_dir: Path) -> Path:
    path = repo_dir / "single-node"
    if not (path / "docker-compose.yml").exists():
        raise SystemExit(
            f"Expected Wazuh single-node compose file at {path / 'docker-compose.yml'}"
        )
    return path


def patch_dashboard_port(single_node: Path, dashboard_port: int) -> None:
    compose_path = single_node / "docker-compose.yml"
    data: dict[str, Any] = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = data.setdefault("services", {})
    dashboard = services.setdefault("wazuh.dashboard", {})
    dashboard["ports"] = [f"{dashboard_port}:5601"]
    compose_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def ensure_certs(single_node: Path) -> None:
    cert_dir = single_node / "config" / "wazuh_indexer_ssl_certs"
    expected = cert_dir / "root-ca.pem"
    if expected.exists():
        print(f"Certificates already exist at {cert_dir}")
        return
    run(
        [
            "docker",
            "compose",
            "-p",
            f"{PROJECT_NAME}-certs",
            "-f",
            "generate-indexer-certs.yml",
            "run",
            "--rm",
            "generator",
        ],
        cwd=single_node,
    )


def compose(single_node: Path, args: list[str], timeout: int = 1800) -> None:
    run(
        ["docker", "compose", "-p", PROJECT_NAME, "-f", "docker-compose.yml", *args],
        cwd=single_node,
        timeout=timeout,
    )


def print_access(dashboard_port: int) -> None:
    print("")
    print("Wazuh access:")
    print(f"  Dashboard: https://localhost:{dashboard_port}")
    print("  Server API from this Mac: https://localhost:55000")
    print("  Indexer API from this Mac: https://localhost:9200")
    print("")
    print("For CSG containers talking to this local Wazuh stack, use:")
    print("  CSG_STATE_PROVIDER=wazuh")
    print("  CSG_EVENT_PROVIDER=wazuh")
    print("  CSG_WAZUH_API_URL=https://host.docker.internal:55000")
    print("  CSG_WAZUH_INDEXER_URL=https://host.docker.internal:9200")
    print(f"  CSG_WAZUH_DASHBOARD_URL=https://localhost:{dashboard_port}")
    print("  CSG_WAZUH_VERIFY_SSL=false")
    print("  CSG_WAZUH_SYNC_ENABLED=true")
    print("  CSG_WAZUH_SYNC_HOST_IDS=<WAZUH_AGENT_ID_OR_NAME>")
    print("")
    print("Set the Wazuh API and indexer passwords in .env before enabling CSG sync.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare and run the CyberStateGuardian Wazuh lab."
    )
    parser.add_argument(
        "action",
        choices=["prepare", "certs", "start", "stop", "down", "status", "logs"],
        nargs="?",
        default="prepare",
    )
    parser.add_argument("--lab-dir", type=Path, default=DEFAULT_LAB_DIR)
    parser.add_argument("--tag", default=DEFAULT_TAG)
    parser.add_argument("--dashboard-port", type=int, default=8443)
    parser.add_argument("--force-reclone", action="store_true")
    parser.add_argument("--tail", default="120", help="log lines for the logs action")
    args = parser.parse_args()

    repo_dir = prepare_repo(args.lab_dir, args.tag, args.force_reclone)
    single_node = single_node_dir(repo_dir)
    patch_dashboard_port(single_node, args.dashboard_port)

    if args.action == "prepare":
        print(f"Prepared Wazuh Docker checkout at {repo_dir}")
        print_access(args.dashboard_port)
        return
    if args.action == "certs":
        ensure_certs(single_node)
        print_access(args.dashboard_port)
        return
    if args.action == "start":
        ensure_certs(single_node)
        compose(single_node, ["up", "-d"])
        print_access(args.dashboard_port)
        return
    if args.action == "stop":
        compose(single_node, ["stop"], timeout=300)
        return
    if args.action == "down":
        compose(single_node, ["down"], timeout=300)
        return
    if args.action == "status":
        compose(single_node, ["ps"], timeout=300)
        return
    if args.action == "logs":
        compose(single_node, ["logs", "--tail", args.tail], timeout=300)


if __name__ == "__main__":
    main()
