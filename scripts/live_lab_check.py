from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]


def run_command(
    command: list[str],
    cwd: Path = ROOT,
    timeout: int = 15,
    include_output: bool = True,
) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        result: dict[str, Any] = {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
        }
        if include_output:
            result["stdout"] = completed.stdout.strip()
            result["stderr"] = completed.stderr.strip()
        return result
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def http_check(url: str) -> dict[str, Any]:
    try:
        response = httpx.get(url, timeout=5)
        return {
            "ok": response.is_success,
            "status_code": response.status_code,
            "body": response.text[:500],
        }
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def env_status() -> dict[str, Any]:
    env_path = ROOT / ".env"
    if not env_path.exists():
        return {"ok": False, "exists": False, "message": "Run python scripts/create_lab_env.py"}
    text = env_path.read_text(encoding="utf-8")
    placeholders = [
        value
        for value in [
            "change-me-for-local-lab",
            "replace-with-lab-token",
            "replace-with-mac-reachable-host",
        ]
        if value in text
    ]
    return {
        "ok": not placeholders,
        "exists": True,
        "placeholder_count": len(placeholders),
        "placeholders": placeholders,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Check CyberStateGuardian live lab readiness")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000/health")
    parser.add_argument("--web-url", default="http://127.0.0.1:3001")
    args = parser.parse_args()

    report = {
        "python": {"ok": True, "version": sys.version.split()[0]},
        "env": env_status(),
        "docker_cli": run_command(["docker", "--version"]),
        "docker_daemon": run_command(["docker", "info", "--format", "{{.ServerVersion}}"]),
        "compose_config": run_command(
            ["docker", "compose", "config", "--quiet"],
            timeout=30,
            include_output=False,
        ),
        "api": http_check(args.api_url),
        "web": http_check(args.web_url),
    }
    print(json.dumps(report, indent=2))
    failed = [
        name
        for name, result in report.items()
        if isinstance(result, dict) and result.get("ok") is False
    ]
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
