from __future__ import annotations

import argparse
import json
import socket
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from csg.config import Settings

ROOT = Path(__file__).resolve().parents[1]
WAZUH_SINGLE_NODE = ROOT / ".wazuh-lab" / "wazuh-docker" / "single-node"


def tcp_check(host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"ok": True, "host": host, "port": port}
    except Exception as exc:
        return {
            "ok": False,
            "host": host,
            "port": port,
            "error": f"{type(exc).__name__}: {exc}",
        }


def http_check(url: str, verify_ssl: bool) -> dict[str, Any]:
    try:
        response = httpx.get(url, verify=verify_ssl, follow_redirects=False, timeout=8)
        return {"ok": response.status_code < 500, "status_code": response.status_code}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def host_side_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.hostname != "host.docker.internal":
        return url
    netloc = "localhost"
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def api_auth_check(settings: Settings) -> dict[str, Any]:
    if not settings.wazuh_api_password:
        return {"ok": False, "skipped": True, "message": "CSG_WAZUH_API_PASSWORD is not set."}
    try:
        response = httpx.post(
            f"{host_side_url(settings.wazuh_api_url).rstrip('/')}/security/user/authenticate",
            params={"raw": "true"},
            auth=(settings.wazuh_api_user, settings.wazuh_api_password),
            verify=settings.wazuh_verify_ssl,
            timeout=8,
        )
        return {
            "ok": response.is_success and bool(response.text.strip()),
            "status_code": response.status_code,
            "token_received": response.is_success and bool(response.text.strip()),
        }
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def indexer_auth_check(settings: Settings) -> dict[str, Any]:
    if not settings.wazuh_indexer_password:
        return {
            "ok": False,
            "skipped": True,
            "message": "CSG_WAZUH_INDEXER_PASSWORD is not set.",
        }
    try:
        response = httpx.get(
            f"{host_side_url(settings.wazuh_indexer_url).rstrip('/')}/",
            auth=(settings.wazuh_indexer_user, settings.wazuh_indexer_password),
            verify=settings.wazuh_verify_ssl,
            timeout=8,
        )
        payload = (
            response.json()
            if response.headers.get("content-type", "").startswith("application/json")
            else {}
        )
        return {
            "ok": response.is_success,
            "status_code": response.status_code,
            "cluster_name": payload.get("cluster_name") if isinstance(payload, dict) else None,
        }
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def compose_status() -> dict[str, Any]:
    if not (WAZUH_SINGLE_NODE / "docker-compose.yml").exists():
        return {
            "ok": False,
            "skipped": True,
            "message": (
                "Wazuh Docker checkout is missing. Run python scripts/setup_wazuh_lab.py prepare."
            ),
        }
    completed = subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            "csg-wazuh",
            "-f",
            "docker-compose.yml",
            "ps",
            "--format",
            "json",
        ],
        cwd=WAZUH_SINGLE_NODE,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        return {"ok": False, "returncode": completed.returncode, "stderr": completed.stderr.strip()}
    rows: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        if line.strip():
            row = json.loads(line)
            rows.append(
                {
                    "name": row.get("Name") or row.get("Names"),
                    "service": row.get("Service"),
                    "image": row.get("Image"),
                    "state": row.get("State"),
                    "status": row.get("Status"),
                    "ports": row.get("Ports"),
                }
            )
    return {"ok": True, "services": rows}


def main() -> None:
    parser = argparse.ArgumentParser(description="Check the local CyberStateGuardian Wazuh lab.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--dashboard-url", default=None)
    args = parser.parse_args()

    settings = Settings()
    dashboard_url = args.dashboard_url or settings.wazuh_dashboard_url
    report = {
        "compose": compose_status(),
        "ports": {
            "manager_events_1514": tcp_check(args.host, 1514),
            "manager_enrollment_1515": tcp_check(args.host, 1515),
            "server_api_55000": tcp_check(args.host, 55000),
            "indexer_9200": tcp_check(args.host, 9200),
            "dashboard_8443": tcp_check(args.host, 8443),
        },
        "dashboard": http_check(dashboard_url, settings.wazuh_verify_ssl),
        "server_api_auth": api_auth_check(settings),
        "indexer_auth": indexer_auth_check(settings),
    }
    print(json.dumps(report, indent=2))
    failed = [
        name
        for name, result in report.items()
        if isinstance(result, dict) and result.get("ok") is False and not result.get("skipped")
    ]
    failed.extend(
        name
        for name, result in report["ports"].items()
        if isinstance(result, dict) and result.get("ok") is False
    )
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
