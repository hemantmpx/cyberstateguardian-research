from __future__ import annotations

import json
import platform
import subprocess
from typing import Any

from cyberstateguardian_probe.normalize import normalize_path, normalize_username


def collect_services() -> dict[str, Any]:
    if platform.system().lower() != "windows":
        return {
            "category": "service",
            "status": "unavailable",
            "items": [],
            "message": "Windows service collection is only available on Windows",
        }

    command = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        (
            "Get-CimInstance Win32_Service | "
            "Select-Object Name,DisplayName,State,StartMode,PathName,StartName | "
            "ConvertTo-Json -Compress"
        ),
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=True,
            text=True,
            timeout=20,
        )
        payload = json.loads(completed.stdout or "[]")
        raw_rows = payload if isinstance(payload, list) else [payload]
        rows = [
            {
                "service_name": row.get("Name"),
                "display_name": row.get("DisplayName"),
                "status": row.get("State"),
                "start_mode": row.get("StartMode"),
                "binary_path": normalize_path(row.get("PathName")),
                "account": normalize_username(row.get("StartName")),
            }
            for row in raw_rows
        ]
        return {"category": "service", "status": "healthy", "items": rows, "message": None}
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError) as exc:
        return {
            "category": "service",
            "status": "error",
            "items": [],
            "message": f"service collection failed: {type(exc).__name__}: {exc}",
        }
