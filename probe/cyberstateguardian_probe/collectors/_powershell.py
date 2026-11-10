from __future__ import annotations

import json
import subprocess
from typing import Any


def run_powershell_json(script: str, timeout: int = 30) -> list[dict[str, Any]]:
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "$ErrorActionPreference = 'Stop'; "
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); " + script,
        ],
        capture_output=True,
        check=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
    )
    payload = json.loads(completed.stdout or "[]")
    if payload is None:
        return []
    rows = payload if isinstance(payload, list) else [payload]
    return [row for row in rows if isinstance(row, dict)]
