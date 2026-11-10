from __future__ import annotations

import platform
from typing import Any

from cyberstateguardian_probe.collectors._powershell import run_powershell_json
from cyberstateguardian_probe.normalize import normalize_path, normalize_username


def collect_scheduled_tasks() -> dict[str, Any]:
    if platform.system().lower() != "windows":
        return _unavailable("Windows scheduled-task collection is only available on Windows")
    script = r"""
Get-ScheduledTask | ForEach-Object {
  [pscustomobject]@{
    TaskName = "$($_.TaskPath)$($_.TaskName)"
    Enabled = $_.Settings.Enabled
    Definition = Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath
    Author = $_.Author
    Principal = $_.Principal.UserId
    Actions = @($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() })
  }
} | ConvertTo-Json -Depth 5 -Compress
"""
    try:
        rows = [
            {
                "task_name": row.get("TaskName"),
                "enabled": row.get("Enabled"),
                "definition_xml": row.get("Definition"),
                "author": normalize_username(row.get("Author")),
                "principal": normalize_username(row.get("Principal")),
                "actions": [
                    normalize_path(action) for action in _as_list(row.get("Actions")) if action
                ],
            }
            for row in run_powershell_json(script)
            if row.get("TaskName")
        ]
        return {"category": "scheduled_task", "status": "healthy", "items": rows, "message": None}
    except Exception as exc:
        return _error(f"scheduled-task collection failed: {type(exc).__name__}: {exc}")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _unavailable(message: str) -> dict[str, Any]:
    return {"category": "scheduled_task", "status": "unavailable", "items": [], "message": message}


def _error(message: str) -> dict[str, Any]:
    return {"category": "scheduled_task", "status": "error", "items": [], "message": message}
