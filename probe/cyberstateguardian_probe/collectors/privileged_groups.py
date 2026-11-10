from __future__ import annotations

import platform
from typing import Any

from cyberstateguardian_probe.collectors._powershell import run_powershell_json
from cyberstateguardian_probe.normalize import normalize_username


def collect_privileged_groups() -> dict[str, Any]:
    if platform.system().lower() != "windows":
        return _result(
            "unavailable", [], "Windows local-group collection is only available on Windows"
        )
    script = r"""
$group = Get-LocalGroup -SID 'S-1-5-32-544'
Get-LocalGroupMember -Group $group | ForEach-Object {
  [pscustomobject]@{
    Group = 'Administrators'
    Member = $_.Name
    SID = [string]$_.SID
    ObjectClass = [string]$_.ObjectClass
    PrincipalSource = [string]$_.PrincipalSource
  }
} | ConvertTo-Json -Depth 4 -Compress
"""
    try:
        rows = [
            {
                "group": str(row.get("Group") or "Administrators"),
                "member": normalize_username(row.get("Member")),
                "sid": row.get("SID"),
                "object_class": row.get("ObjectClass"),
                "principal_source": row.get("PrincipalSource"),
            }
            for row in run_powershell_json(script)
            if row.get("Member")
        ]
        return _result("healthy", rows, None)
    except Exception as exc:
        return _result(
            "error", [], f"privileged-group collection failed: {type(exc).__name__}: {exc}"
        )


def _result(status: str, items: list[dict[str, Any]], message: str | None) -> dict[str, Any]:
    return {"category": "privileged_group", "status": status, "items": items, "message": message}
