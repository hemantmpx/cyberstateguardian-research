from __future__ import annotations

import platform
from typing import Any

from cyberstateguardian_probe.collectors._powershell import run_powershell_json
from cyberstateguardian_probe.normalize import normalize_path


def collect_registry_security_state() -> dict[str, Any]:
    if platform.system().lower() != "windows":
        return _result(
            "unavailable", [], "Windows registry collection is only available on Windows"
        )
    script = r"""
$rows = @()
$currentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$runKeys = @(
  [pscustomobject]@{
    SourcePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    ObjectPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
  },
  [pscustomobject]@{
    SourcePath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    ObjectPath = "HKU:\$currentUserSid\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
  }
)
foreach ($runKey in $runKeys) {
  if (Test-Path $runKey.SourcePath) {
    $item = Get-ItemProperty -Path $runKey.SourcePath
    foreach ($property in $item.PSObject.Properties) {
      if ($property.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
        $rows += [pscustomobject]@{
          ObjectKey = "registry:$($runKey.ObjectPath)/$($property.Name)"
          StateType = 'autorun'
          Path = $runKey.ObjectPath
          Name = $property.Name
          Value = [string]$property.Value
        }
      }
    }
  }
}
try {
  $mp = Get-MpPreference
  foreach ($kind in @('ExclusionPath','ExclusionProcess','ExclusionExtension')) {
    foreach ($value in @($mp.$kind)) {
      if ($null -ne $value -and [string]$value -ne '') {
        $rows += [pscustomobject]@{
          ObjectKey = "registry:defender/$kind/$value"
          StateType = 'defender_exclusion'
          Path = 'Microsoft Defender Preferences'
          Name = $kind
          Value = [string]$value
        }
      }
    }
  }
} catch {
  $rows += [pscustomobject]@{ CollectorError = "Defender preferences: $($_.Exception.Message)" }
}
$rows | ConvertTo-Json -Depth 4 -Compress
"""
    try:
        rows = []
        errors = []
        for row in run_powershell_json(script):
            if row.get("CollectorError"):
                errors.append(str(row["CollectorError"]))
                continue
            object_key = normalize_path(row.get("ObjectKey"))
            if not object_key:
                continue
            rows.append(
                {
                    "object_key": object_key,
                    "state_type": row.get("StateType"),
                    "path": normalize_path(row.get("Path")),
                    "name": row.get("Name"),
                    "value": row.get("Value"),
                }
            )
        return _result("partial" if errors else "healthy", rows, "; ".join(errors) or None)
    except Exception as exc:
        return _result("error", [], f"registry collection failed: {type(exc).__name__}: {exc}")


def _result(status: str, items: list[dict[str, Any]], message: str | None) -> dict[str, Any]:
    return {"category": "registry", "status": status, "items": items, "message": message}
