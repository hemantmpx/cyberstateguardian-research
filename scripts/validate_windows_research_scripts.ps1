$ErrorActionPreference = "Stop"

$targets = @(
  (Join-Path $PSScriptRoot "run_service_drift_drill_windows.ps1"),
  (Join-Path $PSScriptRoot "run_live_telemetry_campaign_windows.ps1")
)
$parseErrors = @()
foreach ($path in $targets) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    $parseErrors += "Missing script: $path"
    continue
  }
  $tokens = $null
  $errors = $null
  [System.Management.Automation.Language.Parser]::ParseFile(
    $path,
    [ref]$tokens,
    [ref]$errors
  ) | Out-Null
  foreach ($errorRecord in $errors) {
    $parseErrors += "$path`:$($errorRecord.Extent.StartLineNumber): $($errorRecord.Message)"
  }
}

if ($parseErrors.Count -gt 0) {
  $parseErrors | ForEach-Object { Write-Error $_ }
  exit 1
}

$targets | ForEach-Object { Write-Output "PARSE_OK $_" }
