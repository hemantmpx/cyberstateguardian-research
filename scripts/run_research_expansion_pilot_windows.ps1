param(
  [string]$DrillPath = "$PSScriptRoot/run_service_drift_drill_windows.ps1",
  [string]$CsgApiBase = "http://replace-with-mac-ip:8000",
  [string]$HostId = "win11-arm-lab",
  [string]$ProbePython = "python.exe",
  [string]$ProbeConfig = "",
  [ValidateRange(1, 20)][int]$CompleteRepetitions = 3,
  [ValidateRange(1, 20)][int]$NoChangeRepetitions = 3,
  [ValidateRange(0, 20)][int]$DistractorRepetitions = 1,
  [ValidateRange(0, 20)][int]$CaptureDropRepetitions = 1,
  [int]$TelemetryWaitSeconds = 20,
  [int]$ProbeObservationTimeoutSeconds = 30,
  [int]$ProbePollIntervalSeconds = 1,
  [int]$LifecycleFinalizationWaitSeconds = 75,
  [int]$CaptureDropFinalizationWaitSeconds = 960,
  [int]$RecoveryWaitSeconds = 60,
  [string]$OutputDirectory = "C:\CSG\research-expansion-pilot",
  [int]$RandomSeed = 530,
  [string]$ExperimentId = ""
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $DrillPath -PathType Leaf)) {
  throw "Drill script not found: $DrillPath"
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$manifestPath = Join-Path $OutputDirectory "campaign-manifest.json"
if (Test-Path -LiteralPath $manifestPath) {
  throw "Refusing to overwrite an existing campaign manifest: $manifestPath"
}

$experimentId = if ($ExperimentId) { $ExperimentId } else {
  "csg-expansion-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))"
}
$counts = [ordered]@{
  complete = $CompleteRepetitions
  no_change = $NoChangeRepetitions
  same_host_distractor = $DistractorRepetitions
  capture_drop = $CaptureDropRepetitions
}
$schedule = @(
  foreach ($condition in $counts.Keys) {
    for ($repetition = 1; $repetition -le $counts[$condition]; $repetition++) {
      $trialId = "{0}-{1:d3}" -f $condition, $repetition
      [pscustomobject]@{
        condition = $condition
        repetition = $repetition
        trial_id = $trialId
        output = Join-Path (Join-Path $OutputDirectory $trialId) "run.json"
        status = "PENDING"
        run_id = $null
        service_name = $null
        started_at = $null
        ended_at = $null
        failure_reason = $null
        failure_script_stack = $null
        failure_position = $null
      }
    }
  }
)
if ($schedule.Count -eq 0) { throw "At least one trial must be assigned." }

$random = New-Object System.Random($RandomSeed)
for ($index = $schedule.Count - 1; $index -gt 0; $index--) {
  $swapIndex = $random.Next(0, $index + 1)
  $temporary = $schedule[$index]
  $schedule[$index] = $schedule[$swapIndex]
  $schedule[$swapIndex] = $temporary
}

$manifest = [ordered]@{
  schema_version = "csg-research-expansion-pilot-v1"
  experiment_id = $experimentId
  host_id = $HostId
  state_categories = @("service")
  assigned_condition_counts = $counts
  random_seed = $RandomSeed
  order_randomized_across_conditions = $true
  schedule = $schedule
  runs = $schedule
  status = "PRECHECK"
  created_at = (Get-Date).ToUniversalTime().ToString("o")
  preflight = $null
  lifecycle_finalization_wait_seconds = $LifecycleFinalizationWaitSeconds
  capture_drop_finalization_wait_seconds = $CaptureDropFinalizationWaitSeconds
  capture_drop_recovery_wait_seconds = $RecoveryWaitSeconds
  interpretation_limit = "Single Windows 11 ARM64 endpoint, service category only; calibration results, not confirmatory or cross-host estimates."
}

function Save-Manifest {
  $manifest | ConvertTo-Json -Depth 20 | Set-Content -Path $manifestPath -Encoding UTF8
}

Save-Manifest
try {
  $health = Invoke-RestMethod -Method Get -DisableKeepAlive -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
  $agent = @($health.server_api.agents | Where-Object { $_.name -eq $HostId }) | Select-Object -First 1
  $wazuhService = Get-Service -Name "WazuhSvc" -ErrorAction Stop
  $preflightPassed = [bool]($health.server_api.ok -and $health.indexer.ok -and $agent -and $agent.status -eq "active" -and $wazuhService.Status -eq "Running")
  $manifest.preflight = [ordered]@{
    checked_at = (Get-Date).ToUniversalTime().ToString("o")
    manager_status = if ($health.server_api.ok) { "AVAILABLE" } else { "UNAVAILABLE" }
    indexer_status = if ($health.indexer.ok) { "AVAILABLE" } else { "UNAVAILABLE" }
    endpoint_agent_status = if ($agent) { [string]$agent.status } else { "NOT_REPORTED" }
    endpoint_wazuh_service_status = [string]$wazuhService.Status
    passed = $preflightPassed
  }
  if (-not $preflightPassed) {
    $manifest.status = "PRECHECK_FAILED"
    Save-Manifest
    throw "Manager, indexer, endpoint agent, or local Wazuh service failed preflight. No trial was run."
  }
  $manifest.status = "RUNNING"
  Save-Manifest
} catch {
  if ($manifest.status -eq "PRECHECK") {
    $manifest.status = "PRECHECK_FAILED"
    $manifest.preflight = [ordered]@{
      checked_at = (Get-Date).ToUniversalTime().ToString("o")
      passed = $false
      failure_reason = $_.Exception.Message
    }
    Save-Manifest
  }
  throw
}

foreach ($entry in $schedule) {
  $trialDirectory = Split-Path -Parent $entry.output
  New-Item -ItemType Directory -Path $trialDirectory -Force | Out-Null
  if (Test-Path -LiteralPath $entry.output) { throw "Refusing to overwrite trial output: $($entry.output)" }
  if (Test-Path -LiteralPath "$($entry.output).heartbeat.jsonl") { throw "Refusing to overwrite heartbeat output for $($entry.trial_id)" }
  $entry.status = "RUNNING"
  $entry.started_at = (Get-Date).ToUniversalTime().ToString("o")
  Save-Manifest
  Write-Host "Running $($entry.trial_id) ($($entry.condition))"
  try {
    & $DrillPath `
      -CsgApiBase $CsgApiBase `
      -HostId $HostId `
      -ProbePython $ProbePython `
      -ProbeConfig $ProbeConfig `
      -TelemetryWaitSeconds $TelemetryWaitSeconds `
      -ProbeObservationTimeoutSeconds $ProbeObservationTimeoutSeconds `
      -ProbePollIntervalSeconds $ProbePollIntervalSeconds `
      -LifecycleFinalizationWaitSeconds $LifecycleFinalizationWaitSeconds `
      -FinalizationWaitSeconds $CaptureDropFinalizationWaitSeconds `
      -RecoveryWaitSeconds $RecoveryWaitSeconds `
      -ExperimentId $experimentId `
      -TrialId $entry.trial_id `
      -TelemetryCondition $entry.condition `
      -OutputPath $entry.output
    if ($LASTEXITCODE -ne 0) { throw "Drill failed with exit code $LASTEXITCODE" }
    $record = Get-Content -Raw -Path $entry.output | ConvertFrom-Json
    $entry.status = "COMPLETED"
    $entry.run_id = $record.run_id
    $entry.service_name = $record.service_name
  } catch {
    $entry.status = "FAILED"
    $entry.failure_reason = $_.Exception.Message
    $entry.failure_script_stack = $_.ScriptStackTrace
    $entry.failure_position = $_.InvocationInfo.PositionMessage
    $failure = [ordered]@{
      schema_version = "csg-research-expansion-trial-failure-v1"
      experiment_id = $experimentId
      trial_id = $entry.trial_id
      condition = $entry.condition
      host_id = $HostId
      started_at = $entry.started_at
      failed_at = (Get-Date).ToUniversalTime().ToString("o")
      failure_reason = $entry.failure_reason
      failure_script_stack = $entry.failure_script_stack
      failure_position = $entry.failure_position
      cleanup_status = "review drill finally block and independently verify Windows service state"
    }
    $failure | ConvertTo-Json -Depth 12 | Set-Content -Path (Join-Path $trialDirectory "failure.json") -Encoding UTF8
    Write-Warning "Retained failed attempt $($entry.trial_id): $($entry.failure_reason)"
  }
  $entry.ended_at = (Get-Date).ToUniversalTime().ToString("o")
  Save-Manifest
}

$manifest.status = if (@($schedule | Where-Object { $_.status -eq "FAILED" }).Count -gt 0) {
  "COMPLETED_WITH_FAILURES"
} else {
  "COMPLETED"
}
$manifest.completed_at = (Get-Date).ToUniversalTime().ToString("o")
Save-Manifest
Write-Host "Campaign manifest finalized: $manifestPath"
