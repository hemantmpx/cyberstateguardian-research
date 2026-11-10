param(
  [string]$DrillPath = "$PSScriptRoot/run_service_drift_drill_windows.ps1",
  [string]$CsgApiBase = "http://replace-with-mac-ip:8000",
  [string]$HostId = "win11-arm-lab",
  [string]$ProbePython = "python.exe",
  [string]$ProbeConfig = "",
  [int]$Repetitions = 3,
  [int]$TelemetryWaitSeconds = 20,
  [int]$ProbeObservationTimeoutSeconds = 30,
  [int]$ProbePollIntervalSeconds = 1,
  [int]$LifecycleFinalizationWaitSeconds = 75,
  [int]$CaptureDropFinalizationWaitSeconds = 960,
  [int]$RecoveryWaitSeconds = 60,
  [int]$ApiTimeoutSeconds = 15,
  [int]$EventTimeToleranceSeconds = 10,
  [int]$EventLookbackSeconds = 300,
  [string]$ProtocolSha256 = "",
  [string]$OutputDirectory = "C:\CSG\research-campaign",
  [int]$RandomSeed = 530,
  [string]$ExperimentId = "",
  [ValidateSet("engineering_pilot_not_pooled", "prospective_same_host_confirmatory_controlled_holdout")]
  [string]$ExecutionKind = "engineering_pilot_not_pooled",
  [ValidateSet("complete", "complete_distractor", "delayed_reconciliation", "telemetry_delay", "capture_drop", "no_change", "no_change_distractor", "same_host_distractor", "target_selective_drop", "target_selective_drop_clean")]
  [string[]]$Conditions = @("complete", "complete_distractor", "target_selective_drop_clean", "target_selective_drop", "no_change_distractor")
)

$ErrorActionPreference = "Stop"
if ($Repetitions -lt 1 -or $Repetitions -gt 20) { throw "Repetitions must be between 1 and 20." }
if ($EventTimeToleranceSeconds -lt 0 -or $EventTimeToleranceSeconds -gt 120) { throw "EventTimeToleranceSeconds must be between 0 and 120." }
if ($EventLookbackSeconds -lt 60 -or $EventLookbackSeconds -gt 86400) { throw "EventLookbackSeconds must be between 60 and 86400." }
if ($ProtocolSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw "ProtocolSha256 must be the frozen protocol's 64-character SHA-256." }
$health = Invoke-RestMethod -Method Get -TimeoutSec $ApiTimeoutSeconds -Uri "$CsgApiBase/api/wazuh/status"
$agent = @($health.agents | Where-Object { $_.name -eq $HostId }) | Select-Object -First 1
if (-not $health.ok -or -not $agent -or $agent.status -ne "active") {
  throw "Preflight failed: CSG/Wazuh health and the target endpoint agent must be active."
}
if ([int]$health.sync.lookback_seconds -ne $EventLookbackSeconds) {
  throw "Configured Wazuh event lookback $($health.sync.lookback_seconds) does not match frozen value $EventLookbackSeconds."
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$conditions = @($Conditions)
$experimentId = if ($ExperimentId) { $ExperimentId } else {
  "service-telemetry-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))"
}
$manifestPath = Join-Path $OutputDirectory "campaign-manifest.json"
if (Test-Path -LiteralPath $manifestPath) {
  throw "Refusing to overwrite an existing campaign manifest: $manifestPath"
}
$controllerSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$drillSha256 = (Get-FileHash -LiteralPath $DrillPath -Algorithm SHA256).Hash.ToLowerInvariant()
$schedule = @(
  foreach ($condition in $conditions) {
    for ($rep = 1; $rep -le $Repetitions; $rep++) {
      $trialId = "$condition-$rep"
      [pscustomobject]@{
        condition = $condition
        repetition = $rep
        trial_id = $trialId
        output = (Join-Path (Join-Path $OutputDirectory $trialId) "run.json")
        status = "PENDING"
        run_id = $null
        started_at = $null
        ended_at = $null
        failure_reason = $null
      }
    }
  }
)
$random = New-Object System.Random($RandomSeed)
$schedule = @($schedule | Sort-Object { $random.Next() })
$manifest = [ordered]@{
  schema_version = "csg-live-telemetry-campaign-v5"
  state_categories = @("service")
  conditions = $conditions
  experiment_id = $experimentId
  repetitions = $Repetitions
  random_seed = $RandomSeed
  execution_kind = $ExecutionKind
  protocol_sha256 = $ProtocolSha256.ToLowerInvariant()
  declared_event_time_tolerance_seconds = $EventTimeToleranceSeconds
  declared_wazuh_event_lookback_seconds = $EventLookbackSeconds
  controller_sha256 = $controllerSha256
  drill_sha256 = $drillSha256
  schedule = $schedule
  runs = $schedule
  status = "RUNNING"
  created_at = (Get-Date).ToUniversalTime().ToString("o")
  capture_drop_definition = "WazuhSvc remains stopped through the observation window and grace period; CSG records the bounded pre-restore result, restores WazuhSvc, then performs a separate post-restore synchronization."
  complete_definition = "Create and modify a fresh randomized inert service with Wazuh available; require exact probe and same-host/type/object Wazuh event evidence."
  distractor_definition = "Index an exact same-host service_created event for a different randomized service, stop WazuhSvc for the target ADD bounded window, and verify the distractor does not reconcile the target object."
  no_change_definition = "The native probe and provider sync run without creating or modifying the randomized service; zero findings is the control outcome."
  probe_sampling_policy = "At the start of every assigned trial, the periodic CyberStateGuardian Probe scheduled task is disabled and any active task run is stopped. The drill uses explicit one-shot probe invocations only, records prior/during/after task state, and restores the original enabled/running state in a finally path."
  bounded_distractor_finalization_policy = "At the pre-restore checkpoint, POST /api/pipeline/process-backlog reevaluates pending findings against events already stored in CSG and the current deadline; it does not query Wazuh. The checkpoint is archived before WazuhSvc is restored."
  delayed_reconciliation_definition = "The Wazuh source remains available; CSG queries before the expected event wait and then re-evaluates after the declared wait. This is a query/reconciliation delay, not delayed endpoint telemetry delivery."
  telemetry_delay_definition = "WazuhSvc is stopped before the controlled changes, the native probe continues, and WazuhSvc is restored before final reconciliation. Event recovery is measured rather than assumed: recovered events demonstrate delayed delivery, while absent events demonstrate source interruption without recovery in the bounded window."
  lifecycle_finalization_wait_seconds = $LifecycleFinalizationWaitSeconds
  capture_drop_finalization_wait_seconds = $CaptureDropFinalizationWaitSeconds
  limitation = "Stopping WazuhSvc may buffer events rather than permanently delete them. A post-restore CONSISTENT result demonstrates recovery, not permanent event-loss resistance; a post-restore UNEXPLAINED result is required before claiming the event was genuinely lost."
}

function Save-Manifest {
  $manifest | ConvertTo-Json -Depth 12 | Set-Content -Path $manifestPath -Encoding UTF8
}

Save-Manifest
Write-Host "Campaign manifest initialized at $manifestPath"

foreach ($entry in $schedule) {
  $trialDirectory = Split-Path -Parent $entry.output
  New-Item -ItemType Directory -Path $trialDirectory -Force | Out-Null
  $entry.status = "RUNNING"
  $entry.started_at = (Get-Date).ToUniversalTime().ToString("o")
  Save-Manifest
  Write-Host "Running service category condition=$($entry.condition) repetition=$($entry.repetition)/$Repetitions trial=$($entry.trial_id)"
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
      -ApiTimeoutSeconds $ApiTimeoutSeconds `
      -ExperimentId $experimentId `
      -TrialId $entry.trial_id `
      -TelemetryCondition $entry.condition `
      -OutputPath $entry.output
    if ($LASTEXITCODE -ne 0) { throw "Drill failed with exit code $LASTEXITCODE" }
    $record = Get-Content -Raw -Path $entry.output | ConvertFrom-Json
    $entry.status = "COMPLETED"
    $entry.run_id = $record.run_id
  } catch {
    $entry.status = "FAILED"
    $entry.failure_reason = $_.Exception.Message
    $failure = [ordered]@{
      schema_version = "csg-live-telemetry-trial-failure-v1"
      experiment_id = $experimentId
      trial_id = $entry.trial_id
      condition = $entry.condition
      host_id = $HostId
      started_at = $entry.started_at
      failed_at = (Get-Date).ToUniversalTime().ToString("o")
      failure_reason = $entry.failure_reason
      cleanup_status = "verify_on_windows_host"
    }
    $failure | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $trialDirectory "failure.json") -Encoding UTF8
    Write-Warning "Trial $($entry.trial_id) failed and was retained: $($entry.failure_reason)"
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
Write-Host "Campaign manifest finalized at $manifestPath"
