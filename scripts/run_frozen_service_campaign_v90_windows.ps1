param(
  [string]$DrillPath = "$PSScriptRoot/run_service_drift_drill_windows.ps1",
  [string]$ValidatorPath = "$PSScriptRoot/validate_service_drift_result.py",
  [string]$CsgApiBase = "http://192.168.64.1:8000",
  [string]$HostId = "win11-arm-lab",
  [string]$ProbePython = "C:\Program Files\CyberStateGuardian\Probe\venv\Scripts\python.exe",
  [string]$ProbeConfig = "C:\Program Files\CyberStateGuardian\Probe\settings.json",
  [string]$OutputDirectory,
  [string]$ProtocolPath = "$PSScriptRoot/PROTOCOL.md",
  [string]$ExperimentId = "csg-service-event-only-v90",
  [string]$ProtocolSha256,
  [int]$Repetitions = 10,
  [int]$RandomSeed = 20261016,
  [int]$TelemetryWaitSeconds = 20,
  [int]$ProbeObservationTimeoutSeconds = 30,
  [int]$ProbePollIntervalSeconds = 1,
  [int]$LifecycleFinalizationWaitSeconds = 240,
  [int]$ApiTimeoutSeconds = 15,
  [int]$EventLookbackSeconds = 900,
  [int]$EventTimeToleranceSeconds = 20,
  [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"
$PostTrialHealthAttemptLimit = 3
$PostTrialHealthRetryIntervalSeconds = 15
if (-not $OutputDirectory) { throw "OutputDirectory is required and must not already exist." }
if ($Repetitions -ne 10) { throw "The frozen protocol requires exactly 10 randomized blocks." }
if ($ProtocolSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw "ProtocolSha256 must be a SHA-256 digest." }
if (-not (Test-Path -LiteralPath $DrillPath -PathType Leaf)) { throw "The frozen service drill is missing." }
if (-not (Test-Path -LiteralPath $ValidatorPath -PathType Leaf)) { throw "The independent validator is missing." }
if (-not (Test-Path -LiteralPath $ProtocolPath -PathType Leaf)) { throw "The frozen protocol is missing." }
if (-not (Test-Path -LiteralPath $ProbePython -PathType Leaf)) { throw "The installed probe Python runtime is missing." }
if (-not (Test-Path -LiteralPath $ProbeConfig -PathType Leaf)) { throw "The installed probe configuration is missing." }
if (Test-Path -LiteralPath $OutputDirectory) { throw "Refusing to overwrite campaign output: $OutputDirectory" }

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Run this campaign from an elevated Administrator PowerShell session." }

$health = Invoke-RestMethod -Method Get -TimeoutSec $ApiTimeoutSeconds -Uri "$CsgApiBase/api/wazuh/status"
$agent = @($health.agents | Where-Object { $_.name -eq $HostId }) | Select-Object -First 1
if (-not $health.ok -or -not $agent -or $agent.status -ne "active" -or -not $health.indexer.ok) {
  throw "Preflight failed: CSG, Wazuh indexer, and the target endpoint agent must be healthy."
}
if ([int]$health.sync.lookback_seconds -ne $EventLookbackSeconds) {
  throw "Live Wazuh lookback does not match the frozen protocol."
}
$settings = (Get-Content -LiteralPath $ProbeConfig | Out-String) | ConvertFrom-Json
if ($settings.CSG_PROBE_HOST_ID -ne $HostId) { throw "Probe host ID does not match the frozen endpoint." }
$wazuhService = Get-Service -Name WazuhSvc -ErrorAction Stop
$wazuhCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction Stop
if ($wazuhService.Status -ne "Running" -or $wazuhCim.ProcessId -le 0) {
  throw "WazuhSvc must be Running with a nonzero process ID before the campaign."
}
$wazuhConfigPath = Join-Path ${env:ProgramFiles(x86)} "ossec-agent\ossec.conf"
if (-not (Test-Path -LiteralPath $wazuhConfigPath -PathType Leaf)) { throw "Wazuh agent configuration is missing." }
$baselineWazuhConfigSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $wazuhConfigPath).Hash.ToLowerInvariant()
$probeConfigSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $ProbeConfig).Hash.ToLowerInvariant()
$probeTask = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction SilentlyContinue
if (-not $probeTask -or -not $probeTask.Settings.Enabled) {
  throw "The installed CSG probe scheduled task must exist and be enabled before the campaign."
}
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$preflight = [ordered]@{
  captured_at = (Get-Date).ToUniversalTime().ToString("o")
  host_id = $HostId
  administrator = $isAdmin
  windows_caption = $os.Caption
  windows_build = $os.BuildNumber
  windows_architecture = $os.OSArchitecture
  csg_api_ok = [bool]$health.ok
  wazuh_server_api_ok = [bool]$health.server_api.ok
  wazuh_indexer_ok = [bool]$health.indexer.ok
  wazuh_agent = $agent
  wazuh_service_status = [string]$wazuhService.Status
  wazuh_service_pid = [int]$wazuhCim.ProcessId
  wazuh_agent_config_path = $wazuhConfigPath
  wazuh_agent_config_sha256 = $baselineWazuhConfigSha256
  probe_config_path = $ProbeConfig
  probe_config_sha256 = $probeConfigSha256
  probe_host_id = $settings.CSG_PROBE_HOST_ID
  probe_task_state = if ($probeTask) { [string]$probeTask.State } else { "MISSING" }
  probe_task_enabled = if ($probeTask) { [bool]$probeTask.Settings.Enabled } else { $null }
  wazuh_event_lookback_seconds = [int]$health.sync.lookback_seconds
  event_time_tolerance_seconds = $EventTimeToleranceSeconds
  observation_window_seconds = 900
  reconciliation_grace_seconds = 180
  source_state = "probe"
  event_source = "wazuh"
  post_trial_health_attempt_limit = $PostTrialHealthAttemptLimit
  post_trial_health_retry_interval_seconds = $PostTrialHealthRetryIntervalSeconds
}

$controllerSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()
$drillSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $DrillPath).Hash.ToLowerInvariant()
$validatorSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $ValidatorPath).Hash.ToLowerInvariant()
$actualProtocolSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $ProtocolPath).Hash.ToLowerInvariant()
if ($actualProtocolSha256 -ne $ProtocolSha256.ToLowerInvariant()) {
  throw "Protocol file hash does not match the preregistered ProtocolSha256."
}
$random = New-Object System.Random($RandomSeed)
$schedule = @(
  for ($blockNumber = 1; $blockNumber -le $Repetitions; $blockNumber++) {
    $blockConditions = @("complete", "target_selective_drop", "no_change")
    for ($i = $blockConditions.Count - 1; $i -gt 0; $i--) {
      $j = $random.Next(0, $i + 1)
      $swap = $blockConditions[$i]
      $blockConditions[$i] = $blockConditions[$j]
      $blockConditions[$j] = $swap
    }
    foreach ($condition in $blockConditions) {
      $serviceName = if ($condition -eq "no_change") { "Winmgmt" } else {
        "CSGResearch$([guid]::NewGuid().ToString('N').Substring(0,12))"
      }
      [pscustomobject]@{
        block = $blockNumber
        condition = $condition
        repetition = $blockNumber
        trial_id = ("block-{0:D2}-{1}" -f $blockNumber, $condition)
        service_name = $serviceName
        distractor_service_name = "CSGDistractor$([guid]::NewGuid().ToString('N').Substring(0,10))"
        status = "PENDING"
        run_id = $null
        validation = $null
        validation_path = $null
        output = $null
        post_trial_health = $null
        started_at = $null
        ended_at = $null
        failure_reason = $null
      }
    }
  }
)

if ($ValidateOnly) {
  [ordered]@{
    preflight_valid = $true
    protocol_sha256 = $actualProtocolSha256
    controller_sha256 = $controllerSha256
    drill_sha256 = $drillSha256
    validator_sha256 = $validatorSha256
    blocks = $Repetitions
    slots = $schedule.Count
    condition_counts = @{
      complete = @($schedule | Where-Object { $_.condition -eq "complete" }).Count
      target_selective_drop = @($schedule | Where-Object { $_.condition -eq "target_selective_drop" }).Count
      no_change = @($schedule | Where-Object { $_.condition -eq "no_change" }).Count
    }
    post_trial_health_policy = @{
      attempts = $PostTrialHealthAttemptLimit
      retry_interval_seconds = $PostTrialHealthRetryIntervalSeconds
      recovered_trial_status = "COMPLETED_WITH_HEALTH_RECOVERY"
    }
    preflight = $preflight
  } | ConvertTo-Json -Depth 10
  return
}

$frozenSchedulePath = Join-Path $OutputDirectory "frozen-schedule.json"
$manifestPath = Join-Path $OutputDirectory "campaign-manifest.json"
$preflightPath = Join-Path $OutputDirectory "preflight.json"
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$preflight | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $preflightPath -Encoding UTF8
$schedule | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $frozenSchedulePath -Encoding UTF8
$frozenScheduleSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $frozenSchedulePath).Hash.ToLowerInvariant()
$manifest = [ordered]@{
  schema_version = "csg-frozen-service-reconciliation-campaign-v1"
  experiment_id = $ExperimentId
  host_id = $HostId
  status = "RUNNING"
  created_at = (Get-Date).ToUniversalTime().ToString("o")
  protocol_sha256 = $ProtocolSha256.ToLowerInvariant()
  protocol_path = $ProtocolPath
  controller_sha256 = $controllerSha256
  drill_sha256 = $drillSha256
  validator_sha256 = $validatorSha256
  frozen_schedule_path = $frozenSchedulePath
  frozen_schedule_sha256 = $frozenScheduleSha256
  preflight_path = $preflightPath
  random_seed = $RandomSeed
  randomization = "10 blocks; each block contains one trial per condition in independently shuffled order"
  repetitions_per_condition = $Repetitions
  event_time_tolerance_seconds = $EventTimeToleranceSeconds
  event_lookback_seconds = $EventLookbackSeconds
  lifecycle_finalization_wait_seconds = $LifecycleFinalizationWaitSeconds
  post_trial_health_policy = [ordered]@{
    attempts = $PostTrialHealthAttemptLimit
    retry_interval_seconds = $PostTrialHealthRetryIntervalSeconds
    required = @("csg_api_ok", "manager_api_ok", "indexer_ok", "agent_active", "lookback_unchanged")
    recovered_trial_status = "COMPLETED_WITH_HEALTH_RECOVERY"
  }
  original_wazuh_agent_config_sha256 = $baselineWazuhConfigSha256
  schedule = $schedule
}
function Save-Manifest {
  $manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
}
Save-Manifest

$completed = 0
$stoppedOnFailure = $false
foreach ($entry in $schedule) {
  $configHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $wazuhConfigPath).Hash.ToLowerInvariant()
  $liveHealth = Invoke-RestMethod -Method Get -TimeoutSec $ApiTimeoutSeconds -Uri "$CsgApiBase/api/wazuh/status"
  $liveAgent = @($liveHealth.agents | Where-Object { $_.name -eq $HostId }) | Select-Object -First 1
  $liveService = Get-Service -Name WazuhSvc -ErrorAction Stop
  if ($configHash -ne $baselineWazuhConfigSha256 -or $liveService.Status -ne "Running" -or
      -not $liveHealth.ok -or -not $liveHealth.indexer.ok -or -not $liveAgent -or $liveAgent.status -ne "active") {
    $entry.status = "NOT_STARTED_PREFLIGHT_FAILURE"
    $entry.failure_reason = "Wazuh configuration or endpoint health did not match the frozen preflight baseline."
    $manifest.status = "STOPPED_BEFORE_TRIAL"
    $stoppedOnFailure = $true
    Save-Manifest
    break
  }
  $trialDirectory = Join-Path $OutputDirectory $entry.trial_id
  New-Item -ItemType Directory -Path $trialDirectory | Out-Null
  $entry.output = Join-Path $trialDirectory "run.json"
  $entry.validation_path = Join-Path $trialDirectory "validation.json"
  $entry.started_at = (Get-Date).ToUniversalTime().ToString("o")
  $entry.status = "RUNNING"
  Save-Manifest
  Write-Host "Trial $($completed + 1)/30: block=$($entry.block), condition=$($entry.condition), id=$($entry.trial_id)"
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
      -ApiTimeoutSeconds $ApiTimeoutSeconds `
      -ExperimentId $ExperimentId `
      -TrialId $entry.trial_id `
      -TelemetryCondition $entry.condition `
      -ServiceName $entry.service_name `
      -DistractorServiceName $entry.distractor_service_name `
      -OutputPath $entry.output
    if (-not (Test-Path -LiteralPath $entry.output -PathType Leaf)) { throw "Drill completed without its raw run artifact." }
    $record = (Get-Content -LiteralPath $entry.output | Out-String) | ConvertFrom-Json
    if ($record.run_status -ne "COMPLETED") { throw "Raw trial artifact reports run_status=$($record.run_status)." }
    if ($record.protocol_adherence.protocol_adherent -ne $true) { throw "The raw trial reports protocol non-adherence." }
    & $ProbePython $ValidatorPath $entry.output --output $entry.validation_path | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Independent raw-artifact validation failed with exit code $LASTEXITCODE." }
    $validation = (Get-Content -LiteralPath $entry.validation_path | Out-String) | ConvertFrom-Json
    if ($validation.passed -ne $true) { throw "Independent validator did not pass." }
    $restoredHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $wazuhConfigPath).Hash.ToLowerInvariant()
    $restoredService = Get-Service -Name WazuhSvc -ErrorAction Stop
    if ($restoredHash -ne $baselineWazuhConfigSha256 -or $restoredService.Status -ne "Running") {
      throw "Wazuh service/configuration was not restored to the recorded preflight baseline."
    }
    $postHealthAttempts = @()
    $postHealth = $null
    $postAgent = $null
    $postHealthValid = $false
    for ($healthAttempt = 1; $healthAttempt -le $PostTrialHealthAttemptLimit; $healthAttempt++) {
      $attemptStartedAt = (Get-Date).ToUniversalTime().ToString("o")
      $attempt = [ordered]@{
        attempt = $healthAttempt
        started_at = $attemptStartedAt
        completed_at = $null
        csg_api_ok = $false
        manager_api_ok = $false
        indexer_ok = $false
        endpoint_agent_status = "UNKNOWN"
        lookback_seconds = $null
        healthy = $false
        failure_reason = $null
      }
      try {
        $candidateHealth = Invoke-RestMethod -Method Get -TimeoutSec $ApiTimeoutSeconds -Uri "$CsgApiBase/api/wazuh/status"
        $candidateAgent = @($candidateHealth.agents | Where-Object { $_.name -eq $HostId }) | Select-Object -First 1
        $attempt.csg_api_ok = [bool]$candidateHealth.ok
        $attempt.manager_api_ok = [bool]$candidateHealth.server_api.ok
        $attempt.indexer_ok = [bool]$candidateHealth.indexer.ok
        $attempt.endpoint_agent_status = if ($candidateAgent) { [string]$candidateAgent.status } else { "MISSING" }
        $attempt.lookback_seconds = [int]$candidateHealth.sync.lookback_seconds
        $postHealthValid = $attempt.csg_api_ok -and $attempt.manager_api_ok -and $attempt.indexer_ok -and
          $candidateAgent -and $candidateAgent.status -eq "active" -and
          $attempt.lookback_seconds -eq $EventLookbackSeconds
        if (-not $postHealthValid) {
          $attempt.failure_reason = "One or more frozen API, agent, indexer, or lookback health checks failed."
        } else {
          $postHealth = $candidateHealth
          $postAgent = $candidateAgent
        }
      } catch {
        $postHealthValid = $false
        $attempt.failure_reason = $_.Exception.Message
      }
      $attempt.healthy = [bool]$postHealthValid
      $attempt.completed_at = (Get-Date).ToUniversalTime().ToString("o")
      $postHealthAttempts += [pscustomobject]$attempt
      $entry.post_trial_health = [ordered]@{
        attempts = @($postHealthAttempts)
        recovered_after_retry = [bool]($postHealthValid -and $healthAttempt -gt 1)
        wazuh_service = [string]$restoredService.Status
        wazuh_config_sha256 = $restoredHash
      }
      Save-Manifest
      if ($postHealthValid) { break }
      if ($healthAttempt -lt $PostTrialHealthAttemptLimit) {
        Start-Sleep -Seconds $PostTrialHealthRetryIntervalSeconds
      }
    }
    if (-not $postHealthValid) {
      throw "Post-trial CSG/Wazuh health failed after $PostTrialHealthAttemptLimit recorded checks."
    }
    $postProbeTask = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction Stop
    if (-not $postProbeTask.Settings.Enabled) { throw "The CSG probe scheduled task was not restored to enabled state." }
    $entry.run_id = $record.run_id
    $entry.validation = if ($entry.post_trial_health.recovered_after_retry) {
      "PASS_WITH_HEALTH_RECOVERY"
    } else {
      "PASS"
    }
    $entry.status = if ($entry.post_trial_health.recovered_after_retry) {
      "COMPLETED_WITH_HEALTH_RECOVERY"
    } else {
      "COMPLETED"
    }
    $completed++
  } catch {
    $entry.status = "FAILED"
    $entry.validation = "FAIL_OR_NOT_RUN"
    $entry.failure_reason = $_.Exception.Message
    $stoppedOnFailure = $true
    $manifest.status = "STOPPED_ON_FIRST_FAILURE"
    Write-Warning "Campaign halted at $($entry.trial_id): $($entry.failure_reason)"
  } finally {
    $entry.ended_at = (Get-Date).ToUniversalTime().ToString("o")
    Save-Manifest
  }
  if ($stoppedOnFailure) { break }
}

if (-not $stoppedOnFailure -and $completed -eq 30) { $manifest.status = "COMPLETED_ALL_30_VALIDATED_TRIALS" }
$manifest.completed_trials = $completed
$manifest.ended_at = (Get-Date).ToUniversalTime().ToString("o")
Save-Manifest
Write-Host "Campaign status: $($manifest.status); independently validated trials: $completed/30"
