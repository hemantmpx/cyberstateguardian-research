param(
  [string]$TrialScript = "$PSScriptRoot\run_registry_reconciliation_trial_windows.ps1",
  [string]$CsgApiBase = "http://192.168.64.1:8000",
  [string]$HostId = "win11-arm-lab",
  [string]$ProbeConfig = "C:\CSG\probe-settings.json",
  [string]$OutputDirectory = "C:\CSG\research\registry-reconciliation-campaign",
  [string]$ProtocolSha256 = "",
  [int]$RepetitionsPerCondition = 10,
  [string[]]$Conditions = @("registry_complete", "registry_wrong_object", "registry_no_change"),
  [int]$RandomSeed = 20261008,
  [int]$PositiveEventWaitSeconds = 30,
  [int]$LifecycleWaitSeconds = 75,
  [int]$ToleranceSeconds = 10,
  [int]$EventLookbackSeconds = 300,
  [string]$ExpectedSysmonRuntimeHash = "",
  [ValidateSet("engineering_pilot_not_pooled", "prospective_same_host_controlled_holdout", "same_host_repeated_controlled_campaign")]
  [string]$ExecutionKind = "same_host_repeated_controlled_campaign"
)

$ErrorActionPreference = "Stop"
$allowedConditions = @("registry_complete", "registry_wrong_object", "registry_selective_drop", "registry_eventid_drop", "registry_distractor_only", "registry_competing_event", "registry_sysmon_target_drop", "registry_no_change")
if ($Conditions.Count -eq 0 -or @($Conditions | Where-Object { $_ -notin $allowedConditions }).Count -gt 0) {
  throw "Conditions must be a nonempty subset of: $($allowedConditions -join ', ')."
}
if (@($Conditions | Select-Object -Unique).Count -ne $Conditions.Count) {
  throw "Condition names must not be repeated."
}
if ($RepetitionsPerCondition -lt 1 -or $RepetitionsPerCondition -gt 30) {
  throw "RepetitionsPerCondition must be between 1 and 30."
}
if ($ProtocolSha256 -notmatch '^[0-9a-fA-F]{64}$') {
  throw "ProtocolSha256 must be the SHA-256 of a frozen protocol file."
}
if ($Conditions -contains "registry_sysmon_target_drop" -and
    $ExpectedSysmonRuntimeHash -notmatch '^[0-9a-fA-F]{64}$') {
  throw "The Sysmon target-drop pilot requires the active runtime hash captured by V87 preflight."
}
if (-not (Test-Path -LiteralPath $TrialScript)) { throw "Trial script missing: $TrialScript" }
if (-not (Test-Path -LiteralPath $ProbeConfig)) { throw "Probe config missing: $ProbeConfig" }
if (Test-Path -LiteralPath $OutputDirectory) {
  throw "Refusing to overwrite campaign directory: $OutputDirectory"
}
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Run the campaign from Administrator PowerShell." }

function Save-Json([string]$Path, [object]$Value) {
  $temporaryPath = "$Path.tmp"
  $Value | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
  Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
}

$probeSettings = Get-Content -LiteralPath $ProbeConfig -Raw | ConvertFrom-Json
if ($probeSettings.CSG_PROBE_HOST_ID -ne $HostId) {
  throw "Probe config host ID '$($probeSettings.CSG_PROBE_HOST_ID)' does not match '$HostId'."
}
$health = Invoke-RestMethod -Method Get -DisableKeepAlive -TimeoutSec 30 -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
$agent = @($health.agents | Where-Object { $_.name -eq $HostId }) | Select-Object -First 1
$wazuh = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
$sysmon = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -match "^Sysmon" })
$task = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction SilentlyContinue
if (-not $health.ok -or -not $agent -or $agent.status -ne "active" -or
    -not $wazuh -or $wazuh.State -ne "Running" -or $sysmon.Count -eq 0) {
  throw "Preflight failed: Wazuh manager/indexer/agent, WazuhSvc, and Sysmon must be healthy."
}

$os = Get-CimInstance Win32_OperatingSystem
$probeTaskState = if ($task) { [string]$task.State } else { "not_installed" }
$probeTaskEnabled = if ($task) { [bool]$task.Settings.Enabled } else { $null }
$trialHash = (Get-FileHash -LiteralPath $TrialScript -Algorithm SHA256).Hash.ToLowerInvariant()
$controllerHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$probeConfigHash = (Get-FileHash -LiteralPath $ProbeConfig -Algorithm SHA256).Hash.ToLowerInvariant()
$environment = [ordered]@{
  captured_at = (Get-Date).ToUniversalTime().ToString("o")
  capture_phase = "immediately_before_campaign"
  host_id = $HostId
  computer_name = $env:COMPUTERNAME
  os_caption = $os.Caption
  os_version = $os.Version
  os_build = $os.BuildNumber
  powershell_version = $PSVersionTable.PSVersion.ToString()
  wazuh_agent_version = $agent.version
  wazuh_service_state = [string]$wazuh.State
  wazuh_service_pid = [int]$wazuh.ProcessId
  sysmon_services = @($sysmon | ForEach-Object {
    [ordered]@{ name = $_.Name; state = $_.State; process_id = [int]$_.ProcessId }
  })
  probe_scheduled_task = [ordered]@{ installed = [bool]$task; enabled = $probeTaskEnabled; state = $probeTaskState }
  api_health_ok = [bool]$health.ok
  wazuh_agent_status = $agent.status
  declared_event_time_tolerance_seconds = $ToleranceSeconds
  declared_event_lookback_seconds = $EventLookbackSeconds
  declared_positive_event_wait_seconds = $PositiveEventWaitSeconds
  declared_lifecycle_finalization_wait_seconds = $LifecycleWaitSeconds
  trial_script_sha256 = $trialHash
  controller_script_sha256 = $controllerHash
  probe_config_sha256 = $probeConfigHash
  protocol_sha256 = $ProtocolSha256.ToLowerInvariant()
  expected_sysmon_runtime_hash = if ($ExpectedSysmonRuntimeHash) { $ExpectedSysmonRuntimeHash.ToLowerInvariant() } else { $null }
  sysmon_config_sha256 = if (Test-Path "C:\CSG\sysmon-csg-lab.xml") {
    (Get-FileHash "C:\CSG\sysmon-csg-lab.xml" -Algorithm SHA256).Hash.ToLowerInvariant()
  } else { $null }
  wazuh_config_sha256 = if (Test-Path "C:\Program Files (x86)\ossec-agent\ossec.conf") {
    (Get-FileHash "C:\Program Files (x86)\ossec-agent\ossec.conf" -Algorithm SHA256).Hash.ToLowerInvariant()
  } else { $null }
}

$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
Save-Json (Join-Path $OutputDirectory "pretrial-environment.json") $environment
$conditions = @($Conditions)
$random = [System.Random]::new($RandomSeed)
$schedule = @(
  foreach ($condition in $conditions) {
    for ($index = 1; $index -le $RepetitionsPerCondition; $index++) {
      [pscustomobject]@{
        trial_id = "$($condition)-{0:D2}" -f $index
        condition = $condition
        status = "PENDING"
        started_at = $null
        ended_at = $null
        trial_pass = $null
        artifact = $null
        failure_reason = $null
        post_trial_health = $null
      }
    }
  }
)
$schedule = @($schedule | Sort-Object { $random.Next() })
$manifest = [ordered]@{
  schema_version = "csg-registry-reconciliation-controlled-campaign-v1"
  experiment_id = "CSG-registry-reconciliation-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))"
  execution_kind = $ExecutionKind
  status = "RUNNING"
  created_at = (Get-Date).ToUniversalTime().ToString("o")
  completed_at = $null
  host_id = $HostId
  protocol_sha256 = $ProtocolSha256.ToLowerInvariant()
  controller_sha256 = $controllerHash
  trial_script_sha256 = $trialHash
  probe_config_sha256 = $probeConfigHash
  random_seed = $RandomSeed
  repetitions_per_condition = $RepetitionsPerCondition
  tolerance_seconds = $ToleranceSeconds
  event_lookback_seconds = $EventLookbackSeconds
  positive_event_wait_seconds = $PositiveEventWaitSeconds
  lifecycle_finalization_wait_seconds = $LifecycleWaitSeconds
  declared_conditions = $conditions
  pretrial_environment = "pretrial-environment.json"
  action_safety = "HKCU Run values contain cmd.exe /c exit 0, are never executed, and are removed with direct-probe cleanup verification."
  condition_policy = if (@($conditions | Where-Object { $_ -in @("registry_selective_drop", "registry_eventid_drop") }).Count -gt 0) {
    "Controlled Wazuh eventchannel query conditions keep Wazuh running, retain local Sysmon events, record direct-provider coverage, and restore the exact baseline config after cleanup. registry_selective_drop filters one randomized object; registry_eventid_drop excludes Sysmon Event ID 13 for a diagnostic control."
  } elseif ($conditions -contains "registry_sysmon_target_drop") {
    "Controlled Sysmon source filtering adds one exact TargetObject exclusion while preserving the baseline include rule; Wazuh stays running and unchanged, the same-host distractor must still be collected, and the exact original Sysmon config hash is restored and verified. This is deliberate source suppression, not natural event loss."
  } else {
    "Condition-specific behavior is defined in the frozen protocol; legacy registry_wrong_object, when explicitly selected, stops Wazuh and is not equivalent to selective collection filtering."
  }
  post_restore_interpretation = if ($conditions -contains "registry_sysmon_target_drop") {
    "An exact Sysmon TargetObject exclusion is a controlled source-collection intervention, not natural permanent telemetry loss."
  } else {
    "A selective eventchannel query is a controlled collection-path intervention, not natural permanent telemetry loss."
  }
  schedule = $schedule
}
$manifestPath = Join-Path $OutputDirectory "campaign-manifest.json"
Save-Json $manifestPath $manifest

$abortRemaining = $false
foreach ($entry in $schedule) {
  if ($abortRemaining) {
    $entry.status = "NOT_RUN_AFTER_PREVIOUS_TRIAL_FAILURE"
    continue
  }
  $entry.started_at = (Get-Date).ToUniversalTime().ToString("o")
  $entry.status = "RUNNING"
  $entry.artifact = Join-Path (Join-Path $OutputDirectory $entry.trial_id) "run.json"
  Save-Json $manifestPath $manifest
  try {
    & $TrialScript `
      -Condition $entry.condition `
      -TrialId $entry.trial_id `
      -CsgApiBase $CsgApiBase `
      -HostId $HostId `
      -ProbeConfig $ProbeConfig `
      -OutputPath $entry.artifact `
      -PositiveEventWaitSeconds $PositiveEventWaitSeconds `
      -LifecycleWaitSeconds $LifecycleWaitSeconds `
      -ToleranceSeconds $ToleranceSeconds `
      -ExpectedSysmonRuntimeHash $ExpectedSysmonRuntimeHash
    $record = Get-Content -LiteralPath $entry.artifact -Raw | ConvertFrom-Json
    $entry.trial_pass = [bool]$record.trial_pass
    $entry.status = if ($record.trial_pass) { "COMPLETED_PASS" } else { "COMPLETED_FAIL" }
    if (-not $record.trial_pass) { $entry.failure_reason = "Trial artifact did not satisfy its prespecified condition rule." }
  } catch {
    $entry.status = "FAILED"
    $entry.failure_reason = $_.Exception.Message
  }
  $entry.ended_at = (Get-Date).ToUniversalTime().ToString("o")
  Save-Json $manifestPath $manifest

  $wazuhPost = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
  $wazuhConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
  $wazuhConfigPostHash = if (Test-Path -LiteralPath $wazuhConfigPath) {
    (Get-FileHash -LiteralPath $wazuhConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
  } else { $null }
  $sysmonPost = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -match "^Sysmon" })
  $healthPost = $null
  try {
    $healthPost = Invoke-RestMethod -Method Get -DisableKeepAlive -TimeoutSec 30 -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
  } catch { }
  $agentPost = if ($healthPost) {
    @($healthPost.agents | Where-Object { $_.name -eq $HostId } | Select-Object -First 1)[0]
  } else { $null }
  $taskPost = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction SilentlyContinue
  $taskRestored = (-not $task) -or (
    $taskPost -and [bool]$taskPost.Settings.Enabled -eq $probeTaskEnabled
  )
  $probeConfigPostHash = (Get-FileHash -LiteralPath $ProbeConfig -Algorithm SHA256).Hash.ToLowerInvariant()
  $configurationRestored = $wazuhConfigPostHash -eq $environment.wazuh_config_sha256 -and
    $probeConfigPostHash -eq $probeConfigHash
  $endpointHealthy = $healthPost -and $healthPost.ok -and $agentPost -and $agentPost.status -eq "active"
  $servicesHealthy = $wazuhPost -and $wazuhPost.State -eq "Running" -and [int]$wazuhPost.ProcessId -gt 0 -and
    $sysmonPost.Count -gt 0 -and @($sysmonPost | Where-Object { $_.State -ne "Running" }).Count -eq 0
  $trialHealthPassed = [bool]($servicesHealthy -and $endpointHealthy -and $configurationRestored -and $taskRestored)
  $entry.post_trial_health = [ordered]@{
    checked_at = (Get-Date).ToUniversalTime().ToString("o")
    wazuh_service = if ($wazuhPost) { [string]$wazuhPost.State } else { "MISSING" }
    wazuh_service_pid = if ($wazuhPost) { [int]$wazuhPost.ProcessId } else { 0 }
    endpoint_agent_status = if ($agentPost) { [string]$agentPost.status } else { "NOT_REPORTED" }
    csg_wazuh_health_ok = [bool]($healthPost -and $healthPost.ok)
    sysmon_services_running = [bool]($sysmonPost.Count -gt 0 -and @($sysmonPost | Where-Object { $_.State -ne "Running" }).Count -eq 0)
    probe_task_enabled = if ($taskPost) { [bool]$taskPost.Settings.Enabled } else { $null }
    wazuh_config_sha256 = $wazuhConfigPostHash
    probe_config_sha256 = $probeConfigPostHash
    configuration_restored = [bool]$configurationRestored
    passed = $trialHealthPassed
  }
  if (-not $trialHealthPassed) {
    $abortRemaining = $true
    $manifest.host_recovery_failure = [ordered]@{
      at = (Get-Date).ToUniversalTime().ToString("o")
      wazuh_state = if ($wazuhPost) { [string]$wazuhPost.State } else { "MISSING" }
      wazuh_config_sha256 = $wazuhConfigPostHash
      endpoint_agent_status = if ($agentPost) { [string]$agentPost.status } else { "NOT_REPORTED" }
      sysmon_services_running = $entry.post_trial_health.sysmon_services_running
      probe_task_state = if ($taskPost) { [string]$taskPost.State } else { "MISSING" }
      probe_task_enabled = if ($taskPost) { [bool]$taskPost.Settings.Enabled } else { $null }
    }
  }
  if ($entry.status -eq "COMPLETED_FAIL" -and $trialHealthPassed) {
    $trialRecord = if (Test-Path -LiteralPath $entry.artifact) {
      Get-Content -LiteralPath $entry.artifact -Raw | ConvertFrom-Json
    } else { $null }
    $cleanupSafe = $trialRecord -and
      $trialRecord.cleanup.cleanup_probe_succeeded -eq $true -and
      $trialRecord.cleanup.target_absent -eq $true -and
      $trialRecord.cleanup.distractor_absent -eq $true -and
      @($trialRecord.cleanup.errors).Count -eq 0
    if ($cleanupSafe) {
      $entry.continued_after_scientific_assertion_failure = $true
      $entry.continuation_reason = "Trial outcome is retained as a failure; direct-probe cleanup and endpoint/config postflight both passed, so prescheduled repetitions continue."
    } else {
      $abortRemaining = $true
      $entry.continued_after_scientific_assertion_failure = $false
      $entry.continuation_reason = "Stopped after trial failure because cleanup safety could not be verified."
    }
  } elseif ($entry.status -ne "COMPLETED_PASS") {
    $abortRemaining = $true
    $entry.continued_after_scientific_assertion_failure = $false
    $entry.continuation_reason = "Stopped after execution failure or unverified host postflight."
  }
}

$manifest.completed_at = (Get-Date).ToUniversalTime().ToString("o")
$notRun = @($schedule | Where-Object { $_.status -like "NOT_RUN_*" }).Count
$failed = @($schedule | Where-Object { $_.status -in @("FAILED", "COMPLETED_FAIL") }).Count
$manifest.pass_counts = @(
  foreach ($condition in $conditions) {
    $rows = @($schedule | Where-Object { $_.condition -eq $condition })
    [ordered]@{
      condition = $condition
      assigned = $rows.Count
      completed = @($rows | Where-Object { $_.status -like "COMPLETED_*" }).Count
      passed = @($rows | Where-Object { $_.status -eq "COMPLETED_PASS" }).Count
      failed = @($rows | Where-Object { $_.status -in @("FAILED", "COMPLETED_FAIL") }).Count
      not_run = @($rows | Where-Object { $_.status -like "NOT_RUN_*" }).Count
    }
  }
)
$wazuhConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$finalWazuh = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction SilentlyContinue
$finalWazuhHash = if (Test-Path -LiteralPath $wazuhConfigPath) {
  (Get-FileHash -LiteralPath $wazuhConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
} else { $null }
$finalHealth = $null
try {
  $finalHealth = Invoke-RestMethod -Method Get -DisableKeepAlive -TimeoutSec 30 -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
} catch { }
$finalAgent = if ($finalHealth) {
  @($finalHealth.agents | Where-Object { $_.name -eq $HostId } | Select-Object -First 1)[0]
} else { $null }
$finalTask = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction SilentlyContinue
$finalProbeHash = (Get-FileHash -LiteralPath $ProbeConfig -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest.postflight = [ordered]@{
  checked_at = (Get-Date).ToUniversalTime().ToString("o")
  wazuh_service = if ($finalWazuh) { [string]$finalWazuh.State } else { "MISSING" }
  wazuh_service_pid = if ($finalWazuh) { [int]$finalWazuh.ProcessId } else { 0 }
  endpoint_agent_status = if ($finalAgent) { [string]$finalAgent.status } else { "NOT_REPORTED" }
  csg_wazuh_health_ok = [bool]($finalHealth -and $finalHealth.ok)
  wazuh_config_sha256 = $finalWazuhHash
  probe_config_sha256 = $finalProbeHash
  probe_task_enabled = if ($finalTask) { [bool]$finalTask.Settings.Enabled } else { $null }
  postflight_valid = [bool]($finalWazuh -and $finalWazuh.State -eq "Running" -and
    [int]$finalWazuh.ProcessId -gt 0 -and $finalAgent -and $finalAgent.status -eq "active" -and
    $finalHealth.ok -and $finalWazuhHash -eq $environment.wazuh_config_sha256 -and
    $finalProbeHash -eq $probeConfigHash -and (($null -eq $task) -or
      ($finalTask -and [bool]$finalTask.Settings.Enabled -eq $probeTaskEnabled)))
}
$manifest.completed_at = (Get-Date).ToUniversalTime().ToString("o")
$manifest.status = if ($notRun -gt 0 -or $failed -gt 0 -or -not $manifest.postflight.postflight_valid) {
  "COMPLETED_WITH_GAPS"
} else { "COMPLETED" }
Save-Json $manifestPath $manifest
Write-Host "Campaign manifest: $manifestPath"
Write-Host "Status=$($manifest.status); assigned=$($schedule.Count); failed=$failed; not_run=$notRun"
