param(
  [string]$ProbeSettingsPath = "$env:ProgramFiles\CyberStateGuardian\Probe\settings.json",
  [string]$OutputDirectory = "$env:ProgramData\CyberStateGuardian\Research\service-dwell-response-v2",
  [ValidateRange(1,20)][int]$RepeatPerCondition = 10,
  [double[]]$DwellLevelsSeconds = @(0.25, 2, 6, 12),
  [ValidateRange(5,120)][int]$PostConditionWaitSeconds = 15,
  [int]$RandomSeed = 2026101102,
  [string]$ProtocolSha256 = '',
  [switch]$PreflightOnly
)

$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw 'Run this limited lab script from an Administrator PowerShell session.' }
if (-not (Test-Path -LiteralPath $ProbeSettingsPath)) { throw "Probe settings not found: $ProbeSettingsPath" }

$config = Get-Content -LiteralPath $ProbeSettingsPath -Raw | ConvertFrom-Json
if (-not $config.CSG_TRANSITION_CAPTURE_ENABLED -or -not $config.CSG_TRANSITION_SERVICES_ENABLED) {
  throw 'The master and service transition-capture settings must both be enabled.'
}
$probeApi = [Uri]$config.CSG_PROBE_API_URL
$apiPath = $probeApi.AbsolutePath -replace '/probe/observations/?$', ''
$apiRoot = "{0}://{1}{2}" -f $probeApi.Scheme, $probeApi.Authority, $apiPath.TrimEnd('/')
$hostId = [string]$config.CSG_PROBE_HOST_ID
$pollSeconds = if ($config.CSG_TRANSITION_POLL_INTERVAL_SECONDS) {
  [Math]::Max(1, [int]$config.CSG_TRANSITION_POLL_INTERVAL_SECONDS)
} else { 5 }
$python = Join-Path (Split-Path -Parent $ProbeSettingsPath) 'venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw "Installed probe Python not found: $python" }
if ($DwellLevelsSeconds.Count -ne 4 -or @($DwellLevelsSeconds | Where-Object { $_ -le 0 -or $_ -gt 60 }).Count -gt 0) {
  throw 'This frozen protocol requires four positive dwell levels no greater than 60 seconds.'
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

function Get-CsgResource([string]$Path) {
  $result = Invoke-RestMethod -Method Get -Uri "$apiRoot$Path" -TimeoutSec 30
  if ($result -is [System.Array]) { foreach ($item in $result) { Write-Output $item } }
  else { $result }
}

function ConvertTo-UtcDateTimeOffset([object]$Value) {
  if ($Value -is [DateTimeOffset]) { return $Value.ToUniversalTime() }
  if ($Value -is [DateTime]) {
    if ($Value.Kind -eq [DateTimeKind]::Unspecified) { $Value = [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
    return ([DateTimeOffset]$Value).ToUniversalTime()
  }
  return [DateTimeOffset]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()
}

function Normalize-ServiceStartMode([string]$Value) {
  switch ($Value.Trim().ToLowerInvariant()) {
    { $_ -in @('auto', 'automatic') } { return 'auto' }
    { $_ -in @('demand', 'manual') } { return 'manual' }
    default { return $Value.Trim().ToLowerInvariant() }
  }
}

function Invoke-CsgSnapshot {
  $process = Start-Process -FilePath $python `
    -ArgumentList @('-m','cyberstateguardian_probe.main','--once','--config',"`"$ProbeSettingsPath`"") `
    -WorkingDirectory (Split-Path -Parent $ProbeSettingsPath) -Wait -PassThru -NoNewWindow
  if ($process.ExitCode -ne 0) { throw "Direct-probe snapshot failed with exit code $($process.ExitCode)." }
  Start-Sleep -Seconds 1
  $state = Get-CsgResource "/hosts/$([Uri]::EscapeDataString($hostId))/state/latest"
  if ($state.source -ne 'direct_probe') { throw 'Latest host state was not collected by the direct CSG probe.' }
  return $state
}

function Get-WazuhServiceProof {
  $service = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction SilentlyContinue
  if (-not $service) { return [ordered]@{ found = $false; captured_at = [DateTime]::UtcNow.ToString('o') } }
  return [ordered]@{
    found = $true; name = $service.Name; status = $service.State
    start_mode = $service.StartMode; process_id = [int]$service.ProcessId
    captured_at = [DateTime]::UtcNow.ToString('o')
  }
}

function Wait-ForCreatedTransition([string]$ObjectKey, [DateTimeOffset]$NotBefore) {
  $deadline = [DateTime]::UtcNow.AddSeconds([Math]::Max(20, $pollSeconds * 4))
  while ([DateTime]::UtcNow -lt $deadline) {
    $start = [Uri]::EscapeDataString($NotBefore.AddSeconds(-2).ToString('o'))
    $end = [Uri]::EscapeDataString([DateTime]::UtcNow.AddSeconds(1).ToString('o'))
    $path = "/hosts/$([Uri]::EscapeDataString($hostId))/transitions?start=$start&end=$end&category=service&object_key=$([Uri]::EscapeDataString($ObjectKey))&limit=100"
    $records = @(Get-CsgResource $path)
    $found = @($records | Where-Object {
      $_.object_key -eq $ObjectKey -and $_.transition_type -eq 'SERVICE_CREATED' -and
      (Normalize-ServiceStartMode ([string]$_.new_state.start_mode)) -eq 'manual' -and
      (ConvertTo-UtcDateTimeOffset $_.observed_at) -ge $NotBefore
    })
    if ($found.Count -gt 0) { return ($found | Sort-Object observed_at | Select-Object -First 1) }
    Start-Sleep -Seconds 1
  }
  throw "Timed out waiting for the exact CSG-created transition for $ObjectKey."
}

function Get-SystemServiceChangeEvents([string]$ServiceName, [DateTime]$StartLocal, [DateTime]$EndLocal) {
  $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7040; StartTime = $StartLocal; EndTime = $EndLocal } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -and $_.Message -match [regex]::Escape($ServiceName) } |
    ForEach-Object {
      [ordered]@{ event_id = $_.Id; record_id = $_.RecordId; provider = $_.ProviderName
        time_created_utc = $_.TimeCreated.ToUniversalTime().ToString('o'); message = $_.Message }
    })
  return $events
}

$conditionList = [System.Collections.Generic.List[object]]::new()
for ($i = 0; $i -lt $DwellLevelsSeconds.Count; $i++) {
  for ($rep = 1; $rep -le $RepeatPerCondition; $rep++) {
    $conditionList.Add([ordered]@{ condition = 'dwell'; dwell_seconds = [double]$DwellLevelsSeconds[$i]; replicate = $rep })
  }
}
for ($rep = 1; $rep -le $RepeatPerCondition; $rep++) {
  $conditionList.Add([ordered]@{ condition = 'stable_no_change'; dwell_seconds = 12.0; replicate = $rep })
}
$random = [System.Random]::new($RandomSeed)
$schedule = @($conditionList | Sort-Object { $random.Next() })

$campaignId = "service-dwell-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))-$([Guid]::NewGuid().ToString('N').Substring(0,6))"
$campaignPath = Join-Path $OutputDirectory $campaignId
New-Item -ItemType Directory -Path $campaignPath -Force | Out-Null
$os = Get-CimInstance Win32_OperatingSystem
$scriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
$settingsHash = (Get-FileHash -LiteralPath $ProbeSettingsPath -Algorithm SHA256).Hash
$campaign = [ordered]@{
  schema_version = '1.0'; campaign_id = $campaignId; experiment_family = 'service_transition_dwell_response'
  execution_kind = 'live_windows_native_probe_sampling_calibration'; created_at = [DateTime]::UtcNow.ToString('o')
  host_id = $hostId; random_seed = $RandomSeed; planned_trials = $schedule; trials = @()
  windows = [ordered]@{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber; architecture = $env:PROCESSOR_ARCHITECTURE }
  probe = [ordered]@{ settings_sha256 = $settingsHash; transition_enabled = [bool]$config.CSG_TRANSITION_CAPTURE_ENABLED
    services_enabled = [bool]$config.CSG_TRANSITION_SERVICES_ENABLED; poll_interval_seconds = $pollSeconds
    python_version = (& $python --version 2>&1 | Out-String).Trim() }
  implementation_sha256 = $scriptHash; protocol_sha256 = $ProtocolSha256
  wazuh_service_at_start = Get-WazuhServiceProof; wazuh_service_at_end = $null
  status = 'PRECHECK_PENDING'; stop_reason = $null
  limitations = @('Single Windows 11 ARM64 VM; exploratory sampling calibration only; not an attack-detection evaluation.')
}

$scriptFailure = $null
try {
  $captureStatus = Get-CsgResource "/transition-capture/status?host_id=$([Uri]::EscapeDataString($hostId))"
  $serviceHealth = $captureStatus.categories.service.monitor_health
  if (-not $captureStatus.enabled -or -not $captureStatus.categories.service.enabled -or
      -not $serviceHealth -or $serviceHealth.status -ne 'HEALTHY' -or -not $serviceHealth.baseline_established) {
    throw 'Precondition failed: service monitor must be enabled, HEALTHY, and have a baseline.'
  }
  if ($campaign.wazuh_service_at_start.status -ne 'Running') { throw 'Precondition failed: WazuhSvc was not Running.' }
  $campaign.initial_monitor_health = $serviceHealth
  $campaign.status = 'RUNNING'
  if ($PreflightOnly) { $schedule = @() }

  for ($index = 0; $index -lt $schedule.Count; $index++) {
    $plan = $schedule[$index]
    $trialId = 'trial-{0:D3}' -f ($index + 1)
    $trialPath = Join-Path $campaignPath $trialId
    New-Item -ItemType Directory -Path $trialPath -Force | Out-Null
    $serviceName = "CSGDw$([Guid]::NewGuid().ToString('N').Substring(0,12))"
    $displayName = "CSG dwell study $serviceName"
    $objectKey = "service:$($serviceName.ToLowerInvariant())"
    $created = $false
    $autoApplied = $false
    $actionStart = $null
    $actionEnd = $null
    $autoCompleted = $null
    $dwellEnd = $null
    $trial = [ordered]@{
      schema_version = '1.0'; campaign_id = $campaignId; trial_id = $trialId; schedule_index = $index + 1
      condition = $plan.condition; planned_dwell_seconds = [double]$plan.dwell_seconds; replicate = $plan.replicate
      host_id = $hostId; target = [ordered]@{ category = 'service'; service_name = $serviceName; object_key = $objectKey }
      started_at = [DateTime]::UtcNow.ToString('o'); monitor_health_before = $null; monitor_health_after = $null
      wazuh_service_before = $null; wazuh_service_after = $null
      action_timeline = @(); snapshot_before = $null; snapshot_after = $null; transition_records = @()
      windows_system_7040 = @(); reconciliation_attempts = @(); validation = $null
      cleanup = [ordered]@{ attempted = $false; completed = $false; error = $null }
    }
    try {
      $beforeStatus = Get-CsgResource "/transition-capture/status?host_id=$([Uri]::EscapeDataString($hostId))"
      $trial.monitor_health_before = $beforeStatus.categories.service.monitor_health
      if ($trial.monitor_health_before.status -ne 'HEALTHY') { throw 'Service monitor lost HEALTHY status before trial.' }
      $trial.wazuh_service_before = Get-WazuhServiceProof
      if ($trial.wazuh_service_before.status -ne 'Running') { throw 'WazuhSvc was not Running before trial.' }

      $binaryPath = Join-Path $env:SystemRoot 'System32\cmd.exe'
      $serviceBinaryCommand = "`"$binaryPath`" /c exit 0"
      $createAt = [DateTimeOffset]::UtcNow
      & sc.exe create $serviceName binPath= $serviceBinaryCommand start= demand DisplayName= $displayName | Out-Null
      $createCode = $LASTEXITCODE
      $trial.action_timeline += [ordered]@{ action = 'create_manual_service'; invoked_at_utc = $createAt.ToString('o'); exit_code = $createCode }
      if ($createCode -ne 0) { throw "sc.exe create failed with exit code $createCode." }
      $created = $true
      $createdTransition = Wait-ForCreatedTransition -ObjectKey $objectKey -NotBefore $createAt
      $trial.action_timeline += [ordered]@{ action = 'service_created_transition'; transition_id = $createdTransition.transition_id; observed_at = $createdTransition.observed_at }
      $snapshotA = Invoke-CsgSnapshot
      $trial.snapshot_before = $snapshotA
      $objectsA = @($snapshotA.objects | Where-Object { $_.object_key -eq $objectKey })
      if ($objectsA.Count -ne 1) { throw 'Snapshot A did not contain exactly one target service.' }
      $modeA = Normalize-ServiceStartMode ([string]$objectsA[0].attributes.start_mode)
      if ($modeA -ne 'manual') { throw "Snapshot A start mode was $modeA, expected manual." }

      if ($plan.condition -eq 'dwell') {
        $actionStart = [DateTimeOffset]::UtcNow
        & sc.exe config $serviceName start= auto | Out-Null
        $autoCode = $LASTEXITCODE
        $autoCompleted = [DateTimeOffset]::UtcNow
        $trial.action_timeline += [ordered]@{ action = 'manual_to_auto'; invoked_at_utc = $actionStart.ToString('o'); completed_at_utc = $autoCompleted.ToString('o'); exit_code = $autoCode }
        if ($autoCode -ne 0) { throw "sc.exe set Automatic failed with exit code $autoCode." }
        $autoApplied = $true
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        Start-Sleep -Milliseconds ([Math]::Max(1, [int][Math]::Round($plan.dwell_seconds * 1000)))
        $watch.Stop()
        $dwellEnd = [DateTimeOffset]::UtcNow
        & sc.exe config $serviceName start= demand | Out-Null
        $manualCode = $LASTEXITCODE
        $manualCompleted = [DateTimeOffset]::UtcNow
        $actionEnd = $manualCompleted
        $trial.action_timeline += [ordered]@{ action = 'auto_to_manual'; invoked_at_utc = $dwellEnd.ToString('o'); completed_at_utc = $manualCompleted.ToString('o'); exit_code = $manualCode }
        $trial.actual_dwell_seconds = $watch.Elapsed.TotalSeconds
        $trial.dwell_interval_start_utc = $autoCompleted.ToString('o')
        $trial.dwell_interval_end_utc = $dwellEnd.ToString('o')
        if ($manualCode -ne 0) { throw "sc.exe restoring Manual failed with exit code $manualCode." }
        $autoApplied = $false
      } else {
        $actionStart = [DateTimeOffset]::UtcNow
        $actionEnd = $actionStart.AddSeconds(12)
        $trial.action_timeline += [ordered]@{ action = 'stable_no_change_interval'; start_utc = $actionStart.ToString('o'); planned_end_utc = $actionEnd.ToString('o') }
        Start-Sleep -Seconds 12
      }

      Start-Sleep -Seconds $PostConditionWaitSeconds
      $trial.snapshot_after = Invoke-CsgSnapshot
      $objectsB = @($trial.snapshot_after.objects | Where-Object { $_.object_key -eq $objectKey })
      $modeB = if ($objectsB.Count -eq 1) { Normalize-ServiceStartMode ([string]$objectsB[0].attributes.start_mode) } else { $null }
      $trial.monitor_health_after = (Get-CsgResource "/transition-capture/status?host_id=$([Uri]::EscapeDataString($hostId))").categories.service.monitor_health
      $trial.wazuh_service_after = Get-WazuhServiceProof

      $queryStart = [Uri]::EscapeDataString($actionStart.AddSeconds(-1).ToString('o'))
      $queryEnd = [Uri]::EscapeDataString((ConvertTo-UtcDateTimeOffset $trial.snapshot_after.built_at).AddSeconds(1).ToString('o'))
      $query = "start=$queryStart&end=$queryEnd&category=service&object_key=$([Uri]::EscapeDataString($objectKey))&limit=100"
      $trial.transition_records = @(Get-CsgResource "/hosts/$([Uri]::EscapeDataString($hostId))/transitions?$query")
      $trial.windows_system_7040 = @(Get-SystemServiceChangeEvents -ServiceName $serviceName -StartLocal $actionStart.LocalDateTime.AddSeconds(-2) -EndLocal ([DateTime]::Now.AddSeconds(1)))

      foreach ($record in $trial.transition_records) {
        try {
          $reconciliation = Invoke-RestMethod -Method Post -Uri "$apiRoot/transitions/$([Uri]::EscapeDataString($record.transition_id))/reconcile" -TimeoutSec 60
          $trial.reconciliation_attempts += $reconciliation
        } catch {
          $trial.reconciliation_attempts += [ordered]@{ transition_id = $record.transition_id; query_status = 'ERROR'; error = $_.Exception.Message }
        }
      }

      $autoRecords = @()
      if ($plan.condition -eq 'dwell') {
        $autoRecords = @($trial.transition_records | Where-Object {
          $_.object_key -eq $objectKey -and $_.transition_type -eq 'SERVICE_START_MODE_CHANGED' -and
          (Normalize-ServiceStartMode ([string]$_.new_state.start_mode)) -eq 'auto' -and
          (ConvertTo-UtcDateTimeOffset $_.observed_at) -ge $autoCompleted -and
          (ConvertTo-UtcDateTimeOffset $_.observed_at) -le $dwellEnd
        })
      }
      $modeRecords = @($trial.transition_records | Where-Object { $_.transition_type -eq 'SERVICE_START_MODE_CHANGED' })
      $exactOnly = @($trial.transition_records | Where-Object { $_.object_key -ne $objectKey }).Count -eq 0
      $healthy = $trial.monitor_health_before.status -eq 'HEALTHY' -and $trial.monitor_health_after.status -eq 'HEALTHY'
      $wazuhHealthy = $trial.wazuh_service_before.status -eq 'Running' -and $trial.wazuh_service_after.status -eq 'Running'
      $snapshotsValid = $objectsB.Count -eq 1 -and $modeA -eq 'manual' -and $modeB -eq 'manual'
      if (-not $healthy) { $outcome = 'INCOMPLETE_MONITOR_UNHEALTHY' }
      elseif (-not $wazuhHealthy) { $outcome = 'INCOMPLETE_WAZUH_AGENT_STATE' }
      elseif (-not $snapshotsValid) { $outcome = 'INCOMPLETE_SNAPSHOT_INVALID' }
      elseif (-not $exactOnly) { $outcome = 'INTEGRITY_FAILURE_WRONG_OBJECT_RETURNED' }
      elseif ($plan.condition -eq 'stable_no_change' -and $modeRecords.Count -gt 0) { $outcome = 'CONTROL_FALSE_TRANSITION' }
      elseif ($plan.condition -eq 'stable_no_change') { $outcome = 'CONTROL_NO_FALSE_TRANSITION' }
      elseif ($autoRecords.Count -gt 0) { $outcome = 'CAPTURED' }
      else { $outcome = 'NOT_CAPTURED' }
      $trial.validation = [ordered]@{
        outcome = $outcome
        primary_capture = if ($plan.condition -eq 'dwell' -and $outcome -eq 'CAPTURED') { $true } elseif ($plan.condition -eq 'dwell' -and $outcome -eq 'NOT_CAPTURED') { $false } else { $null }
        exact_auto_transition_count = $autoRecords.Count; exact_mode_transition_count = $modeRecords.Count
        exact_object_only = $exactOnly; snapshot_a_start_mode = $modeA; snapshot_b_start_mode = $modeB
        snapshots_both_manual = $snapshotsValid; monitor_healthy_before_and_after = $healthy
        wazuh_service_running_before_and_after = $wazuhHealthy
        window_bounds_used = 'transition observed_at must fall between successful auto-command completion and manual-restore invocation'
      }
    } catch {
      $trial.validation = [ordered]@{ outcome = 'INCOMPLETE_ERROR'; primary_capture = $null; error = $_.Exception.Message
        error_line = $_.InvocationInfo.ScriptLineNumber; error_stack = $_.ScriptStackTrace }
      $scriptFailure = $_.Exception.Message
    } finally {
      if ($created) {
        $trial.cleanup.attempted = $true
        $trial.cleanup.command_timestamp_utc = [DateTime]::UtcNow.ToString('o')
        if ($autoApplied) {
          & sc.exe config $serviceName start= demand | Out-Null
          $trial.cleanup.restore_manual_exit_code = $LASTEXITCODE
        }
        & sc.exe delete $serviceName | Out-Null
        $trial.cleanup.delete_exit_code = $LASTEXITCODE
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
          $remaining = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
          if (-not $remaining) { break }
          Start-Sleep -Milliseconds 500
        } while ([DateTime]::UtcNow -lt $deadline)
        $trial.cleanup.service_absent = -not [bool]$remaining
        $restoreOk = -not $trial.cleanup.Contains('restore_manual_exit_code') -or $trial.cleanup.restore_manual_exit_code -eq 0
        $trial.cleanup.completed = ($trial.cleanup.delete_exit_code -eq 0 -and $trial.cleanup.service_absent -and $restoreOk)
        if (-not $trial.cleanup.completed) { $trial.cleanup.error = 'Service deletion/restoration was not fully confirmed.' }
      }
      $trial.ended_at = [DateTime]::UtcNow.ToString('o')
      $trial | ConvertTo-Json -Depth 35 | Set-Content -LiteralPath (Join-Path $trialPath 'run.json') -Encoding UTF8
      $campaign.trials += [ordered]@{
        trial_id = $trial.trial_id; condition = $trial.condition
        planned_dwell_seconds = $trial.planned_dwell_seconds; actual_dwell_seconds = $trial.actual_dwell_seconds
        service_name = $serviceName; outcome = $trial.validation.outcome
        primary_capture = $trial.validation.primary_capture
        transition_count = @($trial.transition_records).Count
        cleanup_completed = $trial.cleanup.completed
        started_at = $trial.started_at; ended_at = $trial.ended_at
      }
    }
    if ($scriptFailure -or ($trial.cleanup.attempted -and -not $trial.cleanup.completed) -or
        ($trial.monitor_health_after -and $trial.monitor_health_after.status -ne 'HEALTHY') -or
        ($trial.wazuh_service_after -and $trial.wazuh_service_after.status -ne 'Running')) {
      $campaign.stop_reason = if ($scriptFailure) { $scriptFailure } elseif (-not $trial.cleanup.completed) { 'Cleanup integrity stop.' } elseif ($trial.monitor_health_after.status -ne 'HEALTHY') { 'Service monitor lost HEALTHY status.' } else { 'WazuhSvc stopped or became unavailable.' }
      break
    }
  }
} catch {
  $scriptFailure = $_.Exception.Message
  $campaign.stop_reason = $scriptFailure
} finally {
  $campaign.wazuh_service_at_end = Get-WazuhServiceProof
  $campaign.ended_at = [DateTime]::UtcNow.ToString('o')
  $campaign.completed_trials = $campaign.trials.Count
  $campaign.scheduled_trials = $campaign.planned_trials.Count
  $campaign.not_run_trials = $campaign.scheduled_trials - $campaign.trials.Count
  if ($PreflightOnly -and -not $campaign.stop_reason) { $campaign.status = 'PREFLIGHT_ONLY' }
  else { $campaign.status = if ($campaign.trials.Count -eq $campaign.scheduled_trials -and -not $campaign.stop_reason) { 'COMPLETED' } else { 'INCOMPLETE' } }
  $campaign | ConvertTo-Json -Depth 45 | Set-Content -LiteralPath (Join-Path $campaignPath 'campaign-manifest.json') -Encoding UTF8
}

Write-Output "Campaign artifacts: $campaignPath"
Write-Output "Campaign status: $($campaign.status) ($($campaign.completed_trials)/$($campaign.scheduled_trials) trials)"
if ($scriptFailure) { throw $scriptFailure }
