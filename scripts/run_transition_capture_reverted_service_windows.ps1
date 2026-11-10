param(
  [string]$ProbeSettingsPath = "$env:ProgramFiles\CyberStateGuardian\Probe\settings.json",
  [string]$OutputDirectory = "$env:ProgramData\CyberStateGuardian\Research\transition-capture",
  [ValidateRange(1,10)][int]$Repeat = 1,
  [ValidateRange(5,300)][int]$EvidenceWaitSeconds = 30
)

$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw 'Run from an Administrator PowerShell session.' }
if (-not (Test-Path -LiteralPath $ProbeSettingsPath)) {
  throw "Probe settings not found: $ProbeSettingsPath"
}

$config = Get-Content -LiteralPath $ProbeSettingsPath -Raw | ConvertFrom-Json
if (-not $config.CSG_TRANSITION_CAPTURE_ENABLED -or -not $config.CSG_TRANSITION_SERVICES_ENABLED) {
  throw 'Enable CSG_TRANSITION_CAPTURE_ENABLED and CSG_TRANSITION_SERVICES_ENABLED in the probe settings first.'
}
$probeApi = [Uri]$config.CSG_PROBE_API_URL
$apiPath = $probeApi.AbsolutePath -replace '/probe/observations/?$', ''
$apiRoot = "{0}://{1}{2}" -f $probeApi.Scheme, $probeApi.Authority, $apiPath.TrimEnd('/')
$hostId = [string]$config.CSG_PROBE_HOST_ID
$pollSeconds = 5
if ($config.CSG_TRANSITION_POLL_INTERVAL_SECONDS) {
  $pollSeconds = [Math]::Max(1, [int]$config.CSG_TRANSITION_POLL_INTERVAL_SECONDS)
}
$python = Join-Path (Split-Path -Parent $ProbeSettingsPath) 'venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw "Installed probe Python not found: $python" }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

function Get-CsgResource([string]$Path) {
  $result = Invoke-RestMethod -Method Get -Uri "$apiRoot$Path" -TimeoutSec 30
  if ($result -is [System.Array]) {
    foreach ($item in $result) { Write-Output $item }
  } else {
    $result
  }
}

function Get-WazuhServiceProof {
  $service = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction SilentlyContinue
  if (-not $service) {
    return [ordered]@{ found = $false; captured_at = [DateTime]::UtcNow.ToString('o') }
  }
  return [ordered]@{
    found = $true
    name = $service.Name
    status = $service.State
    start_mode = $service.StartMode
    process_id = [int]$service.ProcessId
    captured_at = [DateTime]::UtcNow.ToString('o')
  }
}

function Invoke-CsgSnapshot {
  $process = Start-Process -FilePath $python `
    -ArgumentList @('-m','cyberstateguardian_probe.main','--once','--config',"`"$ProbeSettingsPath`"") `
    -WorkingDirectory (Split-Path -Parent $ProbeSettingsPath) -Wait -PassThru -NoNewWindow
  if ($process.ExitCode -ne 0) { throw "One-shot CSG snapshot failed with exit code $($process.ExitCode)." }
  Start-Sleep -Seconds 1
  $state = Get-CsgResource "/hosts/$([Uri]::EscapeDataString($hostId))/state/latest"
  if ($state.source -ne 'direct_probe') { throw 'The authoritative latest snapshot is not from the direct CSG probe.' }
  return $state
}

function Normalize-ServiceStartMode([string]$Value) {
  switch ($Value.Trim().ToLowerInvariant()) {
    { $_ -in @('auto', 'automatic') } { return 'auto' }
    { $_ -in @('demand', 'manual') } { return 'manual' }
    default { return $_ }
  }
}

function ConvertTo-UtcDateTimeOffset([object]$Value) {
  if ($Value -is [System.Array]) {
    if ($Value.Count -ne 1) { throw "Expected one timestamp value; received $($Value.Count)." }
    $Value = $Value[0]
  }
  if ($Value -is [DateTimeOffset]) { return $Value.ToUniversalTime() }
  if ($Value -is [DateTime]) {
    if ($Value.Kind -eq [DateTimeKind]::Unspecified) {
      $Value = [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc)
    }
    return ([DateTimeOffset]$Value).ToUniversalTime()
  }
  return [DateTimeOffset]::Parse(
    [string]$Value,
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AssumeUniversal
  ).ToUniversalTime()
}

function Wait-ForTargetTransition(
  [string]$ObjectKey,
  [object]$NotBefore,
  [string]$ExpectedType,
  [string]$ExpectedStartMode = '',
  [int]$TimeoutSeconds = 0
) {
  if ($TimeoutSeconds -le 0) { $TimeoutSeconds = [Math]::Max(15, ($pollSeconds * 3 + 10)) }
  $notBeforeUtc = ConvertTo-UtcDateTimeOffset $NotBefore
  $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  $encodedObject = [Uri]::EscapeDataString($ObjectKey)
  $encodedHost = [Uri]::EscapeDataString($hostId)
  $start = [Uri]::EscapeDataString($notBeforeUtc.AddSeconds(-2).ToString('o'))

  while ([DateTime]::UtcNow -lt $deadline) {
    $end = [Uri]::EscapeDataString([DateTime]::UtcNow.AddSeconds(1).ToString('o'))
    $path = "/hosts/$encodedHost/transitions?start=$start&end=$end&category=service&object_key=$encodedObject&limit=100"
    $records = @(Get-CsgResource $path)
    $matches = @(
      foreach ($record in $records) {
        if ($record.object_key -ne $ObjectKey -or $record.transition_type -ne $ExpectedType) {
          continue
        }
        $recordObservedAt = [DateTimeOffset]::Parse(
          [string]$record.observed_at,
          [Globalization.CultureInfo]::InvariantCulture,
          [Globalization.DateTimeStyles]::AssumeUniversal
        ).ToUniversalTime()
        if ($recordObservedAt -lt $notBeforeUtc) { continue }
        if ($ExpectedStartMode -and
            (Normalize-ServiceStartMode ([string]$record.new_state.start_mode)) -ne $ExpectedStartMode) {
          continue
        }
        $record
      }
    )
    if ($matches.Count -gt 0) {
      return ($matches | Sort-Object observed_at | Select-Object -First 1)
    }
    Start-Sleep -Seconds 1
  }

  $expectation = if ($ExpectedStartMode) { "$ExpectedType with start_mode=$ExpectedStartMode" } else { $ExpectedType }
  throw "Timed out after $TimeoutSeconds seconds waiting for exact transition $expectation on $ObjectKey."
}

$campaignId = "transition-capture-live-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))-$([Guid]::NewGuid().ToString('N').Substring(0,6))"
$campaignPath = Join-Path $OutputDirectory $campaignId
New-Item -ItemType Directory -Path $campaignPath -Force | Out-Null
$campaign = [ordered]@{
  schema_version = '1.0'
  campaign_id = $campaignId
  experiment_family = 'transition_capture'
  execution_kind = 'live_windows_probe_wazuh_evidence'
  created_at = [DateTime]::UtcNow.ToString('o')
  host_id = $hostId
  windows = $null
  probe = [ordered]@{
    settings_path = $ProbeSettingsPath
    transition_enabled = [bool]$config.CSG_TRANSITION_CAPTURE_ENABLED
    services_enabled = [bool]$config.CSG_TRANSITION_SERVICES_ENABLED
    poll_interval_seconds = $pollSeconds
    python_version = $null
  }
  wazuh_service_at_start = $null
  wazuh_service_at_end = $null
  trials = @()
  limitations = @(
    'This is a live single-host service behavior-family validation, not Windows-APT dataset replication.',
    'The category monitor is sampled at its configured interval and may miss shorter changes.',
    'A Wazuh match is corroboration only; CSG transition capture is independently sourced.'
  )
}
$os = Get-CimInstance Win32_OperatingSystem
$campaign.windows = [ordered]@{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber; architecture = $env:PROCESSOR_ARCHITECTURE }
$campaign.probe.python_version = (& $python --version 2>&1 | Out-String).Trim()
$campaign.wazuh_service_at_start = Get-WazuhServiceProof

$scriptFailure = $null
try {
  $captureStatus = Get-CsgResource "/transition-capture/status?host_id=$([Uri]::EscapeDataString($hostId))"
  if (-not $captureStatus.enabled -or -not $captureStatus.categories.service.enabled) {
    throw 'The CSG API does not report service transition capture enabled for this host.'
  }
  $serviceHealth = $captureStatus.categories.service.monitor_health
  if (
    -not $serviceHealth -or
    $serviceHealth.status -ne 'HEALTHY' -or
    -not $serviceHealth.baseline_established
  ) {
    throw 'Service transition monitor must have HEALTHY status and an established baseline before the trial.'
  }

  for ($trialNumber = 1; $trialNumber -le $Repeat; $trialNumber++) {
    $trialId = "reverted-service-$('{0:D2}' -f $trialNumber)"
    $trialPath = Join-Path $campaignPath $trialId
    New-Item -ItemType Directory -Path $trialPath -Force | Out-Null
    $serviceName = "CSGTr$([Guid]::NewGuid().ToString('N').Substring(0,12))"
    $objectKey = "service:$($serviceName.ToLowerInvariant())"
    $actionLog = [System.Collections.Generic.List[object]]::new()
    $trial = [ordered]@{
      schema_version = '1.0'
      campaign_id = $campaignId
      trial_id = $trialId
      condition = 'reverted_service_configuration'
      host_id = $hostId
      target = [ordered]@{ category = 'service'; service_name = $serviceName; object_key = $objectKey }
      started_at = [DateTime]::UtcNow.ToString('o')
      monitor_health_before = $captureStatus.categories.service.monitor_health
      monitor_health_after = $null
      action_timeline = $actionLog
      snapshot_before = $null
      snapshot_after = $null
      transition_records = @()
      transition_acknowledgements = @()
      trajectories = @()
      reconciliation_attempts = @()
      validation = $null
      cleanup = [ordered]@{ attempted = $false; completed = $false; error = $null }
    }
    $serviceCreated = $false
    try {
      $binaryPath = Join-Path $env:SystemRoot 'System32\cmd.exe'
      $serviceBinaryCommand = "`"$binaryPath`" /c exit 0"
      $createTime = [DateTime]::UtcNow
      & sc.exe create $serviceName binPath= $serviceBinaryCommand start= demand DisplayName= "CSG research transition $serviceName" | Out-Null
      $createCode = $LASTEXITCODE
      $actionLog.Add([ordered]@{ action = 'create_service_manual'; timestamp = $createTime.ToString('o'); exit_code = $createCode })
      if ($createCode -ne 0) { throw "sc.exe create failed with exit code $createCode." }
      $serviceCreated = $true

      $createTransition = Wait-ForTargetTransition `
        -ObjectKey $objectKey `
        -NotBefore $createTime `
        -ExpectedType 'SERVICE_CREATED' `
        -ExpectedStartMode 'manual'
      $trial.transition_acknowledgements += [ordered]@{
        action = 'create_service_manual'
        transition_id = $createTransition.transition_id
        observed_at = $createTransition.observed_at
        action_to_capture_seconds = ((ConvertTo-UtcDateTimeOffset $createTransition.observed_at) - (ConvertTo-UtcDateTimeOffset $createTime)).TotalSeconds
      }
      $snapshotA = Invoke-CsgSnapshot
      $trial.snapshot_before = $snapshotA
      $foundA = @($snapshotA.objects | Where-Object { $_.object_key -eq $objectKey })
      if ($foundA.Count -ne 1) { throw "Snapshot A did not contain exactly one target object $objectKey." }

      $autoTime = [DateTime]::UtcNow
      & sc.exe config $serviceName start= auto | Out-Null
      $autoCode = $LASTEXITCODE
      $actionLog.Add([ordered]@{ action = 'start_mode_manual_to_auto'; timestamp = $autoTime.ToString('o'); exit_code = $autoCode })
      if ($autoCode -ne 0) { throw "sc.exe could not set Automatic start mode; exit code $autoCode." }
      $autoTransition = Wait-ForTargetTransition `
        -ObjectKey $objectKey `
        -NotBefore $autoTime `
        -ExpectedType 'SERVICE_START_MODE_CHANGED' `
        -ExpectedStartMode 'auto'
      $actionLog[$actionLog.Count - 1].transition_id = $autoTransition.transition_id
      $trial.transition_acknowledgements += [ordered]@{
        action = 'start_mode_manual_to_auto'
        transition_id = $autoTransition.transition_id
        observed_at = $autoTransition.observed_at
        action_to_capture_seconds = ((ConvertTo-UtcDateTimeOffset $autoTransition.observed_at) - (ConvertTo-UtcDateTimeOffset $autoTime)).TotalSeconds
      }

      $manualTime = [DateTime]::UtcNow
      & sc.exe config $serviceName start= demand | Out-Null
      $manualCode = $LASTEXITCODE
      $actionLog.Add([ordered]@{ action = 'start_mode_auto_to_manual'; timestamp = $manualTime.ToString('o'); exit_code = $manualCode })
      if ($manualCode -ne 0) { throw "sc.exe could not restore Manual start mode; exit code $manualCode." }
      $manualTransition = Wait-ForTargetTransition `
        -ObjectKey $objectKey `
        -NotBefore $manualTime `
        -ExpectedType 'SERVICE_START_MODE_CHANGED' `
        -ExpectedStartMode 'manual'
      $actionLog[$actionLog.Count - 1].transition_id = $manualTransition.transition_id
      $trial.transition_acknowledgements += [ordered]@{
        action = 'start_mode_auto_to_manual'
        transition_id = $manualTransition.transition_id
        observed_at = $manualTransition.observed_at
        action_to_capture_seconds = ((ConvertTo-UtcDateTimeOffset $manualTransition.observed_at) - (ConvertTo-UtcDateTimeOffset $manualTime)).TotalSeconds
      }

      $snapshotB = Invoke-CsgSnapshot
      $trial.snapshot_after = $snapshotB
      $trial.monitor_health_after = (Get-CsgResource "/transition-capture/status?host_id=$([Uri]::EscapeDataString($hostId))").categories.service.monitor_health
      $start = [Uri]::EscapeDataString((ConvertTo-UtcDateTimeOffset $snapshotA.built_at).ToString('o'))
      $end = [Uri]::EscapeDataString((ConvertTo-UtcDateTimeOffset $snapshotB.built_at).ToString('o'))
      $encodedObject = [Uri]::EscapeDataString($objectKey)
      $query = "start=$start&end=$end&category=service&object_key=$encodedObject"
      $timeline = @(Get-CsgResource "/hosts/$([Uri]::EscapeDataString($hostId))/transition-timeline?$query")
      $trial.transition_records = @($timeline | ForEach-Object { $_.transition })
      $trial.reconciliation_attempts = @($timeline | ForEach-Object { $_.latest_reconciliation })
      $trajectoryQuery = "$query&include_stable=true&limit=50"
      $trial.trajectories = @(Get-CsgResource "/hosts/$([Uri]::EscapeDataString($hostId))/trajectories?$trajectoryQuery")

      foreach ($record in $trial.transition_records) {
        $acknowledgement = $trial.transition_acknowledgements |
          Where-Object { $_.transition_id -eq $record.transition_id } |
          Select-Object -First 1
        if (-not $acknowledgement) {
          throw "Timeline contains an unacknowledged or out-of-trial transition $($record.transition_id)."
        }
        $reconciled = Invoke-RestMethod -Method Post `
          -Uri "$apiRoot/transitions/$([Uri]::EscapeDataString($record.transition_id))/reconcile" `
          -TimeoutSec 60
        $trial.reconciliation_attempts += $reconciled
      }
      if ($EvidenceWaitSeconds -gt 0) {
        Start-Sleep -Seconds $EvidenceWaitSeconds
        foreach ($record in $trial.transition_records) {
          $revised = Invoke-RestMethod -Method Post `
            -Uri "$apiRoot/transitions/$([Uri]::EscapeDataString($record.transition_id))/reconcile" `
            -TimeoutSec 60
          $trial.reconciliation_attempts += $revised
        }
      }

      $firstState = $foundA[0].attributes
      $foundB = @($snapshotB.objects | Where-Object { $_.object_key -eq $objectKey })
      $classification = @($trial.trajectories | Where-Object {
        $_.object_key -eq $objectKey -and
        $_.snapshot_before_id -eq $snapshotA.snapshot_id -and
        $_.snapshot_after_id -eq $snapshotB.snapshot_id
      })
      $modesObserved = @($trial.transition_records | ForEach-Object {
        Normalize-ServiceStartMode ([string]$_.new_state.start_mode)
      })
      $latestReconciliation = @{}
      foreach ($result in $trial.reconciliation_attempts) {
        if ($result -and $result.transition_id -and `
            (-not $latestReconciliation.ContainsKey($result.transition_id) -or `
             $result.version -gt $latestReconciliation[$result.transition_id].version)) {
          $latestReconciliation[$result.transition_id] = $result
        }
      }
      $latestEventStatuses = @($latestReconciliation.Values | ForEach-Object { $_.status })
      $modeTransitionIds = @($trial.transition_acknowledgements | Where-Object {
        $_.action -in @('start_mode_manual_to_auto', 'start_mode_auto_to_manual')
      } | ForEach-Object { $_.transition_id })
      $onlyExpectedModeTransitions = $trial.transition_records.Count -eq 2 -and `
        @($trial.transition_records | Where-Object {
          $_.transition_type -ne 'SERVICE_START_MODE_CHANGED'
        }).Count -eq 0 -and `
        @($trial.transition_records | Where-Object {
          $_.transition_id -notin $modeTransitionIds
        }).Count -eq 0
      $snapshotStartModes = @(
        (Normalize-ServiceStartMode ([string]$firstState.start_mode)),
        $(if ($foundB.Count -eq 1) {
          Normalize-ServiceStartMode ([string]$foundB[0].attributes.start_mode)
        } else { $null })
      )
      $statePassed = $foundB.Count -eq 1 -and `
        $onlyExpectedModeTransitions -and `
        $classification.Count -eq 1 -and `
        $classification[0].trajectory_type -eq 'REVERTED' -and `
        $snapshotStartModes[0] -eq 'manual' -and `
        $snapshotStartModes[1] -eq 'manual' -and `
        $modesObserved -contains 'auto' -and `
        $modesObserved -contains 'manual' -and `
        @($trial.transition_records | Where-Object { $_.object_key -ne $objectKey }).Count -eq 0
      $eventPlanePassed = $latestReconciliation.Count -ge 2 -and `
        @($latestReconciliation.Values | Where-Object { $_.status -ne 'CORROBORATED' }).Count -eq 0
      $trial.validation = [ordered]@{
        status = if ($statePassed -and $eventPlanePassed) { 'PASS' } elseif ($statePassed) { 'STATE_CAPTURE_PASS_EVENT_CORROBORATION_NOT_PROVEN' } else { 'FAIL' }
        state_trajectory_validation = if ($statePassed) { 'PASS' } else { 'FAIL' }
        Wazuh_corroboration_validation = if ($eventPlanePassed) { 'PASS' } else { 'NOT_PROVEN' }
        target_in_snapshot_a = ($foundA.Count -eq 1)
        target_in_snapshot_b = ($foundB.Count -eq 1)
        snapshot_start_modes = $snapshotStartModes
        target_transition_count = $trial.transition_records.Count
        target_transition_ids = @($trial.transition_records | ForEach-Object { $_.transition_id })
        expected_mode_transition_ids = $modeTransitionIds
        only_expected_mode_transitions = $onlyExpectedModeTransitions
        target_snapshot_interval_has_single_trajectory = ($classification.Count -eq 1)
        trajectory_type = if ($classification.Count -eq 1) { $classification[0].trajectory_type } else { 'MISSING' }
        snapshot_delta_for_target = if ($classification.Count -eq 1) { $null -ne $classification[0].snapshot_delta } else { $null }
        exact_object_identity_only = @($trial.transition_records | Where-Object { $_.object_key -ne $objectKey }).Count -eq 0
        reconciliation_statuses = $latestEventStatuses
        reconciled_evidence_ids = @($latestReconciliation.Values | ForEach-Object { $_.matched_evidence_ids })
      }
    }
    catch {
      $trial.validation = [ordered]@{
        status = 'INCOMPLETE'
        error = $_.Exception.Message
        error_line = $_.InvocationInfo.ScriptLineNumber
        error_stack = $_.ScriptStackTrace
      }
      $scriptFailure = $_.Exception.Message
    }
    finally {
      if ($serviceCreated) {
        $trial.cleanup.attempted = $true
        $trial.cleanup.command_timestamp = [DateTime]::UtcNow.ToString('o')
        & sc.exe delete $serviceName | Out-Null
        $trial.cleanup.exit_code = $LASTEXITCODE
        $cleanupDeadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
          $remainingService = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
          if (-not $remainingService) { break }
          Start-Sleep -Milliseconds 500
        } while ([DateTime]::UtcNow -lt $cleanupDeadline)
        $trial.cleanup.service_absent_after_delete = -not [bool]$remainingService
        $trial.cleanup.completed = ($trial.cleanup.exit_code -eq 0 -and $trial.cleanup.service_absent_after_delete)
        if (-not $trial.cleanup.completed) {
          $trial.cleanup.error = "Delete exit code $($trial.cleanup.exit_code); service absence not confirmed."
        }
        if ($trial.validation) {
          $trial.validation.cleanup_validation = if ($trial.cleanup.completed) { 'PASS' } else { 'FAIL' }
          if (-not $trial.cleanup.completed -and $trial.validation.status -eq 'PASS') {
            $trial.validation.status = 'FAIL'
          }
        }
      }
      $trial.ended_at = [DateTime]::UtcNow.ToString('o')
      $trial | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $trialPath 'run.json') -Encoding UTF8
      $campaign.trials += $trial
    }
    if ($scriptFailure) { break }
  }
}
catch {
  $scriptFailure = $_.Exception.Message
}
finally {
  $campaign.wazuh_service_at_end = Get-WazuhServiceProof
  $campaign.ended_at = [DateTime]::UtcNow.ToString('o')
  $campaign.status = if ($scriptFailure) { 'INCOMPLETE' } elseif (@($campaign.trials | Where-Object { $_.validation.status -ne 'PASS' }).Count -eq 0) { 'PASS' } else { 'FAIL' }
  $campaign | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath (Join-Path $campaignPath 'campaign-manifest.json') -Encoding UTF8
}

Write-Output "Campaign artifacts: $campaignPath"
if ($scriptFailure) { throw $scriptFailure }
if ($campaign.status -ne 'PASS') { throw "Live transition campaign status is $($campaign.status). Inspect the saved run artifacts." }
