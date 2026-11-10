param(
  [string]$CsgApiBase = "http://replace-with-mac-ip:8000",
  [string]$HostId = "win11-arm-lab",
  [string]$ProbePython = "python.exe",
  [string]$ProbeConfig = "",
  [int]$WaitSeconds = 35,
  [string]$OutputPath = "",
  [ValidateSet("all", "service", "scheduled_task", "registry", "process")]
  [string]$ScenarioFilter = "all"
)

$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Run this controlled reproduction from Administrator PowerShell." }
if ($WaitSeconds -lt 10 -or $WaitSeconds -gt 180) { throw "WaitSeconds must be between 10 and 180." }

function Invoke-ProbeOnce {
  if ($ProbeConfig) {
    & $ProbePython -m cyberstateguardian_probe.main --config $ProbeConfig --once
  } else {
    & $ProbePython -m cyberstateguardian_probe.main --once
  }
  if ($LASTEXITCODE -ne 0) { throw "CSG direct probe failed with exit code $LASTEXITCODE" }
}

function Get-LatestObservation {
  return Invoke-RestMethod -Method Get -Uri "$CsgApiBase/api/hosts/$HostId/observations/latest"
}

function Invoke-ProviderSync {
  return Invoke-RestMethod -Method Post -Uri "$CsgApiBase/api/hosts/$HostId/provider-sync" -ContentType "application/json"
}

function Get-DeltasForKey {
  param([string]$ObjectKey)
  $deltas = Invoke-RestMethod -Method Get -Uri "$CsgApiBase/api/hosts/$HostId/deltas?limit=500"
  return @($deltas | Where-Object { $_.object_key -eq $ObjectKey })
}

function Get-FindingsForKey {
  param([string]$ObjectKey)
  $findings = Invoke-RestMethod -Method Get -Uri "$CsgApiBase/api/findings?host_id=$HostId&limit=500"
  return @($findings | Where-Object { $_.object_key -eq $ObjectKey })
}

function Get-ReconciliationHistories {
  param([object[]]$Findings)
  $histories = [ordered]@{}
  foreach ($finding in @($Findings)) {
    $histories[$finding.finding_id] = @(
      Invoke-RestMethod -Method Get -Uri "$CsgApiBase/api/findings/$($finding.finding_id)/reconciliations"
    )
  }
  return $histories
}

function Normalize-Identity {
  param([object]$Value)
  if ($null -eq $Value) { return "" }
  $text = ([string]$Value).Trim().ToLowerInvariant().Replace("\", "/")
  while ($text.Contains("//")) { $text = $text.Replace("//", "/") }
  return $text.Replace(":/", "/")
}

function Get-ExactEvents {
  param(
    [datetime]$ActionStarted,
    [datetime]$ActionEnded,
    [string]$ExpectedType,
    [string]$ExpectedKey,
    [string]$ObjectName,
    [string]$ScenarioKind
  )
  $start = $ActionStarted.ToUniversalTime().AddMinutes(-2).ToString("o")
  $end = $ActionEnded.ToUniversalTime().AddMinutes(2).ToString("o")
  $events = Invoke-RestMethod -Method Get -Uri (
    "$CsgApiBase/api/hosts/$HostId/events?start=$([uri]::EscapeDataString($start))" +
    "&end=$([uri]::EscapeDataString($end))"
  )
  $expected = Normalize-Identity $ExpectedKey
  $matches = @($events | Where-Object {
    if ($_.host_id -ne $HostId -or $_.source -ne "wazuh" -or $_.normalized_type -ne $ExpectedType) { return $false }
    $targetKey = Normalize-Identity $_.target.key
    if ($targetKey -eq $expected) { return $true }
    if ($ScenarioKind -eq "service") {
      return (([string]$_.attributes.service_name).ToLowerInvariant() -eq $ObjectName.ToLowerInvariant())
    }
    if ($ScenarioKind -eq "scheduled_task") {
      return (Normalize-Identity $_.attributes.task_name -eq (Normalize-Identity ("\" + $ObjectName)))
    }
    if ($ScenarioKind -eq "registry") {
      return (Normalize-Identity $_.attributes.target_object -eq $expected)
    }
    return $false
  } | ForEach-Object {
    [ordered]@{
      event_id = $_.event_id
      event_time = $_.event_time
      normalized_type = $_.normalized_type
      host_id = $_.host_id
      source = $_.source
      target = $_.target
      attributes = $_.attributes
      source_reference = $_.source_reference
    }
  })
  return $matches
}

function Get-LocalWindowsSourceEvidence {
  param(
    [datetime]$ActionStarted,
    [datetime]$ActionEnded,
    [string]$ScenarioKind,
    [string]$ExpectedKey
  )
  $source = switch ($ScenarioKind) {
    "service" { @{ log = "System"; ids = @(7045, 7040) } }
    "scheduled_task" { @{ log = "Security"; ids = @(4698) } }
    "registry" { @{ log = "Microsoft-Windows-Sysmon/Operational"; ids = @(13) } }
    default { return @{ query_status = "NOT_REQUIRED"; exact_events = @() } }
  }
  $start = $ActionStarted.ToLocalTime().AddMinutes(-2)
  $end = $ActionEnded.ToLocalTime().AddMinutes(2)
  $result = [ordered]@{
    log_name = $source.log
    event_ids = $source.ids
    query_start_local = $start.ToString("o")
    query_end_local = $end.ToString("o")
    query_status = "COMPLETE"
    error = $null
    candidate_count = 0
    exact_events = @()
  }
  try {
    $events = @(Get-WinEvent -FilterHashtable @{
      LogName = $source.log
      Id = $source.ids
      StartTime = $start
      EndTime = $end
    } -ErrorAction Stop)
    $result.candidate_count = $events.Count
    $expected = Normalize-Identity ($ExpectedKey -replace '^[^:]+:', '')
    $result.exact_events = @(
      foreach ($event in $events) {
        [xml]$xml = $event.ToXml()
        $fields = [ordered]@{}
        foreach ($field in @($xml.Event.EventData.Data)) {
          if ($field.Name) { $fields[[string]$field.Name] = [string]$field.InnerText }
        }
        $identities = switch ($ScenarioKind) {
          "service" { @($fields.ServiceName, $fields.param1, $fields.service_name) }
          "scheduled_task" { @($fields.TaskName, $fields.Task_Name) }
          "registry" { @($fields.TargetObject, $fields.targetObject) }
        }
        $matched = @($identities | Where-Object {
          (Normalize-Identity $_) -eq $expected
        }).Count -gt 0
        if ($matched) {
          [ordered]@{
            event_id = [int]$event.Id
            record_id = [long]$event.RecordId
            provider = [string]$event.ProviderName
            log_name = [string]$event.LogName
            event_time_utc = $event.TimeCreated.ToUniversalTime().ToString("o")
            exact_identity_match = $true
            event_data = $fields
            raw_xml = $event.ToXml()
          }
        }
      }
    )
  } catch {
    if ($_.FullyQualifiedErrorId -match '^NoMatchingEventsFound') {
      $result.query_status = "COMPLETE"
    } else {
      $result.query_status = "ERROR"
      $result.error = $_.Exception.Message
    }
  }
  return $result
}

function Get-ObservationMatch {
  param([object]$Observation, [string]$Category, [string]$ExpectedKey, [string]$ObjectName)
  if ($null -eq $Observation -or $null -eq $Observation.categories.$Category) { return @() }
  $expected = Normalize-Identity $ExpectedKey
  return @($Observation.categories.$Category.items | Where-Object {
    if ($Category -eq "service") { return ([string]$_.service_name).ToLowerInvariant() -eq $ObjectName.ToLowerInvariant() }
    if ($Category -eq "scheduled_task") { return ([string]$_.task_name).ToLowerInvariant() -eq ("\" + $ObjectName).ToLowerInvariant() }
    if ($Category -eq "registry") { return (Normalize-Identity $_.object_key) -eq $expected }
    if ($Category -eq "process") { return ([string]$_.name).ToLowerInvariant() -eq "timeout.exe" }
    return $false
  })
}

function Get-ScenarioEvidence {
  param(
    [string]$ScenarioId,
    [string]$Kind,
    [string]$Category,
    [string]$ObjectName,
    [string]$ExpectedKey,
    [string]$ExpectedType,
    [datetime]$ActionStarted,
    [datetime]$ActionEnded,
    [object]$AfterObservation,
    [object]$AfterCleanupObservation,
    [object]$SyncResponse
  )
  $deltas = @(Get-DeltasForKey -ObjectKey $ExpectedKey)
  $findings = @(Get-FindingsForKey -ObjectKey $ExpectedKey)
  $localEvidence = Get-LocalWindowsSourceEvidence -ActionStarted $ActionStarted `
    -ActionEnded $ActionEnded -ScenarioKind $Kind -ExpectedKey $ExpectedKey
  $wazuhMatches = @(Get-ExactEvents -ActionStarted $ActionStarted -ActionEnded $ActionEnded `
    -ExpectedType $ExpectedType -ExpectedKey $ExpectedKey -ObjectName $ObjectName -ScenarioKind $Kind)
  $stateMatches = @(Get-ObservationMatch -Observation $AfterObservation -Category $Category `
    -ExpectedKey $ExpectedKey -ObjectName $ObjectName)
  $cleanupRemoved = @(Get-ObservationMatch -Observation $AfterCleanupObservation -Category $Category `
    -ExpectedKey $ExpectedKey -ObjectName $ObjectName).Count -eq 0
  $positiveControlRequired = $Kind -in @("service", "scheduled_task", "registry")
  $positiveControlPassed = $positiveControlRequired -and
    $localEvidence.query_status -eq "COMPLETE" -and @($localEvidence.exact_events).Count -gt 0 -and
    $wazuhMatches.Count -gt 0 -and $stateMatches.Count -gt 0 -and $cleanupRemoved
  return [ordered]@{
    scenario_id = $ScenarioId
    kind = $Kind
    state_category = $Category
    object_name = $ObjectName
    expected_object_key = $ExpectedKey
    expected_event_type = $ExpectedType
    state_plane = [ordered]@{
      source = "direct_probe"
      after_action_observed = $stateMatches
      cleanup_removed_from_probe = $cleanupRemoved
      after_action_observation_id = $AfterObservation.observation_id
      after_cleanup_observation_id = $AfterCleanupObservation.observation_id
    }
    event_plane = [ordered]@{
      source = "wazuh"
      query_completed = $true
      query_completed_at = (Get-Date).ToUniversalTime().ToString("o")
      exact_identity_rule = "same host + expected normalized type + exact target identity + bounded action window"
      exact_matches = $wazuhMatches
      event_presence_required = $positiveControlRequired
      collection_expectation = if ($positiveControlRequired) { "positive_control" } else { "not_applicable" }
    }
    local_source_evidence = $localEvidence
    positive_control = [ordered]@{
      required = $positiveControlRequired
      passed = $positiveControlPassed
      rule = "direct state observation + exact local Windows event + exact same-host Wazuh event"
    }
    provider_sync = $SyncResponse
    deltas = $deltas
    findings = $findings
    reconciliation_histories = Get-ReconciliationHistories -Findings $findings
    evidence_match_count = $wazuhMatches.Count
  }
}

function Invoke-Scenario {
  param(
    [string]$ScenarioId,
    [string]$Kind,
    [string]$Category,
    [string]$ObjectName,
    [string]$ExpectedKey,
    [string]$ExpectedType,
    [scriptblock]$Create,
    [scriptblock]$Cleanup
  )
  $started = (Get-Date).ToUniversalTime()
  $created = $false
  $after = $null
  $afterCleanup = $null
  $sync = $null
  $errorMessage = $null
  try {
    Write-Host "[$ScenarioId] Creating $ObjectName"
    & $Create
    if ($LASTEXITCODE -ne 0) { throw "controlled action returned exit code $LASTEXITCODE" }
    $created = $true
    Start-Sleep -Seconds 2
    Invoke-ProbeOnce
    $after = Get-LatestObservation
    Write-Host "[$ScenarioId] Waiting $WaitSeconds seconds for Wazuh delivery"
    Start-Sleep -Seconds $WaitSeconds
    $sync = Invoke-ProviderSync
    $ended = (Get-Date).ToUniversalTime()
  } catch {
    $errorMessage = $_.Exception.Message
    $ended = (Get-Date).ToUniversalTime()
  } finally {
    try {
      & $Cleanup
    } catch {
      if (-not $errorMessage) { $errorMessage = "cleanup failed: $($_.Exception.Message)" }
    }
    Start-Sleep -Seconds 2
    try {
      Invoke-ProbeOnce
      $afterCleanup = Get-LatestObservation
    } catch {
      if (-not $errorMessage) { $errorMessage = "cleanup probe failed: $($_.Exception.Message)" }
    }
  }

  if ($null -eq $after) { $after = Get-LatestObservation }
  if ($null -eq $afterCleanup) { $afterCleanup = $after }
  if ($null -eq $ended) { $ended = (Get-Date).ToUniversalTime() }
  $record = Get-ScenarioEvidence -ScenarioId $ScenarioId -Kind $Kind -Category $Category -ObjectName $ObjectName -ExpectedKey $ExpectedKey -ExpectedType $ExpectedType -ActionStarted $started -ActionEnded $ended -AfterObservation $after -AfterCleanupObservation $afterCleanup -SyncResponse $sync
  $record.action = [ordered]@{
    started_at = $started.ToString("o")
    ended_at = $ended.ToString("o")
    cleanup_completed = $created -and ($record.state_plane.cleanup_removed_from_probe -eq $true)
    error = $errorMessage
  }
  return $record
}

if ($ProbeConfig) {
  $probeSettings = (Get-Content -Path $ProbeConfig | Out-String) | ConvertFrom-Json
  if ($probeSettings.CSG_PROBE_HOST_ID -ne $HostId) { throw "Probe config host ID does not match HostId." }
} elseif ($env:CSG_PROBE_HOST_ID -ne $HostId) {
  throw "Set CSG_PROBE_HOST_ID to the reproduction HostId or supply -ProbeConfig."
}

$campaignId = "windows-apt-behavior-family-live-validation-$(Get-Date -Format yyyyMMdd-HHmmss)"
if (-not $OutputPath) { $OutputPath = "C:\CSG\results\$campaignId\run.json" }
if (Test-Path -LiteralPath $OutputPath) { throw "Refusing to overwrite an existing run artifact: $OutputPath" }
$runDirectory = Split-Path -Parent $OutputPath
if (-not $runDirectory) { $runDirectory = (Get-Location).Path }
$progressPath = Join-Path $runDirectory "progress.json"
$trialDirectory = Join-Path $runDirectory "trials"
if (Test-Path -LiteralPath $progressPath) { throw "Refusing to overwrite an existing progress artifact: $progressPath" }
$baseline = $null
$scenarios = @()
$campaignStartedAt = (Get-Date).ToUniversalTime().ToString("o")
$trialArtifacts = @()
$null = New-Item -ItemType Directory -Path $trialDirectory -Force

function Write-JsonArtifact {
  param([string]$Path, [object]$Value)
  $temporaryPath = "$Path.tmp"
  $Value | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
  Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
}

function Save-CampaignProgress {
  param([string]$Status, [string]$ErrorMessage = $null)
  $progress = [ordered]@{
    schema_version = "csg-windows-behavior-family-progress-v1"
    campaign_id = $campaignId
    scenario_filter = $ScenarioFilter
    status = $Status
    started_at = $campaignStartedAt
    updated_at = (Get-Date).ToUniversalTime().ToString("o")
    output_path = $OutputPath
    baseline_observation_id = if ($baseline) { $baseline.observation_id } else { $null }
    completed_scenario_count = $scenarios.Count
    scenarios = $scenarios
    trial_artifacts = $trialArtifacts
    error = $ErrorMessage
  }
  Write-JsonArtifact -Path $progressPath -Value $progress
}

function Save-CompletedScenario {
  param([object]$Scenario)
  $script:scenarios += $Scenario
  $fileName = "trial-{0:D2}-{1}.json" -f $script:scenarios.Count, $Scenario.scenario_id
  $trialPath = Join-Path $trialDirectory $fileName
  Write-JsonArtifact -Path $trialPath -Value $Scenario
  $script:trialArtifacts += $trialPath
  Save-CampaignProgress -Status "IN_PROGRESS"
  Write-Host "[$($Scenario.scenario_id)] checkpoint saved: $trialPath"
}

$serviceName = "CSGAPTService$([guid]::NewGuid().ToString('N').Substring(0,10))"
$taskName = "CSGAPTTask$([guid]::NewGuid().ToString('N').Substring(0,10))"
$registryName = "CSGAPTRun$([guid]::NewGuid().ToString('N').Substring(0,10))"
$currentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value.ToLowerInvariant()
$registryKey = "registry:hku/$currentUserSid/software/microsoft/windows/currentversion/run/$($registryName.ToLowerInvariant())"
$taskKey = "scheduled_task:\$($taskName.ToLowerInvariant())"

try {
  Save-CampaignProgress -Status "IN_PROGRESS"
  Write-Host "Recording campaign baseline"
  Invoke-ProbeOnce
  $baseline = Get-LatestObservation
  Write-JsonArtifact -Path (Join-Path $runDirectory "baseline.json") -Value $baseline
  Save-CampaignProgress -Status "IN_PROGRESS"

  if ($ScenarioFilter -in @("all", "service")) {
    $scenario = Invoke-Scenario `
      -ScenarioId "service-persistence" -Kind "service" -Category "service" `
      -ObjectName $serviceName -ExpectedKey "service:$($serviceName.ToLowerInvariant())" `
      -ExpectedType "service_created" `
      -Create { & sc.exe create $serviceName binPath= 'C:\Windows\System32\cmd.exe /c exit 0' start= demand DisplayName= $serviceName | Out-Null } `
      -Cleanup { & sc.exe stop $serviceName 2>$null | Out-Null; & sc.exe delete $serviceName 2>$null | Out-Null }
    Save-CompletedScenario -Scenario $scenario
  }

  if ($ScenarioFilter -in @("all", "scheduled_task")) {
    $scenario = Invoke-Scenario `
      -ScenarioId "scheduled-task-persistence" -Kind "scheduled_task" -Category "scheduled_task" `
      -ObjectName $taskName -ExpectedKey $taskKey -ExpectedType "scheduled_task_created" `
      -Create { $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c exit 0"; $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1); Register-ScheduledTask -TaskName $taskName -TaskPath "\" -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest -Force | Out-Null } `
      -Cleanup { Unregister-ScheduledTask -TaskName $taskName -TaskPath "\" -Confirm:$false -ErrorAction SilentlyContinue }
    Save-CompletedScenario -Scenario $scenario
  }

  if ($ScenarioFilter -in @("all", "registry")) {
    $scenario = Invoke-Scenario `
      -ScenarioId "registry-autorun-persistence" -Kind "registry" -Category "registry" `
      -ObjectName $registryName -ExpectedKey $registryKey -ExpectedType "registry_value_modified" `
      -Create { New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $registryName -PropertyType String -Value "C:\Windows\System32\cmd.exe /c exit 0" -Force | Out-Null } `
      -Cleanup { Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $registryName -Force -ErrorAction SilentlyContinue }
    Save-CompletedScenario -Scenario $scenario
  }

  if ($ScenarioFilter -in @("all", "process")) {
    $scenario = Invoke-Scenario `
      -ScenarioId "process-execution" -Kind "process" -Category "process" `
      -ObjectName "timeout.exe" -ExpectedKey "process:timeout.exe" -ExpectedType "process_start" `
      -Create { Start-Process -FilePath "C:\Windows\System32\timeout.exe" -ArgumentList "/t", "25", "/nobreak" -WindowStyle Hidden } `
      -Cleanup { Get-Process -Name timeout -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
    Save-CompletedScenario -Scenario $scenario
  }
} catch {
  $failureMessage = $_.Exception.Message
  Save-CampaignProgress -Status "INTERRUPTED_OR_FAILED" -ErrorMessage $failureMessage
  throw
} finally {
  try { Get-Service -Name WazuhSvc -ErrorAction Stop | Start-Service -ErrorAction SilentlyContinue } catch { }
}

$requiredControls = @($scenarios | Where-Object { $_.positive_control.required })
$passedControls = @($requiredControls | Where-Object { $_.positive_control.passed })
$result = [ordered]@{
  schema_version = "csg-windows-behavior-family-live-validation-v4"
  campaign_id = $campaignId
  scenario_filter = $ScenarioFilter
  started_at = $baseline.observed_at
  ended_at = (Get-Date).ToUniversalTime().ToString("o")
  dataset_reference = "Windows-APT 2025 revision 3, used only for behavior-family mapping"
  exact_replication = $false
  status = if ($requiredControls.Count -eq $passedControls.Count -and $requiredControls.Count -gt 0) { "ALL_REQUIRED_POSITIVE_CONTROLS_PASSED" } else { "POSITIVE_CONTROL_GAPS_REMAIN" }
  interpretation = "Controlled live validation of selected Windows-APT-inspired behavior families on the CSG Windows VM; not a replay, reproduction, or exact copy of the public dataset."
  environment = [ordered]@{
    host_id = $HostId
    csg_api = $CsgApiBase
    state_plane = "native CSG Windows probe"
    event_plane = "Wazuh agent plus Windows/Sysmon event collection"
    probe_observation_id = $baseline.observation_id
  }
  scenarios = $scenarios
  validation = [ordered]@{
    required_positive_controls = $requiredControls.Count
    passed_positive_controls = $passedControls.Count
    all_positive_controls_passed = $requiredControls.Count -gt 0 -and $requiredControls.Count -eq $passedControls.Count
    failed_scenarios = @($requiredControls | Where-Object { -not $_.positive_control.passed } |
      ForEach-Object { $_.scenario_id })
    rule = "A category passes only when native state is observed, exact local Windows event and exact same-host Wazuh evidence are present, and cleanup is confirmed."
  }
  safety_scope = @($scenarios | ForEach-Object {
    switch ($_.kind) {
      "service" { "Temporary service '$($_.object_name)' running only cmd.exe exit 0" }
      "scheduled_task" { "Temporary task '$($_.object_name)' running only cmd.exe exit 0" }
      "registry" { "Temporary HKCU Run value '$($_.object_name)' set to cmd.exe exit 0" }
      "process" { "Temporary timeout.exe process" }
    }
  })
  limitations = @(
    "This campaign does not reproduce the public archive's original hosts, malware, timing, or ground truth.",
    "A missing exact Wazuh match means the event was not observed in the bounded retrieval window; it does not by itself prove permanent event loss.",
    "The process scenario is transient and may be visible in direct probe state without producing a persistent state finding.",
    "ATT&CK or campaign labels are behavior-family analogues, not authoritative classifications of the public dataset."
  )
  trial_artifacts = $trialArtifacts
}
$parent = Split-Path -Parent $OutputPath
if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
Write-JsonArtifact -Path $OutputPath -Value $result
Save-CampaignProgress -Status $result.status
Write-Host "Research live validation written to $OutputPath"
Write-Host "Campaign status: $($result.status)"
Write-Host "Positive controls: $($result.validation.passed_positive_controls)/$($result.validation.required_positive_controls)"
