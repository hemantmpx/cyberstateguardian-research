param(
  [string]$CsgApiBase = "http://replace-with-mac-ip:8000",
  [string]$HostId = "win11-arm-lab",
  [string]$ProbePython = "python.exe",
  [string]$ProbeConfig = "",
  [int]$WaitSeconds = 35,
  [string]$OutputPath = "",
  [ValidateRange(180, 600)]
  [int]$ReconciliationWaitSeconds = 300,
  [string]$ScheduledTaskName = "",
  [string]$DistractorTaskName = "",
  [string]$PreTargetEvaluationGatePath = "",
  [int]$PreTargetEvaluationGateTimeoutSeconds = 120,
  [ValidateSet("all", "service", "scheduled_task", "registry", "process")]
  [string]$ScenarioFilter = "all",
  [switch]$ExpectedEventSuppressed,
  [switch]$DistractorAfterSuppressedTarget,
  [string]$WazuhAgentConfigBackupPath = "",
  [string]$ExpectedAgentConfigSha256 = ""
)

$ErrorActionPreference = "Stop"
$script:probeScheduleState = $null
$script:midtrialConfigRestoration = $null
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Run this controlled reproduction from Administrator PowerShell." }
if ($WaitSeconds -lt 10 -or $WaitSeconds -gt 180) { throw "WaitSeconds must be between 10 and 180." }
if ($ScheduledTaskName -and $ScheduledTaskName -notmatch '^CSGAPTTask[a-fA-F0-9]{10}$') {
  throw "ScheduledTaskName must be a CSGAPTTask name with ten hexadecimal characters."
}
if ($DistractorTaskName -and $DistractorTaskName -notmatch '^CSGAPTDis[a-fA-F0-9]{10}$') {
  throw "DistractorTaskName must be a CSGAPTDis name with ten hexadecimal characters."
}
if ($DistractorTaskName -and -not $ScheduledTaskName) {
  throw "A distractor task requires an explicitly assigned target task."
}
if ($DistractorAfterSuppressedTarget -and (-not $ExpectedEventSuppressed -or -not $DistractorTaskName)) {
  throw "Post-target distractor mode requires intentional target suppression and a distinct distractor task."
}
if ($DistractorAfterSuppressedTarget -and
  ($ExpectedAgentConfigSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
    -not (Test-Path -LiteralPath $WazuhAgentConfigBackupPath -PathType Leaf))) {
  throw "Post-target distractor mode requires the frozen original agent config and its SHA-256."
}

function Suspend-ProbeSchedule {
  if (-not $DistractorAfterSuppressedTarget -or $script:probeScheduleState) { return }
  $task = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction Stop
  if (-not $task.Settings.Enabled) {
    throw "The CSG probe schedule was already disabled; refusing to alter its prior state."
  }
  $script:probeScheduleState = [ordered]@{
    task_name = "CyberStateGuardian Probe"
    enabled_before = [bool]$task.Settings.Enabled
    state_before = [string]$task.State
    suspended_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    restored_at_utc = $null
    enabled_after = $null
  }
  if ($task.State -eq "Running") {
    Stop-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction Stop
  }
  Disable-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction Stop | Out-Null
  Start-Sleep -Seconds 2
}

function Restore-ProbeSchedule {
  if (-not $script:probeScheduleState -or $script:probeScheduleState.restored_at_utc) { return }
  if ($script:probeScheduleState.enabled_before) {
    Enable-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction Stop | Out-Null
  }
  $task = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction Stop
  $script:probeScheduleState.restored_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  $script:probeScheduleState.enabled_after = [bool]$task.Settings.Enabled
  if ($script:probeScheduleState.enabled_after -ne $script:probeScheduleState.enabled_before) {
    throw "The CSG probe schedule did not return to its original enabled state."
  }
}

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

function Test-ExactEventIdentity {
  param(
    [object]$Event,
    [string]$ExpectedType,
    [string]$ExpectedKey,
    [string]$ObjectName,
    [string]$ScenarioKind
  )
  if ($Event.host_id -ne $HostId -or $Event.source -ne "wazuh" -or $Event.normalized_type -ne $ExpectedType) {
    return $false
  }
  $expected = Normalize-Identity $ExpectedKey
  if ((Normalize-Identity $Event.target.key) -eq $expected) { return $true }
  switch ($ScenarioKind) {
    "service" {
      return ([string]$Event.attributes.service_name -eq $ObjectName)
    }
    "scheduled_task" {
      return ((Normalize-Identity $Event.attributes.task_name) -eq (Normalize-Identity ("\" + $ObjectName)))
    }
    "registry" {
      $rawExpected = Normalize-Identity ($ExpectedKey -replace '^[^:]+:', '')
      return ((Normalize-Identity $Event.attributes.target_object) -eq $rawExpected)
    }
  }
  return $false
}

function Get-WindowsEventIdentityKey {
  param([object]$Event)
  $identity = if ($null -ne $Event.metadata -and $null -ne $Event.metadata.windows_event_identity) {
    $Event.metadata.windows_event_identity
  } elseif ($null -ne $Event.windows_event_identity) {
    $Event.windows_event_identity
  } else {
    return ""
  }
  $parts = @(
    [string]$identity.agent_id,
    [string]$identity.channel,
    [string]$identity.event_record_id,
    [string]$identity.event_code,
    [string]$identity.provider_name
  )
  if (@($parts | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
    return ""
  }
  return ($parts -join "|").ToLowerInvariant()
}

function Invoke-BoundedEventRetrieval {
  param(
    [datetime]$ActionStarted,
    [datetime]$ActionEnded,
    [string]$ExpectedType,
    [string]$ExpectedKey,
    [string]$ObjectName,
    [string]$ScenarioKind,
    [string]$DistractorTaskName
  )
  $start = $ActionStarted.ToUniversalTime().AddMinutes(-2).ToString("o")
  $end = $ActionEnded.ToUniversalTime().AddMinutes(2).ToString("o")
  $clientRequestStartedAt = (Get-Date).ToUniversalTime()
  $clientRequestTimer = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    $observation = Invoke-RestMethod -Method Get -TimeoutSec 90 -Uri (
      "$CsgApiBase/api/hosts/$HostId/provider-event-observation?start=$([uri]::EscapeDataString($start))" +
      "&end=$([uri]::EscapeDataString($end))"
    )
  } catch {
    $clientRequestTimer.Stop()
    $clientRequestCompletedAt = (Get-Date).ToUniversalTime()
    return [ordered]@{
      retrieval_mode = "bounded_wazuh_provider_query"
      query_start = $start
      query_end = $end
      query_complete = $false
      client_request_started_at_utc = $clientRequestStartedAt.ToString("o")
      client_request_completed_at_utc = $clientRequestCompletedAt.ToString("o")
      client_elapsed_seconds = [math]::Round($clientRequestTimer.Elapsed.TotalSeconds, 6)
      request_error = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
      exact_target_event_ids = @()
      exact_target_event_identity_keys = @()
      exact_target_event_source_references = @()
      ingested_event_ids = @()
    }
  }
  $clientRequestCompletedAt = (Get-Date).ToUniversalTime()
  $clientRequestTimer.Stop()
  $candidateEvents = @($observation.events)
  $exactEvents = @($candidateEvents | Where-Object {
    Test-ExactEventIdentity -Event $_ -ExpectedType $ExpectedType -ExpectedKey $ExpectedKey `
      -ObjectName $ObjectName -ScenarioKind $ScenarioKind
  })
  $distractorKey = if ($DistractorTaskName) {
    "scheduled_task:\$($DistractorTaskName.ToLowerInvariant())"
  } else { $null }
  $distractorEvents = if ($DistractorTaskName) {
    @($candidateEvents | Where-Object {
      Test-ExactEventIdentity -Event $_ -ExpectedType "scheduled_task_created" `
        -ExpectedKey $distractorKey -ObjectName $DistractorTaskName -ScenarioKind "scheduled_task"
    })
  } else { @() }
  if ($distractorEvents.Count -gt 1) {
    throw "Provider returned multiple exact distractor events; refusing ambiguous ingestion."
  }
  $eventsToIngest = @($exactEvents) + @($distractorEvents)
  $ingested = @()
  $ingestError = $null
  $ingestElapsedSeconds = 0.0
  $ingestStartedAt = $null
  $ingestCompletedAt = $null
  if ($eventsToIngest.Count -gt 0) {
    $body = ConvertTo-Json -InputObject $eventsToIngest -Depth 30 -Compress
    $ingestStartedAt = (Get-Date).ToUniversalTime()
    $ingestTimer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
      $ingestResponse = Invoke-RestMethod -Method Post -TimeoutSec 30 `
        -Uri "$CsgApiBase/api/events" -ContentType "application/json" -Body $body
      $valueProperty = $ingestResponse.PSObject.Properties['value']
      $ingested = if ($valueProperty) { @($valueProperty.Value) } else { @($ingestResponse) }
    } catch {
      $ingestError = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
    } finally {
      $ingestTimer.Stop()
      $ingestCompletedAt = (Get-Date).ToUniversalTime()
      $ingestElapsedSeconds = [math]::Round($ingestTimer.Elapsed.TotalSeconds, 6)
    }
  }
  return [ordered]@{
    retrieval_mode = "bounded_wazuh_provider_query"
    query_start = $start
    query_end = $end
    client_request_started_at_utc = $clientRequestStartedAt.ToString("o")
    client_request_completed_at_utc = $clientRequestCompletedAt.ToString("o")
    client_elapsed_seconds = [math]::Round($clientRequestTimer.Elapsed.TotalSeconds, 6)
    request_error = $null
    query_complete = $observation.query_complete
    endpoint_collection_status = $observation.endpoint_collection_status
    transport_status = $observation.transport_status
    index_status = $observation.index_status
    coverage_status = $observation.coverage_status
    retrieval_pages = $observation.retrieval_pages
    retrieved_count = $observation.retrieved_count
    total_hits = $observation.total_hits
    candidate_count = $candidateEvents.Count
    exact_target_event_ids = @($exactEvents | ForEach-Object { $_.event_id })
    exact_target_event_identity_keys = @($exactEvents | ForEach-Object {
      Get-WindowsEventIdentityKey -Event $_
    })
    exact_target_event_source_references = @($exactEvents | ForEach-Object {
      $_.source_reference
    })
    exact_distractor_events = $distractorEvents
    exact_distractor_event_ids = @($distractorEvents | ForEach-Object { $_.event_id })
    ingested_event_ids = @($ingested | ForEach-Object { $_.event_id })
    ingested_distractor_event_ids = @($ingested | Where-Object {
      $_.event_id -in @($distractorEvents | ForEach-Object { $_.event_id })
    } | ForEach-Object { $_.event_id })
    ingest_started_at_utc = if ($ingestStartedAt) { $ingestStartedAt.ToString("o") } else { $null }
    ingest_completed_at_utc = if ($ingestCompletedAt) { $ingestCompletedAt.ToString("o") } else { $null }
    ingest_elapsed_seconds = $ingestElapsedSeconds
    ingest_error = $ingestError
    provider_metadata = $observation.metadata
  }
}

function Get-DeltasForKey {
  param([string]$ObjectKey)
  $encodedKey = [uri]::EscapeDataString($ObjectKey)
  $deltas = Invoke-RestMethod -Method Get `
    -Uri "$CsgApiBase/api/hosts/$HostId/deltas?limit=500&object_key=$encodedKey"
  return @($deltas | Where-Object { $_.object_key -eq $ObjectKey })
}

function Get-FindingsForKey {
  param([string]$ObjectKey)
  $encodedKey = [uri]::EscapeDataString($ObjectKey)
  $findings = Invoke-RestMethod -Method Get `
    -Uri "$CsgApiBase/api/findings?host_id=$HostId&limit=500&object_key=$encodedKey"
  return @($findings | Where-Object { $_.object_key -eq $ObjectKey })
}

function Get-ReconciliationHistories {
  param([object[]]$Findings)
  $histories = [ordered]@{}
  foreach ($finding in @($Findings)) {
    $response = Invoke-RestMethod -Method Get `
      -Uri "$CsgApiBase/api/findings/$($finding.finding_id)/reconciliations"
  if ($response -is [System.Array]) {
      $histories[$finding.finding_id] = @($response)
    } elseif ($null -ne $response.PSObject.Properties['value']) {
      $histories[$finding.finding_id] = @($response.value)
    } else {
      $histories[$finding.finding_id] = @($response)
    }
  }
  return $histories
}

function Get-ExactTargetCreationReconciliation {
  param([string]$ObjectKey, [string[]]$ExpectedEventIds)
  $deltas = @(Get-DeltasForKey -ObjectKey $ObjectKey | Where-Object {
    $_.delta_type -eq "ADD" -and $_.object_key -eq $ObjectKey
  })
  $findings = @(Get-FindingsForKey -ObjectKey $ObjectKey)
  foreach ($delta in $deltas | Sort-Object created_at -Descending) {
    $finding = $findings | Where-Object { $_.delta_id -eq $delta.delta_id } | Select-Object -First 1
    if (-not $finding) { continue }
    $histories = Get-ReconciliationHistories -Findings @($finding)
    $history = @($histories[$finding.finding_id])
    if ($history.Count -eq 0) { continue }
    $latest = $history[-1]
    $matchedIds = @($latest.matched_evidence_ids | Sort-Object -Unique)
    $expectedIds = @($ExpectedEventIds | Sort-Object -Unique)
    $exactSet = $expectedIds.Count -gt 0 -and $matchedIds.Count -eq $expectedIds.Count -and
      @($matchedIds | Where-Object { $_ -notin $expectedIds }).Count -eq 0
    return [ordered]@{
      checked_at_utc = (Get-Date).ToUniversalTime().ToString("o")
      delta_id = $delta.delta_id
      delta_type = $delta.delta_type
      delta_created_at = $delta.created_at
      finding_id = $finding.finding_id
      reconciliation_id = $latest.reconciliation_id
      reconciliation_status = $latest.status
      finalized = [bool]$latest.finalized
      finalized_at = $latest.finalized_at
      expected_event_ids = $expectedIds
      matched_evidence_ids = $matchedIds
      matched_exact_event_set = [bool]$exactSet
      passed = [bool]($latest.status -eq "CONSISTENT" -and $latest.finalized -eq $true -and $exactSet)
      history = $history
    }
  }
  return $null
}

function Wait-ForExactTargetCreationReconciliation {
  param([string]$ObjectKey, [string[]]$ExpectedEventIds, [int]$TimeoutSeconds = 120)
  $deadline = (Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)
  $attempts = 0
  $lastResult = $null
  $lastError = $null
  do {
    $attempts++
    try {
      $lastResult = Get-ExactTargetCreationReconciliation `
        -ObjectKey $ObjectKey -ExpectedEventIds $ExpectedEventIds
      if ($lastResult -and $lastResult.passed) {
        $lastResult.attempts = $attempts
        $lastResult.wait_timeout_seconds = $TimeoutSeconds
        return $lastResult
      }
    } catch {
      $lastError = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
    }
    if ((Get-Date).ToUniversalTime() -lt $deadline) { Start-Sleep -Seconds 2 }
  } while ((Get-Date).ToUniversalTime() -lt $deadline)
  if (-not $lastResult) {
    $lastResult = [ordered]@{ passed = $false; error = $lastError }
  }
  $lastResult.attempts = $attempts
  $lastResult.wait_timeout_seconds = $TimeoutSeconds
  $lastResult.last_error = $lastError
  return $lastResult
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
  $limit = 500
  $events = Invoke-RestMethod -Method Get -Uri (
    "$CsgApiBase/api/hosts/$HostId/events?start=$([uri]::EscapeDataString($start))" +
    "&end=$([uri]::EscapeDataString($end))" +
    "&normalized_type=$([uri]::EscapeDataString($ExpectedType))" +
    "&source=wazuh" +
    "&object_key=$([uri]::EscapeDataString($ExpectedKey))" +
    "&object_name=$([uri]::EscapeDataString($ObjectName))" +
    "&limit=$limit"
  ) -TimeoutSec 30
  if (@($events).Count -ge $limit) {
    throw "Wazuh evidence query reached its $limit-result cap; absence or completeness cannot be inferred."
  }
  $expected = Normalize-Identity $ExpectedKey
  $matches = @($events | Where-Object {
    Test-ExactEventIdentity -Event $_ -ExpectedType $ExpectedType -ExpectedKey $ExpectedKey `
      -ObjectName $ObjectName -ScenarioKind $ScenarioKind
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
      windows_event_identity = $_.metadata.windows_event_identity
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
          $fieldName = [string]$field.GetAttribute("Name")
          if ($fieldName) { $fields[$fieldName] = [string]$field.InnerText }
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

function Wait-ForExactTaskCreationEvent {
  param(
    [string]$TaskName,
    [datetime]$ActionStarted,
    [int]$TimeoutSeconds = 15
  )
  $deadline = (Get-Date).ToUniversalTime().AddSeconds($TimeoutSeconds)
  $normalizedName = $TaskName.TrimStart([char]92)
  $attempts = 0
  do {
    $attempts++
    $events = @()
    try {
      $events = @(Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id = 4698
        StartTime = $ActionStarted.ToLocalTime().AddSeconds(-2)
        EndTime = (Get-Date)
      } -MaxEvents 200 -ErrorAction Stop)
    } catch {
      if ($_.FullyQualifiedErrorId -notmatch '^NoMatchingEventsFound') {
        $script:distractorLocalEventSearch = [ordered]@{
          status = "ERROR"
          attempts = $attempts
          error = $_.Exception.Message
          completed_at_utc = [DateTime]::UtcNow.ToString("o")
        }
        return $null
      }
    }
    foreach ($event in $events) {
      [xml]$eventXml = $event.ToXml()
      $taskField = @($eventXml.Event.EventData.Data | Where-Object {
        $_.GetAttribute("Name") -eq "TaskName"
      } | Select-Object -First 1)[0]
      if ($taskField -and ([string]$taskField.InnerText).TrimStart([char]92) -ieq $normalizedName) {
        $script:distractorLocalEventSearch = [ordered]@{
          status = "FOUND"
          attempts = $attempts
          completed_at_utc = [DateTime]::UtcNow.ToString("o")
        }
        return [ordered]@{
          event_id = [int]$event.Id
          record_id = [long]$event.RecordId
          provider = [string]$event.ProviderName
          log_name = [string]$event.LogName
          event_time_utc = $event.TimeCreated.ToUniversalTime().ToString("o")
          exact_identity_match = $true
          task_name = [string]$taskField.InnerText
          raw_xml = $event.ToXml()
        }
      }
    }
    if ((Get-Date).ToUniversalTime() -lt $deadline) { Start-Sleep -Milliseconds 500 }
  } while ((Get-Date).ToUniversalTime() -lt $deadline)
  $script:distractorLocalEventSearch = [ordered]@{
    status = "NOT_FOUND"
    attempts = $attempts
    completed_at_utc = [DateTime]::UtcNow.ToString("o")
  }
  return $null
}

function Get-ObservationMatch {
  param([object]$Observation, [string]$Category, [string]$ExpectedKey, [string]$ObjectName)
  if ($null -eq $Observation -or $null -eq $Observation.categories.$Category) { return @() }
  $expected = Normalize-Identity $ExpectedKey
  return @($Observation.categories.$Category.items | Where-Object {
    if ($Category -eq "service") { return ([string]$_.service_name).ToLowerInvariant() -eq $ObjectName.ToLowerInvariant() }
    if ($Category -eq "scheduled_task") {
      $actualTaskName = (Normalize-Identity $_.task_name).TrimStart("/")
      $expectedTaskName = (Normalize-Identity $ObjectName).TrimStart("/")
      return $actualTaskName -eq $expectedTaskName
    }
    if ($Category -eq "registry") { return (Normalize-Identity $_.object_key) -eq $expected }
    if ($Category -eq "process") { return ([string]$_.name).ToLowerInvariant() -eq "timeout.exe" }
    return $false
  })
}

function Get-TargetObservationEvidence {
  param([object]$Observation, [string]$Category, [string]$ExpectedKey, [string]$ObjectName)
  $items = @(Get-ObservationMatch -Observation $Observation -Category $Category `
    -ExpectedKey $ExpectedKey -ObjectName $ObjectName)
  $categoryObservation = if ($Observation) { $Observation.categories.$Category } else { $null }
  return [ordered]@{
    observation_id = if ($Observation) { $Observation.observation_id } else { $null }
    observed_at = if ($Observation) { $Observation.observed_at } else { $null }
    category = $Category
    category_status = if ($categoryObservation) { $categoryObservation.status } else { "UNKNOWN" }
    category_observed_at = if ($categoryObservation) { $categoryObservation.observed_at } else { $null }
    collection_started_at = if ($Observation) { $Observation.metadata.collection_started_at } else { $null }
    collection_wall_seconds = if ($Observation) { $Observation.metadata.collection_wall_seconds } else { $null }
    target_items = $items
  }
}

function Test-NativeScheduledTaskPresence {
  param([string]$ObjectName)
  $tasks = @(Get-ScheduledTask -TaskName $ObjectName -TaskPath "\" -ErrorAction SilentlyContinue)
  return $tasks.Count -gt 0
}

function Restart-WazuhAgentService {
  param([int]$MaxAttempts = 3, [int]$AttemptTimeoutSeconds = 25)
  $before = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction Stop
  if (-not $before -or [int]$before.ProcessId -le 0) {
    throw "WazuhSvc has no running process before the requested configuration reload."
  }
  $beforeProcessId = [int]$before.ProcessId
  $attemptErrors = @()
  $current = $before
  for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    try {
      Restart-Service -Name WazuhSvc -Force -ErrorAction Stop
    } catch {
      $attemptErrors += "attempt ${attempt}: $($_.Exception.Message)"
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($AttemptTimeoutSeconds)
    do {
      $current = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction Stop
      if ($current.State -eq "Running" -and [int]$current.ProcessId -gt 0 -and
        [int]$current.ProcessId -ne $beforeProcessId) {
        return [ordered]@{
          status = "RESTART_CONFIRMED"
          attempts = $attempt
          process_id_before = $beforeProcessId
          process_id_after = [int]$current.ProcessId
          service_state_after = [string]$current.State
          attempt_errors = $attemptErrors
          confirmed_at_utc = [DateTime]::UtcNow.ToString("o")
        }
      }
      if ((Get-Date).ToUniversalTime() -lt $deadline) { Start-Sleep -Seconds 1 }
    } while ((Get-Date).ToUniversalTime() -lt $deadline)
    if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds 2 }
  }
  $errorSummary = if ($attemptErrors.Count) { $attemptErrors -join " | " } else { "service process ID did not change" }
  throw "Could not confirm WazuhSvc restart after $MaxAttempts attempts; before PID $beforeProcessId, current state $($current.State), current PID $($current.ProcessId). $errorSummary"
}

function Restore-WazuhConfigBeforeDistractor {
  $configPath = Join-Path ${env:ProgramFiles(x86)} "ossec-agent\ossec.conf"
  Copy-Item -LiteralPath $WazuhAgentConfigBackupPath -Destination $configPath -Force
  $restoredHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($restoredHash -ne $ExpectedAgentConfigSha256.ToLowerInvariant()) {
    throw "The original Wazuh agent config hash did not restore before distractor creation."
  }
  $restartEvidence = Restart-WazuhAgentService
  $deadline = (Get-Date).ToUniversalTime().AddSeconds(120)
  do {
    $service = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
    $health = $null
    try {
      $health = Invoke-RestMethod -Method Get -TimeoutSec 10 -Uri "$CsgApiBase/api/wazuh/status"
    } catch { }
    $agent = if ($health) {
      @($health.agents | Where-Object { $_.name -eq $HostId } | Select-Object -First 1)[0]
    } else { $null }
    if ($service.Status -eq "Running" -and $health.ok -and $agent.status -eq "active") {
      return [ordered]@{
        restored_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        original_config_sha256 = $ExpectedAgentConfigSha256.ToLowerInvariant()
        restored_config_sha256 = $restoredHash
        service_restart = $restartEvidence
        service_status = [string]$service.Status
        service_process_id = (Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'").ProcessId
        endpoint_agent_status = $agent.status
        manager_api_healthy = [bool]$health.ok
      }
    }
    Start-Sleep -Seconds 2
  } while ((Get-Date).ToUniversalTime() -lt $deadline)
  throw "Wazuh did not return to healthy/active state before distractor creation."
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
    [object]$BeforeObservation,
    [object]$AfterObservation,
    [object]$AfterCleanupObservation,
    [object]$NativeBeforePresent,
    [object]$NativeAfterPresent,
    [object]$NativeAfterCleanupPresent,
    [object]$SyncResponse,
    [object]$CreationReconciliation
  )
  $deltas = @(Get-DeltasForKey -ObjectKey $ExpectedKey)
  $findings = @(Get-FindingsForKey -ObjectKey $ExpectedKey)
  $localEvidence = Get-LocalWindowsSourceEvidence -ActionStarted $ActionStarted `
    -ActionEnded $ActionEnded -ScenarioKind $Kind -ExpectedKey $ExpectedKey
  $wazuhMatches = @(Get-ExactEvents -ActionStarted $ActionStarted -ActionEnded $ActionEnded `
    -ExpectedType $ExpectedType -ExpectedKey $ExpectedKey -ObjectName $ObjectName -ScenarioKind $Kind)
  $stateMatches = @(Get-ObservationMatch -Observation $AfterObservation -Category $Category `
    -ExpectedKey $ExpectedKey -ObjectName $ObjectName)
  $beforeStateMatches = @(Get-ObservationMatch -Observation $BeforeObservation -Category $Category `
    -ExpectedKey $ExpectedKey -ObjectName $ObjectName)
  $cleanupRemoved = @(Get-ObservationMatch -Observation $AfterCleanupObservation -Category $Category `
    -ExpectedKey $ExpectedKey -ObjectName $ObjectName).Count -eq 0
  $nativeCheckRequired = $Kind -eq "scheduled_task"
  $nativePresenceSequencePassed = -not $nativeCheckRequired -or (
    $NativeBeforePresent -eq $false -and $NativeAfterPresent -eq $true -and
    $NativeAfterCleanupPresent -eq $false
  )
  $positiveControlRequired = $Kind -in @("service", "scheduled_task", "registry") -and
    -not $ExpectedEventSuppressed
  $positiveControlPassed = $positiveControlRequired -and $SyncResponse.query_complete -eq $true -and
    $localEvidence.query_status -eq "COMPLETE" -and @($localEvidence.exact_events).Count -gt 0 -and
    $wazuhMatches.Count -gt 0 -and $beforeStateMatches.Count -eq 0 -and
    $stateMatches.Count -gt 0 -and $cleanupRemoved
  $histories = Get-ReconciliationHistories -Findings $findings
  $addDelta = $deltas | Where-Object { $_.delta_type -eq "ADD" } |
    Sort-Object created_at | Select-Object -Last 1
  $addFinding = if ($addDelta) {
    $findings | Where-Object { $_.delta_id -eq $addDelta.delta_id } | Select-Object -First 1
  } else { $null }
  $targetHistory = if ($addFinding) { @($histories[$addFinding.finding_id]) } else { @() }
  $latestReconciliation = if ($targetHistory.Count -gt 0) {
    $targetHistory[-1]
  } elseif ($addFinding) { $addFinding.reconciliation } else { $null }
  $matchedIds = if ($latestReconciliation) {
    @($latestReconciliation.matched_evidence_ids | Sort-Object -Unique)
  } else { @() }
  $exactEventDocuments = @($wazuhMatches | ForEach-Object {
    [ordered]@{
      event_id = [string]$_.event_id
      identity_key = Get-WindowsEventIdentityKey -Event $_
    }
  })
  $exactEventIds = @($exactEventDocuments | ForEach-Object { $_.event_id } | Sort-Object -Unique)
  $exactPhysicalIdentityKeys = @(
    $exactEventDocuments | Where-Object { -not [string]::IsNullOrWhiteSpace($_.identity_key) } |
      ForEach-Object { $_.identity_key } | Sort-Object -Unique
  )
  $matchedPhysicalIdentityKeys = @(
    $exactEventDocuments | Where-Object { $_.event_id -in $matchedIds -and
      -not [string]::IsNullOrWhiteSpace($_.identity_key) } |
      ForEach-Object { $_.identity_key } | Sort-Object -Unique
  )
  $matchedOnlyExactEvents = $exactPhysicalIdentityKeys.Count -gt 0 -and
    $matchedIds.Count -eq $exactPhysicalIdentityKeys.Count -and
    @($matchedIds | Where-Object { $_ -notin $exactEventIds }).Count -eq 0 -and
    @($matchedPhysicalIdentityKeys | Where-Object { $_ -notin $exactPhysicalIdentityKeys }).Count -eq 0 -and
    $matchedPhysicalIdentityKeys.Count -eq $exactPhysicalIdentityKeys.Count
  $creationGatePassed = $Kind -ne "scheduled_task" -or $CreationReconciliation.passed -eq $true
  $csgExactReconciliation = $latestReconciliation -and
    $latestReconciliation.status -eq "CONSISTENT" -and $latestReconciliation.finalized -eq $true -and
    $matchedOnlyExactEvents -and $creationGatePassed
  $positiveControlPassed = $positiveControlPassed -and $csgExactReconciliation -and
    $nativePresenceSequencePassed
  return [ordered]@{
    scenario_id = $ScenarioId
    kind = $Kind
    state_category = $Category
    object_name = $ObjectName
    expected_object_key = $ExpectedKey
    expected_event_type = $ExpectedType
    state_plane = [ordered]@{
      source = "direct_probe"
      before_action_observation = Get-TargetObservationEvidence -Observation $BeforeObservation `
        -Category $Category -ExpectedKey $ExpectedKey -ObjectName $ObjectName
      after_action_observed = $stateMatches
      after_action_observation = Get-TargetObservationEvidence -Observation $AfterObservation `
        -Category $Category -ExpectedKey $ExpectedKey -ObjectName $ObjectName
      after_cleanup_observation = Get-TargetObservationEvidence -Observation $AfterCleanupObservation `
        -Category $Category -ExpectedKey $ExpectedKey -ObjectName $ObjectName
      target_absent_before_action = $beforeStateMatches.Count -eq 0
      cleanup_removed_from_probe = $cleanupRemoved
      direct_windows_verification = if ($nativeCheckRequired) {
        [ordered]@{
          target_absent_before_action = ($NativeBeforePresent -eq $false)
          target_present_after_action = ($NativeAfterPresent -eq $true)
          target_absent_after_cleanup = ($NativeAfterCleanupPresent -eq $false)
        }
      } else { $null }
      after_action_observation_id = $AfterObservation.observation_id
      after_cleanup_observation_id = $AfterCleanupObservation.observation_id
      creation_delta_reconciliation_before_cleanup = $CreationReconciliation
    }
    event_plane = [ordered]@{
      source = "wazuh"
      query_completed = ($null -ne $SyncResponse)
      query_complete = if ($SyncResponse) { $SyncResponse.query_complete } else { $false }
      query_completed_at = if ($SyncResponse.client_request_completed_at_utc) {
        $SyncResponse.client_request_completed_at_utc
      } else { $null }
      exact_identity_rule = "same host + normalized type + exact target + bounded action window + Windows physical event identity"
      exact_matches = $wazuhMatches
      exact_physical_event_count = $exactPhysicalIdentityKeys.Count
      exact_document_count = $exactEventDocuments.Count
      retrieval = $SyncResponse
      event_presence_required = $positiveControlRequired
      collection_expectation = if ($ExpectedEventSuppressed -and $Kind -eq "scheduled_task") {
        "intentional_eventid_4698_suppression"
      } elseif ($positiveControlRequired) { "positive_control" } else { "not_applicable" }
    }
    local_source_evidence = $localEvidence
    positive_control = [ordered]@{
      required = $positiveControlRequired
      passed = $positiveControlPassed
      rule = "target absent/present/absent in probe + exact local Windows event + exact same-host Wazuh physical identity + finalized CSG CONSISTENT with one exact evidence ID per physical event + cleanup"
    }
    csg_reconciliation = [ordered]@{
      finding_id = if ($addFinding) { $addFinding.finding_id } else { $null }
      status = if ($latestReconciliation) { $latestReconciliation.status } else { "MISSING" }
      finalized = if ($latestReconciliation) { $latestReconciliation.finalized } else { $false }
      matched_evidence_ids = $matchedIds
      matched_only_exact_target_events = $matchedOnlyExactEvents
      matched_physical_event_identity_keys = $matchedPhysicalIdentityKeys
      deduplicated_windows_event_aliases = if ($latestReconciliation.metadata) {
        @($latestReconciliation.metadata.deduplicated_windows_event_aliases)
      } else { @() }
      history = $targetHistory
    }
    event_retrieval = $SyncResponse
    deltas = $deltas
    findings = $findings
    reconciliation_histories = $histories
    evidence_match_count = $wazuhMatches.Count
    exact_physical_event_count = $exactPhysicalIdentityKeys.Count
    exact_document_count = $exactEventDocuments.Count
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
    [string]$DistractorTaskName,
    [scriptblock]$Create,
    [scriptblock]$Cleanup
  )
  $started = (Get-Date).ToUniversalTime()
  $created = $false
  $beforeObservation = $null
  $after = $null
  $afterCleanup = $null
  $nativeBeforePresent = $null
  $nativeAfterPresent = $null
  $nativeAfterCleanupPresent = $null
  $sync = $null
  $creationReconciliation = $null
  $preTargetEvaluationGate = $null
  $targetQueryStartedAt = $null
  $distractorLocalEvent = $null
  $script:distractorLocalEvent = $null
  $script:distractorLocalEventSearch = $null
  $distractorReadback = @()
  $distractorEvidence = $null
  $distractorProbeAttempts = @()
  $distractorProbePairPassed = $false
  $distractorProbePairObservation = $null
  $errorMessage = $null
  try {
    Suspend-ProbeSchedule
    Write-Host "[$ScenarioId] Recording immediate pre-action state"
    Invoke-ProbeOnce
    $beforeObservation = Get-LatestObservation
    $beforeItems = @(Get-ObservationMatch -Observation $beforeObservation -Category $Category `
      -ExpectedKey $ExpectedKey -ObjectName $ObjectName)
    if ($beforeItems.Count -gt 0) { throw "Randomized target already exists before the action." }
    if ($Kind -eq "scheduled_task" -and $DistractorTaskName) {
      $distractorKey = "scheduled_task:\$($DistractorTaskName.ToLowerInvariant())"
      $beforeDistractorItems = @(Get-ObservationMatch -Observation $beforeObservation `
        -Category $Category -ExpectedKey $distractorKey -ObjectName $DistractorTaskName)
      if ($beforeDistractorItems.Count -gt 0 -or
        (Test-NativeScheduledTaskPresence -ObjectName $DistractorTaskName)) {
        throw "Randomized distractor already exists before the action."
      }
    }
    if ($Kind -eq "scheduled_task") {
      $nativeBeforePresent = Test-NativeScheduledTaskPresence -ObjectName $ObjectName
      if ($nativeBeforePresent) { throw "Randomized scheduled task exists before the action." }
    }
    $started = (Get-Date).ToUniversalTime()
    Write-Host "[$ScenarioId] Creating $ObjectName"
    & $Create
    if ($LASTEXITCODE -ne 0) { throw "controlled action returned exit code $LASTEXITCODE" }
    $created = $true
    Start-Sleep -Seconds 2
    $afterDeadline = (Get-Date).ToUniversalTime().AddSeconds(90)
    do {
      Invoke-ProbeOnce
      $candidate = Get-LatestObservation
      $candidateItems = @(Get-ObservationMatch -Observation $candidate -Category $Category `
        -ExpectedKey $ExpectedKey -ObjectName $ObjectName)
      $candidateDistractorItems = @()
      $nativeDistractorPresent = $null
      $nativeTargetPresent = $null
      if ($Kind -eq "scheduled_task") {
        $nativeTargetPresent = Test-NativeScheduledTaskPresence -ObjectName $ObjectName
        $nativeAfterPresent = $nativeTargetPresent
        if ($DistractorTaskName) {
          $distractorKey = "scheduled_task:\$($DistractorTaskName.ToLowerInvariant())"
          $candidateDistractorItems = @(Get-ObservationMatch -Observation $candidate `
            -Category $Category -ExpectedKey $distractorKey -ObjectName $DistractorTaskName)
          $nativeDistractorPresent = Test-NativeScheduledTaskPresence -ObjectName $DistractorTaskName
        }
      }
      $freshCandidate = $candidate.observation_id -ne $beforeObservation.observation_id -and
        $candidate.observed_at -gt $started.ToString("o")
      $pairRequired = $Kind -eq "scheduled_task" -and $DistractorTaskName -and
        $DistractorAfterSuppressedTarget
      $candidateHasTarget = $freshCandidate -and $candidateItems.Count -gt 0 -and
        ($Kind -ne "scheduled_task" -or $nativeTargetPresent)
      $candidateHasPair = $candidateHasTarget -and $candidateDistractorItems.Count -gt 0 -and
        $nativeDistractorPresent
      if ($pairRequired) {
        $distractorProbeAttempts += [ordered]@{
          attempt = $distractorProbeAttempts.Count + 1
          observation_id = $candidate.observation_id
          observed_at_utc = $candidate.observed_at
          category_status = $candidate.categories.$Category.status
          target_exact_item_count = $candidateItems.Count
          distractor_exact_item_count = $candidateDistractorItems.Count
          windows_target_present = $nativeTargetPresent
          windows_distractor_present = $nativeDistractorPresent
          fresh_after_action = [bool]$freshCandidate
          pair_observed_in_same_probe = [bool]$candidateHasPair
        }
      }
      if ($candidateHasTarget -and (-not $pairRequired -or $candidateHasPair)) {
        $after = $candidate
        if ($pairRequired) {
          $distractorProbePairPassed = $true
          $distractorProbePairObservation = $candidate
        }
        break
      }
      if ($candidateHasTarget) { $after = $candidate }
      if ((Get-Date).ToUniversalTime() -lt $afterDeadline) { Start-Sleep -Seconds 2 }
    } while ((Get-Date).ToUniversalTime() -lt $afterDeadline)
    if (-not $after -or @(Get-ObservationMatch -Observation $after -Category $Category `
      -ExpectedKey $ExpectedKey -ObjectName $ObjectName).Count -eq 0) {
      throw "A fresh post-action probe did not capture the exact target within 90 seconds."
    }
    Write-Host "[$ScenarioId] Waiting $WaitSeconds seconds for Wazuh delivery"
    Start-Sleep -Seconds $WaitSeconds
    if ($Kind -eq "scheduled_task" -and $PreTargetEvaluationGatePath) {
      $gateDeadline = (Get-Date).ToUniversalTime().AddSeconds($PreTargetEvaluationGateTimeoutSeconds)
      while (-not (Test-Path -LiteralPath $PreTargetEvaluationGatePath -PathType Leaf) -and
        (Get-Date).ToUniversalTime() -lt $gateDeadline) {
        Start-Sleep -Seconds 1
      }
      if (-not (Test-Path -LiteralPath $PreTargetEvaluationGatePath -PathType Leaf)) {
        throw "Exact distractor event-store readback gate was not received before target evaluation."
      }
      $gateDocument = Get-Content -LiteralPath $PreTargetEvaluationGatePath -Raw | ConvertFrom-Json
      $normalizedDistractorName = ([string]$gateDocument.distractor_task_name).ToLowerInvariant()
      $expectedDistractorKey = "scheduled_task:\$normalizedDistractorName"
      $validGate = $gateDocument.schema_version -eq "csg-pre-target-event-evaluation-gate-v1" -and
        $gateDocument.host_id -eq $HostId -and
        $gateDocument.target_task_name -eq $ObjectName -and
        $gateDocument.distractor_task_name -and
        $gateDocument.distractor_task_name -ne $ObjectName -and
        $gateDocument.normalized_type -eq "scheduled_task_created" -and
        $gateDocument.exact_identity_verified -eq $true -and
        $gateDocument.event_store_readback_complete -eq $true -and
        $gateDocument.event_id -match '^wazuh-' -and
        $gateDocument.object_key -eq $expectedDistractorKey
      if (-not $validGate) { throw "Pre-target gate did not prove the exact distinct distractor event." }
      $gateReadbackAt = [datetimeoffset]::Parse([string]$gateDocument.verified_at_utc).UtcDateTime
      $targetQueryStartedAt = (Get-Date).ToUniversalTime()
      if ($gateReadbackAt -gt $targetQueryStartedAt.AddSeconds(5)) {
        throw "Distractor event-store readback was not before target evaluation start."
      }
      $preTargetEvaluationGate = [ordered]@{
        gate_file = $PreTargetEvaluationGatePath
        received_at_utc = $targetQueryStartedAt.ToString("o")
        distractor_readback_at_utc = $gateReadbackAt.ToString("o")
        target_query_started_at_utc = $targetQueryStartedAt.ToString("o")
        host_id = [string]$gateDocument.host_id
        target_task_name = [string]$gateDocument.target_task_name
        distractor_task_name = [string]$gateDocument.distractor_task_name
        distractor_event_id = [string]$gateDocument.event_id
        normalized_type = [string]$gateDocument.normalized_type
        distractor_object_key = [string]$gateDocument.object_key
        event_store_readback_complete = [bool]$gateDocument.event_store_readback_complete
        verified = $true
      }
    } else {
      $targetQueryStartedAt = (Get-Date).ToUniversalTime()
    }
    if ($Kind -eq "scheduled_task" -and $DistractorTaskName -and $PreTargetEvaluationGatePath) {
      Write-Host "[$ScenarioId] Capturing a shared probe observation after exact distractor readback"
      $pairedProbeDeadline = (Get-Date).ToUniversalTime().AddSeconds(90)
      $pairedObservation = $null
      do {
        Invoke-ProbeOnce
        $candidatePair = Get-LatestObservation
        $candidateTarget = @(Get-ObservationMatch -Observation $candidatePair -Category $Category `
          -ExpectedKey $ExpectedKey -ObjectName $ObjectName)
        $candidateDistractorKey = "scheduled_task:\$($DistractorTaskName.ToLowerInvariant())"
        $candidateDistractor = @(Get-ObservationMatch -Observation $candidatePair -Category $Category `
          -ExpectedKey $candidateDistractorKey -ObjectName $DistractorTaskName)
        if ($candidatePair.observation_id -ne $after.observation_id -and
          $candidatePair.observed_at -gt $targetQueryStartedAt.ToString("o") -and
          $candidateTarget.Count -gt 0 -and $candidateDistractor.Count -gt 0 -and
          (Test-NativeScheduledTaskPresence -ObjectName $ObjectName) -and
          (Test-NativeScheduledTaskPresence -ObjectName $DistractorTaskName)) {
          $pairedObservation = $candidatePair
          break
        }
        if ((Get-Date).ToUniversalTime() -lt $pairedProbeDeadline) { Start-Sleep -Seconds 2 }
      } while ((Get-Date).ToUniversalTime() -lt $pairedProbeDeadline)
      if (-not $pairedObservation) {
        throw "A fresh probe did not observe both exact scheduled tasks together within 90 seconds."
      }
      $after = $pairedObservation
    }
    $retrievalEnd = (Get-Date).ToUniversalTime()
    $sync = Invoke-BoundedEventRetrieval -ActionStarted $started -ActionEnded $retrievalEnd `
      -ExpectedType $ExpectedType -ExpectedKey $ExpectedKey -ObjectName $ObjectName `
      -ScenarioKind $Kind -DistractorTaskName $DistractorTaskName
    if ($Kind -eq "scheduled_task" -and $DistractorTaskName) {
      $distractorKey = "scheduled_task:\$($DistractorTaskName.ToLowerInvariant())"
      $distractorReadback = @(Get-ExactEvents -ActionStarted $started -ActionEnded $retrievalEnd `
        -ExpectedType "scheduled_task_created" -ExpectedKey $distractorKey `
        -ObjectName $DistractorTaskName -ScenarioKind "scheduled_task")
      $providerIds = @($sync.exact_distractor_event_ids | Sort-Object -Unique)
      $ingestedIds = @($sync.ingested_distractor_event_ids | Sort-Object -Unique)
      $readbackIds = @($distractorReadback | ForEach-Object { $_.event_id } | Sort-Object -Unique)
      $distractorState = @(Get-ObservationMatch -Observation $after -Category $Category `
        -ExpectedKey $distractorKey -ObjectName $DistractorTaskName)
      $distractorPresentAfterCleanup = @(Get-ObservationMatch -Observation $afterCleanup `
        -Category $Category -ExpectedKey $distractorKey -ObjectName $DistractorTaskName).Count -gt 0
      $distractorEventInProbeInterval = $false
      if ($script:distractorLocalEvent -and $beforeObservation.observed_at -and $after.observed_at) {
        $probeStart = [DateTimeOffset]::Parse([string]$beforeObservation.observed_at).UtcDateTime
        $probeEnd = [DateTimeOffset]::Parse([string]$after.observed_at).UtcDateTime
        $distractorTime = [DateTimeOffset]::Parse(
          [string]$script:distractorLocalEvent.event_time_utc
        ).UtcDateTime
        $distractorEventInProbeInterval = $distractorTime -ge $probeStart -and $distractorTime -le $probeEnd
      }
      $distractorEvidence = [ordered]@{
        task_name = $DistractorTaskName
        object_key = $distractorKey
        local_windows_event = $script:distractorLocalEvent
        local_windows_event_search = $script:distractorLocalEventSearch
        probe_observation_id = $after.observation_id
        probe_observed_at = $after.observed_at
        target_and_distractor_observed_same_probe = (
          @(Get-ObservationMatch -Observation $after -Category $Category `
            -ExpectedKey $ExpectedKey -ObjectName $ObjectName).Count -gt 0 -and
          $distractorState.Count -gt 0
        )
        probe_target_items = @(Get-ObservationMatch -Observation $after -Category $Category `
          -ExpectedKey $ExpectedKey -ObjectName $ObjectName)
        probe_distractor_items = $distractorState
        shared_probe_capture = [ordered]@{
          required = [bool]($DistractorAfterSuppressedTarget)
          passed = [bool]$distractorProbePairPassed
          observation_id = if ($distractorProbePairObservation) {
            $distractorProbePairObservation.observation_id
          } else { $null }
          attempts = $distractorProbeAttempts
        }
        state_observed_after_action = ($distractorState.Count -gt 0)
        state_still_present_after_cleanup = $distractorPresentAfterCleanup
        event_inside_before_after_probe_interval = $distractorEventInProbeInterval
        probe_schedule_pause = $script:probeScheduleState
        midtrial_config_restoration = $script:midtrialConfigRestoration
        provider_events = @($sync.exact_distractor_events)
        provider_event_ids = $providerIds
        csg_ingest_event_ids = $ingestedIds
        csg_event_store_readback = $distractorReadback
        csg_event_store_readback_event_ids = $readbackIds
        exact_provider_ingest_readback_match = ($providerIds.Count -eq 1 -and
          $providerIds[0] -in $ingestedIds -and $providerIds[0] -in $readbackIds)
        local_event_present = [bool]$script:distractorLocalEvent
        cleanup_absence_verified = (-not $distractorPresentAfterCleanup)
      }
    }
    if ($Kind -eq "scheduled_task" -and $sync.query_complete -eq $true) {
      $providerExactIds = @($sync.exact_target_event_ids | Sort-Object -Unique)
      $storedExactEvents = @(Get-ExactEvents -ActionStarted $started -ActionEnded $retrievalEnd `
        -ExpectedType $ExpectedType -ExpectedKey $ExpectedKey -ObjectName $ObjectName `
        -ScenarioKind $Kind)
      $storedExactIds = @($storedExactEvents | ForEach-Object { $_.event_id } | Sort-Object -Unique)
      $providerIdentityKeys = @($sync.exact_target_event_identity_keys |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
      $storedIdentityKeys = @($storedExactEvents | ForEach-Object {
        Get-WindowsEventIdentityKey -Event $_
      } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
      $allProviderEventsHaveIdentity = @($sync.exact_target_event_identity_keys).Count -eq
        $providerExactIds.Count -and $providerExactIds.Count -gt 0
      $allStoredEventsHaveIdentity = @($storedExactEvents | Where-Object {
        [string]::IsNullOrWhiteSpace((Get-WindowsEventIdentityKey -Event $_))
      }).Count -eq 0 -and $storedExactEvents.Count -gt 0
      $logicalIdentityReadbackComplete = $allProviderEventsHaveIdentity -and
        $allStoredEventsHaveIdentity -and $providerIdentityKeys.Count -eq 1 -and
        $storedIdentityKeys.Count -eq 1 -and $providerIdentityKeys[0] -eq $storedIdentityKeys[0]
      $rawIdReadbackComplete = $providerExactIds.Count -gt 0 -and
        $providerExactIds.Count -eq $storedExactIds.Count -and
        @($providerExactIds | Where-Object { $_ -notin $storedExactIds }).Count -eq 0
      $eventStoreReadbackComplete = $logicalIdentityReadbackComplete -or
        ($rawIdReadbackComplete -and -not $allProviderEventsHaveIdentity -and
          -not $allStoredEventsHaveIdentity)
      if ($ExpectedEventSuppressed) {
        $eventStoreReadbackComplete = $providerExactIds.Count -eq 0 -and $storedExactIds.Count -eq 0
        $creationReconciliation = [ordered]@{
          validation_mode = "intentional_event_suppression_capture_gate"
          capture_gate_passed = [bool]($sync.query_complete -and
            $sync.coverage_status -eq "COMPLETE" -and $eventStoreReadbackComplete)
          final_reconciliation_deferred = $true
          provider_exact_target_event_ids = $providerExactIds
          provider_logical_event_identity_keys = $providerIdentityKeys
          ingest_post_acknowledged_ids = @($sync.ingested_event_ids)
          event_store_readback_ids = $storedExactIds
          event_store_logical_event_identity_keys = $storedIdentityKeys
          provider_source_references = @($sync.exact_target_event_source_references)
          event_store_source_references = @($storedExactEvents | ForEach-Object {
            $_.source_reference
          })
          event_store_readback_complete = [bool]$eventStoreReadbackComplete
          logical_event_count = if ($logicalIdentityReadbackComplete) { 1 } else { $storedIdentityKeys.Count }
          finalized = $false
          passed = $false
        }
        if (-not $creationReconciliation.capture_gate_passed) {
          throw "Intentional-absence capture gate failed: provider query or exact-target event-store readback was incomplete."
        }
      } else {
        $creationReconciliation = Wait-ForExactTargetCreationReconciliation `
          -ObjectKey $ExpectedKey -ExpectedEventIds $storedExactIds `
          -TimeoutSeconds $ReconciliationWaitSeconds
        if ($creationReconciliation) {
          $creationReconciliation.provider_exact_target_event_ids = $providerExactIds
          $creationReconciliation.provider_logical_event_identity_keys = $providerIdentityKeys
          $creationReconciliation.ingest_post_acknowledged_ids = @($sync.ingested_event_ids)
          $creationReconciliation.event_store_readback_ids = $storedExactIds
          $creationReconciliation.event_store_logical_event_identity_keys = $storedIdentityKeys
          $creationReconciliation.provider_source_references = @($sync.exact_target_event_source_references)
          $creationReconciliation.event_store_source_references = @($storedExactEvents | ForEach-Object {
            $_.source_reference
          })
          $creationReconciliation.event_store_readback_complete = [bool]$eventStoreReadbackComplete
          $creationReconciliation.logical_event_count = if ($logicalIdentityReadbackComplete) { 1 } else { $storedIdentityKeys.Count }
          $creationReconciliation.passed = [bool]($creationReconciliation.passed -and $eventStoreReadbackComplete)
        }
        if (-not $creationReconciliation.passed) {
          throw "The target ADD did not reach finalized exact-event CONSISTENT with complete event-store readback before cleanup."
        }
      }
    }
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
      $cleanupDeadline = (Get-Date).ToUniversalTime().AddSeconds(90)
      do {
        Invoke-ProbeOnce
        $candidateCleanup = Get-LatestObservation
        $cleanupItems = @(Get-ObservationMatch -Observation $candidateCleanup -Category $Category `
          -ExpectedKey $ExpectedKey -ObjectName $ObjectName)
        if ($Kind -eq "scheduled_task") {
          $nativeAfterCleanupPresent = Test-NativeScheduledTaskPresence -ObjectName $ObjectName
        }
        $afterCleanup = $candidateCleanup
        if ($cleanupItems.Count -eq 0 -and
          ($Kind -ne "scheduled_task" -or $nativeAfterCleanupPresent -eq $false)) { break }
        if ((Get-Date).ToUniversalTime() -lt $cleanupDeadline) { Start-Sleep -Seconds 2 }
      } while ((Get-Date).ToUniversalTime() -lt $cleanupDeadline)
    } catch {
      if (-not $errorMessage) { $errorMessage = "cleanup probe failed: $($_.Exception.Message)" }
    }
    try { Restore-ProbeSchedule } catch {
      if (-not $errorMessage) { $errorMessage = "probe schedule restoration failed: $($_.Exception.Message)" }
    }
  }

  if ($null -eq $after) { $after = Get-LatestObservation }
  if ($null -eq $afterCleanup) { $afterCleanup = $after }
  if ($null -eq $ended) { $ended = (Get-Date).ToUniversalTime() }
    $record = Get-ScenarioEvidence -ScenarioId $ScenarioId -Kind $Kind -Category $Category -ObjectName $ObjectName -ExpectedKey $ExpectedKey -ExpectedType $ExpectedType -ActionStarted $started -ActionEnded $ended -BeforeObservation $beforeObservation -AfterObservation $after -AfterCleanupObservation $afterCleanup -NativeBeforePresent $nativeBeforePresent -NativeAfterPresent $nativeAfterPresent -NativeAfterCleanupPresent $nativeAfterCleanupPresent -SyncResponse $sync -CreationReconciliation $creationReconciliation
  if ($record -and $DistractorTaskName) {
    $record.distractor_evidence = $distractorEvidence
    $record.event_plane.collection_expectation = "target_scoped_eventid_4698_suppression"
  }
  if ($record.event_plane) {
    $record.event_plane.pre_target_evaluation_gate = $preTargetEvaluationGate
    $record.event_plane.target_query_started_at_utc = if ($targetQueryStartedAt) {
      $targetQueryStartedAt.ToString("o")
    } else { $null }
  }
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
$taskName = if ($ScheduledTaskName) { $ScheduledTaskName } else {
  "CSGAPTTask$([guid]::NewGuid().ToString('N').Substring(0,10))"
}
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
      -DistractorTaskName $DistractorTaskName `
      -Create {
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c exit 0"
        $triggerAt = if ($DistractorAfterSuppressedTarget) {
          (Get-Date).AddDays(1)
        } else { (Get-Date).AddHours(1) }
        $trigger = New-ScheduledTaskTrigger -Once -At $triggerAt
        if ($DistractorTaskName -and -not $DistractorAfterSuppressedTarget) {
          Register-ScheduledTask -TaskName $DistractorTaskName -TaskPath "\" `
            -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest -Force | Out-Null
          $script:distractorLocalEvent = Wait-ForExactTaskCreationEvent `
            -TaskName $DistractorTaskName -ActionStarted $started
          Unregister-ScheduledTask -TaskName $DistractorTaskName -TaskPath "\" `
            -Confirm:$false -ErrorAction Stop
        }
        Register-ScheduledTask -TaskName $taskName -TaskPath "\" -Action $action `
          -Trigger $trigger -User "SYSTEM" -RunLevel Highest -Force | Out-Null
        if ($DistractorTaskName -and $DistractorAfterSuppressedTarget) {
          $script:midtrialConfigRestoration = Restore-WazuhConfigBeforeDistractor
          $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(1)
          Register-ScheduledTask -TaskName $DistractorTaskName -TaskPath "\" `
            -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest -Force | Out-Null
          $script:distractorLocalEvent = Wait-ForExactTaskCreationEvent `
            -TaskName $DistractorTaskName -ActionStarted $started
        }
      } `
      -Cleanup {
        Unregister-ScheduledTask -TaskName $taskName -TaskPath "\" -Confirm:$false -ErrorAction SilentlyContinue
        if ($DistractorTaskName -and $DistractorAfterSuppressedTarget) {
          Unregister-ScheduledTask -TaskName $DistractorTaskName -TaskPath "\" `
            -Confirm:$false -ErrorAction SilentlyContinue
        }
      }
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
  try { Restore-ProbeSchedule } catch {
    if (-not $errorMessage) { $errorMessage = "probe schedule restoration failed: $($_.Exception.Message)" }
  }
}

$requiredControls = @($scenarios | Where-Object { $_.positive_control.required })
$passedControls = @($requiredControls | Where-Object { $_.positive_control.passed })
$result = [ordered]@{
  schema_version = "csg-windows-behavior-family-live-validation-v7"
  campaign_id = $campaignId
  scenario_filter = $ScenarioFilter
  started_at = $baseline.observed_at
  ended_at = (Get-Date).ToUniversalTime().ToString("o")
  dataset_reference = "Windows-APT 2025 revision 3, used only for behavior-family mapping"
  exact_replication = $false
  status = if ($requiredControls.Count -eq $passedControls.Count -and $requiredControls.Count -gt 0) { "ALL_REQUIRED_POSITIVE_CONTROLS_PASSED" } else { "POSITIVE_CONTROL_GAPS_REMAIN" }
  experiment_condition = if ($ExpectedEventSuppressed) { "scheduled_task_eventid_4698_intentionally_suppressed" } else { "category_positive_control" }
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
