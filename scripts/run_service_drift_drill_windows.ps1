param(
  [string]$CsgApiBase = "http://replace-with-mac-ip:8000",
  [string]$HostId = "win11-arm-lab",
  [string]$ProbePython = "python.exe",
  [string]$ProbeConfig = "",
  [string]$ServiceName = "CSGResearch$([guid]::NewGuid().ToString('N').Substring(0,12))",
  [string]$DistractorServiceName = "",
  [string]$NoChangeServiceName = "Winmgmt",
  [int]$TelemetryWaitSeconds = 20,
  [int]$ProbeObservationTimeoutSeconds = 30,
  [int]$ProbePollIntervalSeconds = 1,
  [string]$OutputPath = "C:\CSG\research-service-drift-result.json",
  [switch]$KeepService,
  [int]$FinalizationWaitSeconds = 960,
  [int]$LifecycleFinalizationWaitSeconds = 75,
  [int]$RecoveryWaitSeconds = 60,
  [int]$ApiTimeoutSeconds = 15,
  [int]$MaximumProtocolWaitOverrunSeconds = 120,
  [string]$ExperimentId = "",
  [string]$TrialId = "",
  [ValidateSet("complete", "complete_distractor", "delayed", "delayed_reconciliation", "telemetry_delay", "source_unavailable", "capture_drop", "no_change", "no_change_distractor", "same_host_distractor", "target_selective_drop", "target_selective_drop_clean")]
  [string]$TelemetryCondition = "complete"
)

$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
  throw "Run this controlled research drill from Administrator PowerShell."
}
if ($ApiTimeoutSeconds -lt 5 -or $ApiTimeoutSeconds -gt 120) {
  throw "ApiTimeoutSeconds must be between 5 and 120."
}

function Invoke-ProbeOnce {
  $requestStartedAt = (Get-Date).ToUniversalTime()
  $previousErrorActionPreference = $ErrorActionPreference
  $previousProbeApiUrl = $env:CSG_PROBE_API_URL
  $previousProbeHostId = $env:CSG_PROBE_HOST_ID
  $probeConfigForInvocation = $ProbeConfig
  $temporaryProbeConfig = $null
  $probeExitCode = 0
  try {
    if ($ProbeConfig) {
      $probeSettings = (Get-Content -Path $ProbeConfig | Out-String) | ConvertFrom-Json
      $probeSettings.CSG_PROBE_API_URL = "$($CsgApiBase.TrimEnd('/'))/api/probe/observations"
      $probeSettings.CSG_PROBE_HOST_ID = $HostId
      $temporaryProbeConfig = Join-Path (Split-Path -Parent $ProbeConfig) (
        "settings-run-$([guid]::NewGuid().ToString('N')).json"
      )
      $probeSettings | ConvertTo-Json -Depth 8 | Set-Content -Path $temporaryProbeConfig -Encoding UTF8
      $probeConfigForInvocation = $temporaryProbeConfig
    } else {
      $env:CSG_PROBE_API_URL = "$($CsgApiBase.TrimEnd('/'))/api/probe/observations"
      $env:CSG_PROBE_HOST_ID = $HostId
    }
    # The probe writes transport counters through its logger. Windows PowerShell can
    # promote native stderr records to terminating errors under Stop, even when the
    # process exits successfully. The exit code remains the authoritative boundary.
    $ErrorActionPreference = "Continue"
    if ($probeConfigForInvocation) {
      & $ProbePython -m cyberstateguardian_probe.main --config $probeConfigForInvocation --once 2>&1 | Out-Null
    } else {
      & $ProbePython -m cyberstateguardian_probe.main --once 2>&1 | Out-Null
    }
    $probeExitCode = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $previousErrorActionPreference
    if (-not $ProbeConfig) {
      if ($null -eq $previousProbeApiUrl) {
        Remove-Item Env:CSG_PROBE_API_URL -ErrorAction SilentlyContinue
      } else {
        $env:CSG_PROBE_API_URL = $previousProbeApiUrl
      }
      if ($null -eq $previousProbeHostId) {
        Remove-Item Env:CSG_PROBE_HOST_ID -ErrorAction SilentlyContinue
      } else {
        $env:CSG_PROBE_HOST_ID = $previousProbeHostId
      }
    }
    if ($temporaryProbeConfig -and (Test-Path -LiteralPath $temporaryProbeConfig)) {
      Remove-Item -LiteralPath $temporaryProbeConfig -Force -ErrorAction SilentlyContinue
    }
  }
  if ($probeExitCode -ne 0) { throw "CSG direct probe failed with exit code $probeExitCode" }
  Start-Sleep -Milliseconds 500
  $observation = Invoke-RestMethod -Method Get -DisableKeepAlive -TimeoutSec $ApiTimeoutSeconds -Uri "$CsgApiBase/api/hosts/$HostId/observations/latest"
  $observation | Add-Member -NotePropertyName csg_request_started_at -NotePropertyValue $requestStartedAt.ToString("o")
  $observation | Add-Member -NotePropertyName csg_observation_received_at -NotePropertyValue ((Get-Date).ToUniversalTime().ToString("o"))
  $observation | Add-Member -NotePropertyName csg_probe_api_url -NotePropertyValue "$($CsgApiBase.TrimEnd('/'))/api/probe/observations"
  return $observation
}

function Get-WazuhServiceProof {
  $command = "Get-Service -Name WazuhSvc"
  try {
    $service = Get-Service -Name WazuhSvc -ErrorAction Stop
    $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction Stop
    return [ordered]@{
      command = $command
      command_exit_code = 0
      status = [string]$service.Status
      start_mode = [string]$cim.StartMode
      process_id = [int]$cim.ProcessId
      service_name = [string]$service.Name
      display_name = [string]$service.DisplayName
      captured_at = (Get-Date).ToUniversalTime().ToString("o")
    }
  } catch {
    return [ordered]@{
      command = $command
      command_exit_code = 1
      status = "UNKNOWN"
      start_mode = "UNKNOWN"
      process_id = $null
      service_name = "WazuhSvc"
      captured_at = (Get-Date).ToUniversalTime().ToString("o")
      error = $_.Exception.Message
    }
  }
}

function Wait-WazuhAgentActive {
  param([int]$TimeoutSeconds = 90)
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $service = Get-WazuhServiceProof
    if ($service.status -eq "Running" -and $service.process_id -gt 0) {
      $health = Get-CsgWazuhHealth
      if ([string]$health.endpoint_agent.status -ieq "active" -and [string]$health.indexer.status -ieq "available") {
        return [ordered]@{ service = $service; health = $health; checked_at = (Get-Date).ToUniversalTime().ToString("o") }
      }
    }
    Start-Sleep -Seconds 2
  } while ((Get-Date) -lt $deadline)
  throw "Wazuh did not return to an active endpoint and available indexer state within $TimeoutSeconds seconds."
}

function Apply-TargetSelectiveSuppression {
  if ($ServiceName -notmatch '^CSGResearch[A-Za-z0-9_-]{1,40}$') {
    throw "Target-selective suppression requires a unique CSGResearch service name."
  }
  $configPath = Join-Path ${env:ProgramFiles(x86)} "ossec-agent\ossec.conf"
  if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    throw "Wazuh agent configuration was not found at the expected path."
  }
  $service = Get-WazuhServiceProof
  if ($service.status -ne "Running" -or $service.process_id -le 0) {
    throw "Target-selective suppression requires WazuhSvc Running with a nonzero PID."
  }

  $backupDirectory = Join-Path $env:ProgramData "CyberStateGuardian\config-backups"
  New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
  $backupPath = Join-Path $backupDirectory "$runId.ossec.conf"
  if (Test-Path -LiteralPath $backupPath) { throw "Refusing to overwrite an existing Wazuh configuration backup." }
  Copy-Item -LiteralPath $configPath -Destination $backupPath
  $originalHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $configPath).Hash.ToLowerInvariant()
  $registryPath = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\$ServiceName"
  $query = "Event[System/EventID != 7040 or EventData/Data[@Name='param1'] != '$ServiceName']"
  $script:targetSuppressionProof = [ordered]@{
    config_path = $configPath
    backup_path = $backupPath
    original_config_sha256 = $originalHash
    system_eventchannel_query = $query
    ignored_registry_path = $registryPath
    status = "APPLYING"
  }
  $temporaryPath = "$configPath.$runId.tmp"
  try {
    $document = New-Object System.Xml.XmlDocument
    $document.PreserveWhitespace = $true
    $document.Load($configPath)
    $systemBlocks = @($document.SelectNodes("/ossec_config/localfile") | Where-Object {
      $_.SelectSingleNode("location") -and $_.SelectSingleNode("location").InnerText -eq "System" -and
      $_.SelectSingleNode("log_format") -and $_.SelectSingleNode("log_format").InnerText -eq "eventchannel"
    })
    if ($systemBlocks.Count -ne 1) { throw "Expected exactly one System eventchannel block; found $($systemBlocks.Count)." }
    if ($systemBlocks[0].SelectSingleNode("query")) { throw "System eventchannel already has a query; refusing to replace existing policy." }
    $queryNode = $document.CreateElement("query")
    $queryNode.InnerText = $query
    [void]$systemBlocks[0].AppendChild($queryNode)

    $syscheckNodes = @($document.SelectNodes("/ossec_config/syscheck"))
    if ($syscheckNodes.Count -ne 1) { throw "Expected exactly one syscheck block; found $($syscheckNodes.Count)." }
    $monitoredServiceTree = @($syscheckNodes[0].SelectNodes("windows_registry") | Where-Object {
      $_.InnerText -eq "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services"
    })
    if ($monitoredServiceTree.Count -ne 1) { throw "The configured Wazuh FIM service-registry route was not uniquely verified." }
    $existingIgnore = @($syscheckNodes[0].SelectNodes("registry_ignore") | Where-Object { $_.InnerText -eq $registryPath })
    if ($existingIgnore.Count -gt 0) { throw "The unique target registry path is already ignored; refusing to claim an active manipulation." }
    $ignoreNode = $document.CreateElement("registry_ignore")
    $ignoreNode.SetAttribute("arch", "both")
    $ignoreNode.InnerText = $registryPath
    [void]$syscheckNodes[0].AppendChild($ignoreNode)

    $document.Save($temporaryPath)
    $checkDocument = New-Object System.Xml.XmlDocument
    $checkDocument.Load($temporaryPath)
    $readbackSystem = @($checkDocument.SelectNodes("/ossec_config/localfile") | Where-Object {
      $_.SelectSingleNode("location") -and $_.SelectSingleNode("location").InnerText -eq "System"
    })
    if ($readbackSystem.Count -ne 1 -or $readbackSystem[0].SelectSingleNode("query").InnerText -ne $query) {
      throw "Saved event-channel suppression query did not pass XML readback."
    }
    if (@($checkDocument.SelectNodes("/ossec_config/syscheck/registry_ignore") | Where-Object { $_.InnerText -eq $registryPath }).Count -eq 0) {
      throw "Saved registry FIM suppression path did not pass XML readback."
    }
    Copy-Item -LiteralPath $temporaryPath -Destination $configPath -Force
    $effectiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $configPath).Hash.ToLowerInvariant()
    $script:targetSuppressionApplied = $true
    Restart-Service -Name WazuhSvc -Force
    $activeProof = Wait-WazuhAgentActive
    $script:wazuhWasRunning = $true
    return [ordered]@{
      status = "APPLIED_AND_HEALTHY"
      scope = "Only System Event 7040 whose param1 equals the randomized target service, plus that exact service's FIM registry key. The agent remains running."
      config_path = $configPath
      original_config_sha256 = $originalHash
      effective_config_sha256 = $effectiveHash
      system_eventchannel_query = $query
      ignored_registry_path = $registryPath
      verified_routes = [ordered]@{ system_eventchannel = $true; services_registry_fim = $true; wazuh_service = $activeProof.service; endpoint_agent = $activeProof.health.endpoint_agent; manager = $activeProof.health.manager; indexer = $activeProof.health.indexer }
      applied_at = (Get-Date).ToUniversalTime().ToString("o")
      backup_path = $backupPath
    }
  } catch {
    if ((Test-Path -LiteralPath $backupPath) -and (Test-Path -LiteralPath $configPath)) {
      Copy-Item -LiteralPath $backupPath -Destination $configPath -Force
      Restart-Service -Name WazuhSvc -Force -ErrorAction SilentlyContinue
      $restoredHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $configPath).Hash.ToLowerInvariant()
      if ($restoredHash -eq $originalHash) {
        $script:targetSuppressionApplied = $false
        Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
      }
    }
    throw
  } finally {
    if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue }
  }
}

function Restore-TargetSelectiveSuppression {
  if (-not $script:targetSuppressionApplied) { return $script:targetSuppressionProof }
  $configPath = [string]$script:targetSuppressionProof.config_path
  $backupPath = [string]$script:targetSuppressionProof.backup_path
  Copy-Item -LiteralPath $backupPath -Destination $configPath -Force
  $restoredHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $configPath).Hash.ToLowerInvariant()
  if ($restoredHash -ne $script:targetSuppressionProof.original_config_sha256) {
    throw "Restored Wazuh configuration hash does not match the pre-trial hash."
  }
  Restart-Service -Name WazuhSvc -Force
  $activeProof = Wait-WazuhAgentActive
  Remove-Item -LiteralPath $backupPath -Force
  $script:targetSuppressionApplied = $false
  $script:targetSuppressionProof.restoration = [ordered]@{
    status = "RESTORED_AND_HEALTHY"
    restored_config_sha256 = $restoredHash
    service = $activeProof.service
    endpoint_agent = $activeProof.health.endpoint_agent
    manager = $activeProof.health.manager
    indexer = $activeProof.health.indexer
    restored_at = (Get-Date).ToUniversalTime().ToString("o")
  }
  return $script:targetSuppressionProof
}

function Stop-WazuhServiceAndWait {
  param([int]$TimeoutSeconds = 45)
  $before = Get-WazuhServiceProof
  if ($before.status -ne "Running") {
    throw "WazuhSvc must be Running before a controlled stop; observed $($before.status)."
  }

  $requestedAt = (Get-Date).ToUniversalTime().ToString("o")
  & sc.exe stop WazuhSvc | Out-Null
  $controlExitCode = $LASTEXITCODE

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $proof = Get-WazuhServiceProof
    if ($proof.status -eq "Stopped" -and $proof.process_id -eq 0) {
      if ($controlExitCode -notin @(0, 1053)) {
        throw "sc.exe stop WazuhSvc returned exit code $controlExitCode despite a stopped-state observation."
      }
      $proof.control_command = "sc.exe stop WazuhSvc"
      $proof.control_command_exit_code = $controlExitCode
      $proof.control_command_interpretation = if ($controlExitCode -eq 0) {
        "success"
      } else {
        "timeout_but_stopped_state_verified"
      }
      $proof.stop_requested_at = $requestedAt
      return $proof
    }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)

  throw "sc.exe stop WazuhSvc did not reach Stopped/PID 0 within $TimeoutSeconds seconds."
}

function Get-ObservedService {
  param([object]$Observation)
  if ($null -eq $Observation) { return $null }
  $items = @($Observation.categories.service.items)
  return @($items | Where-Object {
    $_.object_key -eq "service:$($ServiceName.ToLower())" -or
    $_.service_name -eq $ServiceName
  }) | Select-Object -First 1
}

function Wait-ObservedService {
  param(
    [object]$InitialObservation,
    [string]$ExpectedStartMode,
    [int]$TimeoutSeconds = $ProbeObservationTimeoutSeconds
  )
  $attempts = @()
  $observation = $InitialObservation
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $service = Get-ObservedService -Observation $observation
    $modeMatches = $service -and ([string]$service.start_mode -ieq $ExpectedStartMode)
    $attempts += [ordered]@{
      observation_id = $observation.observation_id
      requested_at = $observation.csg_request_started_at
      received_at = $observation.csg_observation_received_at
      probe_api_url = $observation.csg_probe_api_url
      observed_at = $observation.observed_at
      service_present = [bool]$service
      observed_start_mode = if ($service) { [string]$service.start_mode } else { $null }
      expected_start_mode = $ExpectedStartMode
      matched = [bool]$modeMatches
    }
    if ($modeMatches) {
      return [pscustomobject]@{ observation = $observation; service = $service; attempts = $attempts }
    }
    if ((Get-Date) -ge $deadline) { break }
    Start-Sleep -Seconds $ProbePollIntervalSeconds
    $observation = Invoke-ProbeOnce
  } while ((Get-Date) -lt $deadline)
  throw "Probe did not observe $ServiceName with start mode '$ExpectedStartMode' within $TimeoutSeconds seconds. Attempts: $($attempts.Count)."
}

function Get-TargetStateDeltas {
  $response = Invoke-RestMethod -Method Get -DisableKeepAlive -TimeoutSec $ApiTimeoutSeconds -Uri "$CsgApiBase/api/hosts/$HostId/deltas?limit=500"
  $expectedKey = "service:$($ServiceName.ToLower())"
  return @($response | Where-Object {
    $_.category -eq "service" -and $_.object_key -eq $expectedKey
  })
}

function Test-WazuhServiceEventIdentity {
  param([object]$Event, [string]$ExpectedName)
  $expectedKey = "service:$($ExpectedName.ToLowerInvariant())"
  return ($Event.target.key -eq $expectedKey -or $Event.attributes.service_name -eq $ExpectedName)
}

function Invoke-ProviderSync {
  $requestStartedAt = (Get-Date).ToUniversalTime()
  $start = $experimentStartedAt.AddMinutes(-2).ToString("o")
  $end = (Get-Date).ToUniversalTime().AddMinutes(2).ToString("o")
  $observation = Invoke-RestMethod -Method Get -DisableKeepAlive -TimeoutSec 90 -Uri (
    "$CsgApiBase/api/hosts/$HostId/provider-event-observation?start=$([uri]::EscapeDataString($start))" +
    "&end=$([uri]::EscapeDataString($end))"
  )
  $candidateEvents = @($observation.events)
  $targetEvents = @($candidateEvents | Where-Object {
    $_.host_id -eq $HostId -and $_.source -eq "wazuh" -and
    $_.normalized_type -in @("service_created", "service_modified") -and
    (Test-WazuhServiceEventIdentity -Event $_ -ExpectedName $ServiceName)
  })
  $distractorEvents = @()
  if ($hasDistractor) {
    $distractorEvents = @($candidateEvents | Where-Object {
      $_.host_id -eq $HostId -and $_.source -eq "wazuh" -and
      $_.normalized_type -in @("service_created", "service_modified") -and
      (Test-WazuhServiceEventIdentity -Event $_ -ExpectedName $distractorServiceName)
    })
  }
  $exactEvents = @($targetEvents) + @($distractorEvents)
  $affectedObjectKeys = @("service:$($ServiceName.ToLowerInvariant())")
  if ($hasDistractor) {
    $affectedObjectKeys += "service:$($distractorServiceName.ToLowerInvariant())"
  }
  $newEvents = @($exactEvents | Where-Object { -not $script:ingestedEventIds.ContainsKey($_.event_id) })
  $ingestedEvents = @()
  if ($newEvents.Count -gt 0) {
    $body = ConvertTo-Json -InputObject $newEvents -Depth 30 -Compress
    $ingestedEvents = @(Invoke-RestMethod -Method Post -DisableKeepAlive -TimeoutSec 90 `
      -Uri "$CsgApiBase/api/events" -ContentType "application/json" -Body $body)
    foreach ($event in $newEvents) { $script:ingestedEventIds[$event.event_id] = $true }
  }
  $ingestedIds = @($ingestedEvents | ForEach-Object { $_.event_id })
  $wazuhServiceProof = Get-WazuhServiceProof
  $wazuhHealth = Get-CsgWazuhHealth
  $agentStatus = [string]$wazuhHealth.endpoint_agent.status
  $endpointCollectionStatus = if (
    $wazuhServiceProof.status -ne "Running" -or $agentStatus -eq "disconnected"
  ) {
    "UNAVAILABLE"
  } elseif ($agentStatus -eq "active") {
    "AVAILABLE"
  } else {
    "UNKNOWN"
  }
  $transportStatus = if ($agentStatus -eq "disconnected") {
    "UNAVAILABLE"
  } else {
    [string]$observation.transport_status
  }
  $eventObservationPayload = [ordered]@{
    events = @($exactEvents)
    query_complete = [bool]$observation.query_complete
    endpoint_collection_status = $endpointCollectionStatus
    transport_status = $transportStatus
    index_status = [string]$observation.index_status
    coverage_status = [string]$observation.coverage_status
    retrieval_pages = [int]$observation.retrieval_pages
    retrieved_count = [int]$observation.retrieved_count
    total_hits = $observation.total_hits
    metadata = [ordered]@{
      query_start = $start
      query_end = $end
      source_health_checked_at = $wazuhHealth.checked_at
      affected_object_keys = $affectedObjectKeys
      source_degradation_interval = if (
      $TelemetryCondition -eq "capture_drop" -and $captureDropActive -and
        $captureDropProof.during_drop.status -eq "Stopped"
      ) {
        [ordered]@{
          start = $captureDropProof.during_drop.captured_at
          end = $wazuhHealth.checked_at
          proof = "Get-Service WazuhSvc reported Stopped/PID 0 through the bounded pre-restore query"
        }
      } else { $null }
      endpoint_agent_status = $agentStatus
      wazuh_service_proof = $wazuhServiceProof
      provider_metadata = $observation.metadata
    }
  }
  $observationBody = ConvertTo-Json -InputObject $eventObservationPayload -Depth 30 -Compress
  $reconciliationObservation = Invoke-RestMethod -Method Post -DisableKeepAlive -TimeoutSec 90 `
    -Uri "$CsgApiBase/api/hosts/$HostId/event-observations" `
    -ContentType "application/json" -Body $observationBody
  return [ordered]@{
    retrieval_mode = "bounded_wazuh_provider_query"
    request_started_at = $requestStartedAt.ToString("o")
    response_received_at = (Get-Date).ToUniversalTime().ToString("o")
    query_start = $start
    query_end = $end
    query_complete = $observation.query_complete
    endpoint_collection_status = $observation.endpoint_collection_status
    transport_status = $observation.transport_status
    index_status = $observation.index_status
    coverage_status = $observation.coverage_status
    retrieval_pages = $observation.retrieval_pages
    retrieved_count = $observation.retrieved_count
    total_hits = $observation.total_hits
    candidate_count = $candidateEvents.Count
    exact_target_event_ids = @($targetEvents | ForEach-Object { $_.event_id })
    exact_distractor_event_ids = @($distractorEvents | ForEach-Object { $_.event_id })
    newly_ingested_target_event_ids = @($targetEvents | Where-Object { $_.event_id -in $ingestedIds } | ForEach-Object { $_.event_id })
    newly_ingested_distractor_event_ids = @($distractorEvents | Where-Object { $_.event_id -in $ingestedIds } | ForEach-Object { $_.event_id })
    newly_ingested_event_ids = $ingestedIds
    reconciliation_observation = $reconciliationObservation
    provider_metadata = $observation.metadata
  }
}

function Get-CsgResearchFindings {
  $all = @(Get-CsgHostFindings)
  return @($all | Where-Object { $_.object_key -eq "service:$($ServiceName.ToLower())" })
}

function Get-CsgHostFindings {
  $response = Invoke-RestMethod -Method Get -DisableKeepAlive -TimeoutSec $ApiTimeoutSeconds -Uri "$CsgApiBase/api/findings?host_id=$HostId&limit=500"
  if ($null -eq $response) { return @() }
  return @($response | ForEach-Object { $_ })
}

function Get-ExactWazuhServiceEvidence {
  param([string]$ExpectedType, [string]$EvidenceServiceName = $ServiceName)
  $start = $experimentStartedAt.AddMinutes(-2).ToString("o")
  $end = (Get-Date).ToUniversalTime().AddMinutes(2).ToString("o")
  $objectKey = "service:$($EvidenceServiceName.ToLowerInvariant())"
  $events = Invoke-RestMethod -Method Get -DisableKeepAlive -TimeoutSec $ApiTimeoutSeconds -Uri (
    "$CsgApiBase/api/hosts/$HostId/events?start=$([uri]::EscapeDataString($start))" +
    "&end=$([uri]::EscapeDataString($end))" +
    "&normalized_type=$([uri]::EscapeDataString($ExpectedType))" +
    "&source=wazuh" +
    "&object_key=$([uri]::EscapeDataString($objectKey))" +
    "&object_name=$([uri]::EscapeDataString($EvidenceServiceName))" +
    "&limit=500"
  )
  return @($events | Where-Object {
    $_.source -eq "wazuh" -and
    $_.normalized_type -eq $ExpectedType -and
    (($_.target.key -eq $objectKey) -or ($_.attributes.service_name -eq $EvidenceServiceName))
  } | ForEach-Object {
    [ordered]@{
      event_id = $_.event_id
      event_time = $_.event_time
      normalized_type = $_.normalized_type
      source = $_.source
      host_id = $_.host_id
      service_name = $_.attributes.service_name
      reported_service_name = $_.attributes.reported_service_name
      target_key = $_.target.key
      old_start_mode = $_.attributes.old_start_mode
      new_start_mode = $_.attributes.new_start_mode
      binary_path = $_.attributes.binary_path
      account = $_.attributes.account
      actor = $_.actor
      target = $_.target
      attributes = $_.attributes
      source_reference = $_.source_reference
      metadata = $_.metadata
      retrieved_at = (Get-Date).ToUniversalTime().ToString("o")
    }
  })
}

function Get-WindowsServiceEventEvidence {
  param(
    [string]$EvidenceServiceName = $ServiceName,
    [datetime]$StartTime = (Get-Date).AddHours(-1),
    [datetime]$EndTime = (Get-Date)
  )
  $query = [ordered]@{
    log_name = "System"
    event_ids = @(7040, 7045)
    start_time = $StartTime.ToUniversalTime().ToString("o")
    end_time = $EndTime.ToUniversalTime().ToString("o")
    exact_service_name = $EvidenceServiceName
  }
  # Get-WinEvent interprets FilterHashtable DateTime bounds as local wall time.
  # Keep the archived bounds in UTC, but pass explicitly local bounds to the cmdlet.
  $localStartTime = $StartTime.ToUniversalTime().ToLocalTime()
  $localEndTime = $EndTime.ToUniversalTime().ToLocalTime()
  try {
    $events = @(
      Get-WinEvent -FilterHashtable @{
        LogName = "System"
        Id = @(7040, 7045)
        StartTime = $localStartTime
        EndTime = $localEndTime
      } -ErrorAction Stop | Where-Object {
        $_.Message -and $_.Message.IndexOf($EvidenceServiceName, [StringComparison]::OrdinalIgnoreCase) -ge 0
      }
    )
    return [ordered]@{
      query_status = "SUCCEEDED"
      query = $query
      exact_event_count = $events.Count
      events = @($events | ForEach-Object {
        [ordered]@{
          log_name = $_.LogName
          provider = $_.ProviderName
          event_id = [int]$_.Id
          record_id = [long]$_.RecordId
          event_time = $_.TimeCreated.ToUniversalTime().ToString("o")
          machine_name = $_.MachineName
          message = $_.Message
          raw_xml = $_.ToXml()
        }
      })
    }
  } catch {
    if ($_.FullyQualifiedErrorId -like "*NoMatchingEventsFound*") {
      return [ordered]@{
        query_status = "SUCCEEDED"
        query = $query
        exact_event_count = 0
        events = @()
      }
    }
    return [ordered]@{
      query_status = "FAILED"
      query = $query
      exact_event_count = 0
      events = @()
      error = $_.Exception.Message
    }
  }
}

function Get-CsgWazuhHealth {
  try {
    $health = Invoke-RestMethod -Method Get -DisableKeepAlive -TimeoutSec $ApiTimeoutSeconds -Uri "$CsgApiBase/api/wazuh/status"
    $agent = @($health.agents | Where-Object { $_.name -eq $HostId }) | Select-Object -First 1
    return [ordered]@{
      query_status = "SUCCEEDED"
      checked_at = (Get-Date).ToUniversalTime().ToString("o")
      manager = [ordered]@{ status = if ($health.server_api.ok) { "AVAILABLE" } else { "UNAVAILABLE" }; details = $health.server_api }
      indexer = [ordered]@{ status = if ($health.indexer.ok) { "AVAILABLE" } else { "UNAVAILABLE" }; details = $health.indexer }
      endpoint_agent = [ordered]@{
        status = if ($agent) { [string]$agent.status } else { "NOT_REPORTED" }
        details = $agent
      }
    }
  } catch {
    return [ordered]@{
      query_status = "FAILED"
      checked_at = (Get-Date).ToUniversalTime().ToString("o")
      manager = [ordered]@{ status = "UNKNOWN" }
      indexer = [ordered]@{ status = "UNKNOWN" }
      endpoint_agent = [ordered]@{ status = "UNKNOWN" }
      error = $_.Exception.Message
    }
  }
}

function Wait-ResearchInterval {
  param([int]$Seconds, [string]$Phase)
  $startedAtUtc = [DateTimeOffset]::UtcNow
  $startedTick = [Diagnostics.Stopwatch]::GetTimestamp()
  $previousBeatUtc = $startedAtUtc
  $maximumHeartbeatGapSeconds = 0.0
  $heartbeatPath = "$OutputPath.heartbeat.jsonl"
  $heartbeatLimit = $startedAtUtc.AddSeconds($Seconds)
  while ([DateTimeOffset]::UtcNow -lt $heartbeatLimit) {
    Start-Sleep -Seconds 5
    $nowUtc = [DateTimeOffset]::UtcNow
    $gap = ($nowUtc - $previousBeatUtc).TotalSeconds
    if ($gap -gt $maximumHeartbeatGapSeconds) { $maximumHeartbeatGapSeconds = $gap }
    $monotonicSeconds = ([Diagnostics.Stopwatch]::GetTimestamp() - $startedTick) / [Diagnostics.Stopwatch]::Frequency
    [ordered]@{
      phase = $Phase
      at = $nowUtc.ToString("o")
      elapsed_wall_seconds = ($nowUtc - $startedAtUtc).TotalSeconds
      elapsed_monotonic_seconds = $monotonicSeconds
      gap_since_prior_heartbeat_seconds = $gap
    } | ConvertTo-Json -Compress | Add-Content -Path $heartbeatPath -Encoding UTF8
    $previousBeatUtc = $nowUtc
  }
  $endedAtUtc = [DateTimeOffset]::UtcNow
  $endedTick = [Diagnostics.Stopwatch]::GetTimestamp()
  $wallSeconds = ($endedAtUtc - $startedAtUtc).TotalSeconds
  $monotonicSeconds = ($endedTick - $startedTick) / [Diagnostics.Stopwatch]::Frequency
  $finalGap = ($endedAtUtc - $previousBeatUtc).TotalSeconds
  if ($finalGap -gt $maximumHeartbeatGapSeconds) { $maximumHeartbeatGapSeconds = $finalGap }
  $clockDivergence = [Math]::Abs($wallSeconds - $monotonicSeconds)
  $adherent = $wallSeconds -le ($Seconds + $MaximumProtocolWaitOverrunSeconds) -and
    $maximumHeartbeatGapSeconds -le 30 -and $clockDivergence -le 30
  [ordered]@{
    phase = $Phase
    scheduled_seconds = $Seconds
    started_at = $startedAtUtc.ToString("o")
    ended_at = $endedAtUtc.ToString("o")
    wall_elapsed_seconds = $wallSeconds
    monotonic_elapsed_seconds = $monotonicSeconds
    maximum_heartbeat_gap_seconds = $maximumHeartbeatGapSeconds
    wall_monotonic_divergence_seconds = $clockDivergence
    heartbeat_path = $heartbeatPath
    protocol_adherent = [bool]$adherent
  }
}

function Get-ServiceComparisonState {
  param([object]$Service)
  if ($null -eq $Service) { return $null }
  return [ordered]@{
    object_key = $Service.object_key
    service_name = $Service.service_name
    start_mode = $Service.start_mode
    binary_path = $Service.binary_path
    account = $Service.account
    status = $Service.status
  }
}

function Get-IndependentWindowsServiceState {
  param([string]$Name = $ServiceName)
  $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
  if (-not $service) { return $null }
  return [ordered]@{
    service_name = [string]$service.Name
    display_name = [string]$service.DisplayName
    status = [string]$service.State
    start_mode = [string]$service.StartMode
    binary_path = [string]$service.PathName
    account = [string]$service.StartName
    process_id = [int]$service.ProcessId
    captured_at = (Get-Date).ToUniversalTime().ToString("o")
    source = "Get-CimInstance Win32_Service on endpoint"
  }
}

function Get-ResearchSnapshot {
  param([string]$Phase)

  $snapshotFindings = @(Get-CsgResearchFindings)
  $hostFindings = @(Get-CsgHostFindings)
  $snapshotReconciliations = [pscustomobject]@{}
  $captureErrors = @()
  foreach ($finding in $snapshotFindings) {
    $findingId = [string]$finding.finding_id
    try {
      $history = @(
        Invoke-RestMethod `
          -Method Get `
          -DisableKeepAlive `
          -Uri "$CsgApiBase/api/findings/$findingId/reconciliations"
      )
      $snapshotReconciliations | Add-Member -NotePropertyName $findingId -NotePropertyValue $history
    } catch {
      $captureErrors += [pscustomobject]@{
        finding_id = $findingId
        error = $_.Exception.Message
        captured_at = (Get-Date).ToUniversalTime().ToString("o")
      }
      $snapshotReconciliations | Add-Member -NotePropertyName $findingId -NotePropertyValue @()
    }
  }
  $createdEvidence = @(Get-ExactWazuhServiceEvidence -ExpectedType "service_created")
  $modifiedEvidence = @(Get-ExactWazuhServiceEvidence -ExpectedType "service_modified")
  $addDistractorEvidence = @()
  if ($hasDistractor) {
    $addDistractorEvidence = @(Get-ExactWazuhServiceEvidence -ExpectedType "service_created" -EvidenceServiceName $distractorServiceName)
    $modifyDistractorEvidence = @(Get-ExactWazuhServiceEvidence -ExpectedType "service_modified" -EvidenceServiceName $distractorServiceName)
  } else {
    $modifyDistractorEvidence = @()
  }
  $targetDeltas = @(Get-TargetStateDeltas)
  $wazuhProof = Get-WazuhServiceProof
  $wazuhHealth = Get-CsgWazuhHealth
  $transitionEventStatus = [ordered]@{
    ADD = if ($createdEvidence.Count -gt 0) { "PRESENT" } else { "ABSENT" }
    MODIFY = if ($modifiedEvidence.Count -gt 0) { "PRESENT" } else { "ABSENT" }
  }
  $transitionStatuses = @($transitionEventStatus.Values)
  $expectedEventStatus = if ($transitionStatuses -contains "PRESENT" -and $transitionStatuses -contains "ABSENT") {
    "PARTIAL"
  } elseif ($transitionStatuses -contains "PRESENT") {
    "PRESENT"
  } else {
    "ABSENT"
  }

  return [ordered]@{
    phase = $Phase
    captured_at = (Get-Date).ToUniversalTime().ToString("o")
    findings = $snapshotFindings
    host_findings = $hostFindings
    target_state_deltas = $targetDeltas
    verified_distractor_wazuh_evidence = [ordered]@{
      service_name = if ($hasDistractor) { $distractorServiceName } else { $null }
      service_created = $addDistractorEvidence
      service_modified = $modifyDistractorEvidence
      exact_create_count = $addDistractorEvidence.Count
      exact_modify_count = $modifyDistractorEvidence.Count
      host_id = $HostId
      role = "same-host wrong-object evidence; it must not reconcile the randomized target service"
    }
    reconciliation_histories = $snapshotReconciliations
    capture_errors = $captureErrors
    verified_exact_wazuh_evidence = [ordered]@{
      rule = "same host + expected normalized type + exact internal service name or exact target key"
      service_key = "service:$($ServiceName.ToLower())"
      service_name = $ServiceName
      service_created = $createdEvidence
      service_modified = $modifiedEvidence
      exact_create_count = $createdEvidence.Count
      exact_modify_count = $modifiedEvidence.Count
    }
    event_plane_status = [ordered]@{
      event_query_status = "SUCCEEDED"
      event_query_scope = "CSG database event query; query completion is not proof of endpoint collection completeness"
      event_query_completed_at = (Get-Date).ToUniversalTime().ToString("o")
      endpoint_service_status = [string]$wazuhProof.status
      endpoint_collection_status = [string]$wazuhHealth.endpoint_agent.status
      endpoint_collection_status_source = "Windows Get-Service WazuhSvc proof"
      coverage_status = if ($wazuhProof.status -eq "Running") { "UNKNOWN" } else { "UNAVAILABLE" }
      manager_status = [string]$wazuhHealth.manager.status
      indexer_status = [string]$wazuhHealth.indexer.status
      indexer_health_checked_at = $wazuhHealth.checked_at
      indexer_health_source = "GET /api/wazuh/status"
      expected_event_status = $expectedEventStatus
      expected_events = [ordered]@{
        service_created = $transitionEventStatus.ADD
        service_modified = $transitionEventStatus.MODIFY
      }
      transition_event_status = $transitionEventStatus
    }
    provider_health = $wazuhHealth
    artifact_scope = [ordered]@{
      host_findings = "host-wide historical findings returned by the CSG API"
      findings = "target-scoped findings for the randomized service object"
      exact_evidence = "target-scoped Wazuh events matched by host, normalized type, and exact service identity"
    }
    wazuh_service_proof = $wazuhProof
  }
}

function Get-BoundedDistractorSnapshot {
  param([string]$Phase)

  # Finalize expired findings from local CSG data only; Wazuh stays stopped until
  # the bounded snapshot has been archived.
  $localFinalization = Invoke-RestMethod -Method Post -DisableKeepAlive -TimeoutSec $ApiTimeoutSeconds `
    -Uri "$CsgApiBase/api/pipeline/process-backlog"
  $findings = @(Get-CsgResearchFindings)
  $histories = [pscustomobject]@{}
  foreach ($finding in $findings) {
    $history = Invoke-RestMethod -Method Get -DisableKeepAlive -TimeoutSec $ApiTimeoutSeconds `
      -Uri "$CsgApiBase/api/findings/$($finding.finding_id)/reconciliations"
    $histories | Add-Member -NotePropertyName ([string]$finding.finding_id) -NotePropertyValue $history
  }
  # The target name is generated after the exact distractor was indexed; while
  # WazuhSvc is stopped, no target event can have been delivered to the manager.
  $targetCreated = @()
  $targetModified = @()
  $distractorCreated = @($sameHostDistractorProof.distractor_event)

  return [ordered]@{
    phase = $Phase
    captured_at = (Get-Date).ToUniversalTime().ToString("o")
    local_reconciliation_finalization = $localFinalization
    findings = $findings
    target_state_deltas = @(Get-TargetStateDeltas)
    reconciliation_histories = $histories
    verified_exact_wazuh_evidence = [ordered]@{
      service_key = "service:$($ServiceName.ToLower())"
      service_name = $ServiceName
      service_created = $targetCreated
      service_modified = $targetModified
      exact_create_count = $targetCreated.Count
      exact_modify_count = $targetModified.Count
    }
    verified_distractor_wazuh_evidence = [ordered]@{
      service_name = $distractorServiceName
      service_created = $distractorCreated
      exact_create_count = $distractorCreated.Count
      host_id = $HostId
      role = "same-host wrong-object event; it must not reconcile the target service"
    }
    wazuh_service_proof = Get-WazuhServiceProof
  }
}

function Suspend-ProbeSchedule {
  $probeTask = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction SilentlyContinue
  if (-not $probeTask) {
    $probeTaskProof.status = "not_installed"
    return
  }

  $probeTaskProof.before = [string]$probeTask.State
  $probeTaskProof.enabled_before = [bool]$probeTask.Settings.Enabled
  $script:probeTaskWasEnabled = [bool]$probeTask.Settings.Enabled
  $script:probeTaskWasRunning = ([string]$probeTask.State -eq "Running")
  if ($script:probeTaskWasEnabled) {
    $script:probeTaskDisabledByDrill = $true
    Disable-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction Stop | Out-Null
  }
  if ($script:probeTaskWasRunning) {
    Stop-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction Stop
  }

  $taskDeadline = (Get-Date).AddSeconds(30)
  do {
    $probeTask = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction Stop
    if ([string]$probeTask.State -ne "Running") { break }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $taskDeadline)
  if ([string]$probeTask.State -eq "Running") {
    throw "The periodic CSG probe task did not stop within 30 seconds."
  }
  $probeTaskProof.during_trial = [string]$probeTask.State
  $probeTaskProof.enabled_during_trial = [bool]$probeTask.Settings.Enabled
}

function Restore-ProbeSchedule {
  if ($script:probeTaskDisabledByDrill) {
    Enable-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction Stop | Out-Null
    $script:probeTaskDisabledByDrill = $false
  }
  if ($script:probeTaskWasRunning) {
    Start-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction Stop
    $script:probeTaskWasRunning = $false
  }
  $probeTask = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction SilentlyContinue
  if ($probeTask) {
    $probeTaskProof.after = [string]$probeTask.State
    $probeTaskProof.enabled_after = [bool]$probeTask.Settings.Enabled
    $probeTaskProof.restored_at = (Get-Date).ToUniversalTime().ToString("o")
  }
}

$runId = [guid]::NewGuid().ToString()
$startedAt = (Get-Date).ToUniversalTime().ToString("o")
$experimentStartedAt = (Get-Date).ToUniversalTime()
$isNoChange = $TelemetryCondition -in @("no_change", "no_change_distractor")
$isTargetSelectiveDrop = $TelemetryCondition -in @("target_selective_drop", "target_selective_drop_clean")
$hasDistractor = $TelemetryCondition -in @(
  "same_host_distractor",
  "target_selective_drop",
  "complete_distractor",
  "no_change_distractor"
)
$script:ingestedEventIds = @{}
$timeline = @()
$createdByDrill = $false
$distractorCreatedByDrill = $false
$distractorServiceName = if ($DistractorServiceName) {
  $DistractorServiceName
} else {
  "CSGDistractor$([guid]::NewGuid().ToString('N').Substring(0,10))"
}
$targetSuppressionApplied = $false
$targetSuppressionProof = [ordered]@{}
$probeTaskWasRunning = $false
$probeTaskWasEnabled = $false
$probeTaskDisabledByDrill = $false
$probeTaskProof = [ordered]@{}
$wazuhWasRunning = $false
$captureDropActive = $false
$captureDropFinalizedSnapshot = $null
$captureDropRecoverySnapshot = $null
$captureDropProof = [ordered]@{}
$sameHostDistractorProof = [ordered]@{}
$noChangeDistractorProof = [ordered]@{}
$sameHostDistractorAddBoundedSnapshot = $null
$sameHostDistractorRecoverySnapshot = $null
$telemetryDelayActive = $false
$telemetryDelayProof = [ordered]@{}
$baselineObservation = $null
$afterCreateObservation = $null
$afterModifyObservation = $null
$afterCleanupObservation = $null
$serviceCreatedAt = $null
$serviceModifiedAt = $null
$serviceCleanupAt = $null
$createCommandStartedAt = $null
$createCommandCompletedAt = $null
$modifyCommandStartedAt = $null
$modifyCommandCompletedAt = $null
$cleanupCommandStartedAt = $null
$cleanupCommandCompletedAt = $null
$experimentId = if ($ExperimentId) { $ExperimentId } else { "service-drift-$runId" }
$trialId = if ($TrialId) { $TrialId } else { $runId }
$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
  New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}
if (Test-Path -LiteralPath $OutputPath) { throw "Refusing to overwrite existing result artifact: $OutputPath" }
$heartbeatArtifactPath = "$OutputPath.heartbeat.jsonl"
if (Test-Path -LiteralPath $heartbeatArtifactPath) { throw "Refusing to overwrite existing heartbeat artifact: $heartbeatArtifactPath" }
$captureDropWaitProof = $null
$baselineTargetState = $null
$baselineIndependentServiceState = $null
$createIndependentServiceState = $null
$modifyIndependentServiceState = $null
$cleanupIndependentServiceState = $null
$createCommandExitCode = $null
$modifyCommandExitCode = $null
$cleanupCommandExitCode = $null
$baselineTargetDeltaIds = @()
$baselineTargetFindingIds = @()
if (-not $ProbeConfig) {
  $probeInstallRoot = Join-Path $env:ProgramFiles "CyberStateGuardian\Probe"
  $installedConfig = Join-Path $probeInstallRoot "settings.json"
  $installedPython = Join-Path $probeInstallRoot "venv\Scripts\python.exe"
  if (Test-Path -LiteralPath $installedConfig -PathType Leaf) {
    $ProbeConfig = $installedConfig
    if ($ProbePython -eq "python.exe" -and (Test-Path -LiteralPath $installedPython -PathType Leaf)) {
      $ProbePython = $installedPython
    }
  }
}
if ($ProbeConfig) {
  # Windows PowerShell 2/3 does not expose Get-Content -Raw.
  $probeSettings = (Get-Content -Path $ProbeConfig | Out-String) | ConvertFrom-Json
  if ($probeSettings.CSG_PROBE_HOST_ID -ne $HostId) {
    throw "Drill HostId must match the native probe configuration."
  }
} elseif ($env:CSG_PROBE_HOST_ID -ne $HostId) {
  throw "Set CSG_PROBE_HOST_ID to the drill HostId or supply -ProbeConfig."
}
if ($isNoChange) {
  $ServiceName = $NoChangeServiceName
  if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    throw "The no-change target service '$ServiceName' must already exist."
  }
} else {
  if ($ServiceName -notmatch '^CSGResearch[A-Za-z0-9_-]{1,40}$') {
    throw "Use a unique service name starting with CSGResearch."
  }
  if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service $ServiceName already exists. This drill will not modify or delete it."
  }
}
if ($hasDistractor) {
  if ($distractorServiceName -notmatch '^CSGDistractor[A-Za-z0-9_-]{1,40}$') {
    throw "Use a unique distractor service name starting with CSGDistractor."
  }
  if ($distractorServiceName -ieq $ServiceName -or
      (Get-Service -Name $distractorServiceName -ErrorAction SilentlyContinue)) {
    throw "The distractor service name must be distinct and absent before the trial."
  }
}

try {
  Suspend-ProbeSchedule
  if ($isTargetSelectiveDrop) {
    Write-Host "[0/6] Applying target-scoped Wazuh suppression while preserving collection health..."
    $targetSuppressionProof = Apply-TargetSelectiveSuppression
    $script:targetSuppressionProof = $targetSuppressionProof
    $timeline += @{
      phase = "target_selective_suppression_applied"
      at = $targetSuppressionProof.applied_at
      config_sha256 = $targetSuppressionProof.effective_config_sha256
      wazuh_service = $targetSuppressionProof.verified_routes.wazuh_service
      endpoint_agent_status = $targetSuppressionProof.verified_routes.endpoint_agent.status
      indexer_status = $targetSuppressionProof.verified_routes.indexer.status
    }
  }
  Write-Host "[1/6] Recording direct-probe baseline..."
  $baselineObservation = Invoke-ProbeOnce
  $baselineTarget = Get-ObservedService -Observation $baselineObservation
  if ($isNoChange) {
    if (-not $baselineTarget) { throw "The probe did not report existing no-change target '$ServiceName'." }
    $baselineTargetState = Get-ServiceComparisonState -Service $baselineTarget
    $baselineIndependentServiceState = Get-IndependentWindowsServiceState -Name $ServiceName
    $baselineTargetDeltas = @(Get-TargetStateDeltas)
    $baselineTargetFindings = @(Get-CsgResearchFindings)
    $baselineTargetDeltaIds = @($baselineTargetDeltas | ForEach-Object { if ($_.delta_id) { [string]$_.delta_id } })
    $baselineTargetFindingIds = @($baselineTargetFindings | ForEach-Object { if ($_.finding_id) { [string]$_.finding_id } })
  } elseif ($baselineTarget) {
    throw "The randomized target service is already present in the direct-probe baseline."
  }
  $timeline += @{ phase = "baseline"; at = (Get-Date).ToUniversalTime().ToString("o"); observation_id = $baselineObservation.observation_id }

  if ($isNoChange) {
    Write-Host "[2/6] Running no-change control; target '$ServiceName' will not be modified."
    if ($TelemetryCondition -eq "no_change_distractor") {
      $sourceBefore = Get-WazuhServiceProof
      if ($sourceBefore.status -ne "Running" -or $sourceBefore.process_id -le 0) {
        throw "no_change_distractor requires WazuhSvc running with a verified process ID."
      }
      $distractorBinary = 'C:\Windows\System32\cmd.exe /c exit 0'
      & sc.exe create $distractorServiceName binPath= $distractorBinary start= demand DisplayName= $distractorServiceName | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "Could not create the no-change distractor service." }
      $distractorCreatedByDrill = $true
      $distractorBefore = Get-IndependentWindowsServiceState -Name $distractorServiceName
      if (-not $distractorBefore -or $distractorBefore.start_mode -ne "Manual") {
        throw "Independent Windows state did not confirm the distractor's Manual baseline."
      }
      $createdEvents = @()
      $createdDeadline = (Get-Date).AddSeconds([Math]::Max(60, $TelemetryWaitSeconds * 3))
      do {
        Start-Sleep -Seconds ([Math]::Min(5, $TelemetryWaitSeconds))
        $noChangeDistractorProof.create_sync = Invoke-ProviderSync
        $createdEvents = @(Get-ExactWazuhServiceEvidence -ExpectedType "service_created" -EvidenceServiceName $distractorServiceName)
      } while ($createdEvents.Count -eq 0 -and (Get-Date) -lt $createdDeadline)
      if ($createdEvents.Count -eq 0) { throw "Wazuh did not collect the exact no-change distractor create event." }

      $distractorActionStartedAt = (Get-Date).ToUniversalTime()
      & sc.exe config $distractorServiceName start= auto | Out-Null
      $distractorCommandExitCode = $LASTEXITCODE
      $distractorActionCompletedAt = (Get-Date).ToUniversalTime()
      if ($distractorCommandExitCode -ne 0) { throw "Could not modify the no-change distractor service." }
      $distractorAfter = Get-IndependentWindowsServiceState -Name $distractorServiceName
      if (-not $distractorAfter -or $distractorAfter.start_mode -ne "Auto") {
        throw "Independent Windows state did not confirm the distractor's Auto transition."
      }
      $modifiedEvents = @()
      $modifiedDeadline = (Get-Date).AddSeconds([Math]::Max(60, $TelemetryWaitSeconds * 3))
      do {
        $noChangeDistractorProof.modify_sync = Invoke-ProviderSync
        $modifiedEvents = @(Get-ExactWazuhServiceEvidence -ExpectedType "service_modified" -EvidenceServiceName $distractorServiceName)
        if ($modifiedEvents.Count -gt 0) { break }
        Start-Sleep -Seconds 2
      } while ((Get-Date) -lt $modifiedDeadline)
      if ($modifiedEvents.Count -eq 0) { throw "Wazuh did not collect the exact no-change distractor modification event." }
      $sameHostDistractorProof = [ordered]@{
        condition_role = "same-host service_modified distractor; target Winmgmt remains unchanged"
        target_service_name = $ServiceName
        host_id = $HostId
        source_before = $sourceBefore
        distractor_service_name = $distractorServiceName
        distractor_create_state = $distractorBefore
        distractor_create_events = $createdEvents
        modify = [ordered]@{
          service_name = $distractorServiceName
          host_id = $HostId
          before = $distractorBefore
          after = $distractorAfter
          action_started_at = $distractorActionStartedAt.ToString("o")
          action_completed_at = $distractorActionCompletedAt.ToString("o")
          exact_wazuh_events = $modifiedEvents
          local_windows_events = Get-WindowsServiceEventEvidence -EvidenceServiceName $distractorServiceName -StartTime $experimentStartedAt.AddMinutes(-1) -EndTime (Get-Date)
        }
        source_after = Get-WazuhServiceProof
      }
      $timeline += @{
        phase = "no_change_wrong_object_service_modified_verified"
        at = (Get-Date).ToUniversalTime().ToString("o")
        target_service_name = $ServiceName
        distractor_service_name = $distractorServiceName
        distractor_event_ids = @($modifiedEvents | ForEach-Object { $_.event_id })
        wazuh_service_status = (Get-WazuhServiceProof).status
      }
    }
    Start-Sleep -Seconds $TelemetryWaitSeconds
    $controlSync = Invoke-ProviderSync
    $timeline += @{ phase = "no_change_control_sync"; at = (Get-Date).ToUniversalTime().ToString("o"); response = $controlSync }
    $noChangeObservation = Invoke-ProbeOnce
    $afterNoChangeTarget = Get-ObservedService -Observation $noChangeObservation
    $afterNoChangeState = Get-ServiceComparisonState -Service $afterNoChangeTarget
    $afterNoChangeIndependentState = Get-IndependentWindowsServiceState -Name $ServiceName
    $currentTargetDeltas = @(Get-TargetStateDeltas)
    $currentTargetFindings = @(Get-CsgResearchFindings)
    $newTargetDeltas = @($currentTargetDeltas | Where-Object { $_.delta_id -notin $baselineTargetDeltaIds })
    $newTargetFindings = @($currentTargetFindings | Where-Object { $_.finding_id -notin $baselineTargetFindingIds })
    $newTargetDeltaIds = @($newTargetDeltas | ForEach-Object { if ($_.delta_id) { [string]$_.delta_id } })
    $newTargetFindingIds = @($newTargetFindings | ForEach-Object { if ($_.finding_id) { [string]$_.finding_id } })
    $finalSnapshot = Get-ResearchSnapshot -Phase "no_change_control_final"
    if ($TelemetryCondition -eq "no_change_distractor" -and $distractorCreatedByDrill) {
      $distractorCleanupStartedAt = (Get-Date).ToUniversalTime()
      & sc.exe delete $distractorServiceName 2>$null | Out-Null
      $distractorCleanupExitCode = $LASTEXITCODE
      Start-Sleep -Seconds 2
      $distractorCleanupState = Get-IndependentWindowsServiceState -Name $distractorServiceName
      $distractorCreatedByDrill = $false
      $sameHostDistractorProof.cleanup = [ordered]@{
        command = "sc.exe delete $distractorServiceName"
        command_exit_code = $distractorCleanupExitCode
        started_at = $distractorCleanupStartedAt.ToString("o")
        absent_after_cleanup = ($null -eq $distractorCleanupState)
        independent_state_after_cleanup = $distractorCleanupState
        cleanup_probe_observation = Invoke-ProbeOnce
      }
    }
    $targetDeltasAfterBaseline = @($finalSnapshot.target_state_deltas | Where-Object { $_.delta_id -notin $baselineTargetDeltaIds })
    $findingsAfterBaseline = @($finalSnapshot.findings | Where-Object { $_.finding_id -notin $baselineTargetFindingIds })
    $unchanged = $baselineTargetState -and $afterNoChangeState -and
      ((Get-ServiceComparisonState -Service $baselineTarget | ConvertTo-Json -Compress) -eq ($afterNoChangeState | ConvertTo-Json -Compress))
    $noChangeSourceEvidence = Get-WindowsServiceEventEvidence -EvidenceServiceName $ServiceName -StartTime $experimentStartedAt.AddMinutes(-2) -EndTime (Get-Date)
    $noChangeArtifactValid = @($finalSnapshot.capture_errors).Count -eq 0 -and $noChangeSourceEvidence.query_status -eq "SUCCEEDED"
    $noChangeDistractorAdherent = $true
    if ($TelemetryCondition -eq "no_change_distractor") {
      $noChangeDistractorAdherent = [bool](
        @($sameHostDistractorProof.distractor_create_events).Count -gt 0 -and
        @($sameHostDistractorProof.modify.exact_wazuh_events).Count -gt 0 -and
        $sameHostDistractorProof.modify.local_windows_events.query_status -eq "SUCCEEDED" -and
        $sameHostDistractorProof.source_before.status -eq "Running" -and
        $sameHostDistractorProof.source_after.status -eq "Running" -and
        $sameHostDistractorProof.cleanup.absent_after_cleanup -eq $true
      )
    }
    $noChangeProtocolAdherent = [bool]($baselineTarget -and $afterNoChangeTarget -and $noChangeArtifactValid -and $noChangeDistractorAdherent)
    $independentNoChange = $baselineIndependentServiceState -and $afterNoChangeIndependentState -and
      $baselineIndependentServiceState.start_mode -eq $afterNoChangeIndependentState.start_mode -and
      $baselineIndependentServiceState.binary_path -eq $afterNoChangeIndependentState.binary_path -and
      $baselineIndependentServiceState.account -eq $afterNoChangeIndependentState.account -and
      $baselineIndependentServiceState.status -eq $afterNoChangeIndependentState.status
    $noChangeOutcome = [bool]($unchanged -and $independentNoChange -and $newTargetDeltaIds.Count -eq 0 -and $newTargetFindingIds.Count -eq 0 -and $noChangeDistractorAdherent)
    Restore-ProbeSchedule
    $result = [ordered]@{
      schema_version = "3"
      run_id = $runId
      experiment_id = $experimentId
      trial_id = $trialId
      host_id = $HostId
      service_name = $ServiceName
      telemetry_condition = $TelemetryCondition
      probe_scheduled_task = $probeTaskProof
      started_at = $startedAt
      ended_at = (Get-Date).ToUniversalTime().ToString("o")
      timeline = $timeline
      findings = $findingsAfterBaseline
      target_state_deltas = $targetDeltasAfterBaseline
      host_findings = @($finalSnapshot.host_findings)
      verified_distractor_wazuh_evidence = $finalSnapshot.verified_distractor_wazuh_evidence
      reconciliation_histories = $finalSnapshot.reconciliation_histories
      verified_exact_wazuh_evidence = $finalSnapshot.verified_exact_wazuh_evidence
      event_plane_status = $finalSnapshot.event_plane_status
      provider_health = $finalSnapshot.provider_health
      action_journal = [ordered]@{
        mutation_performed = $false
        before_independent_state = $baselineIndependentServiceState
        after_independent_state = $afterNoChangeIndependentState
      }
      state_transition = [ordered]@{
        object = "service:$($ServiceName.ToLower())"
        delta_type = "NONE"
        before_observation_id = $baselineObservation.observation_id
        after_observation_id = $noChangeObservation.observation_id
        before_observed_at = $baselineObservation.observed_at
        after_observed_at = $noChangeObservation.observed_at
        before = $baselineTargetState
        after = $afterNoChangeState
        attributes_unchanged = [bool]$unchanged
        independent_os_before = $baselineIndependentServiceState
        independent_os_after = $afterNoChangeIndependentState
        independent_os_attributes_unchanged = [bool]$independentNoChange
        new_target_delta_count = $newTargetDeltas.Count
        new_target_finding_count = $newTargetFindings.Count
        new_target_delta_ids = $newTargetDeltaIds
        new_target_finding_ids = $newTargetFindingIds
      }
      windows_source_evidence = $noChangeSourceEvidence
      protocol_adherence = [ordered]@{
        artifact_valid = $noChangeArtifactValid
        protocol_adherent = $noChangeProtocolAdherent
        hypothesis_outcome = if ($noChangeOutcome) { "NO_NEW_TARGET_CHANGE_OR_FINDING" } else { "TARGET_CHANGE_OR_FINDING_OBSERVED" }
        distractor_control_adherent = $noChangeDistractorAdherent
        applicable_checks = @("existing_target_observed_before_and_after", "source_event_query_succeeded", "new_target_delta_and_finding_count", "same_host_distractor_event_and_cleanup")
      }
      expected_windows_events = @("7045 service_created", "7040 service_modified")
      expected_capture_drop_outcome = "no state change expected; no finding expected"
      control_scope = "pre-existing monitored service Winmgmt (or the selected NoChangeServiceName) was observed before and after; new target findings/deltas are counted since baseline"
      run_status = if (@($finalSnapshot.capture_errors).Count -gt 0) { "FAILED" } else { "COMPLETED" }
      capture_errors = @($finalSnapshot.capture_errors)
      capture_drop_proof = $null
      telemetry_delay_proof = $null
      same_host_distractor_proof = if ($TelemetryCondition -eq "no_change_distractor") {
        [ordered]@{ details = $sameHostDistractorProof; target_control = "Winmgmt unchanged; distractor is a distinct service object" }
      } else { $null }
    }
    $directory = Split-Path -Parent $OutputPath
    if ($directory) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $result | ConvertTo-Json -Depth 20 | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "[6/6] No-change control record written to $OutputPath"
    if ($result.run_status -eq "FAILED") {
      throw "No-change record contains capture errors; inspect capture_errors in $OutputPath."
    }
    if (-not $result.protocol_adherence.protocol_adherent) {
      throw "No-change trial did not meet its observation/data-capture preconditions; inspect $OutputPath."
    }
    return
  }

  if ($hasDistractor) {
    $wazuh = Get-Service -Name WazuhSvc -ErrorAction Stop
    $wazuhWasRunning = $wazuh.Status -eq "Running"
    if (-not $wazuhWasRunning) {
      throw "$TelemetryCondition requires WazuhSvc to capture a wrong-object service event."
    }
    $sameHostDistractorProof.source_before = Get-WazuhServiceProof
    $sameHostDistractorProof.distractor_service_name = $distractorServiceName
    $distractorBinary = 'C:\Windows\System32\cmd.exe /c exit 0'
    & sc.exe create $distractorServiceName binPath= $distractorBinary start= demand DisplayName= $distractorServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not create the same-host distractor service." }
    $distractorCreatedByDrill = $true
    if ($TelemetryCondition -eq "same_host_distractor") {
      & sc.exe delete $distractorServiceName 2>$null | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "Could not remove the same-host distractor service." }
      $distractorCreatedByDrill = $false
    }
    $timeline += @{
      phase = "same_host_add_distractor_generated"
      at = (Get-Date).ToUniversalTime().ToString("o")
      distractor_service = $distractorServiceName
      host_id = $HostId
      event_type = "service_created"
    }

    $distractorDeadline = (Get-Date).AddSeconds([Math]::Max(60, $TelemetryWaitSeconds * 3))
    do {
      Start-Sleep -Seconds ([Math]::Min(5, $TelemetryWaitSeconds))
      $sameHostDistractorProof.event_sync = Invoke-ProviderSync
      $distractorEvents = @(Get-ExactWazuhServiceEvidence -ExpectedType "service_created" -EvidenceServiceName $distractorServiceName)
    } while ($distractorEvents.Count -eq 0 -and (Get-Date) -lt $distractorDeadline)
    if ($distractorEvents.Count -eq 0) {
      throw "Wazuh did not provide the exact wrong-object service_created event."
    }
    $sameHostDistractorProof.distractor_event = $distractorEvents
    $sameHostDistractorProof.target_service_name = $ServiceName
    $sameHostDistractorProof.target_exact_events_absent_before_action = $true
    $sameHostDistractorProof.source_before_target_add = Get-WazuhServiceProof
    if ($TelemetryCondition -eq "same_host_distractor") {
      $sameHostDistractorProof.source_during_target_add = Stop-WazuhServiceAndWait
      if (
        $sameHostDistractorProof.source_during_target_add.status -ne "Stopped" -or
        $sameHostDistractorProof.source_during_target_add.process_id -ne 0
      ) {
        throw "WazuhSvc did not stop before the target ADD transition."
      }
    } else {
      $sameHostDistractorProof.source_during_target_add = Get-WazuhServiceProof
      if (
        $sameHostDistractorProof.source_during_target_add.status -ne "Running" -or
        $sameHostDistractorProof.source_during_target_add.process_id -le 0
      ) {
        throw "Target-selective drop requires WazuhSvc to remain Running through target mutation."
      }
    }
    $timeline += @{
      phase = if ($TelemetryCondition -eq "same_host_distractor") {
        "same_host_add_distractor_indexed_and_source_stopped"
      } else {
        "same_host_distractor_indexed_collection_stays_healthy"
      }
      at = (Get-Date).ToUniversalTime().ToString("o")
      exact_distractor_event_count = $distractorEvents.Count
      wazuh_service_proof = $sameHostDistractorProof.source_during_target_add
    }
  }

  if ($TelemetryCondition -eq "telemetry_delay") {
    Write-Host "[2/6] Pausing Wazuh collection before the controlled changes to create a measured ingestion delay..."
    $wazuh = Get-Service -Name WazuhSvc -ErrorAction Stop
    $wazuhWasRunning = $wazuh.Status -eq "Running"
    if (-not $wazuhWasRunning) {
      throw "telemetry_delay requires WazuhSvc to be running before the controlled pause."
    }
    $telemetryDelayProof.before_pause = Get-WazuhServiceProof
    $telemetryDelayActive = $true
    $telemetryDelayProof.during_pause = Stop-WazuhServiceAndWait
    $timeline += @{
      phase = "telemetry_delay_window_started"
      at = (Get-Date).ToUniversalTime().ToString("o")
      event_source = "WazuhSvc"
      wazuh_service_proof = $telemetryDelayProof.during_pause
    }
  }

  Write-Host "[2/6] Creating controlled service $ServiceName..."
  $binary = 'C:\Windows\System32\cmd.exe /c exit 0'
  # Keep the display name unique so Wazuh evidence can be verified against the
  # internal service object rather than a shared human-readable label.
  $createCommandStartedAt = (Get-Date).ToUniversalTime()
  & sc.exe create $ServiceName binPath= $binary start= demand DisplayName= $ServiceName | Out-Null
  $createCommandExitCode = $LASTEXITCODE
  if ($createCommandExitCode -ne 0) { throw "sc.exe create failed with exit code $createCommandExitCode" }
  $createCommandCompletedAt = (Get-Date).ToUniversalTime()
  $createdByDrill = $true
  $createIndependentServiceState = Get-IndependentWindowsServiceState -Name $ServiceName
  $serviceCreatedAt = (Get-Date).ToUniversalTime()
  $timeline += @{ phase = "service_created"; at = $serviceCreatedAt.ToString("o") }
  $createObservation = Wait-ObservedService `
    -InitialObservation (Invoke-ProbeOnce) `
    -ExpectedStartMode "Manual"
  $afterCreateObservation = $createObservation.observation
  $timeline += @{
    phase = "service_created_probe_observed"
    at = (Get-Date).ToUniversalTime().ToString("o")
    observation_id = $afterCreateObservation.observation_id
    expected_start_mode = "Manual"
    observation_attempts = $createObservation.attempts
  }

  Write-Host "[3/6] Collecting create evidence under telemetry condition $TelemetryCondition..."
  if ($TelemetryCondition -in @("delayed", "delayed_reconciliation")) {
    $createInitialSync = Invoke-ProviderSync
    $timeline += @{ phase = "create_synced_before_event_wait"; at = (Get-Date).ToUniversalTime().ToString("o"); response = $createInitialSync }
    Start-Sleep -Seconds $TelemetryWaitSeconds
  } elseif ($TelemetryCondition -eq "telemetry_delay") {
    Start-Sleep -Seconds $TelemetryWaitSeconds
    $timeline += @{ phase = "create_state_observed_while_event_source_paused"; at = (Get-Date).ToUniversalTime().ToString("o") }
  } elseif ($TelemetryCondition -eq "source_unavailable") {
    $wazuh = Get-Service -Name WazuhSvc -ErrorAction Stop
    $wazuhWasRunning = $wazuh.Status -eq "Running"
    if ($wazuhWasRunning) { $sourceUnavailableProof = Stop-WazuhServiceAndWait }
    $timeline += @{ phase = "event_source_unavailable_started"; at = (Get-Date).ToUniversalTime().ToString("o") }
    Start-Sleep -Seconds $TelemetryWaitSeconds
    $unavailableSync = Invoke-ProviderSync
    $timeline += @{ phase = "create_synced_while_event_source_unavailable"; at = (Get-Date).ToUniversalTime().ToString("o"); response = $unavailableSync }
    if ($wazuhWasRunning) { Start-Service -Name WazuhSvc }
    $timeline += @{ phase = "event_source_restored"; at = (Get-Date).ToUniversalTime().ToString("o") }
    Start-Sleep -Seconds $TelemetryWaitSeconds
  } elseif ($TelemetryCondition -eq "capture_drop") {
    $wazuh = Get-Service -Name WazuhSvc -ErrorAction Stop
    $wazuhWasRunning = $wazuh.Status -eq "Running"
    if (-not $wazuhWasRunning) {
      throw "capture_drop requires WazuhSvc to be running before the controlled drop window."
    }
    $createEvidenceDeadline = (Get-Date).AddSeconds([Math]::Max(30, $TelemetryWaitSeconds * 2))
    $sourceCreateEvidence = Get-WindowsServiceEventEvidence `
      -EvidenceServiceName $ServiceName `
      -StartTime $experimentStartedAt.AddMinutes(-2) `
      -EndTime (Get-Date)
    $sourceCreateEvent = @($sourceCreateEvidence.events | Where-Object { $_.event_id -eq 7045 })
    $indexedCreateEvidence = @()
    do {
      $captureDropProof.precondition_provider_sync = Invoke-ProviderSync
      $indexedCreateEvidence = @(Get-ExactWazuhServiceEvidence -ExpectedType "service_created")
      if ($sourceCreateEvent.Count -gt 0 -and $indexedCreateEvidence.Count -gt 0) { break }
      Start-Sleep -Seconds 2
      $sourceCreateEvidence = Get-WindowsServiceEventEvidence `
        -EvidenceServiceName $ServiceName `
        -StartTime $experimentStartedAt.AddMinutes(-2) `
        -EndTime (Get-Date)
      $sourceCreateEvent = @($sourceCreateEvidence.events | Where-Object { $_.event_id -eq 7045 })
    } while ((Get-Date) -lt $createEvidenceDeadline)
    if ($sourceCreateEvent.Count -eq 0 -or $indexedCreateEvidence.Count -eq 0) {
      throw "capture_drop requires the exact Windows 7045 source event and matching indexed Wazuh service_created evidence before stopping WazuhSvc."
    }
    $captureDropProof.precondition = [ordered]@{
      windows_system_event_7045 = $sourceCreateEvent
      exact_wazuh_service_created = $indexedCreateEvidence
      verified_at = (Get-Date).ToUniversalTime().ToString("o")
    }
    $captureDropProof.before_stop = Get-WazuhServiceProof
    $captureDropActive = $true
    $captureDropProof.during_drop = Stop-WazuhServiceAndWait
    if ($captureDropProof.during_drop.status -ne "Stopped" -or $captureDropProof.during_drop.process_id -ne 0) {
      throw "WazuhSvc did not reach a verified Stopped state with process ID 0."
    }
    $timeline += @{ phase = "capture_drop_window_started"; at = (Get-Date).ToUniversalTime().ToString("o"); event_source = "WazuhSvc"; wazuh_service_proof = $captureDropProof.during_drop }
    Start-Sleep -Seconds $TelemetryWaitSeconds
  } else {
    Start-Sleep -Seconds $TelemetryWaitSeconds
  }
  $createSync = Invoke-ProviderSync
  $timeline += @{
    phase = "create_synced"
    at = (Get-Date).ToUniversalTime().ToString("o")
    response = $createSync
  }

  if ($TelemetryCondition -eq "same_host_distractor") {
    Write-Host "[3/6] Holding the bounded distractor result for the reconciliation grace period ($LifecycleFinalizationWaitSeconds seconds)..."
    try {
      Start-Sleep -Seconds $LifecycleFinalizationWaitSeconds
      $sameHostDistractorAddBoundedSnapshot = Get-BoundedDistractorSnapshot `
        -Phase "same_host_distractor_add_before_restore"
    } finally {
      Start-Service -Name WazuhSvc
      $restoreDeadline = (Get-Date).AddSeconds(30)
      do {
        $restoredService = Get-Service -Name WazuhSvc -ErrorAction Stop
        if ($restoredService.Status -eq "Running") { break }
        Start-Sleep -Seconds 1
      } while ((Get-Date) -lt $restoreDeadline)
      if ($restoredService.Status -ne "Running") {
        throw "WazuhSvc did not return to Running after the bounded distractor window."
      }
      $sameHostDistractorProof.source_after_add_restore = Get-WazuhServiceProof
    }
    $sameHostDistractorProof.add_bounded_finding = @(
      $sameHostDistractorAddBoundedSnapshot.findings | Where-Object {
        $_.category -eq "service" -and $_.object_key -eq "service:$($ServiceName.ToLower())"
      }
    )
    $sameHostDistractorProof.add_bounded_snapshot_time = $sameHostDistractorAddBoundedSnapshot.captured_at
    $sameHostDistractorProof.add_source_during_bounded_check = $sameHostDistractorAddBoundedSnapshot.wazuh_service_proof
    Start-Sleep -Seconds $RecoveryWaitSeconds
    $sameHostDistractorProof.add_recovery_sync = Invoke-ProviderSync
    $sameHostDistractorRecoverySnapshot = Get-ResearchSnapshot -Phase "same_host_distractor_add_after_restore"
    $sameHostDistractorProof.add_recovery_finding = @(
      $sameHostDistractorRecoverySnapshot.findings | Where-Object {
        $_.category -eq "service" -and $_.object_key -eq "service:$($ServiceName.ToLower())"
      }
    )
    $timeline += @{
      phase = "same_host_distractor_add_checked_then_source_restored"
      at = (Get-Date).ToUniversalTime().ToString("o")
      bounded_status = if ($sameHostDistractorProof.add_bounded_finding.Count -gt 0) {
        $sameHostDistractorProof.add_bounded_finding[0].reconciliation.status
      } else { "MISSING_FINDING" }
      restored_status = if ($sameHostDistractorProof.add_recovery_finding.Count -gt 0) {
        $sameHostDistractorProof.add_recovery_finding[0].reconciliation.status
      } else { "MISSING_FINDING" }
      wazuh_service_proof = $sameHostDistractorProof.source_after_add_restore
    }
  }

  if ($TelemetryCondition -in @("target_selective_drop", "complete_distractor")) {
    $distractorBefore = Get-IndependentWindowsServiceState -Name $distractorServiceName
    if (-not $distractorBefore -or $distractorBefore.start_mode -ne "Manual") {
      throw "The wrong-object control must independently exist in Manual mode before its event is generated."
    }
    $distractorActionStartedAt = (Get-Date).ToUniversalTime()
    & sc.exe config $distractorServiceName start= auto | Out-Null
    $distractorCommandExitCode = $LASTEXITCODE
    $distractorActionCompletedAt = (Get-Date).ToUniversalTime()
    if ($distractorCommandExitCode -ne 0) { throw "Could not generate the same-host service_modified distractor event." }
    $distractorAfter = Get-IndependentWindowsServiceState -Name $distractorServiceName
    if (-not $distractorAfter -or $distractorAfter.start_mode -ne "Auto") {
      throw "Independent Windows inspection did not verify the distractor transition to Auto."
    }
    $distractorDeadline = (Get-Date).AddSeconds([Math]::Max(60, $TelemetryWaitSeconds * 3))
    $distractorModifyEvidence = @()
    do {
      $sameHostDistractorProof.modify_sync = Invoke-ProviderSync
      $distractorModifyEvidence = @(Get-ExactWazuhServiceEvidence -ExpectedType "service_modified" -EvidenceServiceName $distractorServiceName)
      if ($distractorModifyEvidence.Count -gt 0) { break }
      Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $distractorDeadline)
    if ($distractorModifyEvidence.Count -eq 0) {
      throw "Wazuh did not collect the exact wrong-object service_modified control event."
    }
    $sameHostDistractorProof.modify = [ordered]@{
      service_name = $distractorServiceName
      host_id = $HostId
      before = $distractorBefore
      after = $distractorAfter
      command = "sc.exe config $distractorServiceName start= auto"
      command_exit_code = $distractorCommandExitCode
      action_started_at = $distractorActionStartedAt.ToString("o")
      action_completed_at = $distractorActionCompletedAt.ToString("o")
      exact_wazuh_events = $distractorModifyEvidence
      wazuh_service_status = (Get-WazuhServiceProof).status
      local_windows_events = Get-WindowsServiceEventEvidence -EvidenceServiceName $distractorServiceName `
        -StartTime $distractorActionStartedAt.AddMinutes(-1) -EndTime (Get-Date)
    }
    $timeline += @{
      phase = "same_host_wrong_object_service_modified_event_verified"
      at = (Get-Date).ToUniversalTime().ToString("o")
      distractor_service_name = $distractorServiceName
      exact_event_ids = @($distractorModifyEvidence | ForEach-Object { $_.event_id })
      wazuh_service_status = (Get-WazuhServiceProof).status
    }
  }

  Write-Host "[4/6] Modifying service start mode to generate state drift and Event 7040..."
  $modifyBeforeService = Get-ObservedService -Observation $afterCreateObservation
  if (-not $modifyBeforeService -or [string]$modifyBeforeService.start_mode -ine "Manual") {
    throw "Refusing to modify the service: the archived probe state does not prove its Manual starting mode."
  }
  $modifyCommandStartedAt = (Get-Date).ToUniversalTime()
  & sc.exe config $ServiceName start= auto | Out-Null
  $modifyCommandExitCode = $LASTEXITCODE
  if ($modifyCommandExitCode -ne 0) { throw "sc.exe config failed with exit code $modifyCommandExitCode" }
  $modifyCommandCompletedAt = (Get-Date).ToUniversalTime()
  $modifyIndependentServiceState = Get-IndependentWindowsServiceState -Name $ServiceName
  $serviceModifiedAt = (Get-Date).ToUniversalTime()
  $timeline += @{ phase = "service_modified"; at = $serviceModifiedAt.ToString("o") }
  $modifyObservation = Wait-ObservedService `
    -InitialObservation (Invoke-ProbeOnce) `
    -ExpectedStartMode "Auto"
  $afterModifyObservation = $modifyObservation.observation
  $modifyAfterService = $modifyObservation.service
  $timeline += @{
    phase = "service_modified_probe_observed"
    at = (Get-Date).ToUniversalTime().ToString("o")
    observation_id = $afterModifyObservation.observation_id
    expected_start_mode = "Auto"
    observation_attempts = $modifyObservation.attempts
  }
  if ($TelemetryCondition -in @("delayed", "delayed_reconciliation")) {
    $modifyInitialSync = Invoke-ProviderSync
    $timeline += @{ phase = "modify_synced_before_event_wait"; at = (Get-Date).ToUniversalTime().ToString("o"); response = $modifyInitialSync }
    Start-Sleep -Seconds $TelemetryWaitSeconds
  } elseif ($TelemetryCondition -eq "telemetry_delay") {
    Start-Sleep -Seconds $TelemetryWaitSeconds
    if (-not $telemetryDelayActive) {
      throw "telemetry_delay source pause was not active during the modify phase."
    }
    Start-Service -Name WazuhSvc
    $serviceDeadline = (Get-Date).AddSeconds(30)
    do {
      $wazuh = Get-Service -Name WazuhSvc -ErrorAction Stop
      if ($wazuh.Status -eq "Running") { break }
      Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $serviceDeadline)
    if ($wazuh.Status -ne "Running") { throw "WazuhSvc did not return to Running after telemetry_delay." }
    $telemetryDelayProof.after_pause = Get-WazuhServiceProof
    $telemetryDelayActive = $false
    $timeline += @{
      phase = "telemetry_delay_window_closed_and_source_restored"
      at = (Get-Date).ToUniversalTime().ToString("o")
      wazuh_service_proof = $telemetryDelayProof.after_pause
    }
    Start-Sleep -Seconds $RecoveryWaitSeconds
  } elseif ($TelemetryCondition -eq "source_unavailable") {
    if ($wazuhWasRunning) { $sourceUnavailableProof = Stop-WazuhServiceAndWait }
    $timeline += @{ phase = "event_source_unavailable_started_for_modify"; at = (Get-Date).ToUniversalTime().ToString("o") }
    Start-Sleep -Seconds $TelemetryWaitSeconds
    $modifyUnavailableSync = Invoke-ProviderSync
    $timeline += @{ phase = "modify_synced_while_event_source_unavailable"; at = (Get-Date).ToUniversalTime().ToString("o"); response = $modifyUnavailableSync }
    if ($wazuhWasRunning) { Start-Service -Name WazuhSvc }
    $timeline += @{ phase = "event_source_restored_for_modify"; at = (Get-Date).ToUniversalTime().ToString("o") }
    Start-Sleep -Seconds $TelemetryWaitSeconds
  } elseif ($TelemetryCondition -eq "capture_drop") {
    $timeline += @{ phase = "capture_drop_window_continued_for_modify"; at = (Get-Date).ToUniversalTime().ToString("o") }
    Start-Sleep -Seconds $TelemetryWaitSeconds
  } else {
    Start-Sleep -Seconds $TelemetryWaitSeconds
  }
  $modifySync = Invoke-ProviderSync
  $timeline += @{
    phase = "modify_synced"
    at = (Get-Date).ToUniversalTime().ToString("o")
    response = $modifySync
  }
  if ($TelemetryCondition -in @("complete", "complete_distractor", "delayed", "delayed_reconciliation", "telemetry_delay", "target_selective_drop", "target_selective_drop_clean")) {
    Write-Host "[5/6] Waiting $LifecycleFinalizationWaitSeconds seconds for the reconciliation lifecycle deadline..."
    Start-Sleep -Seconds $LifecycleFinalizationWaitSeconds
    $lifecycleFinalizationSync = Invoke-ProviderSync
    $timeline += @{
      phase = "lifecycle_finalization_sync"
      at = (Get-Date).ToUniversalTime().ToString("o")
      response = $lifecycleFinalizationSync
    }
  }
  if ($TelemetryCondition -eq "capture_drop") {
    Write-Host "[5/6] Waiting $FinalizationWaitSeconds seconds for the observation window and grace period..."
    $captureDropWaitProof = Wait-ResearchInterval -Seconds $FinalizationWaitSeconds -Phase "capture_drop_finalization_wait"
    $finalizationSync = Invoke-ProviderSync
    $timeline += @{
      phase = "capture_drop_finalization_sync"
      at = (Get-Date).ToUniversalTime().ToString("o")
      elapsed_wall_seconds = $captureDropWaitProof.wall_elapsed_seconds
      elapsed_monotonic_seconds = $captureDropWaitProof.monotonic_elapsed_seconds
      max_heartbeat_gap_seconds = $captureDropWaitProof.maximum_heartbeat_gap_seconds
      response = $finalizationSync
    }

    $captureDropFinalizedSnapshot = Get-ResearchSnapshot -Phase "capture_drop_finalized_before_restore"
    Write-Host "[5/6] Restoring Wazuh and checking whether the buffered event is recovered..."
    Start-Service -Name WazuhSvc
    $serviceDeadline = (Get-Date).AddSeconds(30)
    do {
      $wazuh = Get-Service -Name WazuhSvc -ErrorAction Stop
      if ($wazuh.Status -eq "Running") { break }
      Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $serviceDeadline)
    if ($wazuh.Status -ne "Running") { throw "WazuhSvc did not return to Running after capture_drop." }
    $captureDropProof.after_restore = Get-WazuhServiceProof
    if ($captureDropProof.after_restore.process_id -le 0) { throw "WazuhSvc is Running but has no verified process ID after restore." }
    $captureDropActive = $false
    $timeline += @{ phase = "capture_drop_window_closed_and_source_restored"; at = (Get-Date).ToUniversalTime().ToString("o"); wazuh_service_proof = $captureDropProof.after_restore }
    Start-Sleep -Seconds $RecoveryWaitSeconds
    $recoverySync = Invoke-ProviderSync
    $timeline += @{
      phase = "capture_drop_post_restore_sync"
      at = (Get-Date).ToUniversalTime().ToString("o")
      response = $recoverySync
    }
    $captureDropRecoverySnapshot = Get-ResearchSnapshot -Phase "capture_drop_after_restore"
  }

  if ($createdByDrill -and -not $KeepService) {
    Write-Host "[6/6] Removing the controlled service and archiving the cleanup observation..."
    $cleanupCommandStartedAt = (Get-Date).ToUniversalTime()
    & sc.exe delete $ServiceName 2>$null | Out-Null
    $cleanupCommandExitCode = $LASTEXITCODE
    $cleanupCommandCompletedAt = (Get-Date).ToUniversalTime()
    Start-Sleep -Seconds 2
    $cleanupIndependentServiceState = Get-IndependentWindowsServiceState -Name $ServiceName
    $afterCleanupObservation = Invoke-ProbeOnce
    $serviceCleanupAt = (Get-Date).ToUniversalTime()
    $timeline += @{ phase = "service_cleanup_probe_observed"; at = $serviceCleanupAt.ToString("o"); observation_id = $afterCleanupObservation.observation_id }
    $createdByDrill = $false
  }

  if ($hasDistractor -and $distractorCreatedByDrill) {
    $distractorCleanupStartedAt = (Get-Date).ToUniversalTime()
    & sc.exe delete $distractorServiceName 2>$null | Out-Null
    $distractorCleanupExitCode = $LASTEXITCODE
    Start-Sleep -Seconds 2
    $distractorCleanupState = Get-IndependentWindowsServiceState -Name $distractorServiceName
    $distractorCreatedByDrill = $false
    $sameHostDistractorProof.cleanup = [ordered]@{
      command = "sc.exe delete $distractorServiceName"
      command_exit_code = $distractorCleanupExitCode
      started_at = $distractorCleanupStartedAt.ToString("o")
      absent_after_cleanup = ($null -eq $distractorCleanupState)
      independent_state_after_cleanup = $distractorCleanupState
    }
    $sameHostDistractorProof.cleanup_probe_observation = Invoke-ProbeOnce
  }

  Write-Host "[6/6] Capturing findings and reconciliation histories..."
  $finalSnapshot = if ($TelemetryCondition -eq "capture_drop") {
    $captureDropRecoverySnapshot
  } else {
    Get-ResearchSnapshot -Phase "final"
  }
  $windowsSourceEvidence = Get-WindowsServiceEventEvidence `
    -EvidenceServiceName $ServiceName `
    -StartTime $experimentStartedAt.AddMinutes(-2) `
    -EndTime (Get-Date)
  if ($isTargetSelectiveDrop) {
    $sameHostDistractorProof.local_windows_events = Get-WindowsServiceEventEvidence `
      -EvidenceServiceName $distractorServiceName `
      -StartTime $experimentStartedAt.AddMinutes(-2) `
      -EndTime (Get-Date)
    $targetModifyDeltaIds = @($finalSnapshot.target_state_deltas | Where-Object {
      $_.category -eq "service" -and $_.object_key -eq "service:$($ServiceName.ToLower())" -and
      $_.delta_type -eq "MODIFY"
    } | ForEach-Object { $_.delta_id })
    $targetModifyFinding = @($finalSnapshot.findings | Where-Object {
      $_.category -eq "service" -and $_.object_key -eq "service:$($ServiceName.ToLower())" -and
      $_.reconciliation.delta_id -in $targetModifyDeltaIds
    } | Sort-Object { [int]$_.reconciliation.version } -Descending | Select-Object -First 1)
    $targetSuppressionProof.observation = [ordered]@{
      local_target_event_7040_count = @($windowsSourceEvidence.events | Where-Object { $_.event_id -eq 7040 }).Count
      csg_database_target_service_modified_count = $finalSnapshot.verified_exact_wazuh_evidence.exact_modify_count
      wrong_object_wazuh_service_modified_count = $finalSnapshot.verified_distractor_wazuh_evidence.exact_modify_count
      event_query_status = $finalSnapshot.event_plane_status.event_query_status
      endpoint_service_status = $finalSnapshot.event_plane_status.endpoint_service_status
      endpoint_collection_status = $finalSnapshot.event_plane_status.endpoint_collection_status
      manager_status = $finalSnapshot.event_plane_status.manager_status
      indexer_status = $finalSnapshot.event_plane_status.indexer_status
      target_reconciliation_status = if ($targetModifyFinding.Count -gt 0) {
        $targetModifyFinding[0].reconciliation.status
      } else { "MISSING_FINDING" }
      distractor_exact_event_ids = @($finalSnapshot.verified_distractor_wazuh_evidence.service_modified | ForEach-Object { $_.event_id })
    }
    $wrongObjectEvidenceValid = if ($TelemetryCondition -eq "target_selective_drop_clean") {
      $targetSuppressionProof.observation.wrong_object_wazuh_service_modified_count -eq 0
    } else {
      $targetSuppressionProof.observation.wrong_object_wazuh_service_modified_count -gt 0
    }
    $targetSuppressionProof.manipulation_valid = (
      $targetSuppressionProof.observation.local_target_event_7040_count -gt 0 -and
      $targetSuppressionProof.observation.csg_database_target_service_modified_count -eq 0 -and
      $wrongObjectEvidenceValid -and
      $targetSuppressionProof.observation.endpoint_service_status -eq "Running" -and
      $targetSuppressionProof.observation.endpoint_collection_status -eq "active" -and
      $targetSuppressionProof.observation.manager_status -ieq "available" -and
      $targetSuppressionProof.observation.indexer_status -ieq "available" -and
      $targetSuppressionProof.observation.event_query_status -eq "SUCCEEDED" -and
      $targetSuppressionProof.observation.target_reconciliation_status -eq "UNEXPLAINED"
    )
    $targetSuppressionProof.provider_sync = $modifySync
    $targetSuppressionProof = Restore-TargetSelectiveSuppression
  }
  $findings = @($finalSnapshot.findings)
  $reconciliations = $finalSnapshot.reconciliation_histories
  $verifiedExactEvidence = $finalSnapshot.verified_exact_wazuh_evidence
  $stateTransition = [ordered]@{
    object = "service:$($ServiceName.ToLower())"
    delta_type = "MODIFY"
    before_observation_id = $afterCreateObservation.observation_id
    after_observation_id = $afterModifyObservation.observation_id
    cleanup_observation_id = $afterCleanupObservation.observation_id
    before_observed_at = $afterCreateObservation.observed_at
    after_observed_at = $afterModifyObservation.observed_at
    cleanup_observed_at = $afterCleanupObservation.observed_at
    before = Get-ServiceComparisonState -Service $modifyBeforeService
    after = Get-ServiceComparisonState -Service $modifyAfterService
    independent_os_before = $createIndependentServiceState
    independent_os_after = $modifyIndependentServiceState
    independent_os_cleanup = $cleanupIndependentServiceState
    cleanup_present = [bool](Get-ObservedService -Observation $afterCleanupObservation)
  }
  $actionJournal = [ordered]@{
    service_create = [ordered]@{
      command = "sc.exe create $ServiceName binPath= $binary start= demand"
      binary_path = $binary
      command_exit_code = $createCommandExitCode
      started_at = if ($createCommandStartedAt) { $createCommandStartedAt.ToString("o") } else { $null }
      completed_at = if ($createCommandCompletedAt) { $createCommandCompletedAt.ToString("o") } else { $null }
      independent_postcondition = $createIndependentServiceState
    }
    service_start_mode_change = [ordered]@{
      command = "sc.exe config $ServiceName start= auto"
      command_exit_code = $modifyCommandExitCode
      started_at = if ($modifyCommandStartedAt) { $modifyCommandStartedAt.ToString("o") } else { $null }
      completed_at = if ($modifyCommandCompletedAt) { $modifyCommandCompletedAt.ToString("o") } else { $null }
      independent_postcondition = $modifyIndependentServiceState
    }
    service_cleanup = [ordered]@{
      command = "sc.exe delete $ServiceName"
      command_exit_code = $cleanupCommandExitCode
      started_at = if ($cleanupCommandStartedAt) { $cleanupCommandStartedAt.ToString("o") } else { $null }
      completed_at = if ($cleanupCommandCompletedAt) { $cleanupCommandCompletedAt.ToString("o") } else { $null }
      independent_postcondition = $cleanupIndependentServiceState
    }
  }
  $timingBoundaries = [ordered]@{
    create_action_started_at = if ($createCommandStartedAt) { $createCommandStartedAt.ToString("o") } else { $null }
    create_action_completed_at = if ($createCommandCompletedAt) { $createCommandCompletedAt.ToString("o") } else { $null }
    action_started_at = $modifyCommandStartedAt.ToString("o")
    action_completed_at = $modifyCommandCompletedAt.ToString("o")
    state_observation_requested_at = $afterModifyObservation.csg_request_started_at
    state_received_at = $afterModifyObservation.csg_observation_received_at
    event_query_completed_at = $finalSnapshot.event_plane_status.event_query_completed_at
    cleanup_action_started_at = if ($cleanupCommandStartedAt) { $cleanupCommandStartedAt.ToString("o") } else { $null }
    cleanup_action_completed_at = if ($cleanupCommandCompletedAt) { $cleanupCommandCompletedAt.ToString("o") } else { $null }
    trial_ended_at = (Get-Date).ToUniversalTime().ToString("o")
    windows_system_source_query_completed_at = $windowsSourceEvidence.query.end_time
  }
  $latencyMeasurements = [ordered]@{
    window_policy = "event matching uses CSG's configured observation window; action-triggered probe invocation is not autonomous probe latency"
    valid = $true
    state_detection_seconds = if ($timingBoundaries.action_completed_at -and $timingBoundaries.state_received_at) { ([DateTimeOffset]::Parse($timingBoundaries.state_received_at) - [DateTimeOffset]::Parse($timingBoundaries.action_completed_at)).TotalSeconds } else { $null }
    state_observation_interval_seconds = if ($afterCreateObservation.observed_at -and $afterModifyObservation.observed_at) { ([DateTimeOffset]::Parse($afterModifyObservation.observed_at).UtcDateTime - [DateTimeOffset]::Parse($afterCreateObservation.observed_at).UtcDateTime).TotalSeconds } else { $null }
    event_occurrence_offset_from_action_end_seconds = $null
    event_action_to_event_seconds = $null
    event_to_query_seconds = $null
    metric_validity = [ordered]@{}
  }
  if ($verifiedExactEvidence.service_modified.Count -gt 0) {
    $eventTime = [DateTimeOffset]::Parse($verifiedExactEvidence.service_modified[0].event_time).ToUniversalTime()
    $actionCompletedAt = [DateTimeOffset]$modifyCommandCompletedAt.ToUniversalTime()
    $latencyMeasurements.event_occurrence_offset_from_action_end_seconds = ($eventTime - $actionCompletedAt).TotalSeconds
    if ($finalSnapshot.event_plane_status.event_query_completed_at) {
      $queryCompletedAt = [DateTimeOffset]::Parse($finalSnapshot.event_plane_status.event_query_completed_at).ToUniversalTime()
      $latencyMeasurements.event_to_query_seconds = ($queryCompletedAt - $eventTime).TotalSeconds
    }
  }
  foreach ($metricName in @("state_detection_seconds", "state_observation_interval_seconds", "event_to_query_seconds")) {
    $value = $latencyMeasurements[$metricName]
    $latencyMeasurements.metric_validity[$metricName] = if ($null -eq $value) {
      "NOT_MEASURED"
    } elseif ($value -lt 0) {
      "INVALID_NEGATIVE_ELAPSED_DURATION"
    } else {
      "VALID"
    }
    if ($null -ne $value -and $value -lt 0) { $latencyMeasurements[$metricName] = $null }
  }
  $latencyMeasurements.metric_validity.event_occurrence_offset_from_action_end_seconds = if ($null -eq $latencyMeasurements.event_occurrence_offset_from_action_end_seconds) {
    "NOT_MEASURED"
  } else {
    "SIGNED_OFFSET_NOT_LATENCY"
  }
  $invalidElapsedMetrics = @($latencyMeasurements.metric_validity.Values | Where-Object { $_ -eq "INVALID_NEGATIVE_ELAPSED_DURATION" }).Count
  if ($invalidElapsedMetrics -gt 0) {
    $latencyMeasurements.valid = $false
    $latencyMeasurements.invalid_reason = "Only negative elapsed-time metrics were nulled; signed event occurrence offsets remain separate and raw timestamps are retained."
  }

  Restore-ProbeSchedule
  $result = [ordered]@{
    schema_version = "3"
    run_id = $runId
    experiment_id = $experimentId
    trial_id = $trialId
    host_id = $HostId
    service_name = $ServiceName
    telemetry_condition = $TelemetryCondition
    probe_scheduled_task = $probeTaskProof
    started_at = $startedAt
    ended_at = (Get-Date).ToUniversalTime().ToString("o")
    timeline = $timeline
    findings = $findings
    target_state_deltas = @($finalSnapshot.target_state_deltas)
    host_findings = @($finalSnapshot.host_findings)
    run_status = if (@($finalSnapshot.capture_errors).Count -gt 0) { "FAILED" } else { "COMPLETED" }
    capture_errors = @($finalSnapshot.capture_errors)
    reconciliation_histories = $reconciliations
    verified_exact_wazuh_evidence = $verifiedExactEvidence
    event_plane_status = $finalSnapshot.event_plane_status
    provider_health = $finalSnapshot.provider_health
    windows_source_evidence = $windowsSourceEvidence
    action_journal = $actionJournal
    protocol_adherence = [ordered]@{
      artifact_valid = (@($finalSnapshot.capture_errors).Count -eq 0)
      protocol_adherent = if ($TelemetryCondition -eq "capture_drop") {
        [bool]$captureDropWaitProof.protocol_adherent
      } elseif ($isTargetSelectiveDrop) {
        [bool]$targetSuppressionProof.manipulation_valid
      } else { $true }
      evaluated_checks = if ($TelemetryCondition -eq "capture_drop") {
        @("exact_create_event_precondition", "stopped_service_status", "finalization_elapsed_time", "heartbeat_gap", "wall_monotonic_divergence")
      } elseif ($isTargetSelectiveDrop) {
        if ($TelemetryCondition -eq "target_selective_drop_clean") {
          @("target_config_hash_and_readback", "active_agent_and_indexer", "local_target_event_present", "target_event_absent", "no_wrong_object_event_present", "unexplained_target_reconciliation", "config_restored_hash")
        } else {
          @("target_config_hash_and_readback", "active_agent_and_indexer", "local_target_event_present", "target_event_absent", "wrong_object_event_present", "unexplained_target_reconciliation", "config_restored_hash")
        }
      } else { @("artifact_captures_required_fields") }
      capture_drop_wait = $captureDropWaitProof
      source_queries_succeeded = ($windowsSourceEvidence.query_status -eq "SUCCEEDED")
    }
    artifact_scope = [ordered]@{
      host_findings = "host-wide historical findings returned by the CSG API"
      findings = "target-scoped findings for the randomized service object"
      exact_evidence = "target-scoped Wazuh events matched by host, normalized type, and exact service identity"
    }
    state_transition = $stateTransition
    timing_boundaries = $timingBoundaries
    latency_measurements = $latencyMeasurements
    expected_windows_events = @("7045 service_created", "7040 service_modified")
    expected_capture_drop_outcome = if ($TelemetryCondition -eq "capture_drop") { "UNEXPLAINED before restore; re-evaluated after Wazuh restore" } else { "event-dependent" }
    target_selective_suppression_proof = if ($isTargetSelectiveDrop) { $targetSuppressionProof } else { $null }
    capture_drop_proof = if ($TelemetryCondition -eq "capture_drop") {
      [ordered]@{
        exact_create_precondition = $captureDropProof.precondition
        bounded_observation = $captureDropFinalizedSnapshot
        post_restore_recovery = $captureDropRecoverySnapshot
        wazuh_service_proof = $captureDropProof
        finalization_wait = $captureDropWaitProof
        rule = "the pre-restore result proves the bounded capture-drop outcome; only the post-restore exact event may revise it"
      }
    } else { $null }
    telemetry_delay_proof = if ($TelemetryCondition -eq "telemetry_delay") {
      [ordered]@{
        wazuh_service_proof = $telemetryDelayProof
        rule = "WazuhSvc was paused before both controlled changes, then restored before final reconciliation; this measures recoverable ingestion delay, not permanent event loss."
      }
    } else { $null }
    same_host_distractor_proof = if ($hasDistractor) {
      [ordered]@{
        details = $sameHostDistractorProof
        bounded_observation = $sameHostDistractorAddBoundedSnapshot
        post_restore_observation = $sameHostDistractorRecoverySnapshot
        probe_scheduled_task = $probeTaskProof
        rule = if ($isTargetSelectiveDrop) {
          "Wazuh stays healthy; the same-host wrong-object service_modified event is collected while the target event is suppressed."
        } elseif ($TelemetryCondition -eq "complete_distractor") {
          "Wazuh stays healthy and collects exact target and same-host wrong-object service_modified events; only the target event may reconcile the target service."
        } else {
          "same-host, same-type distractor event is archived before restore; it must not explain the target service ADD"
        }
      }
    } else { $null }
  }
  $directory = Split-Path -Parent $OutputPath
  if ($directory) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
  $result | ConvertTo-Json -Depth 20 | Set-Content -Path $OutputPath -Encoding UTF8
  Write-Host "[6/6] Research record written to $OutputPath"
  if ($result.run_status -eq "FAILED") {
    throw "Research record contains capture errors; inspect capture_errors in $OutputPath."
  }
  Write-Host "RUN_STATUS=$($result.run_status); CONDITION=$TelemetryCondition; TARGET_DELTAS=$(@($finalSnapshot.target_state_deltas).Count); EXACT_CREATE=$($verifiedExactEvidence.exact_create_count); EXACT_MODIFY=$($verifiedExactEvidence.exact_modify_count)"
} catch {
  $failureException = $_
  $failureDeltas = @()
  $failureFindings = @()
  $failureReconciliations = [pscustomobject]@{}
  $failureCaptureErrors = @()
  try { $failureDeltas = @(Get-TargetStateDeltas) } catch { $failureCaptureErrors += "deltas: $($_.Exception.Message)" }
  try { $failureFindings = @(Get-CsgResearchFindings) } catch { $failureCaptureErrors += "findings: $($_.Exception.Message)" }
  foreach ($finding in $failureFindings) {
    try {
      $history = @(Invoke-RestMethod -Method Get -DisableKeepAlive -TimeoutSec $ApiTimeoutSeconds `
        -Uri "$CsgApiBase/api/findings/$($finding.finding_id)/reconciliations")
      $failureReconciliations | Add-Member -NotePropertyName ([string]$finding.finding_id) -NotePropertyValue $history
    } catch {
      $failureCaptureErrors += "reconciliation $($finding.finding_id): $($_.Exception.Message)"
    }
  }
  $failureEvidence = [ordered]@{ service_created = @(); service_modified = @() }
  try { $failureEvidence.service_created = @(Get-ExactWazuhServiceEvidence -ExpectedType "service_created") }
  catch { $failureCaptureErrors += "service_created evidence: $($_.Exception.Message)" }
  try { $failureEvidence.service_modified = @(Get-ExactWazuhServiceEvidence -ExpectedType "service_modified") }
  catch { $failureCaptureErrors += "service_modified evidence: $($_.Exception.Message)" }
  $failureWindowsSourceEvidence = $null
  $failureWazuhService = $null
  try {
    $failureWindowsSourceEvidence = Get-WindowsServiceEventEvidence -EvidenceServiceName $ServiceName `
      -StartTime $experimentStartedAt.AddMinutes(-2) -EndTime (Get-Date)
  } catch { $failureCaptureErrors += "Windows source events: $($_.Exception.Message)" }
  try { $failureWazuhService = Get-WazuhServiceProof } catch { $failureCaptureErrors += "Wazuh service status: $($_.Exception.Message)" }
  if ($script:targetSuppressionApplied) {
    try { $targetSuppressionProof = Restore-TargetSelectiveSuppression } catch {
      $failureCaptureErrors += "target suppression restoration: $($_.Exception.Message)"
    }
  }
  $failureCleanup = [ordered]@{ target = $null; distractor = $null }
  if ($createdByDrill -and -not $KeepService) {
    try {
      $cleanupAt = (Get-Date).ToUniversalTime().ToString("o")
      & sc.exe delete $ServiceName 2>$null | Out-Null
      $cleanupExitCode = $LASTEXITCODE
      Start-Sleep -Seconds 2
      $cleanupState = Get-IndependentWindowsServiceState -Name $ServiceName
      $failureCleanup.target = [ordered]@{
        service_name = $ServiceName
        command = "sc.exe delete $ServiceName"
        command_exit_code = $cleanupExitCode
        attempted_at = $cleanupAt
        absent_after_cleanup = ($null -eq $cleanupState)
        independent_state_after_cleanup = $cleanupState
      }
      if ($null -eq $cleanupState) { $createdByDrill = $false }
    } catch { $failureCaptureErrors += "target cleanup: $($_.Exception.Message)" }
  }
  if ($distractorCreatedByDrill) {
    try {
      $cleanupAt = (Get-Date).ToUniversalTime().ToString("o")
      & sc.exe delete $distractorServiceName 2>$null | Out-Null
      $cleanupExitCode = $LASTEXITCODE
      Start-Sleep -Seconds 2
      $cleanupState = Get-IndependentWindowsServiceState -Name $distractorServiceName
      $failureCleanup.distractor = [ordered]@{
        service_name = $distractorServiceName
        command = "sc.exe delete $distractorServiceName"
        command_exit_code = $cleanupExitCode
        attempted_at = $cleanupAt
        absent_after_cleanup = ($null -eq $cleanupState)
        independent_state_after_cleanup = $cleanupState
      }
      if ($null -eq $cleanupState) { $distractorCreatedByDrill = $false }
    } catch { $failureCaptureErrors += "distractor cleanup: $($_.Exception.Message)" }
  }
  $failurePath = if (Test-Path -LiteralPath $OutputPath) { "$OutputPath.failure.json" } else { $OutputPath }
  try {
    [ordered]@{
      schema_version = "failure-capture-1"
      run_id = $runId
      experiment_id = $experimentId
      trial_id = $trialId
      host_id = $HostId
      service_name = $ServiceName
      telemetry_condition = $TelemetryCondition
      run_status = "FAILED"
      failure_phase = if ($timeline.Count -gt 0) { [string]$timeline[-1].phase } else { "initialization" }
      started_at = $startedAt
      failed_at = (Get-Date).ToUniversalTime().ToString("o")
      error = $failureException.Exception.Message
      error_record = $failureException.ToString()
      timeline = $timeline
      observations = [ordered]@{
        baseline = $baselineObservation
        after_create = $afterCreateObservation
        after_modify = $afterModifyObservation
        after_cleanup = $afterCleanupObservation
      }
      action_journal = [ordered]@{
        create_started_at = if ($createCommandStartedAt) { $createCommandStartedAt.ToString("o") } else { $null }
        create_completed_at = if ($createCommandCompletedAt) { $createCommandCompletedAt.ToString("o") } else { $null }
        create_exit_code = $createCommandExitCode
        modify_started_at = if ($modifyCommandStartedAt) { $modifyCommandStartedAt.ToString("o") } else { $null }
        modify_completed_at = if ($modifyCommandCompletedAt) { $modifyCommandCompletedAt.ToString("o") } else { $null }
        modify_exit_code = $modifyCommandExitCode
        cleanup_started_at = if ($cleanupCommandStartedAt) { $cleanupCommandStartedAt.ToString("o") } else { $null }
        cleanup_completed_at = if ($cleanupCommandCompletedAt) { $cleanupCommandCompletedAt.ToString("o") } else { $null }
        cleanup_exit_code = $cleanupCommandExitCode
      }
      failure_cleanup = $failureCleanup
      target_state_deltas = $failureDeltas
      findings = $failureFindings
      reconciliation_histories = $failureReconciliations
      exact_wazuh_evidence = $failureEvidence
      same_host_distractor_proof = $sameHostDistractorProof
      same_host_distractor_bounded_snapshot = $sameHostDistractorAddBoundedSnapshot
      same_host_distractor_recovery_snapshot = $sameHostDistractorRecoverySnapshot
      capture_drop_proof = $captureDropProof
      target_selective_suppression_proof = $targetSuppressionProof
      capture_drop_finalized_snapshot = $captureDropFinalizedSnapshot
      capture_drop_recovery_snapshot = $captureDropRecoverySnapshot
      telemetry_delay_proof = $telemetryDelayProof
      probe_scheduled_task = $probeTaskProof
      windows_source_evidence = $failureWindowsSourceEvidence
      wazuh_service = $failureWazuhService
      capture_errors = $failureCaptureErrors
    } | ConvertTo-Json -Depth 24 | Set-Content -Path $failurePath -Encoding UTF8
    Write-Host "Failure evidence saved to $failurePath"
  } catch {
    Write-Warning "Could not save failure artifact: $($_.Exception.Message)"
  }
  throw
}
finally {
  if ($script:targetSuppressionApplied) {
    try { $script:targetSuppressionProof = Restore-TargetSelectiveSuppression } catch { Write-Warning $_ }
  }
  if ($captureDropActive -or $telemetryDelayActive) { try { Start-Service -Name WazuhSvc -ErrorAction SilentlyContinue } catch { Write-Warning $_ } }
  if ($wazuhWasRunning) {
    try { Start-Service -Name WazuhSvc -ErrorAction SilentlyContinue } catch { Write-Warning $_ }
  }
  if ($createdByDrill -and -not $KeepService) {
    & sc.exe delete $ServiceName 2>$null | Out-Null
    Start-Sleep -Seconds 2
    try { Invoke-ProbeOnce } catch { Write-Warning $_ }
  }
  if ($distractorCreatedByDrill) {
    & sc.exe delete $distractorServiceName 2>$null | Out-Null
  }
  try { Restore-ProbeSchedule } catch { Write-Warning $_ }
}
