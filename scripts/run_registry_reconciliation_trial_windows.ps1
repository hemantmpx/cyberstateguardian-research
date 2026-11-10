param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("registry_complete", "registry_wrong_object", "registry_selective_drop", "registry_eventid_drop", "registry_distractor_only", "registry_competing_event", "registry_sysmon_target_drop", "registry_no_change")]
  [string]$Condition,
  [Parameter(Mandatory = $true)]
  [string]$TrialId,
  [string]$CsgApiBase = "http://192.168.64.1:8000",
  [string]$HostId = "win11-arm-lab",
  [string]$ProbePython = "python.exe",
  [string]$ProbeConfig = "C:\CSG\probe-settings.json",
  [string]$OutputPath = "",
  [int]$PositiveEventWaitSeconds = 30,
  [int]$LifecycleWaitSeconds = 300,
  [int]$ToleranceSeconds = 10,
  [string]$ExpectedSysmonRuntimeHash = ""
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
  $OutputPath = "C:\CSG\research\registry-reconciliation\$TrialId\run.json"
}
if (Test-Path -LiteralPath $OutputPath) {
  throw "Refusing to overwrite existing trial artifact: $OutputPath"
}
if (-not (Test-Path -LiteralPath $ProbeConfig)) {
  throw "Probe configuration is missing: $ProbeConfig"
}
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Run this controlled trial from Administrator PowerShell." }

$CsgApiBase = $CsgApiBase.TrimEnd("/")
$settings = Get-Content -LiteralPath $ProbeConfig -Raw | ConvertFrom-Json
if ($settings.CSG_PROBE_HOST_ID -ne $HostId) {
  throw "Probe host ID '$($settings.CSG_PROBE_HOST_ID)' does not match '$HostId'."
}
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value.ToLowerInvariant()
$prefix = "CSGConfRun$([guid]::NewGuid().ToString('N').Substring(0, 12))"
$targetName = "${prefix}T"
$sourceName = if ($Condition -in @("registry_wrong_object", "registry_selective_drop", "registry_eventid_drop", "registry_distractor_only", "registry_competing_event", "registry_sysmon_target_drop")) { "${prefix}D" } else { $null }
$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$targetKey = "registry:hku/$sid/software/microsoft/windows/currentversion/run/$($targetName.ToLowerInvariant())"
$sourceKey = if ($sourceName) {
  "registry:hku/$sid/software/microsoft/windows/currentversion/run/$($sourceName.ToLowerInvariant())"
} else { $null }
$runDirectory = Split-Path -Parent $OutputPath
$null = New-Item -ItemType Directory -Path $runDirectory -Force

function Save-Json([string]$Path, [object]$Value) {
  $temporaryPath = "$Path.tmp"
  $Value | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
  Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
}

function Invoke-CsgGet([string]$Route) {
  return Invoke-RestMethod -Method Get -DisableKeepAlive -TimeoutSec 30 -Uri "$CsgApiBase$Route"
}

function Invoke-CsgPost([string]$Route, [object]$Body = $null) {
  $parameters = @{
    Method = "Post"
    DisableKeepAlive = $true
    TimeoutSec = 300
    Uri = "$CsgApiBase$Route"
  }
  if ($null -ne $Body) {
    $parameters.ContentType = "application/json"
    $parameters.Body = if ($Body -is [string]) {
      $Body
    } else {
      ConvertTo-Json -InputObject $Body -Depth 32 -Compress
    }
  }
  return Invoke-RestMethod @parameters
}

function Normalize-Identity([object]$Value) {
  $text = ([string]$Value).Trim().ToLowerInvariant().Replace("\", "/")
  while ($text.Contains("//")) { $text = $text.Replace("//", "/") }
  return $text.Replace(":/", "/")
}

function Invoke-ProbeOnce {
  & $ProbePython -m cyberstateguardian_probe.main --config $ProbeConfig --once
  if ($LASTEXITCODE -ne 0) { throw "CSG probe failed with exit code $LASTEXITCODE" }
}

function Get-LatestObservation {
  return Invoke-CsgGet "/api/hosts/$HostId/observations/latest"
}

function Get-RegistryItems([object]$Observation, [string]$ObjectKey, [string]$Name) {
  if ($null -eq $Observation -or $null -eq $Observation.categories.registry) { return @() }
  $expected = Normalize-Identity $ObjectKey
  return @($Observation.categories.registry.items | Where-Object {
    (Normalize-Identity $_.object_key) -eq $expected -or
    ($Name -and [string]::Equals([string]$_.name, $Name, [StringComparison]::OrdinalIgnoreCase))
  })
}

function Test-RegistryObjectPresent([object]$Observation, [string]$ObjectKey, [string]$Name) {
  $items = @(Get-RegistryItems $Observation $ObjectKey $Name)
  return $items.Count -gt 0
}

function Get-TargetDeltas([string]$ObjectKey) {
  $rows = Invoke-CsgGet "/api/hosts/$HostId/deltas?limit=500"
  $expected = Normalize-Identity $ObjectKey
  return @($rows | Where-Object { (Normalize-Identity $_.object_key) -eq $expected })
}

function Get-TargetFindings([string]$ObjectKey) {
  $rows = Invoke-CsgGet "/api/findings?host_id=$HostId&limit=500"
  $expected = Normalize-Identity $ObjectKey
  return @($rows | Where-Object { (Normalize-Identity $_.object_key) -eq $expected })
}

function Test-ExactRegistryEvent([object]$Candidate, [string]$ObjectKey) {
  if ($Candidate.host_id -ne $HostId -or $Candidate.source -ne "wazuh" -or
      $Candidate.normalized_type -ne "registry_value_modified") { return $false }
  $expected = Normalize-Identity $ObjectKey
  $target = Normalize-Identity $Candidate.target.key
  if ($target -eq $expected) { return $true }
  $rawTarget = Normalize-Identity $Candidate.attributes.target_object
  return $rawTarget -eq $expected -or $rawTarget -eq $expected.Replace("registry:", "")
}

function Get-RegistryIdentityDiagnostics([object]$Observation, [string]$ObjectKey, [string]$Name) {
  $items = @($Observation.categories.registry.items)
  $named = @($items | Where-Object { [string]$_.name -like "*CSGConfRun*" })
  return [ordered]@{
    expected_key = $ObjectKey
    expected_normalized_key = Normalize-Identity $ObjectKey
    expected_name = $Name
    registry_item_count = $items.Count
    matched_items = @(Get-RegistryItems $Observation $ObjectKey $Name)
    csg_named_items = @($named | ForEach-Object {
      [ordered]@{
        object_key = [string]$_.object_key
        normalized_object_key = Normalize-Identity $_.object_key
        name = [string]$_.name
      }
    })
  }
}

function Get-EventIdentityDiagnostics([object[]]$Events, [string]$ObjectKey, [string]$Name) {
  $candidates = @($Events | Where-Object {
    $_.normalized_type -eq "registry_value_modified" -and
    ([string]$_.attributes.target_object -like "*$Name*" -or [string]$_.target.key -like "*$Name*")
  })
  return [ordered]@{
    expected_key = $ObjectKey
    expected_normalized_key = Normalize-Identity $ObjectKey
    expected_name = $Name
    event_count_in_query = @($Events).Count
    named_candidate_count = $candidates.Count
    candidates = @($candidates | ForEach-Object {
      [ordered]@{
        event_id = [string]$_.event_id
        host_id = [string]$_.host_id
        source = [string]$_.source
        normalized_type = [string]$_.normalized_type
        event_time = [string]$_.event_time
        target_key = [string]$_.target.key
        normalized_target_key = Normalize-Identity $_.target.key
        target_object = [string]$_.attributes.target_object
        normalized_target_object = Normalize-Identity $_.attributes.target_object
        exact_match = Test-ExactRegistryEvent $_ $ObjectKey
      }
    })
  }
}

function Get-ProviderEvents([datetime]$Start, [datetime]$End) {
  $startText = [uri]::EscapeDataString($Start.ToUniversalTime().ToString("o"))
  $endText = [uri]::EscapeDataString($End.ToUniversalTime().ToString("o"))
  return @(Invoke-CsgGet "/api/hosts/$HostId/provider-events?start=$startText&end=$endText")
}

function Get-ProviderEventObservation([datetime]$Start, [datetime]$End) {
  $startText = [uri]::EscapeDataString($Start.ToUniversalTime().ToString("o"))
  $endText = [uri]::EscapeDataString($End.ToUniversalTime().ToString("o"))
  return Invoke-CsgGet "/api/hosts/$HostId/provider-event-observation?start=$startText&end=$endText"
}

function Get-DatabaseEvents([datetime]$Start, [datetime]$End) {
  $startText = [uri]::EscapeDataString($Start.ToUniversalTime().ToString("o"))
  $endText = [uri]::EscapeDataString($End.ToUniversalTime().ToString("o"))
  return @(Invoke-CsgGet "/api/hosts/$HostId/events?start=$startText&end=$endText")
}

function Get-LocalSysmonRegistryEvents([datetime]$Start, [datetime]$End, [string[]]$Keys) {
  $expected = @($Keys | Where-Object { $_ } | ForEach-Object {
    Normalize-Identity ([string]$_ -replace '^[^:]+:', '')
  })
  $events = @(Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 13
    StartTime = $Start.ToLocalTime().AddMinutes(-1)
    EndTime = $End.ToLocalTime().AddMinutes(1)
  } -ErrorAction SilentlyContinue)
  return @(
    foreach ($event in $events) {
      [xml]$xml = $event.ToXml()
      $fields = [ordered]@{}
      foreach ($field in @($xml.Event.EventData.Data)) {
        if ($field.Name) { $fields[[string]$field.Name] = [string]$field.InnerText }
      }
      $targetObject = Normalize-Identity $fields.TargetObject
      if ($expected -contains $targetObject) {
        [ordered]@{
          event_id = [int]$event.Id
          record_id = [long]$event.RecordId
          event_time_utc = $event.TimeCreated.ToUniversalTime().ToString("o")
          target_object = $fields.TargetObject
          details = $fields.Details
          raw_xml = $event.ToXml()
        }
      }
    }
  )
}

function Get-NativeFilteredRecordProof([string]$Query, [long]$RecordId) {
  if (-not $Query.StartsWith("Event[") -or -not $Query.EndsWith("]")) {
    throw "Cannot validate a non-Event-root XPath filter."
  }
  $predicate = $Query.Substring(6, $Query.Length - 7)
  $recordQuery = "Event[System[EventRecordID = $RecordId] and ($predicate)]"
  try {
    $filteredRecords = @(Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" `
      -FilterXPath $recordQuery -MaxEvents 1 -ErrorAction Stop)
    return [ordered]@{
      query_completed = $true
      record_id = $RecordId
      returned_by_filter = @($filteredRecords | Where-Object { [long]$_.RecordId -eq $RecordId }).Count -gt 0
      filter_query = $recordQuery
      error = $null
    }
  } catch {
    if ($_.Exception.Message -match "No events were found") {
      return [ordered]@{
        query_completed = $true
        record_id = $RecordId
        returned_by_filter = $false
        filter_query = $recordQuery
        error = $null
      }
    }
    return [ordered]@{
      query_completed = $false
      record_id = $RecordId
      returned_by_filter = $false
      filter_query = $recordQuery
      error = $_.Exception.Message
    }
  }
}

function Get-WazuhServiceProof {
  $service = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
  if (-not $service) { throw "WazuhSvc is not installed." }
  return [ordered]@{
    status = [string]$service.State
    start_mode = [string]$service.StartMode
    process_id = [int]$service.ProcessId
    captured_at = (Get-Date).ToUniversalTime().ToString("o")
  }
}

function Get-WazuhHealthProof {
  $health = Invoke-CsgGet "/api/wazuh/status"
  $agent = @($health.agents | Where-Object { $_.name -eq $HostId } | Select-Object -First 1)[0]
  return [ordered]@{
    checked_at = (Get-Date).ToUniversalTime().ToString("o")
    api_ok = [bool]$health.ok
    endpoint_agent_status = if ($agent) { [string]$agent.status } else { "NOT_REPORTED" }
    endpoint_agent = $agent
    manager_api_ok = [bool]$health.server_api.ok
    indexer_ok = [bool]$health.indexer.ok
  }
}

function Wait-WazuhAgentActive([int]$TimeoutSeconds = 120) {
  $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  $lastService = $null
  $lastHealth = $null
  do {
    $lastService = Get-WazuhServiceProof
    try { $lastHealth = Get-WazuhHealthProof } catch { $lastHealth = $null }
    if ($lastService.status -eq "Running" -and $lastService.process_id -gt 0 -and
      $lastHealth -and $lastHealth.api_ok -and $lastHealth.endpoint_agent_status -eq "active" -and
      $lastHealth.manager_api_ok -and $lastHealth.indexer_ok) {
      return [ordered]@{ service = $lastService; health = $lastHealth }
    }
    Start-Sleep -Seconds 2
  } while ([DateTime]::UtcNow -lt $deadline)
  throw "Wazuh did not return to active/healthy state. service=$($lastService | ConvertTo-Json -Compress); health=$($lastHealth | ConvertTo-Json -Compress)"
}

function Apply-RegistryTargetEventFilter([switch]$EventIdOnly, [switch]$DistractorOnly) {
  if ($targetName -notmatch '^CSGConfRun[A-Za-z0-9]{12}T$') {
    throw "Registry event filtering requires a fresh randomized CSGConfRun target name."
  }
  $configPath = Join-Path ${env:ProgramFiles(x86)} "ossec-agent\ossec.conf"
  if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    throw "Wazuh agent configuration is missing: $configPath"
  }
  $serviceBefore = Get-WazuhServiceProof
  $healthBefore = Get-WazuhHealthProof
  if ($serviceBefore.status -ne "Running" -or $serviceBefore.process_id -le 0 -or
    -not $healthBefore.api_ok -or $healthBefore.endpoint_agent_status -ne "active" -or
    -not $healthBefore.manager_api_ok -or -not $healthBefore.indexer_ok) {
    throw "Selective event filtering requires a running Wazuh service and active healthy endpoint."
  }

  $backupDirectory = Join-Path $env:ProgramData "CyberStateGuardian\config-backups"
  New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
  $backupName = "registry-$($TrialId -replace '[^A-Za-z0-9_-]', '_')-$([guid]::NewGuid().ToString('N')).ossec.conf"
  $backupPath = Join-Path $backupDirectory $backupName
  if (Test-Path -LiteralPath $backupPath) { throw "Refusing to overwrite configuration backup: $backupPath" }
  Copy-Item -LiteralPath $configPath -Destination $backupPath
  $originalHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $configPath).Hash.ToLowerInvariant()
  $targetObject = "HKU\$($sid.ToUpperInvariant())\Software\Microsoft\Windows\CurrentVersion\Run\$targetName"
  $distractorObject = if ($sourceName) {
    "HKU\$($sid.ToUpperInvariant())\Software\Microsoft\Windows\CurrentVersion\Run\$sourceName"
  } else { $null }
  $query = if ($EventIdOnly) {
    "Event[System[EventID != 13]]"
  } elseif ($DistractorOnly) {
    "Event[System[EventID = 13] and EventData/Data[@Name='TargetObject'] = '$distractorObject']"
  } else {
    "Event[System[EventID != 13] or EventData[Data[@Name='TargetObject'] != '$targetObject']]"
  }
  $nativeQuerySample = @()
  $nativeQuerySampleStatus = "MATCHED_EXISTING_EVENT"
  try {
    $nativeQuerySample = @(Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" `
      -FilterXPath $query -MaxEvents 1 -ErrorAction Stop)
  } catch {
    if ($_.FullyQualifiedErrorId -like "NoMatchingEventsFound,*") {
      $nativeQuerySampleStatus = "NO_PREEXISTING_MATCH_EXPECTED"
    } else {
      throw
    }
  }
  $temporaryPath = "$configPath.$([guid]::NewGuid().ToString('N')).tmp"
  $proof = [ordered]@{
    status = "APPLYING"
    config_path = $configPath
    backup_path = $backupPath
    original_config_sha256 = $originalHash
    effective_config_sha256 = $null
    event_channel = "Microsoft-Windows-Sysmon/Operational"
    event_id = 13
    filter_scope = if ($EventIdOnly) { "all_event_id_13" } elseif ($DistractorOnly) { "exact_distractor_object_only" } else { "exact_target_object" }
    target_object = $targetObject
    selected_object = if ($DistractorOnly) { $distractorObject } else { $null }
    query = $query
    native_query_validation = [ordered]@{
      passed = $true
      status = $nativeQuerySampleStatus
      sample_event_count = $nativeQuerySample.Count
      sample_event_record_id = if ($nativeQuerySample.Count) { [long]$nativeQuerySample[0].RecordId } else { $null }
    }
    service_before = $serviceBefore
    health_before = $healthBefore
    applied_at = $null
    restoration = $null
  }
  $script:targetFilterProof = $proof
  try {
    $document = New-Object System.Xml.XmlDocument
    $document.PreserveWhitespace = $true
    $document.Load($configPath)
    $blocks = @($document.SelectNodes("/ossec_config/localfile") | Where-Object {
      $_.SelectSingleNode("location") -and
      $_.SelectSingleNode("location").InnerText -eq "Microsoft-Windows-Sysmon/Operational" -and
      $_.SelectSingleNode("log_format") -and $_.SelectSingleNode("log_format").InnerText -eq "eventchannel"
    })
    if ($blocks.Count -ne 1) {
      throw "Expected exactly one Sysmon Operational eventchannel block; found $($blocks.Count)."
    }
    if ($blocks[0].SelectSingleNode("query")) {
      throw "Sysmon Operational already has a query; refusing to replace existing collection policy."
    }
    $queryNode = $document.CreateElement("query")
    $queryNode.InnerText = $query
    [void]$blocks[0].AppendChild($queryNode)
    $document.Save($temporaryPath)

    $readback = New-Object System.Xml.XmlDocument
    $readback.Load($temporaryPath)
    $readbackBlocks = @($readback.SelectNodes("/ossec_config/localfile") | Where-Object {
      $_.SelectSingleNode("location") -and
      $_.SelectSingleNode("location").InnerText -eq "Microsoft-Windows-Sysmon/Operational"
    })
    if ($readbackBlocks.Count -ne 1 -or $readbackBlocks[0].SelectSingleNode("query").InnerText -ne $query) {
      throw "Exact target Event ID 13 query failed XML readback."
    }
    Copy-Item -LiteralPath $temporaryPath -Destination $configPath -Force
    $script:targetFilterApplied = $true
    $proof.effective_config_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $configPath).Hash.ToLowerInvariant()
    $activeConfig = New-Object System.Xml.XmlDocument
    $activeConfig.Load($configPath)
    $activeBlocks = @($activeConfig.SelectNodes("/ossec_config/localfile") | Where-Object {
      $_.SelectSingleNode("location") -and
      $_.SelectSingleNode("location").InnerText -eq "Microsoft-Windows-Sysmon/Operational" -and
      $_.SelectSingleNode("log_format") -and $_.SelectSingleNode("log_format").InnerText -eq "eventchannel"
    })
    if ($activeBlocks.Count -ne 1 -or $activeBlocks[0].SelectSingleNode("query").InnerText -ne $query) {
      throw "The active Wazuh agent configuration did not retain the exact target filter after replacement."
    }
    $proof.effective_query_readback = $activeBlocks[0].SelectSingleNode("query").InnerText
    $proof.status = "CONFIG_APPLIED"
    Restart-Service -Name WazuhSvc -Force -ErrorAction Stop
    $active = Wait-WazuhAgentActive
    if ($active.service.process_id -eq $serviceBefore.process_id) {
      throw "Wazuh service PID did not change after the filtered configuration reload."
    }
    $proof.status = "APPLIED_AND_HEALTHY"
    $proof.applied_at = (Get-Date).ToUniversalTime().ToString("o")
    $proof.service_after_reload = $active.service
    $proof.health_after_reload = $active.health
    return $proof
  } catch {
    if (-not $script:targetFilterApplied -and (Test-Path -LiteralPath $backupPath)) {
      Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    }
    throw
  } finally {
    if (Test-Path -LiteralPath $temporaryPath) {
      Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
  }
}

function Restore-RegistryTargetEventFilter {
  if (-not $script:targetFilterApplied) { return $script:targetFilterProof }
  $proof = $script:targetFilterProof
  $serviceBefore = Get-WazuhServiceProof
  Copy-Item -LiteralPath $proof.backup_path -Destination $proof.config_path -Force
  $restoredHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $proof.config_path).Hash.ToLowerInvariant()
  if ($restoredHash -ne $proof.original_config_sha256) {
    throw "Restored Wazuh config hash differs from the pretrial hash."
  }
  Restart-Service -Name WazuhSvc -Force -ErrorAction Stop
  $active = Wait-WazuhAgentActive
  Remove-Item -LiteralPath $proof.backup_path -Force -ErrorAction Stop
  $proof.status = "RESTORED_AND_HEALTHY"
  $proof.restoration = [ordered]@{
    restored_at = (Get-Date).ToUniversalTime().ToString("o")
    restored_config_sha256 = $restoredHash
    service_before_reload = $serviceBefore
    service_after_reload = $active.service
    health_after_reload = $active.health
    backup_removed_after_verification = $true
  }
  $script:targetFilterApplied = $false
  return $proof
}

function Get-SysmonRuntimeProof {
  $service = Get-CimInstance Win32_Service -Filter "Name='Sysmon64a'"
  if (-not $service) { throw "Sysmon64a service was not found." }
  $exeMatch = [regex]::Match([string]$service.PathName, '^\s*"?([^"].*?\.exe)"?(?:\s|$)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if (-not $exeMatch.Success) { throw "Could not resolve the Sysmon executable from '$($service.PathName)'." }
  $exe = $exeMatch.Groups[1].Value.Trim('"')
  if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Sysmon executable is missing: $exe" }
  $previousErrorAction = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $dump = @(& $exe -c 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
  } finally { $ErrorActionPreference = $previousErrorAction }
  $text = [regex]::Replace(($dump -join "`n"), '\x00', '')
  $pathMatch = [regex]::Match($text, '(?m)^\s*-\s*Config file:\s*(.+?)\s*$')
  $hashMatch = [regex]::Match($text, '(?im)^\s*-\s*Config hash:\s*SHA256=([0-9a-f]{64})\s*$')
  if ($exitCode -ne 0 -or -not $pathMatch.Success -or -not $hashMatch.Success) {
    throw "Sysmon current-configuration dump failed (exit=$exitCode)."
  }
  return [ordered]@{
    captured_at = (Get-Date).ToUniversalTime().ToString("o")
    service_name = [string]$service.Name
    service_state = [string]$service.State
    service_pid = [int]$service.ProcessId
    executable_path = $exe
    config_path = $pathMatch.Groups[1].Value.Trim()
    config_sha256 = $hashMatch.Groups[1].Value.ToLowerInvariant()
    dump_exit_code = $exitCode
    dump_text = $text
  }
}

function Apply-SysmonRegistryTargetFilter {
  $before = Get-SysmonRuntimeProof
  if ($before.service_state -ne "Running" -or $before.service_pid -le 0) {
    throw "Sysmon must be running before a target-specific collection filter is applied."
  }
  if ($ExpectedSysmonRuntimeHash -notmatch '^[0-9a-fA-F]{64}$' -or
      $before.config_sha256 -ne $ExpectedSysmonRuntimeHash.ToLowerInvariant()) {
    throw "Live Sysmon configuration hash differs from preflight; refusing to mutate the endpoint."
  }
  if (-not (Test-Path -LiteralPath $before.config_path -PathType Leaf)) {
    throw "The active Sysmon configuration file is unavailable: $($before.config_path)"
  }
  $originalHash = (Get-FileHash -LiteralPath $before.config_path -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($originalHash -ne $before.config_sha256) {
    throw "Sysmon's active configuration hash does not match its source file."
  }
  $document = New-Object System.Xml.XmlDocument
  $document.PreserveWhitespace = $true
  $document.Load($before.config_path)
  $eventFiltering = $document.SelectSingleNode("/Sysmon/EventFiltering")
  if (-not $eventFiltering) { throw "Active Sysmon XML has no EventFiltering node." }
  $includeRules = @($eventFiltering.SelectNodes("./RegistryEvent[@onmatch='include']"))
  $existingExcludes = @($eventFiltering.SelectNodes("./RegistryEvent[@onmatch='exclude']"))
  if ($includeRules.Count -ne 1 -or $existingExcludes.Count -ne 0) {
    throw "Expected one RegistryEvent include rule and no existing exclude rule; refusing to alter another policy."
  }

  $targetObject = "HKU\$($sid.ToUpperInvariant())\Software\Microsoft\Windows\CurrentVersion\Run\$targetName"
  $temporaryPath = Join-Path $runDirectory "sysmon-target-exclusion-$TrialId.xml"
  if (Test-Path -LiteralPath $temporaryPath) { throw "Refusing to overwrite Sysmon temporary config: $temporaryPath" }
  $script:sysmonTemporaryPath = $temporaryPath
  $excludeRule = $document.CreateElement("RegistryEvent")
  $excludeRule.SetAttribute("onmatch", "exclude")
  $targetNode = $document.CreateElement("TargetObject")
  $targetNode.SetAttribute("condition", "is")
  $targetNode.InnerText = $targetObject
  [void]$excludeRule.AppendChild($targetNode)
  [void]$eventFiltering.AppendChild($excludeRule)
  $document.Save($temporaryPath)

  $readback = New-Object System.Xml.XmlDocument
  $readback.Load($temporaryPath)
  $readbackTarget = $readback.SelectSingleNode("/Sysmon/EventFiltering/RegistryEvent[@onmatch='exclude']/TargetObject")
  if (-not $readbackTarget -or $readbackTarget.GetAttribute("condition") -ne "is" -or
      $readbackTarget.InnerText -cne $targetObject) {
    Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    throw "Temporary Sysmon XML failed exact target-rule readback."
  }
  $temporaryHash = (Get-FileHash -LiteralPath $temporaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $proof = [ordered]@{
    status = "PREPARED"
    manipulation_valid = $false
    mechanism = "Sysmon RegistryEvent exclude rule for exact TargetObject; Wazuh configuration is unchanged"
    target_object = $targetObject
    rule = "RegistryEvent onmatch=exclude; TargetObject condition=is"
    original_config_path = $before.config_path
    original_config_sha256 = $originalHash
    temporary_config_path = $temporaryPath
    temporary_config_sha256 = $temporaryHash
    service_before = $before
    service_after_apply = $null
    applied_at = $null
    restore = $null
  }
  $script:sysmonFilterProof = $proof
  $script:sysmonFilterApplied = $true
  $previousErrorAction = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $applyOutput = @(& $before.executable_path -c $temporaryPath 2>&1 | ForEach-Object { [string]$_ })
    $applyExitCode = $LASTEXITCODE
  } finally { $ErrorActionPreference = $previousErrorAction }
  $proof.apply_exit_code = $applyExitCode
  $proof.apply_output = @($applyOutput | ForEach-Object { [string]$_ })
  if ($applyExitCode -ne 0) { throw "Sysmon rejected the temporary target exclusion (exit=$applyExitCode)." }
  $after = Get-SysmonRuntimeProof
  $proof.service_after_apply = $after
  if ($after.service_state -ne "Running" -or $after.config_sha256 -ne $temporaryHash -or
      $after.dump_text.IndexOf($targetObject, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw "Sysmon did not report the exact exclusion as its active configuration."
  }
  $proof.manipulation_valid = $true
  $proof.status = "APPLIED_AND_VERIFIED"
  $proof.applied_at = (Get-Date).ToUniversalTime().ToString("o")
  return $proof
}

function Restore-SysmonRegistryTargetFilter {
  if (-not $script:sysmonFilterApplied) { return $script:sysmonFilterProof }
  $proof = $script:sysmonFilterProof
  $previousErrorAction = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    $restoreOutput = @(& $proof.service_before.executable_path -c $proof.original_config_path 2>&1 | ForEach-Object { [string]$_ })
  $restoreExitCode = $LASTEXITCODE
  } finally { $ErrorActionPreference = $previousErrorAction }
  $after = Get-SysmonRuntimeProof
  if ($restoreExitCode -ne 0 -or $after.service_state -ne "Running" -or
      $after.config_sha256 -ne $proof.original_config_sha256 -or
      $after.dump_text -ne $proof.service_before.dump_text) {
    throw "Sysmon configuration restoration failed or original SHA-256 did not return."
  }
  if (Test-Path -LiteralPath $proof.temporary_config_path) {
    Remove-Item -LiteralPath $proof.temporary_config_path -Force -ErrorAction Stop
  }
  $proof.status = "RESTORED_CONFIG"
  $proof.restore = [ordered]@{
    restored_at = (Get-Date).ToUniversalTime().ToString("o")
    exit_code = $restoreExitCode
    output = @($restoreOutput | ForEach-Object { [string]$_ })
    active_configuration = $after
    restored_config_sha256 = $after.config_sha256
    temporary_config_removed = -not (Test-Path -LiteralPath $proof.temporary_config_path)
  }
  $script:sysmonFilterApplied = $false
  $wazuhService = Get-WazuhServiceProof
  $wazuhHealth = Get-WazuhHealthProof
  if ($wazuhService.status -ne "Running" -or -not $wazuhHealth.api_ok -or
      $wazuhHealth.endpoint_agent_status -ne "active" -or -not $wazuhHealth.manager_api_ok -or
      -not $wazuhHealth.indexer_ok) {
    throw "Wazuh did not remain healthy while the Sysmon filter was applied/restored."
  }
  $proof.status = "RESTORED_AND_HEALTHY"
  $proof.restore.wazuh_service = $wazuhService
  $proof.restore.wazuh_health = $wazuhHealth
  return $proof
}

function Get-LatestReconciliation([object[]]$Findings) {
  $rows = @(
    foreach ($finding in $Findings) {
      $history = Invoke-CsgGet "/api/findings/$($finding.finding_id)/reconciliations"
      [pscustomobject]@{
        finding_id = $finding.finding_id
        revisions = @($history)
        latest = $finding.reconciliation
      }
    }
  )
  return $rows
}

function Get-MatchedEvidenceIds([object]$Reconciliation) {
  $ids = @()
  if ($Reconciliation -and $Reconciliation.matched_evidence_ids) {
    $ids = @($Reconciliation.matched_evidence_ids)
  }
  return ,$ids
}

$task = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction SilentlyContinue
$taskBefore = if ($task) {
  [ordered]@{ enabled = [bool]$task.Settings.Enabled; state = [string]$task.State }
} else {
  [ordered]@{ not_installed = $true }
}
$taskDisabled = $false
$wazuhStoppedByTrial = $false
$targetFilterApplied = $false
$targetFilterProof = [ordered]@{ status = "NOT_APPLIED" }
$sysmonFilterApplied = $false
$sysmonFilterProof = [ordered]@{ status = "NOT_APPLIED"; manipulation_valid = $false }
$sysmonTemporaryPath = $null
$startAt = (Get-Date).ToUniversalTime()
$actionJournal = [ordered]@{}
$errors = [System.Collections.Generic.List[string]]::new()
$artifact = [ordered]@{
  schema_version = "csg-registry-reconciliation-trial-v1"
  trial_id = $TrialId
  condition = $Condition
  host_id = $HostId
  target_name = $targetName
  target_object_key = $targetKey
  distractor_name = $sourceName
  distractor_object_key = $sourceKey
  started_at = $startAt.ToString("o")
  protocol_parameters = [ordered]@{
    event_time_tolerance_seconds = $ToleranceSeconds
    positive_event_wait_seconds = $PositiveEventWaitSeconds
    lifecycle_finalization_wait_seconds = $LifecycleWaitSeconds
    value_data = "C:\Windows\System32\cmd.exe /c exit 0; value is never executed"
  }
  scheduled_probe_task = [ordered]@{ before = $taskBefore; during = $null; after = $null }
  wazuh_service = [ordered]@{ before = $null; during = $null; after = $null }
  sysmon_service = [ordered]@{ before = $null; during = $null; after = $null }
  sysmon_event_filter = $sysmonFilterProof
  observations = [ordered]@{ before = $null; after = $null; after_distractor = $null; cleanup = $null }
  source_event_ingestion = [ordered]@{ provider_query_status = "NOT_RUN"; exact_events = @(); database_verified = @(); identity_diagnostics = $null }
  target_event_filter = $targetFilterProof
  target = [ordered]@{ sysmon_exact_events = @(); wazuh_provider_exact_events = @(); database_exact_events = @(); provider_identity_diagnostics = $null; database_identity_diagnostics = $null; deltas = @(); findings = @(); reconciliation_history = @(); decision_at = $null }
  database_event_window = @()
  target_state = [ordered]@{ absent_before = $null; present_after = $null; identity_diagnostics = $null }
  bounded_distractor = [ordered]@{ wrong_object_event_inside_target_window = $false; finalized_status = $null; matched_ids = @(); backlog_response = $null }
  no_change_control = [ordered]@{ target_absent_before = $null; target_absent_after = $null; new_delta_count = $null; new_finding_count = $null }
  cleanup = [ordered]@{ target_absent = $null; distractor_absent = $null; cleanup_probe_succeeded = $false; errors = @() }
  action_journal = $actionJournal
}

try {
  if ($task) {
    if ($task.State -eq "Running") { Stop-ScheduledTask -TaskName "CyberStateGuardian Probe" }
    Disable-ScheduledTask -TaskName "CyberStateGuardian Probe" | Out-Null
    $taskDisabled = $true
  }
  $taskDuring = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction SilentlyContinue
  $artifact.scheduled_probe_task.during = if ($taskDuring) {
    [ordered]@{ enabled = [bool]$taskDuring.Settings.Enabled; state = [string]$taskDuring.State }
  } else { [ordered]@{ not_installed = $true } }

  $wazuhBefore = Get-WazuhServiceProof
  $artifact.wazuh_service.before = $wazuhBefore
  if ($wazuhBefore.status -ne "Running") { throw "WazuhSvc must be Running before a trial." }
  Invoke-ProbeOnce
  $baseline = Get-LatestObservation
  $artifact.observations.before = $baseline
  $baselineTime = [datetime]::Parse($baseline.categories.registry.observed_at).ToUniversalTime()

  if ($Condition -eq "registry_no_change") {
    $absentBefore = -not (Test-RegistryObjectPresent $baseline $targetKey $targetName)
    Start-Sleep -Seconds 2
    Invoke-ProbeOnce
    $after = Get-LatestObservation
    $absentAfter = -not (Test-RegistryObjectPresent $after $targetKey $targetName)
    $artifact.observations.after = $after
    $actionJournal.no_change = [ordered]@{
      action = "no registry mutation; two explicit native-probe collections"
      started_at = $baselineTime.ToString("o")
      completed_at = (Get-Date).ToUniversalTime().ToString("o")
    }
    Invoke-CsgPost "/api/pipeline/process-backlog" | Out-Null
    $artifact.no_change_control.target_absent_before = $absentBefore
    $artifact.no_change_control.target_absent_after = $absentAfter
    $artifact.target_state.absent_before = $absentBefore
    $artifact.target_state.present_after = -not $absentAfter
    $artifact.no_change_control.new_delta_count = (Get-TargetDeltas $targetKey).Count
    $artifact.no_change_control.new_finding_count = (Get-TargetFindings $targetKey).Count
    $artifact.target.decision_at = (Get-Date).ToUniversalTime().ToString("o")
    $artifact.target.database_exact_events = @(Get-DatabaseEvents $baselineTime (Get-Date).ToUniversalTime() | Where-Object {
      Test-ExactRegistryEvent $_ $targetKey
    })
    $noChangeProviderObservation = Get-ProviderEventObservation $baselineTime (Get-Date).ToUniversalTime()
    $artifact.source_event_ingestion.provider_observation = $noChangeProviderObservation
    $artifact.source_event_ingestion.provider_query_status = if (
      $noChangeProviderObservation.query_complete -eq $true -and
      $noChangeProviderObservation.coverage_status -eq "COMPLETE" -and
      $noChangeProviderObservation.endpoint_collection_status -eq "AVAILABLE" -and
      $noChangeProviderObservation.transport_status -eq "AVAILABLE" -and
      $noChangeProviderObservation.index_status -eq "AVAILABLE"
    ) { "COMPLETE" } else { "INCOMPLETE" }
    $artifact.target.wazuh_provider_exact_events = @($noChangeProviderObservation.events | Where-Object {
      Test-ExactRegistryEvent $_ $targetKey
    })
    $artifact.target.sysmon_exact_events = @(Get-LocalSysmonRegistryEvents $baselineTime (Get-Date).ToUniversalTime() @($targetKey))
  }
  elseif ($Condition -eq "registry_complete") {
    $actionStart = (Get-Date).ToUniversalTime()
    New-ItemProperty -Path $runKeyPath -Name $targetName -PropertyType String `
      -Value "C:\Windows\System32\cmd.exe /c exit 0" -Force | Out-Null
    $actionEnd = (Get-Date).ToUniversalTime()
    $actionJournal.target_create = [ordered]@{
      command = "New-ItemProperty HKCU Run $targetName; inert value, not executed"
      exit_code = 0
      started_at = $actionStart.ToString("o")
      completed_at = $actionEnd.ToString("o")
    }
    Invoke-ProbeOnce
    $after = Get-LatestObservation
    $artifact.observations.after = $after
    $artifact.target_state.absent_before = -not (Test-RegistryObjectPresent $baseline $targetKey $targetName)
    $artifact.target_state.present_after = Test-RegistryObjectPresent $after $targetKey $targetName
    $artifact.target_state.identity_diagnostics = Get-RegistryIdentityDiagnostics $after $targetKey $targetName
    Start-Sleep -Seconds $PositiveEventWaitSeconds
    $sync = Invoke-CsgPost "/api/hosts/$HostId/provider-sync"
    $artifact.action_journal.provider_sync = $sync
    Invoke-CsgPost "/api/pipeline/process-backlog" | Out-Null
    $artifact.target.deltas = @(Get-TargetDeltas $targetKey)
    $artifact.target.findings = @(Get-TargetFindings $targetKey)
    $artifact.target.reconciliation_history = @(Get-LatestReconciliation $artifact.target.findings)
    $databaseQuery = Get-DatabaseEvents $actionStart.AddMinutes(-1) (Get-Date).ToUniversalTime()
    $providerQuery = Get-ProviderEvents $actionStart.AddMinutes(-1) (Get-Date).ToUniversalTime()
    $artifact.target.database_identity_diagnostics = Get-EventIdentityDiagnostics $databaseQuery $targetKey $targetName
    $artifact.target.provider_identity_diagnostics = Get-EventIdentityDiagnostics $providerQuery $targetKey $targetName
    $artifact.target.database_exact_events = @($databaseQuery | Where-Object {
      Test-ExactRegistryEvent $_ $targetKey
    })
    $artifact.target.wazuh_provider_exact_events = @($providerQuery | Where-Object {
      Test-ExactRegistryEvent $_ $targetKey
    })
    $artifact.target.sysmon_exact_events = @(Get-LocalSysmonRegistryEvents $actionStart (Get-Date).ToUniversalTime() @($targetKey))
    $artifact.target.decision_at = (Get-Date).ToUniversalTime().ToString("o")
  }
  elseif ($Condition -eq "registry_competing_event") {
    $sourceStart = (Get-Date).ToUniversalTime()
    New-ItemProperty -Path $runKeyPath -Name $sourceName -PropertyType String `
      -Value "C:\Windows\System32\cmd.exe /c exit 0" -Force | Out-Null
    $sourceEnd = (Get-Date).ToUniversalTime()
    $actionJournal.distractor_create = [ordered]@{
      command = "New-ItemProperty HKCU Run $sourceName; inert same-host/same-class distractor, not executed"
      exit_code = 0
      started_at = $sourceStart.ToString("o")
      completed_at = $sourceEnd.ToString("o")
    }
    Invoke-ProbeOnce
    $artifact.observations.after_distractor = Get-LatestObservation
    $artifact.source_event_ingestion.native_state_present_after =
      Test-RegistryObjectPresent $artifact.observations.after_distractor $sourceKey $sourceName
    Start-Sleep -Seconds $PositiveEventWaitSeconds
    $sourceSync = Invoke-CsgPost "/api/hosts/$HostId/provider-sync"
    $artifact.source_event_ingestion.provider_sync = $sourceSync
    $sourceEvents = Get-DatabaseEvents $sourceStart.AddMinutes(-1) (Get-Date).ToUniversalTime()
    $artifact.source_event_ingestion.identity_diagnostics = Get-EventIdentityDiagnostics $sourceEvents $sourceKey $sourceName
    $artifact.source_event_ingestion.database_verified = @($sourceEvents | Where-Object {
      Test-ExactRegistryEvent $_ $sourceKey
    })
    $artifact.source_event_ingestion.exact_events = $artifact.source_event_ingestion.database_verified
    $artifact.source_event_ingestion.local_sysmon_exact_events = @(
      Get-LocalSysmonRegistryEvents $sourceStart (Get-Date).ToUniversalTime() @($sourceKey)
    )
    if (-not $artifact.source_event_ingestion.native_state_present_after -or
      $artifact.source_event_ingestion.database_verified.Count -eq 0 -or
      $artifact.source_event_ingestion.local_sysmon_exact_events.Count -eq 0) {
      throw "The exact same-host distractor was not independently observed in native state, local Sysmon, and CSG event storage."
    }

    $actionStart = (Get-Date).ToUniversalTime()
    New-ItemProperty -Path $runKeyPath -Name $targetName -PropertyType String `
      -Value "C:\Windows\System32\cmd.exe /c exit 0" -Force | Out-Null
    $actionEnd = (Get-Date).ToUniversalTime()
    $actionJournal.target_create = [ordered]@{
      command = "New-ItemProperty HKCU Run $targetName; inert target, not executed"
      exit_code = 0
      started_at = $actionStart.ToString("o")
      completed_at = $actionEnd.ToString("o")
    }
    Invoke-ProbeOnce
    $artifact.observations.after = Get-LatestObservation
    $artifact.target_state.absent_before = -not (Test-RegistryObjectPresent $baseline $targetKey $targetName)
    $artifact.target_state.present_after = Test-RegistryObjectPresent $artifact.observations.after $targetKey $targetName
    $artifact.target_state.identity_diagnostics = Get-RegistryIdentityDiagnostics $artifact.observations.after $targetKey $targetName
    $artifact.target.sysmon_exact_events = @(
      Get-LocalSysmonRegistryEvents $actionStart (Get-Date).ToUniversalTime() @($targetKey)
    )
    if (-not $artifact.target_state.present_after -or $artifact.target.sysmon_exact_events.Count -eq 0) {
      throw "Native state or local Sysmon did not independently confirm the target mutation."
    }

    Start-Sleep -Seconds $PositiveEventWaitSeconds
    $targetSync = Invoke-CsgPost "/api/hosts/$HostId/provider-sync"
    $actionJournal.provider_sync = $targetSync
    Invoke-CsgPost "/api/pipeline/process-backlog" | Out-Null
    $queryStart = $sourceStart.AddMinutes(-1)
    $queryEnd = (Get-Date).ToUniversalTime()
    $databaseEvents = Get-DatabaseEvents $queryStart $queryEnd
    $providerObservation = Get-ProviderEventObservation $queryStart $queryEnd
    $providerEvents = @($providerObservation.events)
    $targetDatabaseEvents = @($databaseEvents | Where-Object { Test-ExactRegistryEvent $_ $targetKey })
    $distractorDatabaseEvents = @($databaseEvents | Where-Object { Test-ExactRegistryEvent $_ $sourceKey })
    $targetProviderEvents = @($providerEvents | Where-Object { Test-ExactRegistryEvent $_ $targetKey })
    $distractorProviderEvents = @($providerEvents | Where-Object { Test-ExactRegistryEvent $_ $sourceKey })
    $artifact.target.database_identity_diagnostics = Get-EventIdentityDiagnostics $databaseEvents $targetKey $targetName
    $artifact.target.provider_identity_diagnostics = Get-EventIdentityDiagnostics $providerEvents $targetKey $targetName
    $artifact.target.database_exact_events = $targetDatabaseEvents
    $artifact.target.wazuh_provider_exact_events = $targetProviderEvents
    $artifact.source_event_ingestion.database_verified = $distractorDatabaseEvents
    $artifact.source_event_ingestion.exact_events = $distractorDatabaseEvents
    $artifact.source_event_ingestion.provider_observation = $providerObservation
    $artifact.source_event_ingestion.provider_observation_exact_events = $distractorProviderEvents
    $artifact.source_event_ingestion.provider_query_status = if ($providerObservation.query_complete -and
      $providerObservation.coverage_status -eq "COMPLETE" -and
      $providerObservation.endpoint_collection_status -eq "AVAILABLE" -and
      $providerObservation.transport_status -eq "AVAILABLE" -and
      $providerObservation.index_status -eq "AVAILABLE") { "COMPLETE" } else { "INCOMPLETE" }
    $artifact.target.sysmon_exact_events = @(
      Get-LocalSysmonRegistryEvents $actionStart (Get-Date).ToUniversalTime() @($targetKey)
    )
    if ($artifact.source_event_ingestion.provider_query_status -ne "COMPLETE" -or
      $targetDatabaseEvents.Count -eq 0 -or $targetProviderEvents.Count -eq 0 -or
      $distractorDatabaseEvents.Count -eq 0 -or $distractorProviderEvents.Count -eq 0) {
      throw "Complete Wazuh observation must contain exact target and distractor events before reconciliation is evaluated."
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($LifecycleWaitSeconds)
    do {
      $artifact.target.deltas = @(Get-TargetDeltas $targetKey)
      $artifact.target.findings = @(Get-TargetFindings $targetKey)
      $artifact.target.reconciliation_history = @(Get-LatestReconciliation $artifact.target.findings)
      $latest = @($artifact.target.reconciliation_history | Where-Object { $_.latest } |
        Sort-Object { $_.latest.created_at } | Select-Object -Last 1)
      if ($latest.Count -gt 0 -and $latest[0].latest.finalized) { break }
      if ([DateTime]::UtcNow -lt $deadline) { Start-Sleep -Seconds 5 }
    } while ([DateTime]::UtcNow -lt $deadline)
    $artifact.target.findings = @(Get-TargetFindings $targetKey)
    $artifact.target.reconciliation_history = @(Get-LatestReconciliation $artifact.target.findings)
    $latest = @($artifact.target.reconciliation_history | Where-Object { $_.latest } |
      Sort-Object { $_.latest.created_at } | Select-Object -Last 1)
    $final = if ($latest.Count) { $latest[-1].latest } else { $null }
    $artifact.bounded_distractor.finalized_status = if ($final) { [string]$final.status } else { "NO_FINDING" }
    $artifact.bounded_distractor.finalized = [bool]($final -and $final.finalized)
    $artifact.bounded_distractor.matched_ids = Get-MatchedEvidenceIds $final
    $targetIds = @($targetProviderEvents | ForEach-Object { [string]$_.event_id })
    $distractorIds = @($distractorProviderEvents | ForEach-Object { [string]$_.event_id })
    $artifact.bounded_distractor.matched_target_event_ids = @($artifact.bounded_distractor.matched_ids | Where-Object { $_ -in $targetIds })
    $artifact.bounded_distractor.matched_distractor_event_ids = @($artifact.bounded_distractor.matched_ids | Where-Object { $_ -in $distractorIds })
    $targetDelta = @($artifact.target.deltas | Where-Object { $_.delta_type -eq "ADD" } |
      Sort-Object created_at | Select-Object -First 1)
    $targetWindow = if ($targetDelta.Count) { $targetDelta[0].observation_window } else { $null }
    $distractorsInWindow = @()
    if ($targetWindow) {
      $windowStart = ([datetime]$targetWindow.start).ToUniversalTime().AddSeconds(-$ToleranceSeconds)
      $windowEnd = ([datetime]$targetWindow.end).ToUniversalTime().AddSeconds($ToleranceSeconds)
      $distractorsInWindow = @($distractorProviderEvents | Where-Object {
        $_.host_id -eq $HostId -and $_.normalized_type -eq "registry_value_modified" -and
        (Normalize-Identity $_.target.key) -eq (Normalize-Identity $sourceKey) -and
        (Normalize-Identity $_.target.key) -ne (Normalize-Identity $targetKey) -and
        ([datetime]$_.event_time).ToUniversalTime() -ge $windowStart -and
        ([datetime]$_.event_time).ToUniversalTime() -le $windowEnd
      })
    }
    $artifact.bounded_distractor.wrong_object_event_inside_target_window = $distractorsInWindow.Count -gt 0
    $artifact.bounded_distractor.wrong_object_event_ids = @($distractorsInWindow | ForEach-Object { $_.event_id })
    $artifact.target.decision_at = (Get-Date).ToUniversalTime().ToString("o")
  }
  elseif ($Condition -eq "registry_sysmon_target_drop") {
    $sysmonFilterProof = Apply-SysmonRegistryTargetFilter
    $artifact.sysmon_event_filter = $sysmonFilterProof
    $artifact.sysmon_service.before = $sysmonFilterProof.service_before
    $artifact.sysmon_service.during = $sysmonFilterProof.service_after_apply
    if (-not $sysmonFilterProof.manipulation_valid) {
      throw "The exact-target Sysmon exclusion did not pass its active-configuration proof."
    }

    Start-Sleep -Seconds 5
    $stableSysmon = Get-SysmonRuntimeProof
    $artifact.sysmon_event_filter.stability_check = $stableSysmon
    if ($stableSysmon.service_state -ne "Running" -or
        $stableSysmon.config_sha256 -ne $sysmonFilterProof.temporary_config_sha256) {
      throw "Sysmon did not remain stable with the exact-target exclusion active."
    }
    $wazuhDuring = Get-WazuhServiceProof
    $wazuhHealthDuring = Get-WazuhHealthProof
    $artifact.wazuh_service.during = $wazuhDuring
    if ($wazuhDuring.status -ne "Running" -or -not $wazuhHealthDuring.api_ok -or
        $wazuhHealthDuring.endpoint_agent_status -ne "active" -or
        -not $wazuhHealthDuring.manager_api_ok -or -not $wazuhHealthDuring.indexer_ok) {
      throw "Wazuh endpoint/manager/indexer must stay healthy during the Sysmon intervention."
    }

    $actionStart = (Get-Date).ToUniversalTime()
    New-ItemProperty -Path $runKeyPath -Name $targetName -PropertyType String `
      -Value "C:\Windows\System32\cmd.exe /c exit 0" -Force | Out-Null
    $actionEnd = (Get-Date).ToUniversalTime()
    $actionJournal.target_create = [ordered]@{
      command = "New-ItemProperty HKCU Run $targetName under exact Sysmon TargetObject exclusion; inert value, not executed"
      exit_code = 0
      started_at = $actionStart.ToString("o")
      completed_at = $actionEnd.ToString("o")
    }
    Invoke-ProbeOnce
    $afterTarget = Get-LatestObservation
    $artifact.observations.after = $afterTarget
    $artifact.target_state.absent_before = -not (Test-RegistryObjectPresent $baseline $targetKey $targetName)
    $artifact.target_state.present_after = Test-RegistryObjectPresent $afterTarget $targetKey $targetName
    $artifact.target_state.identity_diagnostics = Get-RegistryIdentityDiagnostics $afterTarget $targetKey $targetName
    if (-not $artifact.target_state.absent_before -or -not $artifact.target_state.present_after) {
      throw "The native probe did not prove the target absent-to-present transition."
    }
    Invoke-CsgPost "/api/pipeline/process-backlog" | Out-Null

    $sourceStart = (Get-Date).ToUniversalTime()
    New-ItemProperty -Path $runKeyPath -Name $sourceName -PropertyType String `
      -Value "C:\Windows\System32\cmd.exe /c exit 0" -Force | Out-Null
    $sourceEnd = (Get-Date).ToUniversalTime()
    $actionJournal.distractor_create = [ordered]@{
      command = "New-ItemProperty HKCU Run $sourceName under unchanged include rule; inert same-class distractor, not executed"
      exit_code = 0
      started_at = $sourceStart.ToString("o")
      completed_at = $sourceEnd.ToString("o")
    }
    Invoke-ProbeOnce
    $afterDistractor = Get-LatestObservation
    $artifact.observations.after_distractor = $afterDistractor
    $artifact.source_event_ingestion.native_state_present_after =
      Test-RegistryObjectPresent $afterDistractor $sourceKey $sourceName
    if (-not $artifact.source_event_ingestion.native_state_present_after) {
      throw "The native probe did not observe the distinct distractor state."
    }

    $localEnd = (Get-Date).ToUniversalTime()
    $artifact.target.sysmon_exact_events = @(
      Get-LocalSysmonRegistryEvents $actionStart $localEnd @($targetKey)
    )
    $artifact.source_event_ingestion.local_sysmon_exact_events = @(
      Get-LocalSysmonRegistryEvents $sourceStart $localEnd @($sourceKey)
    )
    if ($artifact.target.sysmon_exact_events.Count -ne 0 -or
        $artifact.source_event_ingestion.local_sysmon_exact_events.Count -eq 0) {
      throw "Local Sysmon must exclude the exact target and retain the exact distractor."
    }

    $artifact.sysmon_event_filter = Restore-SysmonRegistryTargetFilter
    $artifact.sysmon_service.after = Get-SysmonRuntimeProof
    if ($artifact.sysmon_event_filter.status -ne "RESTORED_AND_HEALTHY") {
      throw "Sysmon original configuration did not restore before final evidence collection."
    }
    Start-Sleep -Seconds $PositiveEventWaitSeconds
    $sync = Invoke-CsgPost "/api/hosts/$HostId/provider-sync"
    $actionJournal.provider_sync = $sync
    $queryStart = $actionStart.AddMinutes(-1)
    $queryEnd = (Get-Date).ToUniversalTime()
    $databaseEvents = Get-DatabaseEvents $queryStart $queryEnd
    $artifact.database_event_window = $databaseEvents
    $providerObservation = Get-ProviderEventObservation $queryStart $queryEnd
    $providerEvents = @($providerObservation.events)
    $targetDatabaseEvents = @($databaseEvents | Where-Object { Test-ExactRegistryEvent $_ $targetKey })
    $distractorDatabaseEvents = @($databaseEvents | Where-Object { Test-ExactRegistryEvent $_ $sourceKey })
    $targetProviderEvents = @($providerEvents | Where-Object { Test-ExactRegistryEvent $_ $targetKey })
    $distractorProviderEvents = @($providerEvents | Where-Object { Test-ExactRegistryEvent $_ $sourceKey })
    $artifact.target.database_identity_diagnostics = Get-EventIdentityDiagnostics $databaseEvents $targetKey $targetName
    $artifact.target.provider_identity_diagnostics = Get-EventIdentityDiagnostics $providerEvents $targetKey $targetName
    $artifact.target.database_exact_events = $targetDatabaseEvents
    $artifact.target.wazuh_provider_exact_events = $targetProviderEvents
    $artifact.source_event_ingestion.database_verified = $distractorDatabaseEvents
    $artifact.source_event_ingestion.exact_events = $distractorDatabaseEvents
    $artifact.source_event_ingestion.identity_diagnostics = Get-EventIdentityDiagnostics $providerEvents $sourceKey $sourceName
    $artifact.source_event_ingestion.provider_observation = $providerObservation
    $artifact.source_event_ingestion.provider_observation_exact_events = $distractorProviderEvents
    $providerCoverageComplete = [bool](
      $providerObservation.query_complete -eq $true -and
      $providerObservation.coverage_status -eq "COMPLETE" -and
      $providerObservation.endpoint_collection_status -eq "AVAILABLE" -and
      $providerObservation.transport_status -eq "AVAILABLE" -and
      $providerObservation.index_status -eq "AVAILABLE"
    )
    $artifact.source_event_ingestion.provider_query_status = if ($providerCoverageComplete) { "COMPLETE" } else { "INCOMPLETE" }
    if (-not $providerCoverageComplete -or $targetDatabaseEvents.Count -gt 0 -or
        $targetProviderEvents.Count -gt 0 -or
        $distractorDatabaseEvents.Count -eq 0 -or $distractorProviderEvents.Count -eq 0) {
      throw "Complete Wazuh evidence must omit only the target while retaining the exact distractor."
    }

    Invoke-CsgPost "/api/pipeline/process-backlog" | Out-Null
    $deadline = [DateTime]::UtcNow.AddSeconds($LifecycleWaitSeconds)
    $finalizationSyncTriggered = $false
    $artifact.action_journal.lifecycle_finalization = [ordered]@{
      evidence_deadline = $null
      provider_sync_triggered = $false
      provider_sync = $null
      provider_sync_started_at = $null
      provider_sync_completed_at = $null
      deadline_unavailable = $false
    }
    do {
      $artifact.target.deltas = @(Get-TargetDeltas $targetKey)
      $artifact.target.findings = @(Get-TargetFindings $targetKey)
      $artifact.target.reconciliation_history = @(Get-LatestReconciliation $artifact.target.findings)
      $latest = @($artifact.target.reconciliation_history | Where-Object { $_.latest } |
        Sort-Object { $_.latest.created_at } | Select-Object -Last 1)
      if ($latest.Count -gt 0 -and $latest[0].latest.finalized) { break }
      $evidenceDeadlineText = if ($latest.Count -gt 0) {
        [string]$latest[0].latest.metadata.evidence_deadline
      } else { "" }
      if (-not [string]::IsNullOrWhiteSpace($evidenceDeadlineText)) {
        $evidenceDeadline = [DateTimeOffset]::Parse(
          $evidenceDeadlineText,
          [Globalization.CultureInfo]::InvariantCulture,
          [Globalization.DateTimeStyles]::AssumeUniversal
        ).UtcDateTime
        $artifact.action_journal.lifecycle_finalization.evidence_deadline = $evidenceDeadline.ToString("o")
        if (-not $finalizationSyncTriggered -and [DateTime]::UtcNow -ge $evidenceDeadline) {
          $syncStartedAt = [DateTime]::UtcNow
          $syncResponse = Invoke-CsgPost "/api/hosts/$HostId/provider-sync"
          $syncCompletedAt = [DateTime]::UtcNow
          $artifact.action_journal.lifecycle_finalization.provider_sync_triggered = $true
          $artifact.action_journal.lifecycle_finalization.provider_sync = $syncResponse
          $artifact.action_journal.lifecycle_finalization.provider_sync_started_at = $syncStartedAt.ToString("o")
          $artifact.action_journal.lifecycle_finalization.provider_sync_completed_at = $syncCompletedAt.ToString("o")
          $finalizationSyncTriggered = $true
          continue
        }
      } else {
        $artifact.action_journal.lifecycle_finalization.deadline_unavailable = $true
      }
      if ([DateTime]::UtcNow -lt $deadline) {
        $sleepSeconds = 5
        if (-not $finalizationSyncTriggered -and $evidenceDeadlineText) {
          $untilEvidenceDeadline = [Math]::Ceiling(($evidenceDeadline - [DateTime]::UtcNow).TotalSeconds)
          if ($untilEvidenceDeadline -gt 0) { $sleepSeconds = [Math]::Min($sleepSeconds, $untilEvidenceDeadline) }
        }
        Start-Sleep -Seconds ([Math]::Max(1, $sleepSeconds))
      }
    } while ([DateTime]::UtcNow -lt $deadline)
    $artifact.target.findings = @(Get-TargetFindings $targetKey)
    $artifact.target.reconciliation_history = @(Get-LatestReconciliation $artifact.target.findings)
    $latest = @($artifact.target.reconciliation_history | Where-Object { $_.latest } |
      Sort-Object { $_.latest.created_at } | Select-Object -Last 1)
    $final = if ($latest.Count) { $latest[-1].latest } else { $null }
    $artifact.bounded_distractor.finalized_status = if ($final) { [string]$final.status } else { "NO_FINDING" }
    $artifact.bounded_distractor.finalized = [bool]($final -and $final.finalized)
    $artifact.bounded_distractor.matched_ids = Get-MatchedEvidenceIds $final
    $targetIds = @($targetProviderEvents | ForEach-Object { [string]$_.event_id })
    $distractorIds = @($distractorProviderEvents | ForEach-Object { [string]$_.event_id })
    $artifact.bounded_distractor.matched_target_event_ids = @($artifact.bounded_distractor.matched_ids | Where-Object { $_ -in $targetIds })
    $artifact.bounded_distractor.matched_distractor_event_ids = @($artifact.bounded_distractor.matched_ids | Where-Object { $_ -in $distractorIds })
    $targetDelta = @($artifact.target.deltas | Where-Object { $_.delta_type -eq "ADD" } |
      Sort-Object created_at | Select-Object -First 1)
    $targetWindow = if ($targetDelta.Count) { $targetDelta[0].observation_window } else { $null }
    $distractorsInWindow = @()
    if ($targetWindow) {
      $windowStart = ([datetime]$targetWindow.start).ToUniversalTime().AddSeconds(-$ToleranceSeconds)
      $windowEnd = ([datetime]$targetWindow.end).ToUniversalTime().AddSeconds($ToleranceSeconds)
      $distractorsInWindow = @($distractorProviderEvents | Where-Object {
        $_.host_id -eq $HostId -and $_.normalized_type -eq "registry_value_modified" -and
        (Normalize-Identity $_.target.key) -eq (Normalize-Identity $sourceKey) -and
        ([datetime]$_.event_time).ToUniversalTime() -ge $windowStart -and
        ([datetime]$_.event_time).ToUniversalTime() -le $windowEnd
      })
    }
    $artifact.bounded_distractor.wrong_object_event_inside_target_window = $distractorsInWindow.Count -gt 0
    $artifact.bounded_distractor.wrong_object_event_ids = @($distractorsInWindow | ForEach-Object { $_.event_id })
    $artifact.target.decision_at = (Get-Date).ToUniversalTime().ToString("o")
  }
  elseif ($Condition -in @("registry_selective_drop", "registry_eventid_drop", "registry_distractor_only")) {
    $eventIdOnlyFilter = $Condition -eq "registry_eventid_drop"
    $distractorOnlyFilter = $Condition -eq "registry_distractor_only"
    $targetFilterProof = Apply-RegistryTargetEventFilter -EventIdOnly:$eventIdOnlyFilter -DistractorOnly:$distractorOnlyFilter
    $artifact.target_event_filter = $targetFilterProof
    Start-Sleep -Seconds 30
    $stableService = Get-WazuhServiceProof
    $stableHealth = Get-WazuhHealthProof
    $artifact.target_event_filter.collector_stability = [ordered]@{
      waited_seconds = 30
      captured_at = (Get-Date).ToUniversalTime().ToString("o")
      service = $stableService
      health = $stableHealth
      active = [bool]($stableService.status -eq "Running" -and
        $stableService.process_id -eq $targetFilterProof.service_after_reload.process_id -and
        $stableHealth.api_ok -and $stableHealth.endpoint_agent_status -eq "active" -and
        $stableHealth.manager_api_ok -and $stableHealth.indexer_ok)
    }
    if (-not $artifact.target_event_filter.collector_stability.active) {
      throw "Wazuh agent/collector did not remain healthy through the frozen 30-second post-reload interval."
    }
    $artifact.wazuh_service.during = Get-WazuhServiceProof
    if ($artifact.wazuh_service.during.status -ne "Running" -or
      $artifact.wazuh_service.during.process_id -le 0) {
      throw "Wazuh must remain running while the filtered target mutation is performed."
    }

    $actionStart = (Get-Date).ToUniversalTime()
    New-ItemProperty -Path $runKeyPath -Name $targetName -PropertyType String `
      -Value "C:\Windows\System32\cmd.exe /c exit 0" -Force | Out-Null
    $actionEnd = (Get-Date).ToUniversalTime()
    $actionJournal.target_create = [ordered]@{
      command = "New-ItemProperty HKCU Run $targetName; inert value, not executed"
      exit_code = 0
      started_at = $actionStart.ToString("o")
      completed_at = $actionEnd.ToString("o")
    }
    Invoke-ProbeOnce
    $targetObservation = Get-LatestObservation
    $artifact.observations.after = $targetObservation
    $artifact.target_state.absent_before = -not (Test-RegistryObjectPresent $baseline $targetKey $targetName)
    $artifact.target_state.present_after = Test-RegistryObjectPresent $targetObservation $targetKey $targetName
    $artifact.target_state.identity_diagnostics = Get-RegistryIdentityDiagnostics $targetObservation $targetKey $targetName
    $artifact.target.sysmon_exact_events = @(
      Get-LocalSysmonRegistryEvents $actionStart (Get-Date).ToUniversalTime() @($targetKey)
    )
    if (-not $artifact.target_state.present_after -or $artifact.target.sysmon_exact_events.Count -eq 0) {
      throw "The native probe or local Sysmon did not independently confirm the target mutation."
    }

    $sourceStart = (Get-Date).ToUniversalTime()
    New-ItemProperty -Path $runKeyPath -Name $sourceName -PropertyType String `
      -Value "C:\Windows\System32\cmd.exe /c exit 0" -Force | Out-Null
    $sourceEnd = (Get-Date).ToUniversalTime()
    $actionJournal.distractor_create = [ordered]@{
      command = "New-ItemProperty HKCU Run $sourceName; distinct inert same-class distractor"
      exit_code = 0
      started_at = $sourceStart.ToString("o")
      completed_at = $sourceEnd.ToString("o")
    }
    Invoke-ProbeOnce
    $afterDistractor = Get-LatestObservation
    $artifact.observations.after_distractor = $afterDistractor
    $artifact.source_event_ingestion.native_state_present_after =
      Test-RegistryObjectPresent $afterDistractor $sourceKey $sourceName
    Start-Sleep -Seconds $PositiveEventWaitSeconds
    $sync = Invoke-CsgPost "/api/hosts/$HostId/provider-sync"
    $artifact.action_journal.provider_sync = $sync
    $sourceQuery = Get-DatabaseEvents $sourceStart.AddMinutes(-1) (Get-Date).ToUniversalTime()
    $artifact.source_event_ingestion.provider_sync = $sync
    $artifact.source_event_ingestion.identity_diagnostics = Get-EventIdentityDiagnostics $sourceQuery $sourceKey $sourceName
    $artifact.source_event_ingestion.database_verified = @($sourceQuery | Where-Object {
      Test-ExactRegistryEvent $_ $sourceKey
    })
    $artifact.source_event_ingestion.local_sysmon_exact_events = @(
      Get-LocalSysmonRegistryEvents $sourceStart $sourceEnd @($sourceKey)
    )

    $queryStart = $actionStart.AddMinutes(-1)
    $queryEnd = (Get-Date).ToUniversalTime()
    $databaseQuery = Get-DatabaseEvents $queryStart $queryEnd
    $providerQuery = Get-ProviderEvents $queryStart $queryEnd
    $providerObservation = Get-ProviderEventObservation $queryStart $queryEnd
    $providerObservedEvents = @($providerObservation.events)
    $providerTargetEvents = @($providerObservedEvents | Where-Object {
      Test-ExactRegistryEvent $_ $targetKey
    })
    $providerDistractorEvents = @($providerObservedEvents | Where-Object {
      Test-ExactRegistryEvent $_ $sourceKey
    })
    $targetNativeFilterProofs = @($artifact.target.sysmon_exact_events | ForEach-Object {
      Get-NativeFilteredRecordProof $targetFilterProof.query ([long]$_.record_id)
    })
    $distractorNativeFilterProofs = @($artifact.source_event_ingestion.local_sysmon_exact_events | ForEach-Object {
      Get-NativeFilteredRecordProof $targetFilterProof.query ([long]$_.record_id)
    })
    $nativeFilterLogicValid = [bool](
      $targetNativeFilterProofs.Count -gt 0 -and
      @($targetNativeFilterProofs | Where-Object { -not $_.query_completed -or $_.returned_by_filter }).Count -eq 0 -and
      $distractorNativeFilterProofs.Count -gt 0 -and
      @($distractorNativeFilterProofs | Where-Object {
        -not $_.query_completed -or ($eventIdOnlyFilter -and $_.returned_by_filter) -or
        (-not $eventIdOnlyFilter -and -not $_.returned_by_filter)
      }).Count -eq 0
    )
    $artifact.target_event_filter.native_object_filter_validation = [ordered]@{
      target_record_proofs = $targetNativeFilterProofs
      distractor_record_proofs = $distractorNativeFilterProofs
      logic_valid = $nativeFilterLogicValid
    }
    $providerCoverageComplete = [bool](
      $providerObservation.query_complete -eq $true -and
      $providerObservation.coverage_status -eq "COMPLETE" -and
      $providerObservation.endpoint_collection_status -eq "AVAILABLE" -and
      $providerObservation.transport_status -eq "AVAILABLE" -and
      $providerObservation.index_status -eq "AVAILABLE"
    )
    $artifact.source_event_ingestion.provider_observation = $providerObservation
    $artifact.source_event_ingestion.provider_observation_exact_events = $providerDistractorEvents
    $artifact.source_event_ingestion.provider_query_status = if ($providerCoverageComplete) { "COMPLETE" } else { "INCOMPLETE" }
    $artifact.target.database_identity_diagnostics = Get-EventIdentityDiagnostics $databaseQuery $targetKey $targetName
    $artifact.target.provider_identity_diagnostics = Get-EventIdentityDiagnostics $providerQuery $targetKey $targetName
    $artifact.target.database_exact_events = @($databaseQuery | Where-Object {
      Test-ExactRegistryEvent $_ $targetKey
    })
    $artifact.target.wazuh_provider_exact_events = @($providerQuery | Where-Object {
      Test-ExactRegistryEvent $_ $targetKey
    })
    $artifact.source_event_ingestion.exact_events = @($databaseQuery | Where-Object {
      Test-ExactRegistryEvent $_ $sourceKey
    })
    if (-not $providerCoverageComplete) {
      throw "Direct Wazuh event observation was incomplete; event absence cannot be interpreted."
    }
    if ($providerTargetEvents.Count -gt 0 -or $artifact.target.database_exact_events.Count -gt 0 -or
      $artifact.target.wazuh_provider_exact_events.Count -gt 0) {
      throw "The target-specific Sysmon event reached Wazuh or CSG despite the configured filter."
    }
    if (-not $eventIdOnlyFilter -and $providerDistractorEvents.Count -eq 0) {
      throw "Complete Wazuh observation did not contain the exact same-host distractor event."
    }
    if ($eventIdOnlyFilter -and ($providerDistractorEvents.Count -gt 0 -or
      $artifact.source_event_ingestion.database_verified.Count -gt 0 -or
      $artifact.source_event_ingestion.exact_events.Count -gt 0)) {
      throw "Wazuh event-ID exclusion did not suppress both randomized Event ID 13 records."
    }

    Invoke-CsgPost "/api/pipeline/process-backlog" | Out-Null
    $deadline = [DateTime]::UtcNow.AddSeconds($LifecycleWaitSeconds)
    do {
      $artifact.target.deltas = @(Get-TargetDeltas $targetKey)
      $artifact.target.findings = @(Get-TargetFindings $targetKey)
      $artifact.target.reconciliation_history = @(Get-LatestReconciliation $artifact.target.findings)
      $latest = @($artifact.target.reconciliation_history | Where-Object { $_.latest } |
        Sort-Object { $_.latest.created_at } | Select-Object -Last 1)
      if ($latest.Count -gt 0 -and $latest[0].latest.finalized) { break }
      if ([DateTime]::UtcNow -lt $deadline) { Start-Sleep -Seconds 5 }
    } while ([DateTime]::UtcNow -lt $deadline)

    $artifact.bounded_distractor.backlog_response = Invoke-CsgPost "/api/pipeline/process-backlog"
    $artifact.target.findings = @(Get-TargetFindings $targetKey)
    $artifact.target.reconciliation_history = @(Get-LatestReconciliation $artifact.target.findings)
    $latest = @($artifact.target.reconciliation_history | Where-Object { $_.latest } |
      Sort-Object { $_.latest.created_at } | Select-Object -Last 1)
    $final = if ($latest.Count) { $latest[-1].latest } else { $null }
    $artifact.bounded_distractor.finalized_status = if ($final) { [string]$final.status } else { "NO_FINDING" }
    $artifact.bounded_distractor.finalized = [bool]($final -and $final.finalized)
    $artifact.bounded_distractor.matched_ids = Get-MatchedEvidenceIds $final
    $artifact.target.decision_at = (Get-Date).ToUniversalTime().ToString("o")
    $targetDelta = @($artifact.target.deltas | Where-Object { $_.delta_type -eq "ADD" } |
      Sort-Object created_at | Select-Object -First 1)
    $targetWindow = if ($targetDelta.Count) { $targetDelta[0].observation_window } else { $null }
    $wrongObjectEvents = @($artifact.source_event_ingestion.database_verified | Where-Object {
      $_.host_id -eq $HostId -and $_.normalized_type -eq "registry_value_modified" -and
      (Normalize-Identity $_.target.key) -eq (Normalize-Identity $sourceKey) -and
      (Normalize-Identity $_.target.key) -ne (Normalize-Identity $targetKey)
    })
    if ($targetWindow -and $wrongObjectEvents.Count) {
      $windowStart = ([datetime]$targetWindow.start).ToUniversalTime().AddSeconds(-$ToleranceSeconds)
      $windowEnd = ([datetime]$targetWindow.end).ToUniversalTime().AddSeconds($ToleranceSeconds)
      $insideWindow = @($wrongObjectEvents | Where-Object {
        $eventTime = ([datetime]$_.event_time).ToUniversalTime()
        $eventTime -ge $windowStart -and $eventTime -le $windowEnd
      })
      $artifact.bounded_distractor.wrong_object_event_inside_target_window = $insideWindow.Count -gt 0
      $artifact.bounded_distractor.wrong_object_event_ids = @($insideWindow | ForEach-Object { $_.event_id })
    }
    $artifact.target_event_filter.observation = [ordered]@{
      filter_scope = $artifact.target_event_filter.filter_scope
      local_target_sysmon_event_count = $artifact.target.sysmon_exact_events.Count
      direct_wazuh_target_event_count = $providerTargetEvents.Count
      csg_database_target_event_count = $artifact.target.database_exact_events.Count
      csg_provider_target_event_count = $artifact.target.wazuh_provider_exact_events.Count
      direct_wazuh_distractor_event_count = $providerDistractorEvents.Count
      local_distractor_sysmon_event_count = $artifact.source_event_ingestion.local_sysmon_exact_events.Count
      csg_database_distractor_event_count = $artifact.source_event_ingestion.database_verified.Count
      native_distractor_state_present = [bool]$artifact.source_event_ingestion.native_state_present_after
      local_distractor_same_host_event_class = [bool]($artifact.source_event_ingestion.local_sysmon_exact_events.Count -gt 0)
      distractor_same_host_and_event_type = [bool]($artifact.source_event_ingestion.database_verified.Count -gt 0 -and
        @($artifact.source_event_ingestion.database_verified | Where-Object {
          $_.host_id -eq $HostId -and $_.normalized_type -eq "registry_value_modified"
        }).Count -eq $artifact.source_event_ingestion.database_verified.Count)
      event_query_complete = [bool]$providerObservation.query_complete
      coverage_status = [string]$providerObservation.coverage_status
      endpoint_collection_status = [string]$providerObservation.endpoint_collection_status
      transport_status = [string]$providerObservation.transport_status
      index_status = [string]$providerObservation.index_status
      wazuh_service_pid_during_target = [int]$artifact.wazuh_service.during.process_id
      wazuh_service_pid_after_filter_reload = [int]$artifact.target_event_filter.service_after_reload.process_id
      target_reconciliation_status = $artifact.bounded_distractor.finalized_status
    }
    $distractorPlaneExpectation = if ($eventIdOnlyFilter) {
      $artifact.target_event_filter.observation.local_distractor_sysmon_event_count -gt 0 -and
      $artifact.target_event_filter.observation.direct_wazuh_distractor_event_count -eq 0 -and
      $artifact.target_event_filter.observation.csg_database_distractor_event_count -eq 0
    } else {
      $artifact.target_event_filter.observation.direct_wazuh_distractor_event_count -gt 0 -and
      $artifact.target_event_filter.observation.csg_database_distractor_event_count -gt 0 -and
      $artifact.target_event_filter.observation.native_distractor_state_present -and
      $artifact.target_event_filter.observation.distractor_same_host_and_event_type
    }
    $artifact.target_event_filter.manipulation_valid = (
      $artifact.target_event_filter.status -eq "APPLIED_AND_HEALTHY" -and
      $artifact.target_event_filter.collector_stability.active -and
      $artifact.target_event_filter.observation.local_target_sysmon_event_count -gt 0 -and
      $artifact.target_event_filter.observation.direct_wazuh_target_event_count -eq 0 -and
      $artifact.target_event_filter.observation.csg_database_target_event_count -eq 0 -and
      $artifact.target_event_filter.observation.csg_provider_target_event_count -eq 0 -and
      $distractorPlaneExpectation -and
      $artifact.target_event_filter.observation.event_query_complete -and
      $artifact.target_event_filter.observation.coverage_status -eq "COMPLETE" -and
      $artifact.target_event_filter.observation.endpoint_collection_status -eq "AVAILABLE" -and
      $artifact.target_event_filter.observation.transport_status -eq "AVAILABLE" -and
      $artifact.target_event_filter.observation.index_status -eq "AVAILABLE" -and
      $artifact.wazuh_service.during.status -eq "Running" -and
      $artifact.target_event_filter.native_object_filter_validation.logic_valid -and
      $artifact.target_event_filter.observation.wazuh_service_pid_during_target -eq
        $artifact.target_event_filter.observation.wazuh_service_pid_after_filter_reload -and
      $artifact.bounded_distractor.finalized -and
      $artifact.bounded_distractor.finalized_status -eq "UNEXPLAINED" -and
      $artifact.bounded_distractor.matched_ids.Count -eq 0
    )
  }
  else {
    $sourceStart = (Get-Date).ToUniversalTime()
    New-ItemProperty -Path $runKeyPath -Name $sourceName -PropertyType String `
      -Value "C:\Windows\System32\cmd.exe /c exit 0" -Force | Out-Null
    $sourceEnd = (Get-Date).ToUniversalTime()
    $actionJournal.distractor_create = [ordered]@{
      command = "New-ItemProperty HKCU Run $sourceName; inert value, not executed"
      exit_code = 0
      started_at = $sourceStart.ToString("o")
      completed_at = $sourceEnd.ToString("o")
    }
    Start-Sleep -Seconds $PositiveEventWaitSeconds
    $sourceSync = Invoke-CsgPost "/api/hosts/$HostId/provider-sync"
    $artifact.source_event_ingestion.provider_query_status = "PROVIDER_SYNC_COMPLETED"
    $artifact.source_event_ingestion.provider_sync = $sourceSync
    $sourceQuery = Get-DatabaseEvents $sourceStart.AddMinutes(-1) (Get-Date).ToUniversalTime()
    $artifact.source_event_ingestion.identity_diagnostics = Get-EventIdentityDiagnostics $sourceQuery $sourceKey $sourceName
    $artifact.source_event_ingestion.database_verified = @($sourceQuery | Where-Object {
      Test-ExactRegistryEvent $_ $sourceKey
    })
    if ($artifact.source_event_ingestion.database_verified.Count -eq 0) {
      throw "Provider sync completed, but no exact distractor Wazuh event was verified in CSG before target mutation."
    }
    $artifact.source_event_ingestion.local_sysmon_exact_events = @(
      Get-LocalSysmonRegistryEvents $sourceStart $sourceEnd @($sourceKey)
    )

    $wazuhBeforeStop = Get-WazuhServiceProof
    Stop-Service -Name WazuhSvc
    (Get-Service -Name WazuhSvc).WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20))
    $wazuhDuring = Get-WazuhServiceProof
    if ($wazuhDuring.status -ne "Stopped") { throw "WazuhSvc did not stop before target mutation." }
    $wazuhStoppedByTrial = $true
    $artifact.wazuh_service.during = $wazuhDuring

    $targetStart = (Get-Date).ToUniversalTime()
    New-ItemProperty -Path $runKeyPath -Name $targetName -PropertyType String `
      -Value "C:\Windows\System32\cmd.exe /c exit 0" -Force | Out-Null
    $targetEnd = (Get-Date).ToUniversalTime()
    $actionJournal.target_create = [ordered]@{
      command = "New-ItemProperty HKCU Run $targetName while WazuhSvc is stopped; inert value, not executed"
      exit_code = 0
      started_at = $targetStart.ToString("o")
      completed_at = $targetEnd.ToString("o")
    }
    Invoke-ProbeOnce
    $targetObservation = Get-LatestObservation
    $artifact.observations.after = $targetObservation
    $artifact.target.deltas = @(Get-TargetDeltas $targetKey)
    $artifact.target.findings = @(Get-TargetFindings $targetKey)
    $artifact.source_event_ingestion.local_sysmon_exact_events = @(
      Get-LocalSysmonRegistryEvents $sourceStart $sourceEnd @($sourceKey)
    )
    $artifact.target.sysmon_exact_events = @(
      Get-LocalSysmonRegistryEvents $targetStart (Get-Date).ToUniversalTime() @($targetKey)
    )
    $artifact.target_state.absent_before = -not (Test-RegistryObjectPresent $baseline $targetKey $targetName)
    $artifact.target_state.present_after = Test-RegistryObjectPresent $targetObservation $targetKey $targetName
    $artifact.target_state.identity_diagnostics = Get-RegistryIdentityDiagnostics $targetObservation $targetKey $targetName
    $targetQuery = Get-DatabaseEvents $baselineTime.AddSeconds(-$ToleranceSeconds) (Get-Date).ToUniversalTime()
    $artifact.target.database_identity_diagnostics = Get-EventIdentityDiagnostics $targetQuery $targetKey $targetName
    $artifact.target.database_exact_events = @($targetQuery | Where-Object {
      Test-ExactRegistryEvent $_ $targetKey
    })
    Start-Sleep -Seconds $LifecycleWaitSeconds
    $artifact.bounded_distractor.backlog_response = Invoke-CsgPost "/api/pipeline/process-backlog"
    $artifact.target.findings = @(Get-TargetFindings $targetKey)
    $artifact.target.reconciliation_history = @(Get-LatestReconciliation $artifact.target.findings)
    $artifact.bounded_distractor.finalized_status = if ($artifact.target.reconciliation_history.Count) {
      [string]$artifact.target.reconciliation_history[-1].latest.status
    } else { "NO_FINDING" }
    $artifact.target.decision_at = (Get-Date).ToUniversalTime().ToString("o")
    $latestReconciliation = if ($artifact.target.reconciliation_history.Count) {
      $artifact.target.reconciliation_history[-1].latest
    } else { $null }
    $artifact.bounded_distractor.matched_ids = Get-MatchedEvidenceIds $latestReconciliation
    $targetDelta = @($artifact.target.deltas | Where-Object { $_.delta_type -eq "ADD" }) | Select-Object -First 1
    $targetWindow = if ($targetDelta) { $targetDelta.observation_window } else { $null }
    $wrongObjectEvents = @($artifact.source_event_ingestion.database_verified | Where-Object {
      $_.normalized_type -eq "registry_value_modified" -and $_.host_id -eq $HostId -and
      (Normalize-Identity $_.target.key) -ne (Normalize-Identity $targetKey)
    })
    if ($targetWindow -and $wrongObjectEvents.Count) {
      $windowStart = ([datetime]$targetWindow.start).ToUniversalTime().AddSeconds(-$ToleranceSeconds)
      $windowEnd = ([datetime]$targetWindow.end).ToUniversalTime().AddSeconds($ToleranceSeconds)
      $artifact.bounded_distractor.wrong_object_event_inside_target_window = @($wrongObjectEvents | Where-Object {
        $eventTime = ([datetime]$_.event_time).ToUniversalTime()
        $eventTime -ge $windowStart -and $eventTime -le $windowEnd
      }).Count -gt 0
    }
    $artifact.bounded_distractor.wrong_object_event_ids = @($wrongObjectEvents | ForEach-Object { $_.event_id })
    $artifact.target.database_exact_events = @(Get-DatabaseEvents $baselineTime.AddSeconds(-$ToleranceSeconds) (Get-Date).ToUniversalTime() | Where-Object {
      Test-ExactRegistryEvent $_ $targetKey
    })
    $artifact.action_journal.wazuh_stop_proof = [ordered]@{
      before_target = $wazuhBeforeStop
      during_target = $wazuhDuring
    }
  }
}
catch {
  $errors.Add($_.Exception.Message)
  $artifact.failure_detail = [ordered]@{
    message = $_.Exception.Message
    category = [string]$_.CategoryInfo.Category
    fully_qualified_error_id = $_.FullyQualifiedErrorId
    script_stack_trace = $_.ScriptStackTrace
    position_message = $_.InvocationInfo.PositionMessage
  }
}
finally {
  $artifact.cleanup.started_at = (Get-Date).ToUniversalTime().ToString("o")
  try {
    if ($sysmonFilterApplied) {
      $artifact.sysmon_event_filter = Restore-SysmonRegistryTargetFilter
    } elseif ($sysmonTemporaryPath -and (Test-Path -LiteralPath $sysmonTemporaryPath)) {
      Remove-Item -LiteralPath $sysmonTemporaryPath -Force -ErrorAction Stop
    }
    if ($Condition -eq "registry_sysmon_target_drop") {
      $artifact.sysmon_service.after = Get-SysmonRuntimeProof
    }
  } catch { $errors.Add("Sysmon configuration restore/postflight failed: $($_.Exception.Message)") }

  try {
    if ($wazuhStoppedByTrial) {
      Start-Service -Name WazuhSvc
      (Get-Service -Name WazuhSvc).WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
    }
    if (-not $targetFilterApplied) { $artifact.wazuh_service.after = Get-WazuhServiceProof }
  } catch { $errors.Add("Wazuh restore/postflight failed: $($_.Exception.Message)") }

  try {
    Remove-ItemProperty -Path $runKeyPath -Name $targetName -Force -ErrorAction SilentlyContinue
    if ($sourceName) {
      Remove-ItemProperty -Path $runKeyPath -Name $sourceName -Force -ErrorAction SilentlyContinue
    }
    Invoke-ProbeOnce
    $cleanupObservation = Get-LatestObservation
    $artifact.observations.cleanup = $cleanupObservation
    $artifact.cleanup.target_absent = -not (Test-RegistryObjectPresent $cleanupObservation $targetKey $targetName)
    $artifact.cleanup.distractor_absent = if ($sourceKey) {
      -not (Test-RegistryObjectPresent $cleanupObservation $sourceKey $sourceName)
    } else { $true }
    $artifact.cleanup.cleanup_probe_succeeded = $true
    $artifact.cleanup.completed_at = (Get-Date).ToUniversalTime().ToString("o")
  } catch { $errors.Add("Registry cleanup/probe verification failed: $($_.Exception.Message)") }

  try {
    if ($taskDisabled -and $taskBefore.enabled) {
      Enable-ScheduledTask -TaskName "CyberStateGuardian Probe" | Out-Null
      if ($taskBefore.state -eq "Running") { Start-ScheduledTask -TaskName "CyberStateGuardian Probe" }
    }
    $taskAfter = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction SilentlyContinue
    $artifact.scheduled_probe_task.after = if ($taskAfter) {
      [ordered]@{ enabled = [bool]$taskAfter.Settings.Enabled; state = [string]$taskAfter.State }
    } else { [ordered]@{ not_installed = $true } }
  } catch { $errors.Add("Probe-task restoration failed: $($_.Exception.Message)") }

  try {
    if ($targetFilterApplied) {
      $artifact.target_event_filter = Restore-RegistryTargetEventFilter
    }
    $artifact.wazuh_service.after = Get-WazuhServiceProof
  } catch { $errors.Add("Wazuh configuration restore/postflight failed: $($_.Exception.Message)") }
}

$artifact.ended_at = (Get-Date).ToUniversalTime().ToString("o")
$artifact.cleanup.errors = @($errors)
$artifact.cleanup.target_absent = $artifact.cleanup.target_absent -eq $true
$artifact.cleanup.distractor_absent = $artifact.cleanup.distractor_absent -ne $false
$artifact.cleanup.cleanup_probe_succeeded = $artifact.cleanup.cleanup_probe_succeeded -eq $true
$artifact.protocol_adherent = $errors.Count -eq 0 -and
  $artifact.scheduled_probe_task.during.enabled -eq $false -and
  $artifact.scheduled_probe_task.after.enabled -eq $taskBefore.enabled -and
  ($Condition -notin @("registry_selective_drop", "registry_eventid_drop", "registry_distractor_only") -or
    $artifact.target_event_filter.status -eq "RESTORED_AND_HEALTHY") -and
  ($Condition -ne "registry_distractor_only" -or
    $artifact.target_event_filter.status -eq "RESTORED_AND_HEALTHY") -and
  ($Condition -ne "registry_sysmon_target_drop" -or
    ($artifact.sysmon_event_filter.manipulation_valid -and
      $artifact.sysmon_event_filter.status -eq "RESTORED_AND_HEALTHY" -and
      $artifact.sysmon_event_filter.restore.temporary_config_removed -and
      $artifact.sysmon_event_filter.restore.restored_config_sha256 -eq
        $artifact.sysmon_event_filter.original_config_sha256)) -and
  $artifact.cleanup.target_absent -and $artifact.cleanup.distractor_absent
$artifact.trial_pass = if ($Condition -eq "registry_complete") {
  $artifact.protocol_adherent -and
    $artifact.target_state.absent_before -and $artifact.target_state.present_after -and
    @($artifact.target.deltas | Where-Object { $_.delta_type -eq "ADD" }).Count -eq 1 -and
    $artifact.target.sysmon_exact_events.Count -gt 0 -and
    $artifact.target.wazuh_provider_exact_events.Count -gt 0 -and
    @($artifact.target.reconciliation_history | Where-Object {
      $_.latest.status -eq "CONSISTENT" -and
      $_.latest.matched_evidence_ids.Count -gt 0
    }).Count -gt 0
} elseif ($Condition -eq "registry_wrong_object") {
  $artifact.protocol_adherent -and
    $artifact.target_state.absent_before -and $artifact.target_state.present_after -and
    @($artifact.target.deltas | Where-Object { $_.delta_type -eq "ADD" }).Count -eq 1 -and
    $artifact.target.sysmon_exact_events.Count -gt 0 -and
    $artifact.source_event_ingestion.database_verified.Count -gt 0 -and
    $artifact.bounded_distractor.wrong_object_event_inside_target_window -and
    $artifact.bounded_distractor.finalized_status -eq "UNEXPLAINED" -and
    $artifact.bounded_distractor.matched_ids.Count -eq 0
} elseif ($Condition -eq "registry_selective_drop") {
  $artifact.protocol_adherent -and
    $artifact.target_state.absent_before -and $artifact.target_state.present_after -and
    @($artifact.target.deltas | Where-Object { $_.delta_type -eq "ADD" }).Count -eq 1 -and
    $artifact.target.sysmon_exact_events.Count -gt 0 -and
    $artifact.source_event_ingestion.database_verified.Count -gt 0 -and
    $artifact.bounded_distractor.wrong_object_event_inside_target_window -and
    $artifact.target_event_filter.manipulation_valid -and
    $artifact.target_event_filter.status -eq "RESTORED_AND_HEALTHY" -and
    $artifact.bounded_distractor.finalized -and
    $artifact.bounded_distractor.finalized_status -eq "UNEXPLAINED" -and
    $artifact.bounded_distractor.matched_ids.Count -eq 0
} elseif ($Condition -eq "registry_eventid_drop") {
  $artifact.protocol_adherent -and
    $artifact.target_state.absent_before -and $artifact.target_state.present_after -and
    @($artifact.target.deltas | Where-Object { $_.delta_type -eq "ADD" }).Count -eq 1 -and
    $artifact.target.sysmon_exact_events.Count -gt 0 -and
    $artifact.source_event_ingestion.local_sysmon_exact_events.Count -gt 0 -and
    $artifact.target_event_filter.manipulation_valid -and
    $artifact.target_event_filter.status -eq "RESTORED_AND_HEALTHY" -and
    $artifact.bounded_distractor.finalized -and
    $artifact.bounded_distractor.finalized_status -eq "UNEXPLAINED" -and
    $artifact.bounded_distractor.matched_ids.Count -eq 0
} elseif ($Condition -eq "registry_distractor_only") {
  $artifact.protocol_adherent -and
    $artifact.target_state.absent_before -and $artifact.target_state.present_after -and
    @($artifact.target.deltas | Where-Object { $_.delta_type -eq "ADD" }).Count -eq 1 -and
    $artifact.target.sysmon_exact_events.Count -gt 0 -and
    $artifact.source_event_ingestion.database_verified.Count -gt 0 -and
    $artifact.bounded_distractor.wrong_object_event_inside_target_window -and
    $artifact.target_event_filter.manipulation_valid -and
    $artifact.target_event_filter.status -eq "RESTORED_AND_HEALTHY" -and
    $artifact.bounded_distractor.finalized -and
    $artifact.bounded_distractor.finalized_status -eq "UNEXPLAINED" -and
    $artifact.bounded_distractor.matched_ids.Count -eq 0
} elseif ($Condition -eq "registry_competing_event") {
  $artifact.protocol_adherent -and
    $artifact.target_state.absent_before -and $artifact.target_state.present_after -and
    @($artifact.target.deltas | Where-Object { $_.delta_type -eq "ADD" }).Count -eq 1 -and
    $artifact.target.sysmon_exact_events.Count -gt 0 -and
    $artifact.target.wazuh_provider_exact_events.Count -gt 0 -and
    $artifact.source_event_ingestion.database_verified.Count -gt 0 -and
    $artifact.source_event_ingestion.provider_observation_exact_events.Count -gt 0 -and
    $artifact.bounded_distractor.wrong_object_event_inside_target_window -and
    $artifact.bounded_distractor.finalized -and
    $artifact.bounded_distractor.finalized_status -eq "CONSISTENT" -and
    $artifact.bounded_distractor.matched_target_event_ids.Count -gt 0 -and
    $artifact.bounded_distractor.matched_distractor_event_ids.Count -eq 0
} elseif ($Condition -eq "registry_sysmon_target_drop") {
  $artifact.protocol_adherent -and
    $artifact.target_state.absent_before -and $artifact.target_state.present_after -and
    @($artifact.target.deltas | Where-Object { $_.delta_type -eq "ADD" }).Count -eq 1 -and
    @($artifact.target.findings).Count -eq 1 -and
    $artifact.target.sysmon_exact_events.Count -eq 0 -and
    $artifact.target.wazuh_provider_exact_events.Count -eq 0 -and
    $artifact.target.database_exact_events.Count -eq 0 -and
    $artifact.source_event_ingestion.native_state_present_after -and
    $artifact.source_event_ingestion.local_sysmon_exact_events.Count -gt 0 -and
    $artifact.source_event_ingestion.provider_observation_exact_events.Count -gt 0 -and
    $artifact.source_event_ingestion.database_verified.Count -gt 0 -and
    $artifact.source_event_ingestion.provider_query_status -eq "COMPLETE" -and
    $artifact.action_journal.lifecycle_finalization.provider_sync_triggered -and
    $artifact.action_journal.lifecycle_finalization.provider_sync_started_at -and
    ([datetimeoffset]$artifact.action_journal.lifecycle_finalization.provider_sync_started_at).UtcDateTime -ge
      ([datetimeoffset]$artifact.action_journal.lifecycle_finalization.evidence_deadline).UtcDateTime -and
    $artifact.bounded_distractor.wrong_object_event_inside_target_window -and
    $artifact.bounded_distractor.finalized -and
    $artifact.bounded_distractor.finalized_status -eq "UNEXPLAINED" -and
    $artifact.bounded_distractor.matched_ids.Count -eq 0
} else {
  $artifact.protocol_adherent -and
    $artifact.no_change_control.target_absent_before -and
    $artifact.no_change_control.target_absent_after -and
    -not $artifact.target_state.present_after -and
    $artifact.no_change_control.new_delta_count -eq 0 -and
    $artifact.no_change_control.new_finding_count -eq 0 -and
    $artifact.target.sysmon_exact_events.Count -eq 0 -and
    $artifact.target.database_exact_events.Count -eq 0 -and
    $artifact.target.wazuh_provider_exact_events.Count -eq 0 -and
    $artifact.source_event_ingestion.provider_query_status -eq "COMPLETE"
}
Save-Json $OutputPath $artifact
Write-Host "Trial artifact: $OutputPath"
Write-Host "Condition=$Condition; pass=$($artifact.trial_pass); cleanup=$($artifact.cleanup.target_absent)/$($artifact.cleanup.distractor_absent); errors=$($errors.Count)"
if ($errors.Count -gt 0) { throw ($errors -join "; ") }
