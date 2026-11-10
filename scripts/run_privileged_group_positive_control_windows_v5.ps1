param(
  [string]$ProbeSettingsPath = "$env:ProgramFiles\CyberStateGuardian\Probe\settings.json",
  [Parameter(Mandatory=$true)][string]$ProtocolPath,
  [Parameter(Mandatory=$true)][string]$FreezeManifestPath,
  [string]$OutputRoot = "$env:ProgramData\CyberStateGuardian\Research\privileged-group",
  [ValidateRange(60,300)][int]$EvidenceWaitSeconds = 300
)

$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw 'Run from an elevated Administrator PowerShell session.' }
if (-not (Test-Path -LiteralPath $ProbeSettingsPath)) { throw 'Probe settings file is missing.' }
if (-not (Test-Path -LiteralPath $ProtocolPath)) { throw 'Frozen protocol file is missing.' }
if (-not (Test-Path -LiteralPath $FreezeManifestPath)) { throw 'Frozen source manifest is missing.' }

$runnerHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$protocolHash = (Get-FileHash -LiteralPath $ProtocolPath -Algorithm SHA256).Hash.ToLowerInvariant()
$freezeHash = (Get-FileHash -LiteralPath $FreezeManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$freeze = Get-Content -LiteralPath $FreezeManifestPath -Raw | ConvertFrom-Json
if ($freeze.protocol_id -ne 'csg-privileged-group-positive-control-v5' -or
    $freeze.runner_sha256 -ne $runnerHash -or $freeze.protocol_sha256 -ne $protocolHash) {
  throw 'Runner or protocol hash differs from the frozen source manifest.'
}

$settings = Get-Content -LiteralPath $ProbeSettingsPath -Raw | ConvertFrom-Json
if (-not $settings.CSG_TRANSITION_CAPTURE_ENABLED -or
    -not $settings.CSG_TRANSITION_PRIVILEGED_GROUPS_ENABLED) {
  throw 'CSG privileged-group transition capture must be enabled in the probe settings.'
}
$python = Join-Path (Split-Path -Parent $ProbeSettingsPath) 'venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw 'Installed probe Python is missing.' }
$probeUri = [Uri]$settings.CSG_PROBE_API_URL
$apiPath = $probeUri.AbsolutePath -replace '/probe/observations/?$', ''
$apiRoot = "{0}://{1}{2}" -f $probeUri.Scheme, $probeUri.Authority, $apiPath.TrimEnd('/')
$hostId = [string]$settings.CSG_PROBE_HOST_ID
$group = Get-LocalGroup -SID 'S-1-5-32-544'
$wazuhService = Get-Service -Name WazuhSvc -ErrorAction Stop
if ($wazuhService.Status -ne 'Running') { throw 'WazuhSvc is not running.' }

$runId = "privileged-group-positive-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))-$([guid]::NewGuid().ToString('N').Substring(0,8))"
$runDirectory = Join-Path $OutputRoot $runId
if (Test-Path -LiteralPath $runDirectory) { throw "Refusing to overwrite $runDirectory." }
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
$frozenSourceDirectory = Join-Path $runDirectory 'frozen-source'
New-Item -ItemType Directory -Path $frozenSourceDirectory -Force | Out-Null
Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $frozenSourceDirectory (Split-Path -Leaf $PSCommandPath))
Copy-Item -LiteralPath $ProtocolPath -Destination (Join-Path $frozenSourceDirectory (Split-Path -Leaf $ProtocolPath))
Copy-Item -LiteralPath $FreezeManifestPath -Destination (Join-Path $frozenSourceDirectory (Split-Path -Leaf $FreezeManifestPath))

function Save-Json([string]$Path, [object]$Value) {
  $json = $Value | ConvertTo-Json -Depth 40
  [System.IO.File]::WriteAllText($Path, "$json`n", [System.Text.UTF8Encoding]::new($false))
}

function Get-Csg([string]$Path) {
  Invoke-RestMethod -Method Get -Uri "$apiRoot$Path" -TimeoutSec 30
}

function Invoke-ProbeSnapshot {
  $process = Start-Process -FilePath $python `
    -ArgumentList @('-m','cyberstateguardian_probe.main','--once','--config',"`"$ProbeSettingsPath`"") `
    -WorkingDirectory (Split-Path -Parent $ProbeSettingsPath) -Wait -PassThru -NoNewWindow
  if ($process.ExitCode -ne 0) { throw "One-shot probe snapshot failed: $($process.ExitCode)." }
  Start-Sleep -Seconds 1
  $snapshot = Get-Csg "/hosts/$([uri]::EscapeDataString($hostId))/state/latest"
  if ($snapshot.source -ne 'direct_probe') { throw 'Latest CSG snapshot is not from the native probe.' }
  return $snapshot
}

function Find-TargetLocalEvents([datetime]$FromUtc, [string]$MemberSid) {
  $startLocal = $FromUtc.AddSeconds(-3).ToLocalTime()
  $records = @(Get-WinEvent -FilterHashtable @{
    LogName = 'Security'; Id = 4732; StartTime = $startLocal
  } -MaxEvents 100 -ErrorAction SilentlyContinue)
  foreach ($event in $records) {
    [xml]$xml = $event.ToXml()
    $data = @{}
    foreach ($item in $xml.Event.EventData.Data) {
      $data[[string]$item.GetAttribute('Name')] = [string]$item.InnerText
    }
    if ($data.MemberSid -eq $MemberSid -and $data.TargetUserName -eq 'Administrators') {
      [pscustomobject]@{
        event_id = [int]$event.Id
        event_record_id = [long]$event.RecordId
        time_created_utc = $event.TimeCreated.ToUniversalTime().ToString('o')
        provider = $event.ProviderName
        data = $data
        xml = $event.ToXml()
      }
    }
  }
}

function Wait-ForTargetTransition([string]$ObjectKey, [datetime]$FromUtc) {
  $deadline = [DateTime]::UtcNow.AddSeconds(45)
  $encodedHost = [uri]::EscapeDataString($hostId)
  $key = [uri]::EscapeDataString($ObjectKey)
  $start = [uri]::EscapeDataString($FromUtc.AddSeconds(-5).ToString('o'))
  while ([DateTime]::UtcNow -lt $deadline) {
    $end = [uri]::EscapeDataString([DateTime]::UtcNow.AddSeconds(2).ToString('o'))
    $records = @(Get-Csg "/hosts/$encodedHost/transitions?start=$start&end=$end&category=privileged_group&object_key=$key&limit=100")
    $match = @($records | Where-Object {
      $_.object_key -eq $ObjectKey -and $_.transition_type -eq 'PRIVILEGED_MEMBER_ADDED'
    }) | Select-Object -Last 1
    if ($match) { return $match }
    Start-Sleep -Seconds 2
  }
  return $null
}

function Wait-ForTargetWazuhEvent([string]$MemberSid, [datetime]$FromUtc) {
  $waitStarted = [DateTime]::UtcNow
  $deadline = [DateTime]::UtcNow.AddSeconds($EvidenceWaitSeconds)
  $encodedHost = [uri]::EscapeDataString($hostId)
  $start = [uri]::EscapeDataString($FromUtc.AddSeconds(-5).ToString('o'))
  $candidates = @()
  $errors = [System.Collections.Generic.List[string]]::new()
  $pollAttempts = 0
  while ([DateTime]::UtcNow -lt $deadline) {
    $pollAttempts += 1
    $end = [uri]::EscapeDataString([DateTime]::UtcNow.AddSeconds(2).ToString('o'))
    try {
      $candidates = @(Get-Csg "/hosts/$encodedHost/provider-events?start=$start&end=$end" |
        Where-Object { $_.normalized_type -eq 'privileged_group_member_added' })
      $match = @($candidates | Where-Object {
        $_.host_id -eq $hostId -and -not $_.synthetic -and
        $_.attributes.event_code -eq '4732' -and
        $_.attributes.group -eq 'Administrators' -and
        $_.attributes.member_sid -eq $MemberSid
      }) | Select-Object -Last 1
      if ($match) {
        $observedAt = [DateTime]::UtcNow
        return [pscustomobject]@{
          match = $match
          candidates = $candidates
          errors = @($errors)
          poll_attempts = $pollAttempts
          wait_started_at_utc = $waitStarted.ToString('o')
          match_observed_at_utc = $observedAt.ToString('o')
          elapsed_seconds = [math]::Round(($observedAt - $waitStarted).TotalSeconds, 3)
        }
      }
    } catch {
      $errors.Add($_.Exception.GetType().Name)
    }
    Start-Sleep -Seconds 5
  }
  return [pscustomobject]@{
    match = $null
    candidates = $candidates
    errors = @($errors)
    poll_attempts = $pollAttempts
    wait_started_at_utc = $waitStarted.ToString('o')
    match_observed_at_utc = $null
    elapsed_seconds = [math]::Round(([DateTime]::UtcNow - $waitStarted).TotalSeconds, 3)
  }
}

function Wait-ForCleanProbeState([string]$ObjectKey, [datetime]$AfterUtc) {
  $deadline = [DateTime]::UtcNow.AddMinutes(3)
  $encodedHost = [uri]::EscapeDataString($hostId)
  while ([DateTime]::UtcNow -lt $deadline) {
    $snapshot = Get-Csg "/hosts/$encodedHost/state/latest"
    $builtAt = [DateTime]::Parse($snapshot.built_at).ToUniversalTime()
    if ($snapshot.source -eq 'direct_probe' -and $builtAt -ge $AfterUtc) {
      $remaining = @($snapshot.objects | Where-Object object_key -eq $ObjectKey)
      if ($remaining.Count -eq 0) {
        return [pscustomobject]@{
          snapshot_id = $snapshot.snapshot_id
          built_at = $snapshot.built_at
          source = $snapshot.source
          target_state_absent = $true
        }
      }
    }
    Start-Sleep -Seconds 5
  }
  throw 'No post-cleanup direct-probe snapshot confirmed target-state absence within 3 minutes.'
}

$username = ('csggp' + [guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()
$userSid = $null
$targetKey = $null
$run = [ordered]@{
  schema_version = 'csg-privileged-group-positive-control-v5'
  run_id = $runId
  protocol_id = 'csg-privileged-group-positive-control-v5'
  started_at_utc = [DateTime]::UtcNow.ToString('o')
  host_id = $hostId
  classification = 'authorized_benign_local_administration'
  maliciousness_evaluated = $false
  target = [ordered]@{ username = $username; sid = $null; group = 'Administrators'; object_key = $null }
  source_hashes = [ordered]@{
    runner_sha256 = $runnerHash
    protocol_sha256 = $protocolHash
    freeze_manifest_sha256 = $freezeHash
    probe_settings_sha256_before = (Get-FileHash -LiteralPath $ProbeSettingsPath -Algorithm SHA256).Hash
  }
  environment = [ordered]@{
    windows_caption = (Get-CimInstance Win32_OperatingSystem).Caption
    windows_build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    processor_architecture = $env:PROCESSOR_ARCHITECTURE
    probe_python_version = (& $python --version 2>&1 | Out-String).Trim()
    wazuh_service_before = $wazuhService.Status.ToString()
    security_group_management_audit = (auditpol /get /subcategory:'Security Group Management' | Out-String).Trim()
  }
  wazuh_preflight = $null
  monitor_health_before = $null
  snapshot_before = $null
  target_action_started_utc = $null
  target_action_completed_utc = $null
  snapshot_after = $null
  transition = $null
  local_security_event = $null
  wazuh_query = $null
  reconciliation = $null
  cleanup = [ordered]@{ attempted = $false; membership_removed = $false; account_deleted = $false; errors = @() }
  validation = [ordered]@{}
  success = $false
  failure = $null
}
$userCreated = $false

try {
  $wazuhStatus = Get-Csg '/wazuh/status'
  $endpointAgent = @($wazuhStatus.agents | Where-Object {
    $_.name -eq $hostId -and -not $_.manager -and $_.status -eq 'active'
  }) | Select-Object -First 1
  $run.wazuh_preflight = [ordered]@{
    integration_ok = [bool]$wazuhStatus.ok
    indexer_ok = [bool]$wazuhStatus.indexer.ok
    endpoint_agent_active = [bool]$endpointAgent
    endpoint_agent_version = if ($endpointAgent) { $endpointAgent.version } else { $null }
    manager_version = $wazuhStatus.server_api.version
    indexer_version = $wazuhStatus.indexer.version
  }
  if (-not $wazuhStatus.ok -or -not $wazuhStatus.indexer.ok -or -not $endpointAgent) {
    throw 'CSG Wazuh/indexer integration or the Windows endpoint agent is not healthy.'
  }
  $status = Get-Csg "/transition-capture/status?host_id=$([uri]::EscapeDataString($hostId))"
  $health = $status.categories.privileged_group.monitor_health
  $run.monitor_health_before = $health
  if (-not $status.enabled -or -not $status.categories.privileged_group.enabled -or
      -not $health -or $health.status -ne 'HEALTHY' -or -not $health.baseline_established) {
    throw 'CSG privileged-group monitor is not enabled, healthy, and baseline-established.'
  }
  if ($run.environment.security_group_management_audit -notmatch 'Success') {
    throw 'Windows Security Group Management success auditing is not enabled.'
  }

  $passwordText = [guid]::NewGuid().ToString('N') + 'aA1!'
  $securePassword = ConvertTo-SecureString $passwordText -AsPlainText -Force
  $null = New-LocalUser -Name $username -Password $securePassword -Disabled `
    -Description 'CSG benign research test'
  $userCreated = $true
  $userSid = (Get-LocalUser -Name $username).SID.Value
  $targetKey = "privileged_group:administrators:$($env:COMPUTERNAME.ToLowerInvariant())/$username"
  $run.target.sid = $userSid
  $run.target.object_key = $targetKey
  if ((Get-LocalUser -Name $username).Enabled) { throw 'Temporary test account is unexpectedly enabled.' }

  $before = Invoke-ProbeSnapshot
  $beforeTarget = @($before.objects | Where-Object object_key -eq $targetKey)
  if ($beforeTarget.Count -ne 0) { throw 'Target membership unexpectedly exists before the action.' }
  $run.snapshot_before = [ordered]@{
    snapshot_id = $before.snapshot_id
    built_at = $before.built_at
    source = $before.source
    privileged_group_status = $before.category_statuses | Where-Object category -eq 'privileged_group' | Select-Object -First 1
    target_member_count = $beforeTarget.Count
  }

  $run.target_action_started_utc = [DateTime]::UtcNow.ToString('o')
  Add-LocalGroupMember -Group $group -Member $username
  $run.target_action_completed_utc = [DateTime]::UtcNow.ToString('o')
  $observedMembers = @(Get-LocalGroupMember -Group $group | Where-Object SID -eq $userSid)
  $run.target.local_membership_verified = ($observedMembers.Count -eq 1)
  if ($observedMembers.Count -ne 1) { throw 'Windows did not verify exactly one target group membership.' }

  $after = Invoke-ProbeSnapshot
  $afterTarget = @($after.objects | Where-Object object_key -eq $targetKey)
  $run.snapshot_after = [ordered]@{
    snapshot_id = $after.snapshot_id
    built_at = $after.built_at
    source = $after.source
    target_objects = $afterTarget
  }
  $transition = Wait-ForTargetTransition $targetKey ([DateTime]::Parse($run.target_action_started_utc).ToUniversalTime())
  $run.transition = $transition
  $localEvents = @(Find-TargetLocalEvents ([DateTime]::Parse($run.target_action_started_utc).ToUniversalTime()) $userSid)
  $run.local_security_event = $localEvents | Select-Object -Last 1
  $query = Wait-ForTargetWazuhEvent $userSid ([DateTime]::Parse($run.target_action_started_utc).ToUniversalTime())
  $run.wazuh_query = $query
  if ($transition) {
    $run.reconciliation = Invoke-RestMethod -Method Post `
      -Uri "$apiRoot/transitions/$([uri]::EscapeDataString($transition.transition_id))/reconcile" -TimeoutSec 60
  }
  $matched = $query.match
  $run.validation = [ordered]@{
    target_state_before_absent = ($beforeTarget.Count -eq 0)
    target_state_after_present = ($afterTarget.Count -eq 1)
    exact_transition_present = [bool]$transition
    exact_transition_identity = [bool]($transition -and $transition.object_key -eq $targetKey -and $transition.transition_type -eq 'PRIVILEGED_MEMBER_ADDED')
    exact_local_event_4732_present = [bool]($run.local_security_event -and $run.local_security_event.event_id -eq 4732)
    exact_wazuh_event_present = [bool]$matched
    exact_wazuh_identity = [bool]($matched -and $matched.source -eq 'wazuh' -and
      $matched.host_id -eq $hostId -and -not $matched.synthetic -and
      $matched.normalized_type -eq 'privileged_group_member_added' -and
      $matched.attributes.event_code -eq '4732' -and
      $matched.attributes.group -eq 'Administrators' -and
      $matched.attributes.member_sid -eq $userSid)
    exact_wazuh_record_matches_local_record = [bool]($matched -and $run.local_security_event -and
      [string]$matched.metadata.windows_event_identity.event_record_id -eq
      [string]$run.local_security_event.event_record_id)
    reconciliation_corroborated = [bool]($run.reconciliation -and $run.reconciliation.status -eq 'CORROBORATED')
    reconciliation_cites_exact_wazuh_id = [bool]($matched -and $run.reconciliation.matched_evidence_ids -contains $matched.event_id)
  }
  $run.success = @($run.validation.Values | Where-Object { $_ -ne $true }).Count -eq 0
  if (-not $run.success) { $run.failure = 'One or more predeclared exact-event qualification gates failed.' }
} catch {
  $run.failure = $_.Exception.Message
  $run.success = $false
} finally {
  $run.cleanup.attempted = $true
  if ($userCreated) {
    try {
      $member = @(Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Where-Object SID -eq $userSid)
      if ($member.Count -gt 0) {
        Remove-LocalGroupMember -Group $group -Member $username -ErrorAction Stop
      }
      $run.cleanup.membership_removed = @(
        Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Where-Object SID -eq $userSid
      ).Count -eq 0
    } catch { $run.cleanup.errors += "membership: $($_.Exception.GetType().Name)" }
    try {
      Remove-LocalUser -Name $username -ErrorAction Stop
      $run.cleanup.account_deleted = $null -eq (Get-LocalUser -Name $username -ErrorAction SilentlyContinue)
    } catch { $run.cleanup.errors += "account: $($_.Exception.GetType().Name)" }
  } else {
    $run.cleanup.membership_removed = $true
    $run.cleanup.account_deleted = $true
  }
  $run.cleanup.action_completed_at_utc = [DateTime]::UtcNow.ToString('o')
  if ($targetKey -and $run.cleanup.account_deleted) {
    try {
      $cleanSnapshot = Wait-ForCleanProbeState $targetKey ([DateTime]::Parse($run.cleanup.action_completed_at_utc).ToUniversalTime())
      $run.cleanup.probe_snapshot_id = $cleanSnapshot.snapshot_id
      $run.cleanup.probe_snapshot_built_at = $cleanSnapshot.built_at
      $run.cleanup.target_state_absent = $cleanSnapshot.target_state_absent
    } catch { $run.cleanup.errors += "cleanup_snapshot: $($_.Exception.GetType().Name)" }
  } else {
    $run.cleanup.target_state_absent = $true
  }
  $run.cleanup.completed_at_utc = [DateTime]::UtcNow.ToString('o')
  $run.cleanup.errors = @($run.cleanup.errors)
  $run.source_hashes.probe_settings_sha256_after = (Get-FileHash -LiteralPath $ProbeSettingsPath -Algorithm SHA256).Hash
  try {
    $finalHealth = Get-Csg "/transition-capture/status?host_id=$([uri]::EscapeDataString($hostId))"
    $run.cleanup.privileged_group_monitor_status = $finalHealth.categories.privileged_group.monitor_health.status
    if ($run.cleanup.privileged_group_monitor_status -ne 'HEALTHY') {
      $run.cleanup.errors += 'privileged_group_monitor_not_healthy_after_cleanup'
    }
  } catch { $run.cleanup.errors += 'monitor_postflight_query_failed' }
  Save-Json (Join-Path $runDirectory 'run.json') $run
  $runHash = (Get-FileHash -LiteralPath (Join-Path $runDirectory 'run.json') -Algorithm SHA256).Hash
  [System.IO.File]::WriteAllText(
    (Join-Path $runDirectory 'SHA256SUMS.txt'),
    "$runHash  run.json`n",
    [System.Text.UTF8Encoding]::new($false)
  )
}

[pscustomobject]@{
  run_id = $runId
  success = $run.success
  failure = $run.failure
  target_key = $targetKey
  transition_status = if ($run.reconciliation) { $run.reconciliation.status } else { $null }
  local_event_record_id = if ($run.local_security_event) { $run.local_security_event.event_record_id } else { $null }
  wazuh_event_id = if ($run.wazuh_query.match) { $run.wazuh_query.match.event_id } else { $null }
  cleanup_ok = $run.cleanup.membership_removed -and $run.cleanup.account_deleted -and $run.cleanup.errors.Count -eq 0
  run_directory = $runDirectory
} | ConvertTo-Json -Depth 6

if (-not $run.success -or -not $run.cleanup.membership_removed -or -not $run.cleanup.account_deleted -or
    -not $run.cleanup.target_state_absent -or $run.cleanup.errors.Count -gt 0) {
  exit 1
}
