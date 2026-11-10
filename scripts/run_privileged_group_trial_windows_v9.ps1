param(
  [Parameter(Mandatory=$true)][string]$CampaignId,
  [Parameter(Mandatory=$true)][string]$TrialId,
  [Parameter(Mandatory=$true)][ValidateSet('complete_with_distractor','target_audit_omission_with_distractor','no_target_change_with_distractor')][string]$Condition,
  [Parameter(Mandatory=$true)][string]$TargetUsername,
  [Parameter(Mandatory=$true)][string]$DistractorUsername,
  [Parameter(Mandatory=$true)][string]$ProtocolPath,
  [Parameter(Mandatory=$true)][string]$FreezeManifestPath,
  [Parameter(Mandatory=$true)][string]$SchedulePath,
  [string]$ProbeSettingsPath = "$env:ProgramFiles\CyberStateGuardian\Probe\settings.json",
  [string]$OutputRoot = "$env:ProgramData\CyberStateGuardian\Research\privileged-group-campaign"
)

$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw 'Run from an elevated Administrator PowerShell session.' }

$runnerHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$protocolHash = (Get-FileHash -LiteralPath $ProtocolPath -Algorithm SHA256).Hash.ToLowerInvariant()
$freezeHash = (Get-FileHash -LiteralPath $FreezeManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$scheduleHash = (Get-FileHash -LiteralPath $SchedulePath -Algorithm SHA256).Hash.ToLowerInvariant()
$freeze = Get-Content -LiteralPath $FreezeManifestPath -Raw | ConvertFrom-Json
if ($freeze.study_id -ne 'csg-privileged-group-randomized-v9' -or
    $freeze.source_hashes.windows_runner_sha256 -ne $runnerHash -or
    $freeze.source_hashes.protocol_sha256 -ne $protocolHash -or
    $freeze.source_hashes.schedule_sha256 -ne $scheduleHash) {
  throw 'Frozen runner, protocol, or schedule hash mismatch.'
}
$schedule = Get-Content -LiteralPath $SchedulePath -Raw | ConvertFrom-Json
$assignment = @($schedule.trials | Where-Object trial_id -eq $TrialId | Select-Object -First 1)
if ($assignment.Count -ne 1 -or $assignment[0].condition -ne $Condition -or
    $assignment[0].target_username -ne $TargetUsername -or
    $assignment[0].distractor_username -ne $DistractorUsername) {
  throw 'Runtime assignment differs from the frozen randomized schedule.'
}
foreach ($name in @($TargetUsername, $DistractorUsername)) {
  if ($name -notmatch '^csg[td][a-f0-9]{12}$') { throw 'Account name is outside the frozen naming policy.' }
}
if ($TargetUsername -eq $DistractorUsername) { throw 'Target and distractor account names must differ.' }

$settings = Get-Content -LiteralPath $ProbeSettingsPath -Raw | ConvertFrom-Json
if (-not $settings.CSG_TRANSITION_CAPTURE_ENABLED -or
    -not $settings.CSG_TRANSITION_PRIVILEGED_GROUPS_ENABLED) {
  throw 'Privileged-group transition capture must be enabled.'
}
$python = Join-Path (Split-Path -Parent $ProbeSettingsPath) 'venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw 'Probe Python is missing.' }
$probeUri = [Uri]$settings.CSG_PROBE_API_URL
$apiPath = $probeUri.AbsolutePath -replace '/probe/observations/?$', ''
$apiRoot = "{0}://{1}{2}" -f $probeUri.Scheme, $probeUri.Authority, $apiPath.TrimEnd('/')
$hostId = [string]$settings.CSG_PROBE_HOST_ID
$group = Get-LocalGroup -SID 'S-1-5-32-544'
$runDirectory = Join-Path (Join-Path $OutputRoot $CampaignId) $TrialId
if (Test-Path -LiteralPath $runDirectory) { throw "Refusing to overwrite $runDirectory." }
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $runDirectory 'frozen-source') -Force | Out-Null
foreach ($sourcePath in @($PSCommandPath, $ProtocolPath, $FreezeManifestPath, $SchedulePath)) {
  $destinationPath = Join-Path (Join-Path $runDirectory 'frozen-source') (Split-Path -Leaf $sourcePath)
  Copy-Item -LiteralPath $sourcePath -Destination $destinationPath
}

function Save-Json([string]$Path, [object]$Value) {
  $json = $Value | ConvertTo-Json -Depth 40
  [System.IO.File]::WriteAllText($Path, "$json`n", [System.Text.UTF8Encoding]::new($false))
}
function Get-Csg([string]$Path) {
  Invoke-RestMethod -Method Get -Uri "$apiRoot$Path" -TimeoutSec 30
}
function Get-AuditState {
  $output = @(auditpol /get /subcategory:'Security Group Management') -join "`n"
  $line = @($output -split "`n" | Where-Object { $_ -match 'Security Group Management' } | Select-Object -Last 1)
  if ($line.Count -ne 1) { throw 'Cannot read Security Group Management audit state.' }
  [pscustomobject]@{
    raw = $output
    success = [bool]($line[0] -match 'Success')
    failure = [bool]($line[0] -match 'Failure')
  }
}
function Set-AuditState([bool]$Success, [bool]$Failure) {
  $successValue = if ($Success) { 'enable' } else { 'disable' }
  $failureValue = if ($Failure) { 'enable' } else { 'disable' }
  & auditpol /set /subcategory:'Security Group Management' "/success:$successValue" "/failure:$failureValue" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'auditpol failed to set the temporary audit state.' }
  $actual = Get-AuditState
  if ($actual.success -ne $Success -or $actual.failure -ne $Failure) {
    throw 'Read-back audit state differs from the requested setting.'
  }
  return $actual
}
function Get-LatestState {
  $encodedHost = [uri]::EscapeDataString($hostId)
  Get-Csg "/hosts/$encodedHost/state/latest"
}
function Get-Transition([string]$ObjectKey, [datetime]$FromUtc) {
  $encodedHost = [uri]::EscapeDataString($hostId)
  $key = [uri]::EscapeDataString($ObjectKey)
  $start = [uri]::EscapeDataString($FromUtc.AddSeconds(-10).ToString('o'))
  $deadline = [DateTime]::UtcNow.AddSeconds(90)
  while ([DateTime]::UtcNow -lt $deadline) {
    $end = [uri]::EscapeDataString([DateTime]::UtcNow.AddSeconds(2).ToString('o'))
    $response = Get-Csg "/hosts/$encodedHost/transitions?start=$start&end=$end&category=privileged_group&object_key=$key&limit=100"
    $rows = @($response)
    $matches = @(
      foreach ($row in $rows) {
        if ($row.object_key -eq $ObjectKey -and $row.transition_type -eq 'PRIVILEGED_MEMBER_ADDED') { $row }
      }
    )
    if ($matches.Count -gt 0) { return $matches[-1] }
    Start-Sleep -Seconds 2
  }
  return $null
}
function Wait-State([string[]]$PresentKeys, [string[]]$AbsentKeys, [datetime]$AfterUtc) {
  $deadline = [DateTime]::UtcNow.AddSeconds(90)
  while ([DateTime]::UtcNow -lt $deadline) {
    $snapshot = Get-LatestState
    $builtAt = [DateTime]::Parse($snapshot.built_at).ToUniversalTime()
    $keys = @($snapshot.objects | ForEach-Object { $_.object_key })
    $present = @($PresentKeys | Where-Object { $keys -contains $_ })
    $absent = @($AbsentKeys | Where-Object { $keys -notcontains $_ })
    $health = @($snapshot.category_statuses | Where-Object category -eq 'privileged_group' | Select-Object -First 1)
    if ($snapshot.source -eq 'direct_probe' -and $builtAt -ge $AfterUtc -and
        $present.Count -eq $PresentKeys.Count -and $absent.Count -eq $AbsentKeys.Count -and
        $health.Count -eq 1 -and $health[0].status -eq 'healthy') {
      return [pscustomobject]@{
        snapshot_id = $snapshot.snapshot_id
        built_at = $snapshot.built_at
        source = $snapshot.source
        present_objects = @($snapshot.objects | Where-Object { $_.object_key -in $PresentKeys })
        absent_keys = $AbsentKeys
        category_status = $health[0]
      }
    }
    Start-Sleep -Seconds 2
  }
  throw 'Direct-probe state did not reach the assigned target/distractor state.'
}
function Find-LocalEvents([datetime]$FromUtc, [datetime]$ToUtc, [string]$Sid) {
  $records = @(Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4732; StartTime=$FromUtc.ToLocalTime(); EndTime=$ToUtc.ToLocalTime()
  } -MaxEvents 1000 -ErrorAction SilentlyContinue)
  foreach ($event in $records) {
    [xml]$xml = $event.ToXml()
    $data = @{}
    foreach ($item in $xml.Event.EventData.Data) { $data[[string]$item.GetAttribute('Name')] = [string]$item.InnerText }
    if ($data.MemberSid -eq $Sid -and $data.TargetUserName -eq 'Administrators') {
      [pscustomobject]@{
        event_id = [int]$event.Id
        event_record_id = [long]$event.RecordId
        time_created_utc = $event.TimeCreated.ToUniversalTime().ToString('o')
        member_sid = $data.MemberSid
        group = $data.TargetUserName
        actor = $data.SubjectUserName
        xml = $event.ToXml()
      }
    }
  }
}
function Get-LogicalWindowsEvents([object[]]$Events) {
  $groups = @($Events | Group-Object -Property {
    $identity=$_.metadata.windows_event_identity
    '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.host_id,$_.metadata.agent.id,$identity.channel,
      $identity.event_code,$identity.event_record_id,$_.attributes.member_sid
  })
  foreach ($group in $groups) {
    $ordered=@($group.Group | Sort-Object -Property @{Expression={if($_.metadata.source_kind -eq 'wazuh_alert'){0}else{1}}})
    if ($ordered.Count -gt 0) { $ordered[0] }
  }
}
function Get-WazuhEvents([datetime]$FromUtc, [datetime]$ToUtc, [string[]]$Sids) {
  $encodedHost = [uri]::EscapeDataString($hostId)
  $start = [uri]::EscapeDataString($FromUtc.AddSeconds(-10).ToString('o'))
  $end = [uri]::EscapeDataString($ToUtc.AddSeconds(10).ToString('o'))
  $response = Get-Csg "/hosts/$encodedHost/provider-events?start=$start&end=$end"
  $eventRows = @($response)
  $matches = @(
    foreach ($event in $eventRows) {
      if ($event.host_id -eq $hostId -and -not $event.synthetic -and
          $event.normalized_type -eq 'privileged_group_member_added' -and
          $event.attributes.event_code -eq '4732' -and
          $event.attributes.group -eq 'Administrators' -and
          $event.attributes.member_sid -in $Sids) { $event }
    }
  )
  $logical= @(Get-LogicalWindowsEvents $matches)
  return [pscustomobject]@{ returned_event_count=$eventRows.Count; exact_events=$matches; logical_events=$logical }
}
function Wait-WazuhEvents([datetime]$FromUtc, [string[]]$Sids, [bool]$ExpectTarget) {
  $started=[DateTime]::UtcNow
  $deadline=$started.AddSeconds(300)
  $last=$null
  $attempts=0
  while ([DateTime]::UtcNow -lt $deadline) {
    $attempts++
    $last=Get-WazuhEvents $FromUtc ([DateTime]::UtcNow) $Sids
    $targetRows=@($last.logical_events | Where-Object { $_.attributes.member_sid -eq $targetSid })
    $distractorRows=@($last.logical_events | Where-Object { $_.attributes.member_sid -eq $distractorSid })
    if ($distractorRows.Count -gt 0 -and (($ExpectTarget -and $targetRows.Count -gt 0) -or (-not $ExpectTarget -and $targetRows.Count -eq 0))) {
      return [pscustomobject]@{returned_event_count=$last.returned_event_count;exact_events=$last.exact_events;logical_events=$last.logical_events;attempts=$attempts;elapsed_seconds=[math]::Round(([DateTime]::UtcNow-$started).TotalSeconds,3);expected_rows_observed=$true}
    }
    Start-Sleep -Seconds 5
  }
  return [pscustomobject]@{returned_event_count=$last.returned_event_count;exact_events=$last.exact_events;logical_events=$last.logical_events;attempts=$attempts;elapsed_seconds=[math]::Round(([DateTime]::UtcNow-$started).TotalSeconds,3);expected_rows_observed=$false}
}
function Invoke-TransitionReconciliation([object]$Transition) {
  if (-not $Transition) { return $null }
  $encoded = [uri]::EscapeDataString([string]$Transition.transition_id)
  Invoke-RestMethod -Method Post -Uri "$apiRoot/transitions/$encoded/reconcile" -TimeoutSec 60
}
function Get-TargetFindings([string]$ObjectKey, [datetime]$FromUtc) {
  $encodedHost=[uri]::EscapeDataString($hostId)
  $encodedKey=[uri]::EscapeDataString($ObjectKey)
  $createdAfter=[uri]::EscapeDataString($FromUtc.AddSeconds(-10).ToString('o'))
  $response=Get-Csg "/findings?host_id=$encodedHost&object_key=$encodedKey&created_after=$createdAfter&limit=100"
  return @($response)
}
function Test-EventInsideTransitionWindow([object]$Event, [object]$Transition) {
  if (-not $Event -or -not $Transition -or -not $Transition.window_start -or -not $Transition.window_end) {
    return $false
  }
  $eventTime=[DateTime]::Parse($Event.event_time).ToUniversalTime()
  $start=[DateTime]::Parse($Transition.window_start).ToUniversalTime().AddSeconds(-20)
  $end=[DateTime]::Parse($Transition.window_end).ToUniversalTime().AddSeconds(20)
  return $eventTime -ge $start -and $eventTime -le $end
}
function Wait-CitationEvidence([datetime]$FromUtc, [string[]]$EvidenceIds) {
  $ids=@($EvidenceIds | Where-Object { $_ } | Select-Object -Unique)
  $deadline=[DateTime]::UtcNow.AddSeconds(90)
  $last=$null
  $attempts=0
  do {
    $attempts++
    $last=Get-WazuhEvents $FromUtc ([DateTime]::UtcNow) @($targetSid,$distractorSid)
    $observed=@($last.exact_events | ForEach-Object { $_.event_id } | Select-Object -Unique)
    $missing=@($ids | Where-Object { $_ -notin $observed })
    if ($missing.Count -eq 0) {
      return [pscustomobject]@{exact_events=$last.exact_events;logical_events=$last.logical_events;attempts=$attempts;expected_ids=$ids;observed_ids=$observed;expected_ids_observed=$true}
    }
    Start-Sleep -Seconds 5
  } while ([DateTime]::UtcNow -lt $deadline)
  return [pscustomobject]@{exact_events=$last.exact_events;logical_events=$last.logical_events;attempts=$attempts;expected_ids=$ids;observed_ids=$observed;expected_ids_observed=$false}
}
function Test-CitationIdentity([object[]]$Candidates,[string[]]$EvidenceIds,[string]$Sid,[string]$RecordId,[object]$Transition) {
  $ids=@($EvidenceIds | Where-Object { $_ } | Select-Object -Unique)
  if ($ids.Count -eq 0 -or -not $RecordId -or -not $Transition) { return $false }
  $rows=@($Candidates | Where-Object { $_.event_id -in $ids })
  if ($rows.Count -ne $ids.Count) { return $false }
  foreach ($event in $rows) {
    $identity=$event.metadata.windows_event_identity
    if ($event.host_id -ne $hostId -or $event.source -ne 'wazuh' -or $event.synthetic -or
        $event.normalized_type -ne 'privileged_group_member_added' -or
        $event.attributes.event_code -ne '4732' -or $event.attributes.group -ne 'Administrators' -or
        $event.attributes.member_sid -ne $Sid -or
        [string]$identity.event_code -ne '4732' -or
        [string]$identity.event_record_id -ne $RecordId -or
        [string]$identity.channel -ne 'security' -or
        [string]$identity.provider_name -ne 'microsoft-windows-security-auditing' -or
        [string]$event.metadata.agent.id -ne [string]$run.wazuh_preflight.agent_id -or
        -not (Test-EventInsideTransitionWindow $event $Transition)) { return $false }
  }
  return @($rows | ForEach-Object { [string]$_.metadata.windows_event_identity.event_record_id } | Select-Object -Unique).Count -eq 1
}
function Test-UserMembership([string]$Sid) {
  @(Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $Sid }).Count -eq 1
}

$settingsHashBefore = (Get-FileHash -LiteralPath $ProbeSettingsPath -Algorithm SHA256).Hash
$auditBaseline = Get-AuditState
if (-not $auditBaseline.success) { throw 'Success auditing must be enabled before a trial.' }
$targetKey = "privileged_group:administrators:$($env:COMPUTERNAME.ToLowerInvariant())/$TargetUsername"
$distractorKey = "privileged_group:administrators:$($env:COMPUTERNAME.ToLowerInvariant())/$DistractorUsername"
$runDirectory = (Resolve-Path -LiteralPath $runDirectory).Path
$targetCreated = $false
$distractorCreated = $false
$auditNeedsRestore = $false
$targetSid = $null
$distractorSid = $null
$run = [ordered]@{
  schema_version='csg-privileged-group-randomized-v9'
  campaign_id=$CampaignId; trial_id=$TrialId; condition=$Condition; host_id=$hostId
  started_at_utc=[DateTime]::UtcNow.ToString('o')
  source_hashes=[ordered]@{runner_sha256=$runnerHash; protocol_sha256=$protocolHash; freeze_sha256=$freezeHash; schedule_sha256=$scheduleHash; probe_settings_sha256_before=$settingsHashBefore}
  environment=$null; wazuh_preflight=$null; monitor_health_before=$null; audit_policy=$null
  target=[ordered]@{username=$TargetUsername; sid=$null; object_key=$targetKey; membership_added=$false}
  distractor=[ordered]@{username=$DistractorUsername; sid=$null; object_key=$distractorKey; membership_added=$false}
  snapshot_before=$null; action_timeline=[System.Collections.Generic.List[object]]::new()
  snapshot_after=$null; target_transition=$null; distractor_transition=$null
  local_target_events=@(); local_distractor_events=@(); wazuh_query=$null; citation_resolution_query=$null
  target_reconciliation=$null; distractor_reconciliation=$null
  validation=[ordered]@{}; cleanup=[ordered]@{attempted=$false; errors=@()}; success=$false; failure=$null
}

try {
  $os = Get-CimInstance Win32_OperatingSystem
  $wazuhService = Get-Service WazuhSvc -ErrorAction Stop
  if ($wazuhService.Status -ne 'Running') { throw 'WazuhSvc is not running.' }
  $run.environment=[ordered]@{windows_computer_name=$env:COMPUTERNAME; windows_caption=$os.Caption; windows_build=$os.BuildNumber; architecture=$env:PROCESSOR_ARCHITECTURE; probe_python_version=(& $python --version 2>&1 | Out-String).Trim(); wazuh_service_before=$wazuhService.Status.ToString()}
  $wazuhStatus = Get-Csg '/wazuh/status'
  $agent = @($wazuhStatus.agents | Where-Object { $_.name -eq $hostId -and -not $_.manager -and $_.status -eq 'active' } | Select-Object -First 1)
  $run.wazuh_preflight=[ordered]@{integration_ok=[bool]$wazuhStatus.ok; indexer_ok=[bool]$wazuhStatus.indexer.ok; active_agent=($agent.Count -eq 1); agent_id=if($agent.Count -eq 1){$agent[0].id}else{$null}; agent_version=if($agent.Count -eq 1){$agent[0].version}else{$null}}
  if (-not $wazuhStatus.ok -or -not $wazuhStatus.indexer.ok -or $agent.Count -ne 1) { throw 'Wazuh/indexer or endpoint-agent preflight failed.' }
  $capture = Get-Csg "/transition-capture/status?host_id=$([uri]::EscapeDataString($hostId))"
  $health = $capture.categories.privileged_group.monitor_health
  $run.monitor_health_before=$health
  if (-not $capture.enabled -or -not $capture.categories.privileged_group.enabled -or $health.status -ne 'HEALTHY' -or -not $health.baseline_established) { throw 'Privileged-group probe monitor is not healthy/baselined.' }
  $run.audit_policy=[ordered]@{baseline=$auditBaseline; target_omission_applied=$false; restore_verified=$false; after_restore=$null}
  if ($auditBaseline.failure) { throw 'This protocol requires baseline audit policy Success only; Failure auditing is enabled.' }
  if (Get-LocalUser -Name $TargetUsername -ErrorAction SilentlyContinue) { throw 'Target account name already exists.' }
  if (Get-LocalUser -Name $DistractorUsername -ErrorAction SilentlyContinue) { throw 'Distractor account name already exists.' }

  foreach ($name in @($TargetUsername, $DistractorUsername)) {
    $secret = [guid]::NewGuid().ToString('N') + 'zZ7!'
    $secure = ConvertTo-SecureString $secret -AsPlainText -Force
    $null = New-LocalUser -Name $name -Password $secure -Disabled -Description 'CSG benign research trial'
    $secret=$null
    $secure=$null
    if ($name -eq $TargetUsername) { $targetCreated=$true; $targetSid=(Get-LocalUser -Name $name).SID.Value }
    else { $distractorCreated=$true; $distractorSid=(Get-LocalUser -Name $name).SID.Value }
  }
  if ((Get-LocalUser -Name $TargetUsername).Enabled -or (Get-LocalUser -Name $DistractorUsername).Enabled) { throw 'Research accounts must remain disabled.' }
  $run.target.sid=$targetSid; $run.distractor.sid=$distractorSid
  if (Test-UserMembership $targetSid) { throw 'Target membership existed before trial.' }
  if (Test-UserMembership $distractorSid) { throw 'Distractor membership existed before trial.' }
  $before=Get-LatestState
  $beforeKeys=@($before.objects | ForEach-Object { $_.object_key })
  if ($before.source -ne 'direct_probe' -or $beforeKeys -contains $targetKey -or $beforeKeys -contains $distractorKey) { throw 'Pre-action direct-probe state is not clean for the unique target/distractor.' }
  $run.snapshot_before=[ordered]@{snapshot_id=$before.snapshot_id; built_at=$before.built_at; source=$before.source; target_absent=($beforeKeys -notcontains $targetKey); distractor_absent=($beforeKeys -notcontains $distractorKey)}

  if ($Condition -eq 'target_audit_omission_with_distractor') {
    $run.action_timeline.Add([ordered]@{phase='audit_success_disabled'; at_utc=[DateTime]::UtcNow.ToString('o')})
    $auditNeedsRestore=$true
    $off=Set-AuditState -Success $false -Failure $false
    $run.audit_policy.target_omission_applied=$true
    $run.audit_policy.during_target_action=$off
  }
  if ($Condition -ne 'no_target_change_with_distractor') {
    $run.action_timeline.Add([ordered]@{phase='target_membership_add_started'; at_utc=[DateTime]::UtcNow.ToString('o')})
    Add-LocalGroupMember -Group $group -Member $TargetUsername
    $run.target.membership_added=Test-UserMembership $targetSid
    if (-not $run.target.membership_added) { throw 'Windows did not confirm target membership.' }
    $run.action_timeline.Add([ordered]@{phase='target_membership_add_completed'; at_utc=[DateTime]::UtcNow.ToString('o')})
  } else {
    $run.action_timeline.Add([ordered]@{phase='target_no_change_assigned'; at_utc=[DateTime]::UtcNow.ToString('o')})
  }
  if ($auditNeedsRestore) {
    $restored=Set-AuditState -Success $auditBaseline.success -Failure $auditBaseline.failure
    $auditNeedsRestore=$false
    $run.audit_policy.restore_verified=$true
    $run.audit_policy.after_restore=$restored
    $run.action_timeline.Add([ordered]@{phase='audit_baseline_restored'; at_utc=[DateTime]::UtcNow.ToString('o')})
  }
  $run.action_timeline.Add([ordered]@{phase='distractor_membership_add_started'; at_utc=[DateTime]::UtcNow.ToString('o')})
  Add-LocalGroupMember -Group $group -Member $DistractorUsername
  $run.distractor.membership_added=Test-UserMembership $distractorSid
  if (-not $run.distractor.membership_added) { throw 'Windows did not confirm distractor membership.' }
  $run.action_timeline.Add([ordered]@{phase='distractor_membership_add_completed'; at_utc=[DateTime]::UtcNow.ToString('o')})
  $actionStart=[DateTime]::Parse($run.action_timeline[0].at_utc).ToUniversalTime()
  $actionEnd=[DateTime]::UtcNow

  $presentKeys=@($distractorKey)
  $absentKeys=@()
  if ($Condition -ne 'no_target_change_with_distractor') { $presentKeys+= $targetKey }
  else { $absentKeys=@($targetKey) }
  $run.snapshot_after=Wait-State -PresentKeys $presentKeys -AbsentKeys $absentKeys -AfterUtc $actionStart
  $run.target_transition=Get-Transition $targetKey $actionStart
  $run.distractor_transition=Get-Transition $distractorKey $actionStart
  if ($Condition -eq 'no_target_change_with_distractor' -and $run.target_transition) { throw 'Target transition unexpectedly exists in no-change arm.' }
  if ($Condition -ne 'no_target_change_with_distractor' -and -not $run.target_transition) { throw 'Expected target transition was not observed.' }
  if (-not $run.distractor_transition) { throw 'Expected distractor transition was not observed.' }

  $endUtc=[DateTime]::UtcNow
  $run.local_target_events=@(Find-LocalEvents $actionStart $endUtc $targetSid)
  $run.local_distractor_events=@(Find-LocalEvents $actionStart $endUtc $distractorSid)
  $expectTargetEvent=$Condition -eq 'complete_with_distractor'
  $wazuh=Wait-WazuhEvents $actionStart @($targetSid,$distractorSid) $expectTargetEvent
  $run.wazuh_query=[ordered]@{query_completed_at_utc=[DateTime]::UtcNow.ToString('o'); returned_event_count=$wazuh.returned_event_count; exact_events=$wazuh.exact_events; logical_events=$wazuh.logical_events; attempts=$wazuh.attempts; elapsed_seconds=$wazuh.elapsed_seconds; expected_rows_observed=$wazuh.expected_rows_observed}
  if ($run.target_transition) { $run.target_reconciliation=Invoke-TransitionReconciliation $run.target_transition }
  $run.distractor_reconciliation=Invoke-TransitionReconciliation $run.distractor_transition
  $run.target_findings=Get-TargetFindings $targetKey $actionStart

  $targetLocal=@($run.local_target_events); $distractorLocal=@($run.local_distractor_events)
  $targetWazuh=@($wazuh.logical_events | Where-Object { $_.attributes.member_sid -eq $targetSid })
  $distractorWazuh=@($wazuh.logical_events | Where-Object { $_.attributes.member_sid -eq $distractorSid })
  $targetReconIds=@(); if ($run.target_reconciliation) { $targetReconIds=@($run.target_reconciliation.matched_evidence_ids) }
  $distractorReconIds=@($run.distractor_reconciliation.matched_evidence_ids)
  $citationIds=@($targetReconIds + $distractorReconIds | Where-Object { $_ } | Select-Object -Unique)
  $citationQuery=Wait-CitationEvidence $actionStart $citationIds
  $run.citation_resolution_query=[ordered]@{query_completed_at_utc=[DateTime]::UtcNow.ToString('o'); exact_events=$citationQuery.exact_events; logical_events=$citationQuery.logical_events; attempts=$citationQuery.attempts; expected_ids=$citationQuery.expected_ids; observed_ids=$citationQuery.observed_ids; expected_ids_observed=$citationQuery.expected_ids_observed}
  $targetRecord=if($targetLocal.Count -eq 1){[string]$targetLocal[0].event_record_id}else{$null}
  $distractorRecord=if($distractorLocal.Count -eq 1){[string]$distractorLocal[0].event_record_id}else{$null}
  $targetWazuhRecord=if($targetWazuh.Count -eq 1){[string]$targetWazuh[0].metadata.windows_event_identity.event_record_id}else{$null}
  $distractorWazuhRecord=if($distractorWazuh.Count -eq 1){[string]$distractorWazuh[0].metadata.windows_event_identity.event_record_id}else{$null}
  $targetWazuhEvent=if($targetWazuh.Count -eq 1){$targetWazuh[0]}else{$null}
  $distractorWazuhEvent=if($distractorWazuh.Count -eq 1){$distractorWazuh[0]}else{$null}
  $targetAction=@($run.action_timeline | Where-Object phase -eq 'target_membership_add_started' | Select-Object -First 1)
  $distractorAction=@($run.action_timeline | Where-Object phase -eq 'distractor_membership_add_started' | Select-Object -First 1)
  $actionGap=if($targetAction.Count -eq 1){[math]::Abs(([DateTime]::Parse($distractorAction[0].at_utc)-[DateTime]::Parse($targetAction[0].at_utc)).TotalSeconds)}else{0}
  $expectedTargetPresent=$Condition -ne 'no_target_change_with_distractor'
  $expectedTargetEvent=$Condition -eq 'complete_with_distractor'
  $expectedTargetStatus=if($expectedTargetEvent){'CORROBORATED'}elseif($expectedTargetPresent){'UNEXPLAINED_BY_EVENT_PLANE'}else{$null}
  $targetCitationExact=if($expectedTargetEvent){Test-CitationIdentity $citationQuery.exact_events $targetReconIds $targetSid $targetRecord $run.target_transition}else{$false}
  $distractorCitationExact=Test-CitationIdentity $citationQuery.exact_events $distractorReconIds $distractorSid $distractorRecord $run.distractor_transition
  $run.validation=[ordered]@{
    frozen_assignment_matches=($assignment[0].condition -eq $Condition)
    baseline_audit_success_enabled=$auditBaseline.success
    audit_policy_restored=($Condition -ne 'target_audit_omission_with_distractor' -or ($run.audit_policy.restore_verified -and $run.audit_policy.after_restore.success -eq $auditBaseline.success -and $run.audit_policy.after_restore.failure -eq $auditBaseline.failure))
    direct_probe_target_state_correct=(($run.snapshot_after.present_objects.object_key -contains $targetKey) -eq $expectedTargetPresent)
    direct_probe_distractor_state_present=($run.snapshot_after.present_objects.object_key -contains $distractorKey)
    target_transition_correct=(($null -ne $run.target_transition) -eq $expectedTargetPresent)
    no_target_finding_in_no_change=($Condition -ne 'no_target_change_with_distractor' -or @($run.target_findings | Where-Object { $_ }).Count -eq 0)
    distractor_transition_present=($null -ne $run.distractor_transition)
    target_local_event_count_expected=($targetLocal.Count -eq [int]$expectedTargetEvent)
    distractor_local_event_exactly_once=($distractorLocal.Count -eq 1)
    target_wazuh_event_count_expected=($targetWazuh.Count -eq [int]$expectedTargetEvent)
    distractor_wazuh_event_exactly_once=($distractorWazuh.Count -eq 1)
    provider_poll_observed_expected_rows=($run.wazuh_query.expected_rows_observed -eq $true)
    reconciliation_citation_ids_resolved=($citationQuery.expected_ids_observed -eq $true)
    target_windows_record_id_matches_wazuh=(!$expectedTargetEvent -or ($targetRecord -and $targetRecord -eq $targetWazuhRecord))
    distractor_windows_record_id_matches_wazuh=($distractorRecord -and $distractorRecord -eq $distractorWazuhRecord)
    paired_actions_within_five_seconds=($actionGap -le 5)
    target_event_inside_target_transition_window=(!$expectedTargetEvent -or (Test-EventInsideTransitionWindow $targetWazuhEvent $run.target_transition))
    distractor_event_inside_target_transition_window=(!$expectedTargetPresent -or (Test-EventInsideTransitionWindow $distractorWazuhEvent $run.target_transition))
    target_reconciliation_expected=(!$expectedTargetPresent -or ($run.target_reconciliation.status -eq $expectedTargetStatus))
    target_reconciliation_cites_exact_windows_event=(!$expectedTargetEvent -or $targetCitationExact)
    target_reconciliation_has_no_evidence_when_event_omitted=($Condition -ne 'target_audit_omission_with_distractor' -or $targetReconIds.Count -eq 0)
    distractor_reconciliation_corroborated=($run.distractor_reconciliation.status -eq 'CORROBORATED' -and $distractorCitationExact)
  }
  $run.success=@($run.validation.Values | Where-Object { $_ -ne $true }).Count -eq 0
  if (-not $run.success) { $run.failure='At least one predeclared live-campaign gate failed.' }
} catch {
  $run.failure=$_.Exception.Message
  $run.success=$false
} finally {
  $run.cleanup.attempted=$true
  if ($auditNeedsRestore) {
    try {
      $restored=Set-AuditState -Success $auditBaseline.success -Failure $auditBaseline.failure
      $run.audit_policy.restore_verified=$true
      $run.audit_policy.after_restore=$restored
      $auditNeedsRestore=$false
    } catch { $run.cleanup.errors += 'audit_policy_restore_failed' }
  }
  foreach ($entry in @(@{name=$TargetUsername;sid=$targetSid;created=$targetCreated},@{name=$DistractorUsername;sid=$distractorSid;created=$distractorCreated})) {
    if ($entry.created) {
      try {
        if (Test-UserMembership $entry.sid) { Remove-LocalGroupMember -Group $group -Member $entry.name -ErrorAction Stop }
        $memberGone= -not (Test-UserMembership $entry.sid)
        if (-not $memberGone) { throw 'Membership remains after removal.' }
      } catch { $run.cleanup.errors += "membership_remove:$($entry.name)" }
      try {
        Remove-LocalUser -Name $entry.name -ErrorAction Stop
        if (Get-LocalUser -Name $entry.name -ErrorAction SilentlyContinue) { throw 'Account remains after deletion.' }
      } catch { $run.cleanup.errors += "account_delete:$($entry.name)" }
    }
  }
  try {
    $finalAudit=Get-AuditState
    $run.cleanup.audit_policy_after=$finalAudit
    $run.cleanup.audit_policy_restored=(!$auditNeedsRestore -and $finalAudit.success -eq $auditBaseline.success -and $finalAudit.failure -eq $auditBaseline.failure)
  } catch { $run.cleanup.audit_policy_restored=$false; $run.cleanup.errors += 'audit_policy_postflight_unavailable' }
  try { $run.cleanup.target_account_absent=($null -eq (Get-LocalUser -Name $TargetUsername -ErrorAction SilentlyContinue)) }
  catch { $run.cleanup.target_account_absent=$false; $run.cleanup.errors += 'target_account_postflight_failed' }
  try { $run.cleanup.distractor_account_absent=($null -eq (Get-LocalUser -Name $DistractorUsername -ErrorAction SilentlyContinue)) }
  catch { $run.cleanup.distractor_account_absent=$false; $run.cleanup.errors += 'distractor_account_postflight_failed' }
  $run.cleanup.completed_at_utc=[DateTime]::UtcNow.ToString('o')
  try {
    $refreshStartedAt=[DateTime]::UtcNow
    $run.cleanup.probe_refresh_started_at_utc=$refreshStartedAt.ToString('o')
    & $python -m cyberstateguardian_probe.main --once --config $ProbeSettingsPath | Out-Null
    $run.cleanup.probe_refresh_exit_code=$LASTEXITCODE
    if ($LASTEXITCODE -ne 0) { throw 'The post-cleanup direct-probe refresh failed.' }
    $run.cleanup.probe_refresh_completed_at_utc=[DateTime]::UtcNow.ToString('o')
    $clean=Wait-State -PresentKeys @() -AbsentKeys @($targetKey,$distractorKey) -AfterUtc $refreshStartedAt
    $run.cleanup.probe_snapshot_id=$clean.snapshot_id
    $run.cleanup.probe_snapshot_built_at=$clean.built_at
    $run.cleanup.target_and_distractor_absent=$true
  } catch {
    if ($null -eq $run.cleanup.probe_refresh_exit_code) { $run.cleanup.probe_refresh_exit_code=-1 }
    $run.cleanup.target_and_distractor_absent=$false
    $run.cleanup.errors += 'post_cleanup_probe_state_not_clean'
  }
  try {
    $finalCapture=Get-Csg "/transition-capture/status?host_id=$([uri]::EscapeDataString($hostId))"
    $run.cleanup.monitor_health=$finalCapture.categories.privileged_group.monitor_health.status
  } catch { $run.cleanup.monitor_health='UNAVAILABLE' }
  try { $run.cleanup.wazuh_service=(Get-Service WazuhSvc).Status.ToString() } catch { $run.cleanup.wazuh_service='UNAVAILABLE' }
  $run.cleanup.errors=@($run.cleanup.errors)
  $run.cleanup.probe_settings_sha256_after=(Get-FileHash -LiteralPath $ProbeSettingsPath -Algorithm SHA256).Hash
  $run.cleanup.complete=($run.cleanup.errors.Count -eq 0 -and $run.cleanup.audit_policy_restored -and $run.cleanup.target_account_absent -and $run.cleanup.distractor_account_absent -and $run.cleanup.target_and_distractor_absent -and $run.cleanup.probe_refresh_exit_code -eq 0 -and $run.cleanup.monitor_health -eq 'HEALTHY' -and $run.cleanup.wazuh_service -eq 'Running' -and $run.cleanup.probe_settings_sha256_after -eq $settingsHashBefore)
  $run.completed_at_utc=[DateTime]::UtcNow.ToString('o')
  Save-Json (Join-Path $runDirectory 'run.json') $run
  $hash=(Get-FileHash -LiteralPath (Join-Path $runDirectory 'run.json') -Algorithm SHA256).Hash
  [System.IO.File]::WriteAllText((Join-Path $runDirectory 'SHA256SUMS.txt'), "$hash  run.json`n", [System.Text.UTF8Encoding]::new($false))
}

[pscustomobject]@{campaign_id=$CampaignId;trial_id=$TrialId;condition=$Condition;success=$run.success;failure=$run.failure;target_status=if($run.target_reconciliation){$run.target_reconciliation.status}else{$null};cleanup_complete=$run.cleanup.complete;run_directory=$runDirectory}|ConvertTo-Json -Compress
if (-not $run.success -or -not $run.cleanup.complete) { exit 1 }
