param(
    [Parameter(Mandatory = $true)][string]$TrialId,
    [Parameter(Mandatory = $true)][ValidateSet("complete_exact", "target_event_absent_with_distractor", "no_change_with_distractor")][string]$Condition,
    [Parameter(Mandatory = $true)][ValidateRange(50000, 65000)][int]$TargetPort,
    [Parameter(Mandatory = $true)][ValidateRange(50000, 65000)][int]$DistractorPort,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [ValidateRange(45, 120)][int]$ObservationSeconds = 75,
    [ValidateRange(1, 5)][int]$DistractorSeconds = 2
)

$ErrorActionPreference = "Stop"
$auditSubcategory = "Filtering Platform Connection"
$baselinePolicy = $null
$targetAuditPolicy = $null
$restoredPolicy = $null
$auditEnableAttempted = $false
$auditRestoreExitCode = $null
$securityRecordIdBefore = $null
$securityRecordIdAfter = $null
$securityEvents = @()
$localEventQueryStatus = "NOT_RUN"
$localEventQueryError = $null
$actions = [System.Collections.Generic.List[object]]::new()
$failure = $null
$startedUtc = [DateTime]::UtcNow

function Get-AuditPolicyText {
    $text = @(& auditpol.exe /get "/subcategory:$auditSubcategory" 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Could not read Filtering Platform Connection audit policy." }
    return ($text -join "`n")
}

function Set-AuditSuccess {
    $output = @(& auditpol.exe /set "/subcategory:$auditSubcategory" /success:enable /failure:disable 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Could not enable success auditing: $($output -join ' ')" }
    $script:auditEnableAttempted = $true
    $policy = Get-AuditPolicyText
    if ($policy -notmatch "(?im)Filtering Platform Connection\s+Success") {
        throw "WFP success auditing did not become active."
    }
    return $policy
}

function Set-AuditBaseline {
    $output = @(& auditpol.exe /set "/subcategory:$auditSubcategory" /success:disable /failure:disable 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Could not restore No Auditing: $($output -join ' ')" }
    $script:auditRestoreExitCode = $LASTEXITCODE
    $policy = Get-AuditPolicyText
    if ($policy -notmatch "(?im)Filtering Platform Connection\s+No Auditing") {
        throw "WFP audit policy did not return to the required No Auditing baseline."
    }
    return $policy
}

function Get-ProbeTaskState {
    $task = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction Stop
    return $task.State.ToString()
}

function Invoke-LoopbackListener([int]$Port, [int]$HoldSeconds, [string]$Role) {
    $listener = $null
    $client = $null
    $accepted = $null
    $start = $null
    $cleanup = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        $start = [DateTime]::UtcNow
        $client = [System.Net.Sockets.TcpClient]::new()
        $client.Connect("127.0.0.1", $Port)
        $accepted = $listener.AcceptTcpClient()
        Start-Sleep -Seconds $HoldSeconds
    } finally {
        $cleanup = [DateTime]::UtcNow
        if ($accepted) { $accepted.Dispose() }
        if ($client) { $client.Dispose() }
        if ($listener) { $listener.Stop() }
    }
    $script:actions.Add([ordered]@{
        role = $Role
        port = $Port
        bind_address = "127.0.0.1"
        started_utc = if ($start) { $start.ToString("o") } else { $null }
        cleanup_started_utc = if ($cleanup) { $cleanup.ToString("o") } else { $null }
        hold_seconds = $HoldSeconds
    })
}

function Read-5154Events([long]$RecordIdAfter) {
    $xpath = "*[System[(EventID=5154) and (EventRecordID > $RecordIdAfter)]]"
    try {
        return @(
            Get-WinEvent -LogName "Security" -FilterXPath $xpath |
                ForEach-Object {
                    $xmlText = $_.ToXml()
                    $xml = [xml]$xmlText
                    $data = @{}
                    foreach ($field in $xml.Event.EventData.Data) {
                        $data[[string]$field.Name] = [string]$field.'#text'
                    }
                    [ordered]@{
                        time_created_utc = $_.TimeCreated.ToUniversalTime().ToString("o")
                        event_record_id = [string]$_.RecordId
                        event_id = $_.Id
                        fields = $data
                        raw_xml = $xmlText
                    }
                }
        )
    } catch {
        if ($_.FullyQualifiedErrorId -like "NoMatchingEventsFound,*") { return @() }
        throw
    }
}

function Test-ListenerAbsent([int]$Port) {
    return @(
        Get-NetTCPConnection -State Listen -LocalAddress "127.0.0.1" -LocalPort $Port -ErrorAction SilentlyContinue
    ).Count -eq 0
}

$preflight = [ordered]@{}
$postflight = [ordered]@{}
try {
    if ($TargetPort -eq $DistractorPort) { throw "Target and distractor ports must differ." }
    $wazuhBefore = (Get-Service -Name "WazuhSvc" -ErrorAction Stop).Status.ToString()
    $probeBefore = Get-ProbeTaskState
    if ($wazuhBefore -ne "Running") { throw "WazuhSvc is not running at preflight." }
    if ($probeBefore -ne "Running") { throw "The native probe task is not running at preflight." }
    if (-not (Test-ListenerAbsent $TargetPort) -or -not (Test-ListenerAbsent $DistractorPort)) {
        throw "A randomized trial port is already listening."
    }
    $baselinePolicy = Get-AuditPolicyText
    if ($baselinePolicy -notmatch "(?im)Filtering Platform Connection\s+No Auditing") {
        throw "Audit policy differs from the frozen No Auditing baseline; refusing to overwrite it."
    }
    $securityRecordIdBefore = [long](Get-WinEvent -LogName "Security" -MaxEvents 1).RecordId
    $preflight = [ordered]@{
        wazuh_service = $wazuhBefore
        probe_task = $probeBefore
        wfp_audit_policy = $baselinePolicy
        target_port_absent = $true
        distractor_port_absent = $true
        security_record_id_before = $securityRecordIdBefore
    }

    [void](Set-AuditSuccess)
    Invoke-LoopbackListener -Port $DistractorPort -HoldSeconds $DistractorSeconds -Role "wrong_object_distractor"

    if ($Condition -eq "complete_exact") {
        $targetAuditPolicy = Get-AuditPolicyText
        Invoke-LoopbackListener -Port $TargetPort -HoldSeconds $ObservationSeconds -Role "target"
    } else {
        $restoredPolicy = Set-AuditBaseline
        $targetAuditPolicy = Get-AuditPolicyText
        if ($Condition -eq "target_event_absent_with_distractor") {
            Invoke-LoopbackListener -Port $TargetPort -HoldSeconds $ObservationSeconds -Role "target"
        } else {
            Start-Sleep -Seconds $ObservationSeconds
        }
    }
} catch {
    $failure = $_.Exception.ToString()
} finally {
    if ($auditEnableAttempted) {
        try { $restoredPolicy = Set-AuditBaseline } catch {
            if (-not $failure) { $failure = $_.Exception.ToString() }
            $restoredPolicy = Get-AuditPolicyText
        }
    }
    try {
        if ($null -ne $securityRecordIdBefore) {
            $securityEvents = @(Read-5154Events -RecordIdAfter $securityRecordIdBefore)
            $localEventQueryStatus = if ($securityEvents.Count) { "COMPLETE_WITH_EVENTS" } else { "COMPLETE_NO_MATCHES" }
        }
    } catch {
        $localEventQueryStatus = "ERROR"
        $localEventQueryError = $_.Exception.ToString()
        if (-not $failure) { $failure = $localEventQueryError }
    }
    try { $securityRecordIdAfter = [long](Get-WinEvent -LogName "Security" -MaxEvents 1).RecordId } catch {}
    try {
        $postflight = [ordered]@{
            wazuh_service = (Get-Service -Name "WazuhSvc").Status.ToString()
            probe_task = Get-ProbeTaskState
            target_port_absent = Test-ListenerAbsent $TargetPort
            distractor_port_absent = Test-ListenerAbsent $DistractorPort
            wfp_audit_policy = Get-AuditPolicyText
            security_record_id_after = $securityRecordIdAfter
        }
    } catch {
        if (-not $failure) { $failure = $_.Exception.ToString() }
    }
}

$targetEvents = @($securityEvents | Where-Object {
    $_.fields.SourceAddress -eq "127.0.0.1" -and $_.fields.SourcePort -eq [string]$TargetPort -and $_.fields.Protocol -eq "6"
})
$distractorEvents = @($securityEvents | Where-Object {
    $_.fields.SourceAddress -eq "127.0.0.1" -and $_.fields.SourcePort -eq [string]$DistractorPort -and $_.fields.Protocol -eq "6"
})
$auditRestored = [bool]($restoredPolicy -match "(?im)Filtering Platform Connection\s+No Auditing")
$result = [ordered]@{
    schema_version = "csg-wfp-5154-listener-trial-v1"
    trial_id = $TrialId
    condition = $Condition
    host = $env:COMPUTERNAME
    target = [ordered]@{ address = "127.0.0.1"; port = $TargetPort; object_key = "listener:tcp:127.0.0.1:$TargetPort" }
    distractor = [ordered]@{ address = "127.0.0.1"; port = $DistractorPort; object_key = "listener:tcp:127.0.0.1:$DistractorPort" }
    observation_seconds = $ObservationSeconds
    started_utc = $startedUtc.ToString("o")
    completed_utc = [DateTime]::UtcNow.ToString("o")
    preflight = $preflight
    actions = @($actions)
    target_audit_policy = $targetAuditPolicy
    audit_policy_after_restore = $restoredPolicy
    audit_restored_to_baseline = $auditRestored
    local_event_query_status = $localEventQueryStatus
    local_event_query_error = $localEventQueryError
    local_event_query_method = "Security EventRecordID greater than captured pretrial record ID"
    security_record_id_before = $securityRecordIdBefore
    security_record_id_after = $securityRecordIdAfter
    local_5154_events = $securityEvents
    target_event_count = $targetEvents.Count
    distractor_event_count = $distractorEvents.Count
    target_listener_events = $targetEvents
    distractor_listener_events = $distractorEvents
    postflight = $postflight
    failure = $failure
}

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$json = $result | ConvertTo-Json -Depth 14
[System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.UTF8Encoding]::new($false))
$json
if (
    $failure -or -not $auditRestored -or $postflight.wazuh_service -ne "Running" -or
    $postflight.probe_task -ne "Running" -or -not $postflight.target_port_absent -or
    -not $postflight.distractor_port_absent -or $postflight.wfp_audit_policy -notmatch "(?im)Filtering Platform Connection\s+No Auditing"
) { exit 1 }
