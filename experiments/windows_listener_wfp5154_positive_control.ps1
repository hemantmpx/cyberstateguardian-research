param(
    [ValidateRange(49152, 65535)][int]$Port = 49389,
    [string]$OutputPath = "C:\CSG\listener-wfp5154-positive-control.json",
    [string]$TrialId = "listener-wfp5154-positive-control-20261016-02",
    [ValidateRange(10, 45)][int]$ObservationSeconds = 35
)

$ErrorActionPreference = "Stop"
$auditSubcategory = "Filtering Platform Connection"
$baselinePolicy = $null
$enabledPolicy = $null
$restoredPolicy = $null
$auditEnableAttempted = $false
$listener = $null
$client = $null
$accepted = $null
$failure = $null
$securityEvents = @()
$eventQueryStatus = "NOT_RUN"
$eventQueryError = $null
$securityRecordIdBefore = $null
$securityRecordIdAfter = $null
$listenerStartedUtc = $null
$cleanupStartedUtc = $null
$cleanupCompletedUtc = $null
$auditRestoreExitCode = $null

function Get-AuditPolicyText {
    $text = @(& auditpol.exe /get "/subcategory:$auditSubcategory" 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Could not read Filtering Platform Connection audit policy." }
    return ($text -join "`n")
}

function Read-5154Events([long]$RecordIdAfter) {
    $channel = "Security"
    $xpath = "*[System[(EventID=5154) and (EventRecordID > $RecordIdAfter)]]"
    try {
        return @(
            Get-WinEvent -LogName $channel -FilterXPath $xpath |
                ForEach-Object {
                    $xmlText = $_.ToXml()
                    $xml = [xml]$xmlText
                    $data = @{}
                    foreach ($field in $xml.Event.EventData.Data) {
                        $data[[string]$field.Name] = [string]$field.'#text'
                    }
                    [ordered]@{
                        time_created_utc = $_.TimeCreated.ToUniversalTime().ToString("o")
                        event_record_id = $_.RecordId
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

$startUtc = [DateTime]::UtcNow
$probeTaskState = (Get-ScheduledTask -TaskName "CyberStateGuardian Probe").State.ToString()
$wazuhServiceState = (Get-Service -Name "WazuhSvc").Status.ToString()

try {
    if ($wazuhServiceState -ne "Running") { throw "WazuhSvc is not running at preflight." }
    if ($probeTaskState -ne "Running") { throw "The native probe task is not running at preflight." }
    $baselinePolicy = Get-AuditPolicyText
    if ($baselinePolicy -notmatch "(?im)Filtering Platform Connection\s+No Auditing") {
        throw "Audit policy differs from the frozen No Auditing baseline; refusing to overwrite it."
    }
    if (@(Get-NetTCPConnection -State Listen -LocalAddress "127.0.0.1" -LocalPort $Port -ErrorAction SilentlyContinue).Count) {
        throw "The selected loopback port is already listening."
    }
    $securityRecordIdBefore = [long](Get-WinEvent -LogName "Security" -MaxEvents 1).RecordId

    $auditEnableAttempted = $true
    $enableOutput = @(& auditpol.exe /set "/subcategory:$auditSubcategory" /success:enable /failure:disable 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Could not enable success auditing: $($enableOutput -join ' ')" }
    $enabledPolicy = Get-AuditPolicyText
    if ($enabledPolicy -notmatch "(?im)Filtering Platform Connection\s+Success") {
        throw "Audit policy did not report Success after enablement."
    }

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    $listener.Start()
    $listenerStartedUtc = [DateTime]::UtcNow
    $client = [System.Net.Sockets.TcpClient]::new()
    $client.Connect("127.0.0.1", $Port)
    $accepted = $listener.AcceptTcpClient()
    Start-Sleep -Seconds $ObservationSeconds
} catch {
    $failure = $_.Exception.ToString()
} finally {
    $cleanupStartedUtc = [DateTime]::UtcNow
    if ($accepted) { $accepted.Dispose() }
    if ($client) { $client.Dispose() }
    if ($listener) { $listener.Stop() }
    $cleanupCompletedUtc = [DateTime]::UtcNow

    try {
        if ($null -ne $securityRecordIdBefore) {
            $securityEvents = @(Read-5154Events -RecordIdAfter $securityRecordIdBefore)
        }
        $eventQueryStatus = if ($securityEvents.Count) { "COMPLETE_WITH_EVENTS" } else { "COMPLETE_NO_MATCHES" }
    } catch {
        $eventQueryStatus = "ERROR"
        $eventQueryError = $_.Exception.ToString()
    }

    if ($auditEnableAttempted) {
        $restoreOutput = @(& auditpol.exe /set "/subcategory:$auditSubcategory" /success:disable /failure:disable 2>&1)
        $auditRestoreExitCode = $LASTEXITCODE
        try { $restoredPolicy = Get-AuditPolicyText } catch { $restoredPolicy = $_.Exception.ToString() }
    }
    try { $securityRecordIdAfter = [long](Get-WinEvent -LogName "Security" -MaxEvents 1).RecordId } catch {}
}

$targetEvents = @($securityEvents | Where-Object {
    $_.fields.SourceAddress -eq "127.0.0.1" -and
    $_.fields.SourcePort -eq [string]$Port -and
    $_.fields.Protocol -eq "6"
})
$listenerAbsent = @(
    Get-NetTCPConnection -State Listen -LocalAddress "127.0.0.1" -LocalPort $Port -ErrorAction SilentlyContinue
).Count -eq 0
$auditRestored = $false
if ($auditEnableAttempted -and $auditRestoreExitCode -eq 0 -and $restoredPolicy) {
    $auditRestored = $restoredPolicy -match "(?im)Filtering Platform Connection\s+No Auditing"
}
$endUtc = [DateTime]::UtcNow

$result = [ordered]@{
    schema_version = "csg-wfp-5154-positive-control-v1"
    trial_id = $TrialId
    host = $env:COMPUTERNAME
    port = $Port
    bind_address = "127.0.0.1"
    start_utc = $startUtc.ToString("o")
    listener_started_utc = if ($listenerStartedUtc) { $listenerStartedUtc.ToString("o") } else { $null }
    cleanup_started_utc = if ($cleanupStartedUtc) { $cleanupStartedUtc.ToString("o") } else { $null }
    cleanup_completed_utc = if ($cleanupCompletedUtc) { $cleanupCompletedUtc.ToString("o") } else { $null }
    end_utc = $endUtc.ToString("o")
    observation_seconds = $ObservationSeconds
    preflight = [ordered]@{
        wazuh_service_state = $wazuhServiceState
        probe_task_state = $probeTaskState
        audit_policy = $baselinePolicy
    }
    temporary_audit_policy = $enabledPolicy
    audit_policy_after_restore = $restoredPolicy
    audit_restore_exit_code = $auditRestoreExitCode
    audit_restored_to_baseline = $auditRestored
    local_event_query_status = $eventQueryStatus
    local_event_query_method = "Security EventRecordID greater than captured pre-trial record ID"
    local_event_query_error = $eventQueryError
    security_event_record_id_before = $securityRecordIdBefore
    security_event_record_id_after = $securityRecordIdAfter
    local_5154_event_count = $securityEvents.Count
    exact_listener_5154_match_count = $targetEvents.Count
    listener_events = $securityEvents
    target_listener_events = $targetEvents
    listener_absent_after_cleanup = $listenerAbsent
    failure = $failure
}

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$json = $result | ConvertTo-Json -Depth 12
[System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.UTF8Encoding]::new($false))
$json
if ($failure -or -not $auditRestored -or -not $listenerAbsent) { exit 1 }
