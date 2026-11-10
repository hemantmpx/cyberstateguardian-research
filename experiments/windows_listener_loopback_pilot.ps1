param(
    [ValidateRange(49152, 65535)][int]$Port = 49387,
    [string]$OutputPath = "C:\CSG\listener-loopback-pilot.json",
    [ValidateRange(10, 55)][int]$ObservationSeconds = 45
)

$ErrorActionPreference = "Stop"
$taskName = "CyberStateGuardian Probe"
$channel = "Microsoft-Windows-Sysmon/Operational"
$startUtc = [DateTime]::UtcNow
$sysmonRecordIdBefore = $null
$listener = $null
$client = $null
$accepted = $null
$failure = $null
$activeListenerRows = @()
$clientLocalEndpoint = $null
$probeTaskBefore = $null
$probeTaskDuring = $null
$cleanupStartedUtc = $null
$cleanupCompletedUtc = $null

try {
    $sysmonRecordIdBefore = [long](Get-WinEvent -LogName $channel -MaxEvents 1).RecordId
    $existing = @(Get-NetTCPConnection -State Listen -LocalAddress "127.0.0.1" -LocalPort $Port -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) {
        throw "The preselected loopback port is already listening."
    }

    $probeTaskBefore = Get-ScheduledTaskInfo -TaskName $taskName
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    $listener.Start()
    $client = [System.Net.Sockets.TcpClient]::new()
    $client.Connect("127.0.0.1", $Port)
    $accepted = $listener.AcceptTcpClient()
    $clientLocalEndpoint = [string]$client.Client.LocalEndPoint

    $activeListenerRows = @(
        Get-NetTCPConnection -State Listen -LocalAddress "127.0.0.1" -LocalPort $Port |
            Select-Object LocalAddress, LocalPort, OwningProcess
    )
    if ($activeListenerRows.Count -ne 1) {
        throw "Windows did not report exactly one expected loopback listener."
    }

    Start-ScheduledTask -TaskName $taskName
    Start-Sleep -Seconds $ObservationSeconds
    $probeTaskDuring = Get-ScheduledTaskInfo -TaskName $taskName
} catch {
    $failure = $_.Exception.ToString()
} finally {
    $cleanupStartedUtc = [DateTime]::UtcNow
    if ($accepted) { $accepted.Dispose() }
    if ($client) { $client.Dispose() }
    if ($listener) { $listener.Stop() }
    $cleanupCompletedUtc = [DateTime]::UtcNow
    try {
        Start-ScheduledTask -TaskName $taskName
        Start-Sleep -Seconds 3
    } catch {
        if (-not $failure) { $failure = "Post-cleanup probe trigger failed: $($_.Exception)" }
    }
}

$endUtc = [DateTime]::UtcNow
$sysmonEvents = @()
$sysmonQueryStatus = "COMPLETE"
$sysmonReadError = $null
try {
    if ($null -eq $sysmonRecordIdBefore) {
        throw "Could not capture the pre-trial Sysmon event record ID."
    }
    $xpath = "*[System[(EventID=3) and (EventRecordID > $sysmonRecordIdBefore)]]"
    $sysmonEvents = @(
        Get-WinEvent -LogName $channel -FilterXPath $xpath -ErrorAction Stop |
            ForEach-Object {
                $xml = [xml]$_.ToXml()
                $data = @{}
                foreach ($field in $xml.Event.EventData.Data) {
                    $data[[string]$field.Name] = [string]$field.'#text'
                }
                [ordered]@{
                    time_created_utc = $_.TimeCreated.ToUniversalTime().ToString("o")
                    event_record_id = $_.RecordId
                    event_id = $_.Id
                    fields = $data
                    raw_xml = $_.ToXml()
                }
            }
    )
} catch {
    if ($_.FullyQualifiedErrorId -like "NoMatchingEventsFound,*") {
        $sysmonQueryStatus = "COMPLETE_NO_MATCHES"
    } else {
        $sysmonQueryStatus = "ERROR"
        $sysmonReadError = $_.Exception.ToString()
    }
}

$result = [ordered]@{
    schema_version = "csg-loopback-listener-pilot-v1"
    trial_id = "listener-loopback-20261016-01"
    host = $env:COMPUTERNAME
    port = $Port
    bind_address = "127.0.0.1"
    start_utc = $startUtc.ToString("o")
    end_utc = $endUtc.ToString("o")
    observation_seconds = $ObservationSeconds
    probe_task_before = $probeTaskBefore
    probe_task_during = $probeTaskDuring
    windows_listener_active = $activeListenerRows
    client_local_endpoint = $clientLocalEndpoint
    cleanup_started_utc = if ($cleanupStartedUtc) { $cleanupStartedUtc.ToString("o") } else { $null }
    cleanup_completed_utc = if ($cleanupCompletedUtc) { $cleanupCompletedUtc.ToString("o") } else { $null }
    listener_absent_after_cleanup = @(
        Get-NetTCPConnection -State Listen -LocalAddress "127.0.0.1" -LocalPort $Port -ErrorAction SilentlyContinue
    ).Count -eq 0
    sysmon_event_id_3_count = $sysmonEvents.Count
    sysmon_record_id_before = $sysmonRecordIdBefore
    sysmon_query_method = "Sysmon EventRecordID greater than captured pre-trial record ID"
    sysmon_query_status = $sysmonQueryStatus
    sysmon_events = $sysmonEvents
    sysmon_read_error = $sysmonReadError
    failure = $failure
}

$parent = Split-Path -Parent $OutputPath
if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$json = $result | ConvertTo-Json -Depth 12
[System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.UTF8Encoding]::new($false))
$json
if ($failure -or -not $result.listener_absent_after_cleanup) { exit 1 }
