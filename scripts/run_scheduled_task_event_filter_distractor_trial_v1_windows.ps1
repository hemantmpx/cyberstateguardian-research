param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedAgentConfigSha256,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [string]$CsgApiBase = 'http://192.168.64.1:8000',
    [string]$HostId = 'win11-arm-lab',
    [string]$ProbePython = 'C:\Program Files\CyberStateGuardian\Probe\venv\Scripts\python.exe',
    [string]$ProbeConfig = 'C:\Program Files\CyberStateGuardian\Probe\settings.json',
    [string]$RunnerPath = 'C:\CSG\run_windows_category_positive_controls_target_name_v1.ps1',
    [string]$FilterPilotPath = 'C:\CSG\run_scheduled_task_eventid_filter_pilot_v5_windows.ps1',
    [int]$WaitSeconds = 35,
    [int]$ReconciliationWaitSeconds = 480,
    [int]$ProviderWaitSeconds = 90
)

$ErrorActionPreference = 'Stop'
$configPath = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw "Refusing to overwrite $OutputDirectory" }
foreach ($path in @($configPath, $ProbePython, $ProbeConfig, $RunnerPath, $FilterPilotPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file is missing: $path" }
}
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw 'Run from elevated Administrator PowerShell.' }
if ($WaitSeconds -lt 30 -or $WaitSeconds -gt 180) { throw 'WaitSeconds must be 30..180.' }
if ($ReconciliationWaitSeconds -lt 300 -or $ReconciliationWaitSeconds -gt 900) {
    throw 'ReconciliationWaitSeconds must be 300..900.'
}

$originalHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($originalHash -ne $ExpectedAgentConfigSha256.ToLowerInvariant()) {
    throw "Wazuh config hash differs from frozen precondition: $originalHash"
}
$probeSettings = Get-Content -LiteralPath $ProbeConfig -Raw | ConvertFrom-Json
if ($probeSettings.CSG_PROBE_HOST_ID -ne $HostId) { throw 'Probe host ID does not match.' }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$script:probeLogPath = Join-Path $OutputDirectory 'probe-output.log'
$pilotDirectory = Join-Path $OutputDirectory 'target-event-filter'
$resultPath = Join-Path $OutputDirectory 'paired-trial.json'
$targetName = 'CSGAPTTask' + [guid]::NewGuid().ToString('N').Substring(0, 10)
$distractorName = 'CSGWrongObject' + [guid]::NewGuid().ToString('N').Substring(0, 10)
$targetKey = 'scheduled_task:\' + $targetName.ToLowerInvariant()
$distractorKey = 'scheduled_task:\' + $distractorName.ToLowerInvariant()
$trialStartedAt = [DateTime]::UtcNow
$distractorCreated = $false
$pilotResult = $null
$distractorEvent = $null
$distractorStored = $false
$cleanupVerified = $false
$errorText = $null
$providerTrace = New-Object System.Collections.Generic.List[object]

function Normalize-Identity {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    $valueText = ([string]$Value).Trim().ToLowerInvariant().Replace('/', '\')
    while ($valueText.Contains('\\')) { $valueText = $valueText.Replace('\\', '\') }
    return $valueText
}

function Invoke-ProbeOnce {
    & $ProbePython -m cyberstateguardian_probe.main --config $ProbeConfig --once *>> $script:probeLogPath
    if ($LASTEXITCODE -ne 0) { throw "Direct probe failed with exit code $LASTEXITCODE." }
}

function Get-LatestObservation {
    Invoke-RestMethod -Method Get -TimeoutSec 30 -Uri (
        "$($CsgApiBase.TrimEnd('/'))/api/hosts/$HostId/observations/latest"
    )
}

function Test-ExactTaskEvent {
    param([object]$Event, [string]$TaskName, [string]$ObjectKey)
    if ($Event.host_id -ne $HostId -or $Event.source -ne 'wazuh' -or
        $Event.normalized_type -ne 'scheduled_task_created') { return $false }
    $keyMatch = (Normalize-Identity $Event.target.key) -eq (Normalize-Identity $ObjectKey)
    $name = if ($Event.attributes.task_name) { $Event.attributes.task_name } else { $Event.task_name }
    return $keyMatch -or (Normalize-Identity $name) -eq (Normalize-Identity ('\' + $TaskName))
}

function Get-ProviderObservation {
    param([datetime]$StartUtc, [datetime]$EndUtc)
    $start = [uri]::EscapeDataString($StartUtc.ToUniversalTime().ToString('o'))
    $end = [uri]::EscapeDataString($EndUtc.ToUniversalTime().ToString('o'))
    Invoke-RestMethod -Method Get -TimeoutSec 90 -Uri (
        "$($CsgApiBase.TrimEnd('/'))/api/hosts/$HostId/provider-event-observation?start=$start&end=$end"
    )
}

function Get-EventStoreMatches {
    param([datetime]$StartUtc, [datetime]$EndUtc, [string]$TaskName, [string]$ObjectKey)
    $start = [uri]::EscapeDataString($StartUtc.ToUniversalTime().ToString('o'))
    $end = [uri]::EscapeDataString($EndUtc.ToUniversalTime().ToString('o'))
    $type = [uri]::EscapeDataString('scheduled_task_created')
    $key = [uri]::EscapeDataString($ObjectKey)
    $name = [uri]::EscapeDataString($TaskName)
    $events = @(Invoke-RestMethod -Method Get -TimeoutSec 60 -Uri (
        "$($CsgApiBase.TrimEnd('/'))/api/hosts/$HostId/events?start=$start&end=$end" +
        "&normalized_type=$type&source=wazuh&object_key=$key&object_name=$name&limit=100"
    ))
    if ($events.Count -ge 100) { throw 'Event-store readback reached the 100-event cap; absence is not inferable.' }
    @($events | Where-Object { Test-ExactTaskEvent -Event $_ -TaskName $TaskName -ObjectKey $ObjectKey })
}

function Get-Local4698 {
    param([string]$TaskName, [datetime]$NotBeforeUtc)
    $minimum = $NotBeforeUtc.ToLocalTime().AddMinutes(-1)
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4698; StartTime = $minimum } -ErrorAction Stop)
    foreach ($event in $events) {
        [xml]$xml = $event.ToXml()
        $field = @($xml.Event.EventData.Data | Where-Object { $_.Name -in @('TaskName', 'Task_Name') } |
            Select-Object -First 1)[0]
        if ($field -and (Normalize-Identity $field.InnerText) -eq (Normalize-Identity ('\' + $TaskName))) {
            return [ordered]@{
                event_id = [int]$event.Id
                record_id = [long]$event.RecordId
                event_time_utc = $event.TimeCreated.ToUniversalTime().ToString('o')
                task_name = [string]$field.InnerText
                raw_xml = $event.ToXml()
            }
        }
    }
    return $null
}

function Get-LabHealth {
    $status = Invoke-RestMethod -Method Get -TimeoutSec 25 -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
    $agent = @($status.server_api.agents | Where-Object name -eq $HostId | Select-Object -First 1)[0]
    $service = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
    [ordered]@{
        observed_at_utc = [DateTime]::UtcNow.ToString('o')
        csg_api_healthy = [bool]$status.ok
        wazuh_server_api_healthy = [bool]$status.server_api.ok
        wazuh_indexer_healthy = [bool]$status.indexer.ok
        endpoint_agent_status = if ($agent) { [string]$agent.status } else { 'NOT_FOUND' }
        wazuh_service_status = [string]$service.State
        wazuh_service_pid = [int]$service.ProcessId
    }
}

function Get-TaskPresence {
    param([object]$Observation, [string]$TaskName)
    $items = @($Observation.categories.scheduled_task.items)
    @($items | Where-Object {
        (Normalize-Identity $_.task_name) -eq (Normalize-Identity ('\' + $TaskName))
    }).Count -gt 0
}

function Write-Json {
    param([string]$Path, [object]$Value)
    $Value | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $Path -Encoding UTF8
}

$preflight = $null
$healthBefore = $null
$distractorActionStarted = $null
$distractorActionEnded = $null
$distractorLocalEvent = $null
$distractorProviderQuery = $null
$distractorIngestAck = $null
$distractorReadback = @()
$targetPilotExitCode = $null
$targetScenario = $null
$targetReconciliation = $null
$targetProviderQuery = $null
$targetDistractorReadback = @()
$targetLocalEvidenceCount = 0
$targetStateSequence = $false
$targetExactEventAbsent = $false
$targetFinalUnexplained = $false
$distractorInsideWindow = $false
$distractorReturnedInTargetQuery = $false
$configRestored = $false
$healthAfter = $null

try {
    $healthBefore = Get-LabHealth
    if (-not $healthBefore.csg_api_healthy -or -not $healthBefore.wazuh_server_api_healthy -or
        -not $healthBefore.wazuh_indexer_healthy -or $healthBefore.endpoint_agent_status -ne 'active' -or
        $healthBefore.wazuh_service_status -ne 'Running') { throw 'Preflight health is not fully available.' }
    $probeBefore = Get-Content -LiteralPath $ProbeConfig -Raw | ConvertFrom-Json
    if ($probeBefore.CSG_PROBE_HOST_ID -ne $HostId) { throw 'Probe host ID differs from the requested host.' }
    $securityLog = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
    if (-not $securityLog.IsEnabled) { throw 'Windows Security log is disabled.' }
    $residual = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskName -like 'CSGAPTTask*' -or $_.TaskName -like 'CSGAPTDis*' -or $_.TaskName -like 'CSGWrongObject*'
    } | ForEach-Object { '{0}{1}' -f $_.TaskPath, $_.TaskName })
    if ($residual.Count -gt 0) { throw 'Preflight found residual study tasks.' }
    Invoke-ProbeOnce
    $before = Get-LatestObservation
    if (Get-TaskPresence -Observation $before -TaskName $targetName) { throw 'Randomized target exists before trial.' }
    if (Get-TaskPresence -Observation $before -TaskName $distractorName) { throw 'Randomized distractor exists before trial.' }
    $preflight = [ordered]@{
        captured_at_utc = [DateTime]::UtcNow.ToString('o')
        host_id = $HostId
        computer_name = $env:COMPUTERNAME
        windows_build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        original_agent_config_sha256 = $originalHash
        runner_sha256 = (Get-FileHash -LiteralPath $RunnerPath -Algorithm SHA256).Hash.ToLowerInvariant()
        filter_pilot_sha256 = (Get-FileHash -LiteralPath $FilterPilotPath -Algorithm SHA256).Hash.ToLowerInvariant()
        probe_config_sha256 = (Get-FileHash -LiteralPath $ProbeConfig -Algorithm SHA256).Hash.ToLowerInvariant()
        health = $healthBefore
        security_log_enabled = [bool]$securityLog.IsEnabled
        baseline_observation_id = [string]$before.observation_id
        baseline_observed_at = [string]$before.observed_at
        residual_study_tasks = $residual
    }
    Write-Json -Path (Join-Path $OutputDirectory 'preflight.json') -Value $preflight

    $distractorActionStarted = [DateTime]::UtcNow
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit 0'
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1)
    Register-ScheduledTask -TaskName $distractorName -TaskPath '\' -Action $action -Trigger $trigger `
        -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    $distractorCreated = $true
    $distractorActionEnded = [DateTime]::UtcNow
    $distractorDeadline = [DateTime]::UtcNow.AddSeconds($ProviderWaitSeconds)
    do {
        $distractorLocalEvent = Get-Local4698 -TaskName $distractorName -NotBeforeUtc $distractorActionStarted
        $end = [DateTime]::UtcNow.AddSeconds(2)
        $distractorProviderQuery = Get-ProviderObservation -StartUtc $distractorActionStarted.AddMinutes(-1) -EndUtc $end
        $exact = @($distractorProviderQuery.events | Where-Object {
            Test-ExactTaskEvent -Event $_ -TaskName $distractorName -ObjectKey $distractorKey
        })
        $providerTrace.Add([ordered]@{
            queried_at_utc = [DateTime]::UtcNow.ToString('o')
            query_complete = [bool]$distractorProviderQuery.query_complete
            coverage_status = [string]$distractorProviderQuery.coverage_status
            endpoint_collection_status = [string]$distractorProviderQuery.endpoint_collection_status
            transport_status = [string]$distractorProviderQuery.transport_status
            index_status = [string]$distractorProviderQuery.index_status
            exact_distractor_count = $exact.Count
        })
        if ($exact.Count -eq 1) { $distractorEvent = $exact[0]; break }
        if ($exact.Count -gt 1) { throw 'Provider returned duplicate exact distractor records.' }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $distractorDeadline)
    if (-not $distractorLocalEvent) { throw 'No exact local Windows Security 4698 for the distractor.' }
    if (-not $distractorEvent) { throw 'Wazuh did not return the exact distractor event before the deadline.' }
    if ($distractorProviderQuery.query_complete -ne $true -or
        $distractorProviderQuery.coverage_status -ne 'COMPLETE' -or
        $distractorProviderQuery.endpoint_collection_status -ne 'AVAILABLE' -or
        $distractorProviderQuery.transport_status -ne 'AVAILABLE' -or
        $distractorProviderQuery.index_status -ne 'AVAILABLE') {
        throw 'The exact distractor was returned under incomplete/unavailable provider coverage.'
    }
    $distractorBody = ConvertTo-Json -InputObject @($distractorEvent) -Depth 40 -Compress
    $distractorIngestAck = @(Invoke-RestMethod -Method Post -TimeoutSec 60 `
        -Uri "$($CsgApiBase.TrimEnd('/'))/api/events" -ContentType 'application/json' -Body $distractorBody)
    if (@($distractorIngestAck | Where-Object event_id -eq $distractorEvent.event_id).Count -ne 1) {
        throw 'CSG ingest API did not acknowledge the exact distractor event ID.'
    }
    $distractorReadback = @(Get-EventStoreMatches -StartUtc $distractorActionStarted.AddMinutes(-1) `
        -EndUtc ([DateTime]::UtcNow.AddSeconds(5)) -TaskName $distractorName -ObjectKey $distractorKey)
    if ($distractorReadback.Count -ne 1 -or $distractorReadback[0].event_id -ne $distractorEvent.event_id) {
        throw 'CSG event-store readback did not return exactly the acknowledged distractor.'
    }
    $distractorStored = $true
    Invoke-ProbeOnce
    $afterDistractor = Get-LatestObservation
    if (-not (Get-TaskPresence -Observation $afterDistractor -TaskName $distractorName)) {
        throw 'Fresh direct-probe observation did not contain the distractor task.'
    }
    Write-Json -Path (Join-Path $OutputDirectory 'distractor-evidence.json') -Value ([ordered]@{
        action_started_at_utc = $distractorActionStarted.ToString('o')
        action_ended_at_utc = $distractorActionEnded.ToString('o')
        task_name = $distractorName
        object_key = $distractorKey
        local_windows_event = $distractorLocalEvent
        provider_query_trace = @($providerTrace.ToArray())
        provider_event = $distractorEvent
        csg_ingest_acknowledgement = $distractorIngestAck
        csg_event_store_readback = $distractorReadback
        direct_probe_observation_id = [string]$afterDistractor.observation_id
        direct_probe_observed_at = [string]$afterDistractor.observed_at
        target_task_name = $targetName
    })

    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$FilterPilotPath`" " +
        "-ExpectedAgentConfigSha256 $originalHash -OutputDirectory `"$pilotDirectory`" " +
        "-CsgApiBase `"$CsgApiBase`" -HostId `"$HostId`" " +
        "-ProbePython `"$ProbePython`" -ProbeConfig `"$ProbeConfig`" " +
        "-RunnerPath `"$RunnerPath`" -ScheduledTaskName `"$targetName`" " +
        "-WaitSeconds $WaitSeconds -ReconciliationWaitSeconds $ReconciliationWaitSeconds -PostRestoreQuerySeconds 90"
    $stdout = Join-Path $OutputDirectory 'target-filter.stdout.txt'
    $stderr = Join-Path $OutputDirectory 'target-filter.stderr.txt'
    $pilot = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -PassThru -Wait `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden
    $targetPilotExitCode = [int]$pilot.ExitCode
    $pilotResultPath = Join-Path $pilotDirectory 'result.json'
    if (-not (Test-Path -LiteralPath $pilotResultPath -PathType Leaf)) {
        throw "Target filter pilot produced no result.json (exit $targetPilotExitCode)."
    }
    $pilotResult = Get-Content -LiteralPath $pilotResultPath -Raw | ConvertFrom-Json
    $targetScenario = @($pilotResult.runner_result.scenarios | Where-Object kind -eq 'scheduled_task' |
        Select-Object -First 1)[0]
    if (-not $targetScenario) { throw 'Target runner did not report the scheduled-task scenario.' }
    if ($targetScenario.object_name -ne $targetName) { throw 'Runner used a target name different from the frozen assignment.' }
    $targetReconciliation = $pilotResult.final_target_reconciliation
    $targetLocalEvidenceCount = @($targetScenario.local_source_evidence.exact_events | Where-Object {
        $_.event_id -eq 4698 -and $_.exact_identity_match
    }).Count
    $targetStateSequence = [bool]($pilotResult.direct_probe_state_sequence_passed -and
        $targetScenario.state_plane.target_absent_before_action -and
        $targetScenario.state_plane.cleanup_removed_from_probe)
    $targetExactEventAbsent = [bool]($pilotResult.query_complete_during_filter -and
        $pilotResult.query_coverage_and_source_availability_during_filter -and
        $pilotResult.exact_wazuh_target_event_count_during_filter -eq 0 -and
        $pilotResult.target_absent_from_csg_event_store_during_filter -and
        $pilotResult.target_event_absent_after_restore)
    $targetFinalUnexplained = [bool]($targetReconciliation -and
        $targetReconciliation.status -eq 'UNEXPLAINED' -and $targetReconciliation.finalized -and
        @($targetReconciliation.matched_evidence_ids).Count -eq 0)

    if ($targetReconciliation -and $targetReconciliation.observation_window.start -and
        $targetReconciliation.observation_window.end) {
        $windowStart = [datetimeoffset]::Parse([string]$targetReconciliation.observation_window.start).UtcDateTime
        $windowEnd = [datetimeoffset]::Parse([string]$targetReconciliation.observation_window.end).UtcDateTime
        $distractorTime = [datetimeoffset]::Parse([string]$distractorEvent.event_time).UtcDateTime
        $distractorInsideWindow = $distractorTime -ge $windowStart -and $distractorTime -le $windowEnd
        $targetDistractorReadback = @(Get-EventStoreMatches -StartUtc $windowStart -EndUtc $windowEnd `
            -TaskName $distractorName -ObjectKey $distractorKey)
        $distractorReturnedInTargetQuery = $false
        $targetRetrieval = $targetScenario.event_plane.retrieval
        if ($targetRetrieval.query_start -and $targetRetrieval.query_end) {
            $targetProviderQuery = Get-ProviderObservation `
                -StartUtc ([datetimeoffset]::Parse([string]$targetRetrieval.query_start).UtcDateTime) `
                -EndUtc ([datetimeoffset]::Parse([string]$targetRetrieval.query_end).UtcDateTime)
            $distractorReturnedInTargetQuery = [bool]($targetProviderQuery.query_complete -and
                $targetProviderQuery.coverage_status -eq 'COMPLETE' -and @($targetProviderQuery.events | Where-Object {
                    $_.event_id -eq $distractorEvent.event_id -and
                    (Test-ExactTaskEvent -Event $_ -TaskName $distractorName -ObjectKey $distractorKey)
                }).Count -eq 1)
        }
    }
} catch {
    $errorText = "line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.GetType().Name): $($_.Exception.Message)"
} finally {
    if (Get-ScheduledTask -TaskName $targetName -TaskPath '\' -ErrorAction SilentlyContinue) {
        try { Unregister-ScheduledTask -TaskName $targetName -TaskPath '\' -Confirm:$false -ErrorAction Stop } catch {
            if (-not $errorText) { $errorText = "Target cleanup failed: $($_.Exception.Message)" }
        }
    }
    if (Get-ScheduledTask -TaskName $distractorName -TaskPath '\' -ErrorAction SilentlyContinue) {
        try { Unregister-ScheduledTask -TaskName $distractorName -TaskPath '\' -Confirm:$false -ErrorAction Stop } catch {
            if (-not $errorText) { $errorText = "Distractor cleanup failed: $($_.Exception.Message)" }
        }
    }
    try {
        Invoke-ProbeOnce
        $cleanupObservation = Get-LatestObservation
        $targetNative = @(Get-ScheduledTask -TaskName $targetName -TaskPath '\' -ErrorAction SilentlyContinue).Count -gt 0
        $distractorNative = @(Get-ScheduledTask -TaskName $distractorName -TaskPath '\' -ErrorAction SilentlyContinue).Count -gt 0
        $targetVisible = Get-TaskPresence -Observation $cleanupObservation -TaskName $targetName
        $distractorVisible = Get-TaskPresence -Observation $cleanupObservation -TaskName $distractorName
        $cleanupVerified = -not $targetNative -and -not $distractorNative -and -not $targetVisible -and -not $distractorVisible
    } catch {
        if (-not $errorText) { $errorText = "Cleanup probe verification failed: $($_.Exception.Message)" }
    }
    $configRestored = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant() -eq $originalHash
    try { $healthAfter = Get-LabHealth } catch {
        if (-not $errorText) { $errorText = "Final health check failed: $($_.Exception.Message)" }
    }
}

$sameHostDistractorValid = [bool]($distractorStored -and $distractorInsideWindow -and
    $targetDistractorReadback.Count -eq 1 -and $targetDistractorReadback[0].event_id -eq $distractorEvent.event_id -and
    $distractorReturnedInTargetQuery)
$allChecks = $preflight -and $distractorLocalEvent -and $distractorStored -and
    $targetStateSequence -and $targetLocalEvidenceCount -gt 0 -and $targetExactEventAbsent -and
    $targetFinalUnexplained -and $sameHostDistractorValid -and $configRestored -and $cleanupVerified -and
    $healthAfter -and $healthAfter.csg_api_healthy -and $healthAfter.wazuh_server_api_healthy -and
    $healthAfter.wazuh_indexer_healthy -and $healthAfter.endpoint_agent_status -eq 'active' -and
    $healthAfter.wazuh_service_status -eq 'Running'
$result = [ordered]@{
    schema_version = 'csg-scheduled-task-event-filter-distractor-trial-v1'
    status = if ($allChecks) { 'PASS_PAIRED_MECHANISM_PILOT' } elseif ($configRestored -and $cleanupVerified) {
        'INCOMPLETE_OR_INVALID_SAFE_STATE_RESTORED'
    } else { 'SAFETY_REVIEW_REQUIRED' }
    campaign_id = 'scheduled-task-event-filter-distractor-pilot-20261012-v1'
    trial_id = 'trial-01'
    host_id = $HostId
    computer_name = $env:COMPUTERNAME
    condition = 'same_host_same_event_class_distractor_present_target_4698_filtered'
    started_at_utc = $trialStartedAt.ToString('o')
    ended_at_utc = [DateTime]::UtcNow.ToString('o')
    target_task_name = $targetName
    target_object_key = $targetKey
    distractor_task_name = $distractorName
    distractor_object_key = $distractorKey
    preflight = $preflight
    distractor_action_started_at_utc = if ($distractorActionStarted) { $distractorActionStarted.ToString('o') } else { $null }
    distractor_local_windows_4698 = $distractorLocalEvent
    distractor_provider_event = $distractorEvent
    distractor_csg_ingest_ack = $distractorIngestAck
    distractor_csg_event_store_readback_before_target = $distractorReadback
    distractor_provider_query_trace = @($providerTrace.ToArray())
    target_filter_pilot_status = if ($pilotResult) { $pilotResult.status } else { 'NO_RESULT' }
    target_filter_pilot_exit_code = $targetPilotExitCode
    target_filter_result_path = $pilotDirectory
    target_local_4698_exact_count = $targetLocalEvidenceCount
    target_native_state_sequence_passed = $targetStateSequence
    target_query_complete_with_available_sources_and_exact_event_absent = $targetExactEventAbsent
    target_final_reconciliation = $targetReconciliation
    target_finalized_unexplained_zero_evidence = $targetFinalUnexplained
    distractor_event_time_inside_target_reconciliation_window = $distractorInsideWindow
    distractor_still_in_event_store_for_target_window = $targetDistractorReadback
    distractor_returned_by_target_bounded_provider_query = $distractorReturnedInTargetQuery
    paired_wrong_object_challenge_valid = $sameHostDistractorValid
    target_provider_query_metadata = $targetProviderQuery
    original_agent_config_sha256 = $originalHash
    restored_agent_config_sha256 = if (Test-Path -LiteralPath $configPath) {
        (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    } else { $null }
    config_restored_exactly = $configRestored
    cleanup_verified = $cleanupVerified
    final_health = $healthAfter
    output_hashes = [ordered]@{
        trial_runner_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
        target_runner_sha256 = (Get-FileHash -LiteralPath $RunnerPath -Algorithm SHA256).Hash.ToLowerInvariant()
        filter_pilot_sha256 = (Get-FileHash -LiteralPath $FilterPilotPath -Algorithm SHA256).Hash.ToLowerInvariant()
        distractor_evidence_sha256 = if (Test-Path (Join-Path $OutputDirectory 'distractor-evidence.json')) {
            (Get-FileHash -LiteralPath (Join-Path $OutputDirectory 'distractor-evidence.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        } else { $null }
    }
    error = $errorText
}
Write-Json -Path $resultPath -Value $result
if ($result.status -eq 'SAFETY_REVIEW_REQUIRED') {
    throw 'The endpoint did not return to a verified safe state; inspect the saved artifact immediately.'
}
Write-Output $result.status
