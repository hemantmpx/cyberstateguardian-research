param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [string]$CampaignId = "scheduled-task-complete-distractor-v1",
    [string]$CsgApiBase = "http://192.168.64.1:8000",
    [string]$HostId = "win11-arm-lab",
    [string]$ProbePython = "C:\Program Files\CyberStateGuardian\Probe\venv\Scripts\python.exe",
    [string]$ProbeConfig = "C:\Program Files\CyberStateGuardian\Probe\settings.json",
    [string]$RunnerPath = "C:\CSG\run_windows_category_positive_controls.ps1",
    [int]$WaitSeconds = 35,
    [int]$EventTimeToleranceSeconds = 20
)

$ErrorActionPreference = "Stop"
if ($CampaignId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,100}$') { throw "CampaignId is invalid." }
if ($WaitSeconds -lt 10 -or $WaitSeconds -gt 180) { throw "WaitSeconds must be 10..180." }
if ($EventTimeToleranceSeconds -lt 1 -or $EventTimeToleranceSeconds -gt 120) {
    throw "EventTimeToleranceSeconds must be 1..120."
}
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Run this controlled lab procedure from Administrator PowerShell." }
if (-not (Test-Path -LiteralPath $ProbePython)) { throw "Probe Python was not found: $ProbePython" }
if (-not (Test-Path -LiteralPath $ProbeConfig)) { throw "Probe config was not found: $ProbeConfig" }
if (-not (Test-Path -LiteralPath $RunnerPath)) { throw "Positive-control runner was not found: $RunnerPath" }

$probeSettings = (Get-Content -LiteralPath $ProbeConfig -Raw) | ConvertFrom-Json
if ($probeSettings.CSG_PROBE_HOST_ID -ne $HostId) { throw "Probe host ID does not match HostId." }
$wazuhService = Get-Service -Name WazuhSvc
if ($wazuhService.Status -ne "Running") { throw "WazuhSvc must be running for this complete-telemetry cell." }
$wazuhServiceBefore = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" |
    Select-Object Name, State, ProcessId

$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw "Refusing to overwrite $OutputDirectory" }
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$targetRunDirectory = Join-Path $OutputDirectory "target-run"
$null = New-Item -ItemType Directory -Path $targetRunDirectory -Force
$targetRunPath = Join-Path $targetRunDirectory "run.json"
$stdoutPath = Join-Path $OutputDirectory "target-run.stdout.txt"
$stderrPath = Join-Path $OutputDirectory "target-run.stderr.txt"
$progressPath = Join-Path $OutputDirectory "progress.json"
$resultPath = Join-Path $OutputDirectory "trial.json"
$distractorName = "CSGAPTDis$([guid]::NewGuid().ToString('N').Substring(0,10))"
$distractorKey = "scheduled_task:\$($distractorName.ToLowerInvariant())"
$startedAt = (Get-Date).ToUniversalTime()
$securityHighWater = [long](Get-WinEvent -LogName Security -MaxEvents 1).RecordId
$targetName = $null
$distractorCreated = $false
$distractorEvent = $null
$distractorIngestedIds = @()
$overlapObservation = $null
$providerQueryTrace = New-Object System.Collections.Generic.List[object]
$child = $null
$childExitCode = $null
$runnerDocument = $null
$errorMessage = $null
$nativeDistractorEvent = $null
$cleanupVerified = $false
$distractorActionStart = $null
$distractorActionEnd = $null

function Save-Progress {
    param([string]$Status)
    $value = [ordered]@{
        schema_version = "csg-scheduled-task-complete-distractor-progress-v1"
        status = $Status
        updated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        target_task_name = $targetName
        distractor_task_name = $distractorName
        distractor_event_id = if ($distractorEvent) { $distractorEvent.event_id } else { $null }
        distractor_ingested_event_ids = @($distractorIngestedIds)
        runner_pid = if ($child) { $child.Id } else { $null }
        error = $errorMessage
    }
    $temporaryPath = "$progressPath.tmp"
    $value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
    Move-Item -LiteralPath $temporaryPath -Destination $progressPath -Force
}

function Normalize-Identity {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    $normalized = ([string]$Value).Trim().ToLowerInvariant().Replace("\", "/")
    while ($normalized.Contains("//")) { $normalized = $normalized.Replace("//", "/") }
    return $normalized
}

function Invoke-ProbeOnce {
    & $ProbePython -m cyberstateguardian_probe.main --config $ProbeConfig --once
    if ($LASTEXITCODE -ne 0) { throw "Direct probe failed with exit code $LASTEXITCODE" }
}

function Get-LatestObservation {
    Invoke-RestMethod -Method Get -TimeoutSec 30 -Uri "$($CsgApiBase.TrimEnd('/'))/api/hosts/$HostId/observations/latest"
}

function Get-LocalTaskEvent {
    param([string]$TaskName, [datetime]$NotBefore, [long]$AfterRecordId)
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id = 4698
        StartTime = $NotBefore.ToLocalTime().AddMinutes(-1)
    } -ErrorAction SilentlyContinue)
    foreach ($event in $events) {
        if ([long]$event.RecordId -le $AfterRecordId) { continue }
        [xml]$xml = $event.ToXml()
        $fields = [ordered]@{}
        foreach ($field in @($xml.Event.EventData.Data)) {
            if ($field.Name) { $fields[[string]$field.Name] = [string]$field.InnerText }
        }
        $name = if ($fields.TaskName) { $fields.TaskName } else { $fields.Task_Name }
        if ((Normalize-Identity $name) -eq (Normalize-Identity ("\" + $TaskName))) {
            return [ordered]@{
                event_id = [int]$event.Id
                record_id = [long]$event.RecordId
                provider = [string]$event.ProviderName
                log_name = [string]$event.LogName
                event_time_utc = $event.TimeCreated.ToUniversalTime().ToString("o")
                event_data = $fields
                raw_xml = $event.ToXml()
            }
        }
    }
    return $null
}

function Get-NewTargetTaskName {
    param([datetime]$NotBefore, [long]$AfterRecordId)
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id = 4698
        StartTime = $NotBefore.ToLocalTime().AddMinutes(-1)
    } -ErrorAction SilentlyContinue)
    foreach ($event in $events) {
        if ([long]$event.RecordId -le $AfterRecordId) { continue }
        [xml]$xml = $event.ToXml()
        $taskField = @($xml.Event.EventData.Data | Where-Object { $_.Name -in @("TaskName", "Task_Name") } | Select-Object -First 1)[0]
        if ($null -eq $taskField) { continue }
        $name = ([string]$taskField.InnerText).TrimStart("\")
        if ($name -match '^CSGAPTTask[0-9a-fA-F]+$') { return $name }
    }
    return $null
}

function Get-ProviderEvents {
    param([datetime]$FromUtc, [datetime]$ToUtc)
    $start = [uri]::EscapeDataString($FromUtc.ToUniversalTime().ToString("o"))
    $end = [uri]::EscapeDataString($ToUtc.ToUniversalTime().ToString("o"))
    Invoke-RestMethod -Method Get -TimeoutSec 45 -Uri (
        "$($CsgApiBase.TrimEnd('/'))/api/hosts/$HostId/provider-event-observation?start=$start&end=$end"
    )
}

function Test-ExactTaskEvent {
    param([object]$Event, [string]$TaskName)
    if ($Event.host_id -ne $HostId -or $Event.source -ne "wazuh" -or
        $Event.normalized_type -ne "scheduled_task_created") { return $false }
    $expectedKey = Normalize-Identity ("scheduled_task:\$($TaskName.ToLowerInvariant())")
    $eventKey = Normalize-Identity $Event.target.key
    $eventName = if ($Event.attributes.task_name) { $Event.attributes.task_name } else { $Event.task_name }
    return ($eventKey -eq $expectedKey -or
        (Normalize-Identity $eventName) -eq (Normalize-Identity ("\" + $TaskName)))
}

function New-LabTask {
    param([string]$TaskName)
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c exit 0"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1)
    Register-ScheduledTask -TaskName $TaskName -TaskPath "\" -Action $action -Trigger $trigger `
        -User "SYSTEM" -RunLevel Highest -Force | Out-Null
}

function Test-TaskPresent {
    param([string]$TaskName)
    return (@(Get-ScheduledTask -TaskName $TaskName -TaskPath "\" -ErrorAction SilentlyContinue).Count -gt 0)
}

try {
    Save-Progress -Status "STARTING_TARGET_RUNNER"
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$RunnerPath`" " +
        "-CsgApiBase `"$CsgApiBase`" -HostId `"$HostId`" " +
        "-ProbePython `"$ProbePython`" -ProbeConfig `"$ProbeConfig`" " +
        "-WaitSeconds $WaitSeconds -OutputPath `"$targetRunPath`" -ScenarioFilter scheduled_task"
    $child = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -PassThru `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -WindowStyle Hidden
    Save-Progress -Status "WAITING_FOR_TARGET_ACTION"
    $deadline = (Get-Date).ToUniversalTime().AddMinutes(6)
    $overlapCaptured = $false
    $lastProviderQuery = [datetime]::MinValue

    while ((Get-Date).ToUniversalTime() -lt $deadline) {
        $child.Refresh()
        $outputText = if (Test-Path -LiteralPath $stdoutPath) {
            [string](Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue)
        } else { "" }
        if (-not $targetName) {
            $match = [regex]::Match([string]$outputText, "Creating\s+(CSGAPTTask[0-9a-fA-F]+)")
            if ($match.Success) {
                $targetName = $match.Groups[1].Value
            } else {
                $targetName = Get-NewTargetTaskName -NotBefore $startedAt -AfterRecordId $securityHighWater
            }
            if ($targetName) {
                Save-Progress -Status "TARGET_ACTION_STARTED_CREATING_DISTRACTOR"
                $distractorActionStart = (Get-Date).ToUniversalTime()
                New-LabTask -TaskName $distractorName
                $distractorCreated = $true
                $distractorActionEnd = (Get-Date).ToUniversalTime()
                $nativeDeadline = (Get-Date).ToUniversalTime().AddSeconds(10)
                do {
                    $nativeDistractorEvent = Get-LocalTaskEvent -TaskName $distractorName `
                        -NotBefore $distractorActionStart -AfterRecordId $securityHighWater
                    if ($nativeDistractorEvent) { break }
                    Start-Sleep -Milliseconds 300
                } while ((Get-Date).ToUniversalTime() -lt $nativeDeadline)
                Save-Progress -Status "DISTRACTOR_CREATED"
            }
        }

        if ($distractorCreated -and -not $distractorEvent -and
            ((Get-Date).ToUniversalTime() - $lastProviderQuery).TotalSeconds -ge 2) {
            $lastProviderQuery = (Get-Date).ToUniversalTime()
            $providerQuery = Get-ProviderEvents -FromUtc $startedAt.AddMinutes(-1) -ToUtc $lastProviderQuery.AddSeconds(1)
            $providerQueryTrace.Add([ordered]@{
                query_at_utc = $lastProviderQuery.ToString("o")
                query_complete = [bool]$providerQuery.query_complete
                coverage_status = $providerQuery.coverage_status
                index_status = $providerQuery.index_status
                retrieved_count = $providerQuery.retrieved_count
                total_hits = $providerQuery.total_hits
                error = $providerQuery.error
            })
            $distractorEvent = @($providerQuery.events | Where-Object {
                Test-ExactTaskEvent -Event $_ -TaskName $distractorName
            } | Select-Object -First 1)[0]
            if ($distractorEvent) {
                if ($providerQuery.query_complete -ne $true -or $providerQuery.coverage_status -ne "COMPLETE") {
                    throw "Distractor event returned but provider query/coverage was incomplete."
                }
                $body = ConvertTo-Json -InputObject @($distractorEvent) -Depth 30 -Compress
                $ingested = Invoke-RestMethod -Method Post -TimeoutSec 30 `
                    -Uri "$($CsgApiBase.TrimEnd('/'))/api/events" -ContentType "application/json" -Body $body
                $distractorIngestedIds = @($ingested | ForEach-Object { $_.event_id })
                Save-Progress -Status "DISTRACTOR_EVENT_INGESTED"
            }
        }

        if ($distractorCreated -and -not $overlapCaptured -and
            $outputText.Contains("Waiting $WaitSeconds seconds for Wazuh delivery")) {
            Invoke-ProbeOnce
            $overlapObservation = Get-LatestObservation
            $overlapPath = Join-Path $OutputDirectory "overlap-observation.json"
            $overlapObservation | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $overlapPath -Encoding UTF8
            $overlapCaptured = $true
            Save-Progress -Status "OVERLAP_OBSERVATION_CAPTURED"
        }

        if ($child.HasExited) { break }
        Start-Sleep -Seconds 1
    }
    $child.Refresh()
    if (-not $child.HasExited) { throw "Target runner exceeded the six-minute bounded execution window." }
    $childExitCode = $child.ExitCode
    if (-not (Test-Path -LiteralPath $targetRunPath)) { throw "Target runner did not produce run.json." }
    $runnerDocument = Get-Content -LiteralPath $targetRunPath -Raw | ConvertFrom-Json
    if (-not $targetName -and $runnerDocument.scenarios.Count -gt 0) {
        $targetName = [string]$runnerDocument.scenarios[0].object_name
    }
} catch {
    $errorMessage = "line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
} finally {
    if ($child) {
        $child.Refresh()
        if (-not $child.HasExited) { $null = $child.WaitForExit(180000) }
        $child.Refresh()
        if ($child.HasExited) { $childExitCode = $child.ExitCode }
    }
    if (-not $targetName -and (Test-Path -LiteralPath $stdoutPath)) {
        $finalOutput = [string](Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue)
        $finalMatch = [regex]::Match($finalOutput, "Creating\s+(CSGAPTTask[0-9a-fA-F]+)")
        if ($finalMatch.Success) { $targetName = $finalMatch.Groups[1].Value }
    }
    if ($targetName -and (Test-TaskPresent -TaskName $targetName)) {
        try {
            Unregister-ScheduledTask -TaskName $targetName -TaskPath "\" -Confirm:$false -ErrorAction Stop
        } catch {
            if (-not $errorMessage) { $errorMessage = "Target task cleanup failed: $($_.Exception.Message)" }
        }
    }
    if ($distractorCreated) {
        try {
            Unregister-ScheduledTask -TaskName $distractorName -TaskPath "\" -Confirm:$false -ErrorAction Stop
            $cleanupDeadline = (Get-Date).ToUniversalTime().AddSeconds(90)
            do {
                Invoke-ProbeOnce
                $cleanupObservation = Get-LatestObservation
                $remaining = @($cleanupObservation.categories.scheduled_task.items | Where-Object {
                    (Normalize-Identity $_.task_name) -eq (Normalize-Identity ("\" + $distractorName)) -or
                    ($targetName -and (Normalize-Identity $_.task_name) -eq (Normalize-Identity ("\" + $targetName)))
                })
                $nativeRemaining = (Test-TaskPresent -TaskName $distractorName) -or
                    ($targetName -and (Test-TaskPresent -TaskName $targetName))
                if ($remaining.Count -eq 0 -and -not $nativeRemaining) { $cleanupVerified = $true; break }
                Start-Sleep -Seconds 2
            } while ((Get-Date).ToUniversalTime() -lt $cleanupDeadline)
        } catch {
            if (-not $errorMessage) { $errorMessage = "Cleanup verification failed: $($_.Exception.Message)" }
        }
    }
}

$targetScenario = $null
if ($runnerDocument -and $runnerDocument.scenarios) {
    $targetScenario = @($runnerDocument.scenarios | Where-Object { $_.kind -eq "scheduled_task" } | Select-Object -First 1)[0]
}
$targetEventIds = @()
$matchedIds = @()
$targetExactOnly = $false
$targetWindow = $null
$windowHistory = @()
if ($targetScenario) {
    $targetEventIds = @($targetScenario.event_plane.exact_matches | ForEach-Object { $_.event_id })
    $matchedIds = @($targetScenario.csg_reconciliation.matched_evidence_ids)
    $windowHistory = @($targetScenario.csg_reconciliation.history)
    if ($windowHistory.Count -gt 0) { $targetWindow = $windowHistory[-1].observation_window }
    $targetExactOnly = $targetScenario.csg_reconciliation.status -eq "CONSISTENT" -and
        $targetScenario.csg_reconciliation.finalized -eq $true -and $targetEventIds.Count -gt 0 -and
        $matchedIds.Count -gt 0 -and @($matchedIds | Where-Object { $_ -notin $targetEventIds }).Count -eq 0
}
$overlapItems = if ($overlapObservation) { @($overlapObservation.categories.scheduled_task.items) } else { @() }
$stateContainsBoth = $targetName -and $overlapItems.Count -gt 0 -and
    @($overlapItems | Where-Object { (Normalize-Identity $_.task_name) -eq (Normalize-Identity ("\" + $targetName)) }).Count -gt 0 -and
    @($overlapItems | Where-Object { (Normalize-Identity $_.task_name) -eq (Normalize-Identity ("\" + $distractorName)) }).Count -gt 0
$distractorEventInsideWindow = $false
if ($distractorEvent -and $targetWindow -and $targetWindow.start -and $targetWindow.end) {
    try {
        $sourceTime = if ($distractorEvent.event_time) { $distractorEvent.event_time } else { $distractorEvent.event_time_utc }
        $eventTime = [datetimeoffset]::Parse([string]$sourceTime).UtcDateTime
        $windowStart = [datetimeoffset]::Parse([string]$targetWindow.start).UtcDateTime.AddSeconds(-$EventTimeToleranceSeconds)
        $windowEnd = [datetimeoffset]::Parse([string]$targetWindow.end).UtcDateTime.AddSeconds($EventTimeToleranceSeconds)
        $distractorEventInsideWindow = $eventTime -ge $windowStart -and $eventTime -le $windowEnd
    } catch { $distractorEventInsideWindow = $false }
}
$targetAndDistractorEventClassesAgree = $false
if ($targetScenario -and $distractorEvent) {
    $targetAndDistractorEventClassesAgree = $distractorEvent.host_id -eq $HostId -and
        $distractorEvent.normalized_type -eq $targetScenario.expected_event_type -and
        (Normalize-Identity $distractorEvent.target.key) -ne (Normalize-Identity $targetScenario.expected_object_key)
}
$targetRunGatePassed = $targetScenario -and $targetScenario.positive_control.passed -eq $true
$distractorEventIngested = $distractorIngestedIds -contains $distractorEvent.event_id
$gatePassed = $targetRunGatePassed -and $distractorEventIngested -and $stateContainsBoth -and
    $distractorEventInsideWindow -and $targetAndDistractorEventClassesAgree -and $targetExactOnly -and $cleanupVerified
$wazuhPost = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
$result = [ordered]@{
    schema_version = "csg-scheduled-task-complete-distractor-trial-v1"
    campaign_id = $CampaignId
    controller_version = "v3-campaign-aware-null-stdout-guard"
    trial_id = Split-Path -Leaf $OutputDirectory
    status = if ($gatePassed) { "PASS" } else { "FAIL_OR_MANIPULATION_NOT_ATTAINED" }
    started_at_utc = $startedAt.ToString("o")
    ended_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    host_id = $HostId
    condition = "complete_distractor"
    target_task_name = $targetName
    distractor_task_name = $distractorName
    target_runner_exit_code = $childExitCode
    target_runner = $runnerDocument
    distractor = [ordered]@{
        action_started_at_utc = if ($distractorActionStart) { $distractorActionStart.ToString("o") } else { $null }
        action_ended_at_utc = if ($distractorActionEnd) { $distractorActionEnd.ToString("o") } else { $null }
        native_windows_security_4698 = $nativeDistractorEvent
        exact_wazuh_event = $distractorEvent
        ingested_event_ids = @($distractorIngestedIds)
        provider_query_trace = @($providerQueryTrace.ToArray())
    }
    overlap_observation = if ($overlapObservation) {
        [ordered]@{
            observation_id = $overlapObservation.observation_id
            observed_at = $overlapObservation.observed_at
            category_observed_at = $overlapObservation.categories.scheduled_task.observed_at
            category_status = $overlapObservation.categories.scheduled_task.status
            target_and_distractor_both_present = $stateContainsBoth
        }
    } else { $null }
    target_reconciliation = [ordered]@{
        status = if ($targetScenario) { $targetScenario.csg_reconciliation.status } else { "MISSING" }
        finalized = if ($targetScenario) { $targetScenario.csg_reconciliation.finalized } else { $false }
        observation_window = $targetWindow
        exact_target_event_ids = @($targetEventIds)
        matched_evidence_ids = @($matchedIds)
        cited_only_exact_target_event = $targetExactOnly
    }
    condition_checks = [ordered]@{
        target_positive_control_passed = [bool]$targetRunGatePassed
        distractor_event_ingested = [bool]$distractorEventIngested
        same_host_and_event_class_different_object = [bool]$targetAndDistractorEventClassesAgree
        distractor_event_inside_target_padded_window = [bool]$distractorEventInsideWindow
        both_objects_observed_in_one_probe_snapshot = [bool]$stateContainsBoth
        target_consistent_with_only_target_evidence = [bool]$targetExactOnly
        cleanup_verified = [bool]$cleanupVerified
        wazuh_service_running_after_trial = ($wazuhPost.Status -eq "Running")
    }
    cleanup_verified = $cleanupVerified
    wazuh_service_before_trial = $wazuhServiceBefore
    wazuh_service_after_trial = if ($wazuhPost) { [string]$wazuhPost.Status } else { "NOT_FOUND" }
    error = $errorMessage
}
$result | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $resultPath -Encoding UTF8
$result.status
