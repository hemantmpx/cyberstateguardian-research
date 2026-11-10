param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedAgentConfigSha256,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [string]$CsgApiBase = "http://192.168.64.1:8000",
    [string]$HostId = "win11-arm-lab",
    [string]$WrapperPath = "C:\CSG\run_scheduled_task_eventid_filter_pilot_windows.ps1",
    [string]$RunnerPath = "C:\CSG\run_windows_category_positive_controls_v3.ps1",
    [int]$TrialCount = 10,
    [int]$WaitSeconds = 60,
    [int]$PostRestoreQuerySeconds = 30,
    [int]$ReconciliationWaitSeconds = 1800
)

$ErrorActionPreference = "Stop"
if ($TrialCount -ne 10) { throw "This frozen confirmatory protocol requires exactly ten assigned trials." }
if ($WaitSeconds -lt 10 -or $WaitSeconds -gt 180) { throw "WaitSeconds must be 10..180." }
$configPath = Join-Path ${env:ProgramFiles(x86)} "ossec-agent\ossec.conf"
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
foreach ($path in @($configPath, $WrapperPath, $RunnerPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file is missing: $path" }
}
if (Test-Path -LiteralPath $OutputDirectory) { throw "Refusing to overwrite $OutputDirectory" }
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Run this campaign from elevated Administrator PowerShell." }

$originalHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($originalHash -ne $ExpectedAgentConfigSha256.ToLowerInvariant()) {
    throw "Agent config does not match the frozen original hash: $originalHash"
}
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force

function Get-EndpointHealth {
    $health = Invoke-RestMethod -Method Get -TimeoutSec 20 -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
    $agent = @($health.server_api.agents | Where-Object { $_.name -eq $HostId } | Select-Object -First 1)
    $services = @(Get-CimInstance Win32_Service | Where-Object {
        $_.Name -in @("WazuhSvc", "Sysmon64a", "Sysmon64")
    } | ForEach-Object {
        [ordered]@{ name = $_.Name; state = $_.State; process_id = [int]$_.ProcessId }
    })
    [ordered]@{
        captured_at_utc = [DateTime]::UtcNow.ToString("o")
        csg_api_healthy = [bool]$health.ok
        wazuh_server_api_healthy = [bool]$health.server_api.ok
        wazuh_indexer_healthy = [bool]$health.indexer.ok
        endpoint_agent_status = if ($agent.Count) { $agent[0].status } else { "NOT_FOUND" }
        services = $services
    }
}

function Save-Manifest {
    $temporaryPath = Join-Path $OutputDirectory "campaign-manifest.json.tmp"
    $manifest | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
    Move-Item -LiteralPath $temporaryPath -Destination (Join-Path $OutputDirectory "campaign-manifest.json") -Force
}

function Get-ReconciliationHistory {
    param([string]$FindingId)
    $response = Invoke-RestMethod -Method Get -TimeoutSec 45 -Uri (
        "$($CsgApiBase.TrimEnd('/'))/api/findings/$FindingId/reconciliations"
    )
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($response)) {
        if ($item -is [System.Array]) { foreach ($nested in $item) { $items.Add($nested) } }
        elseif ($null -ne $item) { $items.Add($item) }
    }
    return @($items.ToArray())
}

$wrapperHash = (Get-FileHash -LiteralPath $WrapperPath -Algorithm SHA256).Hash.ToLowerInvariant()
$runnerHash = (Get-FileHash -LiteralPath $RunnerPath -Algorithm SHA256).Hash.ToLowerInvariant()
$assignments = New-Object System.Collections.Generic.List[object]
for ($index = 1; $index -le $TrialCount; $index++) {
    $assignments.Add([ordered]@{
        assignment_id = "filter-{0:D2}" -f $index
        order = $index
        condition = "security_eventchannel_excludes_4698"
        identity_policy = "fresh_random_CSGAPTTask_name_generated_by_frozen_runner"
        creation_add_delta_count = 0
        creation_finding_id = $null
        status = "ASSIGNED"
        output_directory = Join-Path $OutputDirectory ("trial-{0:D2}" -f $index)
    })
}
$manifest = [ordered]@{
    schema_version = "csg-scheduled-task-event-filter-campaign-v1"
    campaign_id = "scheduled-task-eventid-filter-confirmatory-20261012-v3"
    status = "ASSIGNED"
    started_at_utc = $null
    ended_at_utc = $null
    host_id = $HostId
    trial_count_assigned = $TrialCount
    trial_count_completed = 0
    original_agent_config_sha256 = $originalHash
    wrapper_sha256 = $wrapperHash
    positive_runner_sha256 = $runnerHash
    parameters = [ordered]@{
        wait_seconds = $WaitSeconds
        post_restore_query_seconds = $PostRestoreQuerySeconds
        reconciliation_wait_seconds = $ReconciliationWaitSeconds
        csg_api_base = $CsgApiBase
    }
    preflight_health = $null
    postflight_health = $null
    trials = $assignments
    abort_reason = $null
}
Save-Manifest

$preflightHealth = Get-EndpointHealth
$manifest.preflight_health = $preflightHealth
$manifest.started_at_utc = [DateTime]::UtcNow.ToString("o")
$wazuhRunning = @($preflightHealth.services | Where-Object {
    $_.name -eq "WazuhSvc" -and $_.state -eq "Running"
}).Count -eq 1
if (-not $preflightHealth.csg_api_healthy -or -not $preflightHealth.wazuh_server_api_healthy -or
    -not $preflightHealth.wazuh_indexer_healthy -or $preflightHealth.endpoint_agent_status -ne "active" -or
    -not $wazuhRunning) {
    $manifest.status = "PREFLIGHT_FAILED_NO_TRIAL"
    $manifest.abort_reason = "Endpoint/API/indexer health was not fully available."
    $manifest.ended_at_utc = [DateTime]::UtcNow.ToString("o")
    Save-Manifest
    throw $manifest.abort_reason
}
$manifest.status = "IN_PROGRESS"
Save-Manifest

$abortedForSafety = $false
for ($index = 0; $index -lt $assignments.Count; $index++) {
    $assignment = $assignments[$index]
    $assignment.status = "RUNNING"
    $assignment.started_at_utc = [DateTime]::UtcNow.ToString("o")
    Save-Manifest
    $stdoutPath = Join-Path $OutputDirectory ("trial-{0:D2}.stdout.txt" -f ($index + 1))
    $stderrPath = Join-Path $OutputDirectory ("trial-{0:D2}.stderr.txt" -f ($index + 1))
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$WrapperPath`" " +
        "-ExpectedAgentConfigSha256 $originalHash " +
        "-OutputDirectory `"$($assignment.output_directory)`" " +
        "-CsgApiBase `"$CsgApiBase`" -HostId `"$HostId`" " +
        "-RunnerPath `"$RunnerPath`" -WaitSeconds $WaitSeconds " +
        "-PostRestoreQuerySeconds $PostRestoreQuerySeconds " +
        "-ReconciliationWaitSeconds $ReconciliationWaitSeconds -DeferFinalReconciliationWait"
    $child = $null
    $launchError = $null
    try {
        $child = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -PassThru -Wait `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -WindowStyle Hidden
    } catch {
        $launchError = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
    }
    $resultPath = Join-Path $assignment.output_directory "result.json"
    $trialResult = if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
        Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    } else { $null }
    $assignment.ended_at_utc = [DateTime]::UtcNow.ToString("o")
    $assignment.wrapper_exit_code = if ($child) { [int]$child.ExitCode } else { $null }
    $assignment.wrapper_status = if ($trialResult) { $trialResult.status } else { "NO_RESULT_ARTIFACT" }
    $assignment.target_task_name = if ($trialResult) { $trialResult.target_task_name } else { $null }
    $targetScenario = if ($trialResult -and $trialResult.runner_result -and
        $trialResult.runner_result.scenarios) {
        $trialResult.runner_result.scenarios[0]
    } else { $null }
    $creationAddDeltas = if ($targetScenario) {
        @($targetScenario.deltas | Where-Object {
            $_.delta_type -eq "ADD" -and $_.object_key -eq $targetScenario.expected_object_key
        })
    } else { @() }
    $assignment.creation_add_delta_count = $creationAddDeltas.Count
    $assignment.delta_id = if ($creationAddDeltas.Count -eq 1) {
        $creationAddDeltas[0].delta_id
    } else { $null }
    $creationFindings = if ($assignment.delta_id -and $targetScenario) {
        @($targetScenario.findings | Where-Object { $_.delta_id -eq $assignment.delta_id })
    } else { @() }
    $assignment.creation_finding_id = if ($creationFindings.Count -eq 1) {
        $creationFindings[0].finding_id
    } else { $null }
    $assignment.finding_id = $assignment.creation_finding_id
    $assignment.error = if ($launchError) { $launchError } elseif ($trialResult) { $trialResult.error } else { "No result artifact." }
    $configAfter = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $wazuhStatus = (Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue).Status
    $healthAfterTrial = $null
    try { $healthAfterTrial = Get-EndpointHealth } catch { }
    $residualTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskName -like "CSGAPTTask*" -or $_.TaskName -like "CSGAPTDis*"
    } | ForEach-Object { "{0}{1}" -f $_.TaskPath, $_.TaskName })
    $assignment.restored_config_sha256 = $configAfter
    $assignment.wazuh_service_status_after = [string]$wazuhStatus
    $assignment.endpoint_health_after = $healthAfterTrial
    $assignment.residual_study_tasks_after = $residualTasks
    $assignment.safe_to_continue = $configAfter -eq $originalHash -and
        $wazuhStatus -eq "Running" -and $residualTasks.Count -eq 0 -and
        $healthAfterTrial -and $healthAfterTrial.csg_api_healthy -and
        $healthAfterTrial.wazuh_server_api_healthy -and $healthAfterTrial.wazuh_indexer_healthy -and
        $healthAfterTrial.endpoint_agent_status -eq "active"
    $assignment.capture_gates_passed = [bool]($trialResult -and $trialResult.capture_gates_passed -and
        $trialResult.target_event_absent_after_restore -and
        $assignment.creation_add_delta_count -eq 1 -and
        $assignment.creation_finding_id -and
        $trialResult.status -eq "CAPTURE_VALID_RECONCILIATION_DEFERRED")
    $assignment.status = if ($assignment.capture_gates_passed -and
        $assignment.wrapper_exit_code -eq 0) {
        "CAPTURE_VALID_RECONCILIATION_PENDING"
    } elseif ($assignment.safe_to_continue) {
        "COMPLETED_WITH_VALIDITY_GAP"
    } else {
        "ABORTED_UNSAFE"
    }
    $manifest.trial_count_completed++
    Save-Manifest
    if (-not $assignment.safe_to_continue) {
        $manifest.status = "ABORTED_UNSAFE"
        $manifest.abort_reason = "Original Wazuh config, running service, or clean task state failed after $($assignment.assignment_id)."
        $abortedForSafety = $true
        Save-Manifest
        break
    }
}

if (-not $abortedForSafety -and $manifest.trial_count_completed -eq $TrialCount) {
    $manifest.status = "FINAL_RECONCILIATION_PENDING"
    $manifest.final_reconciliation_wait_started_at_utc = [DateTime]::UtcNow.ToString("o")
    Save-Manifest
    $deadline = [DateTime]::UtcNow.AddSeconds($ReconciliationWaitSeconds)
    do {
        $allFinalized = $true
        foreach ($assignment in $assignments) {
            if (-not $assignment.finding_id -or -not $assignment.capture_gates_passed) {
                $assignment.final_reconciliation_passed = $false
                $assignment.final_reconciliation_status = "NOT_EVALUABLE"
                continue
            }
            try {
                $history = @(Get-ReconciliationHistory -FindingId $assignment.finding_id)
                $assignment.reconciliation_history = $history
                $latest = if ($history.Count) { $history[-1] } else { $null }
                $assignment.final_reconciliation_status = if ($latest) { $latest.status } else { "MISSING" }
                $assignment.final_reconciliation_finalized = [bool]($latest -and $latest.finalized)
                $assignment.final_reconciliation_evidence_ids = if ($latest) {
                    @($latest.matched_evidence_ids)
                } else { @() }
                $assignment.final_reconciliation_checked_at_utc = [DateTime]::UtcNow.ToString("o")
                $assignment.final_reconciliation_passed = [bool]($latest -and
                    $latest.status -eq "UNEXPLAINED" -and $latest.finalized -and
                    @($latest.matched_evidence_ids).Count -eq 0)
                if (-not $latest -or -not $latest.finalized) { $allFinalized = $false }
            } catch {
                $assignment.final_reconciliation_error = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
                $assignment.final_reconciliation_passed = $false
                $allFinalized = $false
            }
        }
        Save-Manifest
        if ($allFinalized) { break }
        Start-Sleep -Seconds 5
    } while ([DateTime]::UtcNow -lt $deadline)
    $manifest.final_reconciliation_wait_ended_at_utc = [DateTime]::UtcNow.ToString("o")
    foreach ($assignment in $assignments) {
        $assignment.status = if ($assignment.capture_gates_passed -and
            $assignment.final_reconciliation_passed) { "PASS" } else { "COMPLETED_WITH_VALIDITY_GAP" }
    }
    Save-Manifest
}

try { $manifest.postflight_health = Get-EndpointHealth } catch {
    $manifest.postflight_health = [ordered]@{ error = "$($_.Exception.GetType().Name): $($_.Exception.Message)" }
}
$finalConfigHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
$finalWazuhStatus = (Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue).Status
$finalResidualTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName -like "CSGAPTTask*" -or $_.TaskName -like "CSGAPTDis*"
} | ForEach-Object { "{0}{1}" -f $_.TaskPath, $_.TaskName })
$manifest.final_agent_config_sha256 = $finalConfigHash
$manifest.final_wazuh_service_status = [string]$finalWazuhStatus
$manifest.final_residual_study_tasks = $finalResidualTasks
$postflightHealthy = $manifest.postflight_health.csg_api_healthy -and
    $manifest.postflight_health.wazuh_server_api_healthy -and
    $manifest.postflight_health.wazuh_indexer_healthy -and
    $manifest.postflight_health.endpoint_agent_status -eq "active"
$manifest.ended_at_utc = [DateTime]::UtcNow.ToString("o")
if ($abortedForSafety) {
    $manifest.status = "ABORTED_UNSAFE"
} elseif ($manifest.trial_count_completed -ne $TrialCount) {
    $manifest.status = "ABORTED_INCOMPLETE"
} elseif ($finalConfigHash -ne $originalHash -or $finalWazuhStatus -ne "Running" -or
    $finalResidualTasks.Count -gt 0 -or -not $postflightHealthy) {
    $manifest.status = "COMPLETED_WITH_POSTFLIGHT_SAFETY_FAILURE"
} elseif (@($assignments | Where-Object { $_.status -ne "PASS" }).Count -eq 0) {
    $manifest.status = "COMPLETED_ALL_TRIAL_GATES_PASSED"
} else {
    $manifest.status = "COMPLETED_WITH_VALIDITY_GAPS"
}
Save-Manifest
Write-Output $manifest.status
