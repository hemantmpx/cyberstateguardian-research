param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedAgentConfigSha256,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [string]$CsgApiBase = "http://192.168.64.1:8000",
    [string]$HostId = "win11-arm-lab",
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^CSGAPTTask[a-fA-F0-9]{10}$')]
    [string]$ScheduledTaskName,
    [string]$DistractorTaskName = "",
    [ValidateSet("target_name", "event_id")]
    [string]$FilterMode = "event_id",
    [string]$ProbePython = "C:\Program Files\CyberStateGuardian\Probe\venv\Scripts\python.exe",
    [string]$ProbeConfig = "C:\Program Files\CyberStateGuardian\Probe\settings.json",
    [string]$RunnerPath = "C:\CSG\run_windows_category_same_window_distractor_v9.ps1",
    [int]$WaitSeconds = 60,
    [int]$PostRestoreQuerySeconds = 90,
    [int]$ReconciliationWaitSeconds = 240,
    [int]$ActiveQueryGateTimeoutSeconds = 180,
    [string]$ActiveQueryApprovalFile = "",
    [switch]$DistractorAfterSuppressedTarget,
    [switch]$DeferFinalReconciliationWait,
    [switch]$HoldForActiveQueryVerification
)

$ErrorActionPreference = "Stop"
$configPath = Join-Path ${env:ProgramFiles(x86)} "ossec-agent\ossec.conf"
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw "Refusing to overwrite $OutputDirectory" }
foreach ($path in @($configPath, $ProbePython, $ProbeConfig, $RunnerPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file is missing: $path" }
}
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Run this controlled pilot from elevated Administrator PowerShell." }
if ($WaitSeconds -lt 30 -or $WaitSeconds -gt 180) { throw "WaitSeconds must be 30..180." }
if ($FilterMode -eq "target_name" -and -not $DistractorTaskName) {
    throw "Target-name filter mode requires its assigned wrong-object distractor."
}
if ($FilterMode -eq "event_id" -and $DistractorTaskName -and -not $DistractorAfterSuppressedTarget) {
    throw "Event-ID mode needs explicit post-target distractor ordering because the filter suppresses all 4698 records."
}
if ($DistractorAfterSuppressedTarget -and
    ($FilterMode -ne "event_id" -or -not $DistractorTaskName -or -not $HoldForActiveQueryVerification)) {
    throw "Post-target distractor mode requires EventID filtering, a distractor identity, and the external active-query gate."
}
if ($DistractorTaskName -and $DistractorTaskName -notmatch '^CSGAPTDis[A-Fa-f0-9]{10}$') {
    throw "DistractorTaskName must use the CSGAPTDis prefix followed by ten hexadecimal characters."
}
if ($HoldForActiveQueryVerification -and -not $ActiveQueryApprovalFile) {
    throw "Use a fresh ActiveQueryApprovalFile when the external active-query gate is enabled."
}
if ($DistractorTaskName -and $ScheduledTaskName -ieq $DistractorTaskName) {
    throw "Target and distractor identities must be distinct."
}

$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$runnerOutput = Join-Path $OutputDirectory "runner"
$runnerRunPath = Join-Path $runnerOutput "run.json"
$stdoutPath = Join-Path $OutputDirectory "runner.stdout.txt"
$stderrPath = Join-Path $OutputDirectory "runner.stderr.txt"
$preflightPath = Join-Path $OutputDirectory "preflight.json"
$resultPath = Join-Path $OutputDirectory "result.json"
$configBackup = Join-Path $OutputDirectory "ossec.conf.original.backup"
$configTemporary = Join-Path $OutputDirectory "ossec.conf.filtered.tmp"
$ActiveQueryApprovalFile = if ($ActiveQueryApprovalFile) {
    [IO.Path]::GetFullPath($ActiveQueryApprovalFile)
} else { "" }
if ($ActiveQueryApprovalFile -and (Test-Path -LiteralPath $ActiveQueryApprovalFile)) {
    throw "Refusing to use an approval file that predates this run: $ActiveQueryApprovalFile"
}
$expectedBaselineQuery = "Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and EventID != 4656 and EventID != 4658 and EventID != 4663 and EventID != 4660 and EventID != 4670 and EventID != 4690 and EventID != 4703 and EventID != 4907 and EventID != 5152 and EventID != 5157]"
$targetEventTaskName = "\$ScheduledTaskName"
$baselineEventIds = "System/EventID != 5145 and System/EventID != 5156 and System/EventID != 5447 and " +
    "System/EventID != 4656 and System/EventID != 4658 and System/EventID != 4663 and " +
    "System/EventID != 4660 and System/EventID != 4670 and System/EventID != 4690 and " +
    "System/EventID != 4703 and System/EventID != 4907 and System/EventID != 5152 and " +
    "System/EventID != 5157"
$effectiveQuery = if ($FilterMode -eq "event_id") {
    "Event[$baselineEventIds and System/EventID != 4698]"
} else {
    "Event[$baselineEventIds and (System/EventID != 4698 or " +
        "EventData/Data[@Name='TaskName'] != '$targetEventTaskName')]"
}
$originalHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($originalHash -ne $ExpectedAgentConfigSha256.ToLowerInvariant()) {
    throw "Wazuh agent configuration hash differs from the frozen precondition: $originalHash"
}

$script:backupCreated = $false
$script:filterApplied = $false
$script:restoration = $null
$script:filteredHash = $null
$script:runnerExitCode = $null
$script:runner = $null
$script:filteredRuntimeHealth = $null
$script:filteredLogCapturePath = $null
$script:filteredRestartEvidence = $null
$script:restoreRestartEvidence = $null
$script:postRestoreQueries = New-Object System.Collections.Generic.List[object]
$activeQueryGate = [ordered]@{
    requested = [bool]$HoldForActiveQueryVerification
    status = if ($HoldForActiveQueryVerification) { "NOT_REACHED" } else { "NOT_REQUESTED" }
    expected_query_sha256 = $null
    expected_query_base64 = $null
    gate_opened_at_utc = $null
    approval_file = $ActiveQueryApprovalFile
    approval = $null
    operator_decision = $null
    decision_at_utc = $null
}

function Get-LabHealth {
    $health = Invoke-RestMethod -Method Get -TimeoutSec 20 -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
    $agent = @($health.server_api.agents | Where-Object { $_.name -eq $HostId } | Select-Object -First 1)
    $services = @(
        Get-CimInstance Win32_Service | Where-Object { $_.Name -in @("WazuhSvc", "Sysmon64a", "Sysmon64") } |
            ForEach-Object { [ordered]@{ name = $_.Name; state = $_.State; process_id = [int]$_.ProcessId } }
    )
    [ordered]@{
        captured_at_utc = [DateTime]::UtcNow.ToString("o")
        csg_api_healthy = [bool]$health.ok
        wazuh_server_api_healthy = [bool]$health.server_api.ok
        wazuh_indexer_healthy = [bool]$health.indexer.ok
        endpoint_agent_status = if ($agent.Count) { $agent[0].status } else { "NOT_FOUND" }
        services = $services
    }
}

function Wait-HealthyAgent {
    param([int]$TimeoutSeconds = 120)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $health = Get-LabHealth
        $agentActive = $health.endpoint_agent_status -eq "active"
        $wazuhRunning = @($health.services | Where-Object { $_.name -eq "WazuhSvc" -and $_.state -eq "Running" }).Count -eq 1
        if ($health.csg_api_healthy -and $health.wazuh_server_api_healthy -and
            $health.wazuh_indexer_healthy -and $agentActive -and $wazuhRunning) { return $health }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "CSG/Wazuh/endpoint did not return to healthy state within $TimeoutSeconds seconds."
}

function Restart-WazuhAgentService {
    param([int]$MaxAttempts = 3, [int]$AttemptTimeoutSeconds = 25)
    $before = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction Stop
    if (-not $before -or [int]$before.ProcessId -le 0) {
        throw "WazuhSvc has no running process before the requested configuration reload."
    }
    $beforeProcessId = [int]$before.ProcessId
    $attemptErrors = @()
    $current = $before
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Restart-Service -Name WazuhSvc -Force -ErrorAction Stop
        } catch {
            $attemptErrors += "attempt ${attempt}: $($_.Exception.Message)"
        }
        $deadline = [DateTime]::UtcNow.AddSeconds($AttemptTimeoutSeconds)
        do {
            $current = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction Stop
            if ($current.State -eq "Running" -and [int]$current.ProcessId -gt 0 -and
                [int]$current.ProcessId -ne $beforeProcessId) {
                return [ordered]@{
                    status = "RESTART_CONFIRMED"
                    attempts = $attempt
                    process_id_before = $beforeProcessId
                    process_id_after = [int]$current.ProcessId
                    service_state_after = [string]$current.State
                    attempt_errors = $attemptErrors
                    confirmed_at_utc = [DateTime]::UtcNow.ToString("o")
                }
            }
            if ((Get-Date).ToUniversalTime() -lt $deadline) { Start-Sleep -Seconds 1 }
        } while ((Get-Date).ToUniversalTime() -lt $deadline)
        if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds 2 }
    }
    $errorSummary = if ($attemptErrors.Count) { $attemptErrors -join " | " } else { "service process ID did not change" }
    throw "Could not confirm WazuhSvc restart after $MaxAttempts attempts; before PID $beforeProcessId, current state $($current.State), current PID $($current.ProcessId). $errorSummary"
}

function Test-ExactTaskEvent {
    param([object]$Event, [string]$TaskName)
    if ($Event.host_id -ne $HostId -or $Event.source -ne "wazuh" -or
        $Event.normalized_type -ne "scheduled_task_created") { return $false }
    $expectedName = ("\" + $TaskName).ToLowerInvariant().Replace("/", "\")
    $expectedKey = ("scheduled_task:" + $expectedName).ToLowerInvariant()
    $actualKey = ([string]$Event.target.key).Trim().ToLowerInvariant().Replace("/", "\")
    $actualName = ([string]$Event.attributes.task_name).Trim().ToLowerInvariant().Replace("/", "\")
    return $actualKey -eq $expectedKey -or $actualName -eq $expectedName
}

function Invoke-ProviderQuery {
    param([string]$StartUtc, [string]$EndUtc, [string]$TargetTaskName)
    $start = [uri]::EscapeDataString($StartUtc)
    $end = [uri]::EscapeDataString($EndUtc)
    $started = [DateTime]::UtcNow
    try {
        $response = Invoke-RestMethod -Method Get -TimeoutSec 60 -Uri (
            "$($CsgApiBase.TrimEnd('/'))/api/hosts/$HostId/provider-event-observation?start=$start&end=$end"
        )
        $exactEvents = @($response.events | Where-Object {
            Test-ExactTaskEvent -Event $_ -TaskName $TargetTaskName
        } | ForEach-Object {
            [ordered]@{
                event_id = $_.event_id
                event_time = $_.event_time
                host_id = $_.host_id
                source = $_.source
                normalized_type = $_.normalized_type
                target_key = $_.target.key
                task_name = if ($_.attributes.task_name) { $_.attributes.task_name } else { $_.task_name }
                exact_identity_match = $true
            }
        })
        [ordered]@{
            queried_at_utc = [DateTime]::UtcNow.ToString("o")
            request_started_at_utc = $started.ToString("o")
            request_completed_at_utc = [DateTime]::UtcNow.ToString("o")
            query_complete = [bool]$response.query_complete
            coverage_status = $response.coverage_status
            endpoint_collection_status = $response.endpoint_collection_status
            transport_status = $response.transport_status
            index_status = $response.index_status
            returned_event_count = @($response.events).Count
            exact_target_event_count = @($exactEvents).Count
            events = @($exactEvents)
            request_error = $null
        }
    } catch {
        [ordered]@{
            queried_at_utc = [DateTime]::UtcNow.ToString("o")
            request_started_at_utc = $started.ToString("o")
            request_completed_at_utc = [DateTime]::UtcNow.ToString("o")
            query_complete = $false
            coverage_status = "UNKNOWN"
            endpoint_collection_status = "UNKNOWN"
            transport_status = "UNKNOWN"
            index_status = "UNKNOWN"
            returned_event_count = 0
            exact_target_event_count = $null
            events = @()
            request_error = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
        }
    }
}

function Get-ReconciliationHistory {
    param([string]$FindingId)
    if (-not $FindingId) { return @() }
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

function ConvertTo-UtcOffset {
    param([object]$Value)
    if ($Value -is [datetimeoffset]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetime]) { return ([datetimeoffset]$Value).ToUniversalTime() }
    return [datetimeoffset]::Parse(
        [string]$Value,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    )
}

function Normalize-ObjectKey {
    param([object]$Value)
    return ([string]$Value).Trim().Replace("/", "\").ToLowerInvariant()
}

function Restore-AgentConfig {
    if (-not $script:backupCreated) { return }
    Copy-Item -LiteralPath $configBackup -Destination $configPath -Force
    $restoredHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($restoredHash -ne $originalHash) { throw "Wazuh configuration restoration hash mismatch: $restoredHash" }
    $script:restoreRestartEvidence = Restart-WazuhAgentService
    $health = Wait-HealthyAgent -TimeoutSeconds 120
    $script:restoration = [ordered]@{
        restored_at_utc = [DateTime]::UtcNow.ToString("o")
        original_config_sha256 = $originalHash
        restored_config_sha256 = $restoredHash
        hash_restored = $true
        service_restart = $script:restoreRestartEvidence
        endpoint_health = $health
    }
    $script:filterApplied = $false
}

$preflight = $null
$errorMessage = $null
try {
    $config = New-Object System.Xml.XmlDocument
    $config.PreserveWhitespace = $true
    $config.Load($configPath)
    $securityBlocks = @($config.SelectNodes("/ossec_config/localfile") | Where-Object {
        $_.SelectSingleNode("location") -and $_.SelectSingleNode("location").InnerText -eq "Security" -and
        $_.SelectSingleNode("log_format") -and $_.SelectSingleNode("log_format").InnerText -eq "eventchannel"
    })
    if ($securityBlocks.Count -ne 1) { throw "Expected exactly one Security eventchannel block; found $($securityBlocks.Count)." }
    $queryNode = $securityBlocks[0].SelectSingleNode("query")
    if (-not $queryNode) { throw "The frozen baseline Security query is missing; refusing to change collection policy." }
    $baselineQuery = ($queryNode.InnerText -replace '\s+', ' ').Trim()
    if ($baselineQuery -ne $expectedBaselineQuery) {
        throw "The Security query differs from the frozen baseline; refusing to change collection policy."
    }
    $probeSettings = Get-Content -LiteralPath $ProbeConfig -Raw | ConvertFrom-Json
    if ($probeSettings.CSG_PROBE_HOST_ID -ne $HostId) { throw "Probe config host ID differs from the frozen host." }
    $residualTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskName -like "CSGAPTTask*" -or $_.TaskName -like "CSGAPTDis*"
    } | ForEach-Object { "{0}{1}" -f $_.TaskPath, $_.TaskName })
    if ($residualTasks.Count -gt 0) { throw "Preflight found residual CSG study tasks." }
    $securityLog = Get-WinEvent -ListLog "Security" -ErrorAction Stop
    if (-not $securityLog.IsEnabled) { throw "Windows Security log is not enabled." }
    $null = Get-WinEvent -LogName "Security" -FilterXPath $effectiveQuery -MaxEvents 1 -ErrorAction Stop
    $healthBefore = Wait-HealthyAgent -TimeoutSeconds 10
    $wazuhService = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
    $preflight = [ordered]@{
        captured_at_utc = [DateTime]::UtcNow.ToString("o")
        host_id = $HostId
        computer_name = $env:COMPUTERNAME
        windows_build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        processor_architecture = $env:PROCESSOR_ARCHITECTURE
        original_agent_config_sha256 = $originalHash
        security_query_before = $queryNode.InnerText
        security_query_after = $effectiveQuery
        target_event_filter = $effectiveQuery
        target_filter_xpath_native_validation = "PASS"
        filter_mode = $FilterMode
        security_log_enabled = [bool]$securityLog.IsEnabled
        wazuh_service_pid_before = [int]$wazuhService.ProcessId
        endpoint_health = $healthBefore
        residual_study_tasks = $residualTasks
        runner_sha256 = (Get-FileHash -LiteralPath $RunnerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $preflight | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $preflightPath -Encoding UTF8

    Copy-Item -LiteralPath $configPath -Destination $configBackup
    $script:backupCreated = $true
    $queryNode.InnerText = $effectiveQuery
    $config.Save($configTemporary)
    $verify = New-Object System.Xml.XmlDocument
    $verify.Load($configTemporary)
    $verifyBlock = @($verify.SelectNodes("/ossec_config/localfile") | Where-Object {
        $_.SelectSingleNode("location") -and $_.SelectSingleNode("location").InnerText -eq "Security"
    })
    if ($verifyBlock.Count -ne 1 -or
        (($verifyBlock[0].SelectSingleNode("query").InnerText -replace '\s+', ' ').Trim()) -ne $effectiveQuery) {
        throw "Filtered Security query did not pass XML readback."
    }
    Copy-Item -LiteralPath $configTemporary -Destination $configPath -Force
    $script:filteredHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Copy-Item -LiteralPath $configPath -Destination (Join-Path $OutputDirectory "ossec.conf.filtered.applied.xml")
    $script:filterApplied = $true
    $script:filteredRestartEvidence = Restart-WazuhAgentService
    $filteredHealth = Wait-HealthyAgent -TimeoutSeconds 120

    if ($HoldForActiveQueryVerification) {
        $queryBytes = [Text.Encoding]::UTF8.GetBytes($effectiveQuery)
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $activeQueryGate.expected_query_sha256 = ([BitConverter]::ToString(
                $sha256.ComputeHash($queryBytes)
            )).Replace("-", "").ToLowerInvariant()
        } finally { $sha256.Dispose() }
        $activeQueryGate.expected_query_base64 = [Convert]::ToBase64String($queryBytes)
        $activeQueryGate.gate_opened_at_utc = [DateTime]::UtcNow.ToString("o")
        $activeQueryGate.status = "WAITING_FOR_EXTERNAL_ACTIVE_CONFIG_CHECK"
        Write-Output ("CSG_ACTIVE_QUERY_GATE_READY|" + $OutputDirectory + "|" + $activeQueryGate.expected_query_base64)
        $expectedNormalizedQuery = [regex]::Replace($effectiveQuery, '\s+', ' ').Trim()
        $normalizedSha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $expectedNormalizedHash = ([BitConverter]::ToString(
                $normalizedSha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($expectedNormalizedQuery))
            )).Replace('-', '').ToLowerInvariant()
        } finally { $normalizedSha256.Dispose() }
        $approvalDeadline = [DateTime]::UtcNow.AddSeconds($ActiveQueryGateTimeoutSeconds)
        $approval = $null
        do {
            if (Test-Path -LiteralPath $ActiveQueryApprovalFile -PathType Leaf) {
                $approval = Get-Content -LiteralPath $ActiveQueryApprovalFile -Raw | ConvertFrom-Json
                $approvalCapturedAt = [DateTimeOffset]::MinValue
                $approvalTimeValid = [DateTimeOffset]::TryParse(
                    [string]$approval.captured_at_utc,
                    [ref]$approvalCapturedAt
                ) -and $approvalCapturedAt.UtcDateTime -ge [DateTime]::Parse($activeQueryGate.gate_opened_at_utc).ToUniversalTime()
                $approvalValid = $approval.schema_version -eq "csg-wazuh-active-eventchannel-query-v1" -and
                    $approval.agent_id -eq "001" -and $approval.channel -eq "Security" -and
                    $approval.api_error -eq 0 -and $approval.security_localfile_block_count -eq 1 -and
                    $approval.matches_expected_query -eq $true -and $approvalTimeValid -and
                    $approval.active_query_sha256_normalized -eq $expectedNormalizedHash -and
                    $approval.expected_query_sha256_normalized -eq $expectedNormalizedHash
                if (-not $approvalValid) {
                    $activeQueryGate.status = "ABORTED_BEFORE_TASK_ACTION_INVALID_EXTERNAL_APPROVAL"
                    throw "External active-query approval file failed schema/hash/time checks; restoring original config."
                }
                $activeQueryGate.approval = $approval
                $activeQueryGate.operator_decision = "CONTINUE_VIA_VERIFIED_APPROVAL_FILE"
                $activeQueryGate.decision_at_utc = [DateTime]::UtcNow.ToString("o")
                $activeQueryGate.status = "APPROVED_TO_RUN_TASK_ACTION"
                break
            }
            Start-Sleep -Seconds 1
        } while ([DateTime]::UtcNow -lt $approvalDeadline)
        if ($activeQueryGate.status -ne "APPROVED_TO_RUN_TASK_ACTION") {
            $activeQueryGate.status = "ABORTED_BEFORE_TASK_ACTION_APPROVAL_TIMEOUT"
            throw "Timed out waiting for a fresh matching external query approval; restoring original config."
        }
    }

    $null = New-Item -ItemType Directory -Path $runnerOutput -Force
    $scheduledTaskArgument = "-ScheduledTaskName `"$ScheduledTaskName`" "
    if ($DistractorTaskName) { $scheduledTaskArgument += "-DistractorTaskName `"$DistractorTaskName`" " }
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$RunnerPath`" " +
        "-CsgApiBase `"$CsgApiBase`" -HostId `"$HostId`" " +
        "-ProbePython `"$ProbePython`" -ProbeConfig `"$ProbeConfig`" " +
        "-WaitSeconds $WaitSeconds -OutputPath `"$runnerRunPath`" $scheduledTaskArgument" +
        "-ScenarioFilter scheduled_task -ExpectedEventSuppressed"
    if ($DistractorAfterSuppressedTarget) {
        $arguments += " -DistractorAfterSuppressedTarget " +
            "-WazuhAgentConfigBackupPath `"$configBackup`" " +
            "-ExpectedAgentConfigSha256 `"$ExpectedAgentConfigSha256`""
    }
    $child = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -PassThru -Wait `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -WindowStyle Hidden
    $script:runnerExitCode = [int]$child.ExitCode
    if (-not (Test-Path -LiteralPath $runnerRunPath -PathType Leaf)) {
        throw "Runner did not produce run.json; exit code $script:runnerExitCode"
    }
    $script:runner = Get-Content -LiteralPath $runnerRunPath -Raw | ConvertFrom-Json
} catch {
    $errorMessage = "line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
} finally {
    if ($script:filterApplied) {
        try { $script:filteredRuntimeHealth = Get-LabHealth } catch {
            $script:filteredRuntimeHealth = [ordered]@{ capture_error = $_.Exception.Message }
        }
        try {
            $agentLogPath = Join-Path ${env:ProgramFiles(x86)} "ossec-agent\ossec.log"
            if (Test-Path -LiteralPath $agentLogPath -PathType Leaf) {
                $logLines = @(Get-Content -LiteralPath $agentLogPath -Tail 1000)
                $relevantLogLines = @($logLines | Where-Object {
                    $_ -match '(?i)(logcollector|eventchannel|security|error|warning|query)'
                })
                $script:filteredLogCapturePath = Join-Path $OutputDirectory "filtered-agent-log-diagnostic.txt"
                Set-Content -LiteralPath $script:filteredLogCapturePath -Value $relevantLogLines -Encoding UTF8
            }
        } catch { }
    }
    try { Restore-AgentConfig } catch {
        if (-not $errorMessage) { $errorMessage = "Configuration restoration failed: $($_.Exception.Message)" }
    }
    if (Test-Path -LiteralPath $configTemporary) { Remove-Item -LiteralPath $configTemporary -Force -ErrorAction SilentlyContinue }
}

$scenario = if ($script:runner -and $script:runner.scenarios) { @($script:runner.scenarios | Where-Object { $_.kind -eq "scheduled_task" } | Select-Object -First 1)[0] } else { $null }
$distractorEvidence = if ($scenario) { $scenario.distractor_evidence } else { $null }
$distractorProviderEvents = @()
if ($null -ne $distractorEvidence -and $null -ne $distractorEvidence.provider_events) {
    $distractorProviderEvents = @($distractorEvidence.provider_events)
}
$reconciliationHistory = @()
$postRestoreTargetEventIds = @()
$postRestoreQueryWindow = $null
if ($scenario) {
    $findingId = [string]$scenario.csg_reconciliation.finding_id
    if (-not $findingId) {
        $reconciliationHistory = @()
    } elseif ($DeferFinalReconciliationWait) {
        try { $reconciliationHistory = @(Get-ReconciliationHistory -FindingId $findingId) } catch { }
    } else {
        $deadline = [DateTime]::UtcNow.AddSeconds($ReconciliationWaitSeconds)
        do {
            try { $reconciliationHistory = @(Get-ReconciliationHistory -FindingId $findingId) } catch { }
            $latest = if ($reconciliationHistory.Count) { $reconciliationHistory[-1] } else { $null }
            if ($latest -and $latest.finalized) { break }
            Start-Sleep -Seconds 5
        } while ([DateTime]::UtcNow -lt $deadline)
    }

    $retrieval = $scenario.event_retrieval
    if ($retrieval.query_start -and $retrieval.query_end) {
        $postRestoreQueryWindow = [ordered]@{ start = $retrieval.query_start; end = $retrieval.query_end }
        $postRestoreDeadline = [DateTime]::UtcNow.AddSeconds($PostRestoreQuerySeconds)
        do {
            $query = Invoke-ProviderQuery -StartUtc ([string]$retrieval.query_start) `
                -EndUtc ([string]$retrieval.query_end) -TargetTaskName ([string]$scenario.object_name)
            $exact = @($query.events | Where-Object {
                $_.host_id -eq $HostId -and $_.source -eq "wazuh" -and
                $_.normalized_type -eq "scheduled_task_created" -and $_.exact_identity_match
            } | ForEach-Object { $_.event_id } | Sort-Object -Unique)
            $query.exact_target_event_ids = $exact
            $script:postRestoreQueries.Add($query)
            if ($exact.Count -gt 0) { $postRestoreTargetEventIds = $exact; break }
            Start-Sleep -Seconds 15
        } while ([DateTime]::UtcNow -lt $postRestoreDeadline)
    }
}

$finalReconciliation = if ($reconciliationHistory.Count) { $reconciliationHistory[-1] } else { $null }
$distractorProviderIds = @()
$distractorReadbackIds = @()
if ($null -ne $distractorEvidence) {
    if ($null -ne $distractorEvidence.provider_event_ids) {
        $distractorProviderIds = @($distractorEvidence.provider_event_ids | Sort-Object -Unique)
    }
    if ($null -ne $distractorEvidence.csg_event_store_readback_event_ids) {
        $distractorReadbackIds = @($distractorEvidence.csg_event_store_readback_event_ids | Sort-Object -Unique)
    }
}
$distractorFinalWindow = if ($finalReconciliation) { $finalReconciliation.observation_window } else { $null }
$distractorProviderEvent = if ($distractorProviderEvents.Count -eq 1) { $distractorProviderEvents[0] } else { $null }
$distractorExpectedKey = Normalize-ObjectKey ("scheduled_task:\" + $DistractorTaskName)
$distractorActualKey = if ($distractorProviderEvent) { Normalize-ObjectKey $distractorProviderEvent.target.key } else { "" }
$targetActualKey = if ($scenario) { Normalize-ObjectKey $scenario.expected_object_key } else { "" }
$distractorIdentityChecks = [ordered]@{
    exactly_one_provider_event = ($distractorProviderEvents.Count -eq 1)
    host_matches = [bool]($distractorProviderEvent -and $distractorProviderEvent.host_id -eq $HostId)
    source_is_wazuh = [bool]($distractorProviderEvent -and $distractorProviderEvent.source -eq "wazuh")
    normalized_type_matches = [bool]($distractorProviderEvent -and $distractorProviderEvent.normalized_type -eq "scheduled_task_created")
    exact_distractor_object_key = [bool]($distractorEvidence -and
        (Normalize-ObjectKey $distractorEvidence.object_key) -eq $distractorExpectedKey -and
        $distractorActualKey -eq $distractorExpectedKey)
    different_from_target_object_key = [bool]($distractorActualKey -and $targetActualKey -and
        $distractorActualKey -ne $targetActualKey)
}
$distractorDistinctFromTarget = @($distractorIdentityChecks.Values | Where-Object { -not $_ }).Count -eq 0
$distractorEventTimeUtc = $null
$distractorWindowStartUtc = $null
$distractorWindowEndUtc = $null
$distractorTimeError = $null
try {
    if ($distractorProviderEvent -and $distractorFinalWindow.start -and $distractorFinalWindow.end) {
        $distractorEventTimeUtc = ConvertTo-UtcOffset $distractorProviderEvent.event_time
        $distractorWindowStartUtc = ConvertTo-UtcOffset $distractorFinalWindow.start
        $distractorWindowEndUtc = ConvertTo-UtcOffset $distractorFinalWindow.end
    }
} catch { $distractorTimeError = "$($_.Exception.GetType().Name): $($_.Exception.Message)" }
$distractorInsideFinalWindow = [bool]($distractorEventTimeUtc -and $distractorWindowStartUtc -and
    $distractorWindowEndUtc -and $distractorEventTimeUtc -ge $distractorWindowStartUtc -and
    $distractorEventTimeUtc -le $distractorWindowEndUtc)
$distractorReadbackValid = [bool]($distractorEvidence -and $distractorEvidence.exact_provider_ingest_readback_match -and
    $distractorProviderIds.Count -eq 1 -and $distractorReadbackIds.Count -eq 1 -and
    $distractorProviderIds[0] -eq $distractorReadbackIds[0])
$distractorApplicable = [bool]$DistractorTaskName
$sameWindowDistractorPassed = $distractorApplicable -and $distractorInsideFinalWindow -and
    $distractorDistinctFromTarget -and $distractorReadbackValid
$distractorValidation = [ordered]@{
    event_time_utc = if ($distractorEventTimeUtc) { $distractorEventTimeUtc.ToString("o") } else { $null }
    observation_window_start_utc = if ($distractorWindowStartUtc) { $distractorWindowStartUtc.ToString("o") } else { $null }
    observation_window_end_utc = if ($distractorWindowEndUtc) { $distractorWindowEndUtc.ToString("o") } else { $null }
    time_parse_error = $distractorTimeError
    expected_object_key = $distractorExpectedKey
    observed_object_key = $distractorActualKey
    target_object_key = $targetActualKey
    identity_checks = $distractorIdentityChecks
    inside_final_window = $distractorInsideFinalWindow
    event_store_readback_verified = $distractorReadbackValid
    overall_passed = $sameWindowDistractorPassed
}
$taskName = if ($scenario) { [string]$scenario.object_name } else { $null }
$residualTasksFinal = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName -like "CSGAPTTask*" -or $_.TaskName -like "CSGAPTDis*"
} | ForEach-Object { "{0}{1}" -f $_.TaskPath, $_.TaskName })
$healthAfter = $null
try { $healthAfter = Get-LabHealth } catch { }
$restoredHashFinal = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
$securityLogFinal = Get-WinEvent -ListLog "Security" -ErrorAction SilentlyContinue
$localExact = if ($scenario) { @($scenario.local_source_evidence.exact_events | Where-Object {
    $_.event_id -eq 4698 -and $_.exact_identity_match
}) } else { @() }
$localExactCount = @($localExact).Count
$stateSequence = if ($scenario) { $scenario.state_plane.direct_windows_verification } else { $null }
$queryCompleteDuringFilter = [bool]($scenario -and $scenario.event_plane.query_completed -and
    $scenario.event_plane.retrieval.query_complete)
$queryCoverageCompleteDuringFilter = [bool]($scenario -and
    $scenario.event_plane.retrieval.coverage_status -eq "COMPLETE" -and
    $scenario.event_plane.retrieval.endpoint_collection_status -eq "AVAILABLE" -and
    $scenario.event_plane.retrieval.transport_status -eq "AVAILABLE" -and
    $scenario.event_plane.retrieval.index_status -eq "AVAILABLE")
$targetAbsentFromWazuhDuringFilter = [bool]($scenario -and @($scenario.event_plane.exact_matches).Count -eq 0)
$eventStoreReadback = if ($scenario) {
    $scenario.state_plane.creation_delta_reconciliation_before_cleanup
} else { $null }
$targetAbsentFromEventStore = [bool]($eventStoreReadback -and
    $eventStoreReadback.event_store_readback_complete -and
    @($eventStoreReadback.provider_exact_target_event_ids).Count -eq 0 -and
    @($eventStoreReadback.event_store_readback_ids).Count -eq 0)
$targetStateObserved = [bool]($stateSequence -and $stateSequence.target_absent_before_action -and
    $stateSequence.target_present_after_action -and $stateSequence.target_absent_after_cleanup)
$cleanupVerified = [bool]($scenario -and $scenario.action.cleanup_completed -and
    $scenario.state_plane.cleanup_removed_from_probe -and $residualTasksFinal.Count -eq 0)
$finalizedUnexplained = [bool]($finalReconciliation -and $finalReconciliation.status -eq "UNEXPLAINED" -and
    $finalReconciliation.finalized -and @($finalReconciliation.matched_evidence_ids).Count -eq 0)
$postRestoreQueriesComplete = $script:postRestoreQueries.Count -gt 0 -and
    @($script:postRestoreQueries | Where-Object {
        -not $_.query_complete -or $_.coverage_status -ne "COMPLETE" -or
        $_.endpoint_collection_status -ne "AVAILABLE" -or $_.transport_status -ne "AVAILABLE" -or
        $_.index_status -ne "AVAILABLE"
    }).Count -eq 0
$eventAbsentAfterRestore = $postRestoreQueriesComplete -and $postRestoreTargetEventIds.Count -eq 0
$targetEventPresentDuringFilter = $scenario -and @($scenario.event_plane.exact_matches).Count -gt 0
$pairedWrongObjectTrialPassed = if ($distractorApplicable) {
    $sameWindowDistractorPassed -and -not $targetEventPresentDuringFilter -and
        $targetAbsentFromWazuhDuringFilter -and $targetAbsentFromEventStore -and $finalizedUnexplained
} else { $null }
$distractorGatePassed = -not $distractorApplicable -or $pairedWrongObjectTrialPassed
$configRestored = if ($script:backupCreated) {
    $restoredHashFinal -eq $originalHash -and $script:restoration -and $script:restoration.hash_restored
} else {
    $restoredHashFinal -eq $originalHash
}
$agentActiveFinal = $healthAfter -and $healthAfter.endpoint_agent_status -eq "active" -and
    $healthAfter.wazuh_server_api_healthy -and $healthAfter.wazuh_indexer_healthy
$captureGatesPassed = $configRestored -and $agentActiveFinal -and $targetStateObserved -and
    $localExactCount -gt 0 -and $queryCompleteDuringFilter -and $queryCoverageCompleteDuringFilter -and
    $targetAbsentFromWazuhDuringFilter -and $targetAbsentFromEventStore -and
    $eventAbsentAfterRestore -and $cleanupVerified -and $securityLogFinal.IsEnabled -and
    $distractorGatePassed
$status = if ($activeQueryGate.status -eq "ABORTED_BEFORE_TASK_ACTION" -and $configRestored) {
    "ABORTED_BEFORE_TASK_ACTION_RESTORED"
} elseif (-not $script:backupCreated -and $errorMessage) {
    "PREFLIGHT_REFUSED_NO_MUTATION"
} elseif ($DeferFinalReconciliationWait -and $captureGatesPassed) {
    "CAPTURE_VALID_RECONCILIATION_DEFERRED"
} elseif ($targetEventPresentDuringFilter) {
    "TARGET_EVENT_PRESENT_DURING_FILTER"
} elseif ($configRestored -and $agentActiveFinal -and $targetStateObserved -and
    $localExactCount -gt 0 -and $queryCompleteDuringFilter -and $queryCoverageCompleteDuringFilter -and
    $targetAbsentFromWazuhDuringFilter -and $targetAbsentFromEventStore -and $finalizedUnexplained -and
    $eventAbsentAfterRestore -and $cleanupVerified -and $securityLogFinal.IsEnabled -and
    $distractorGatePassed) {
    if ($FilterMode -eq "event_id") {
        "DIAGNOSTIC_EVENTID_4698_EXCLUSION_CAPTURED"
    } else {
        "PASS_TARGET_FILTER_WITH_IN_WINDOW_DISTRACTOR"
    }
} elseif ($postRestoreTargetEventIds.Count -gt 0) {
    "TARGET_EVENT_FIRST_OBSERVED_AFTER_RESTORE"
} else {
    "INCOMPLETE_OR_INVALID"
}

$result = [ordered]@{
    schema_version = "csg-scheduled-task-event-filter-diagnostic-v1"
    filter_mode = $FilterMode
    filter_mode_interpretation = if ($FilterMode -eq "event_id") {
        "Diagnostic exclusion of all Security Event ID 4698 records; not a wrong-object trial."
    } else {
        "Exclusion of Event ID 4698 for the assigned target task name."
    }
    status = $status
    captured_at_utc = [DateTime]::UtcNow.ToString("o")
    host_id = $HostId
    computer_name = $env:COMPUTERNAME
    runner_exit_code = $script:runnerExitCode
    original_agent_config_sha256 = $originalHash
    filtered_agent_config_sha256 = $script:filteredHash
    effective_security_eventchannel_query = $effectiveQuery
    suppressed_task_name = $ScheduledTaskName
    expected_collected_distractor_task_name = if ($DistractorTaskName) { $DistractorTaskName } else { $null }
    filter_source_health = $filteredHealth
    endpoint_runtime_health_before_restore = $script:filteredRuntimeHealth
    filtered_agent_log_capture = $script:filteredLogCapturePath
    active_query_gate = $activeQueryGate
    restoration = $script:restoration
    service_restart_evidence = [ordered]@{
        filter_application = $script:filteredRestartEvidence
        baseline_restoration = $script:restoreRestartEvidence
    }
    restored_agent_config_sha256 = $restoredHashFinal
    restored_hash_matches_original = $configRestored
    configuration_mutation_attempted = $script:backupCreated
    source_health_after_restore = $healthAfter
    security_log_enabled_after = [bool]$securityLogFinal.IsEnabled
    runner_result = $script:runner
    target_task_name = $taskName
    local_windows_4698_exact_count = $localExactCount
    direct_probe_state_sequence_passed = $targetStateObserved
    query_complete_during_filter = $queryCompleteDuringFilter
    query_coverage_and_source_availability_during_filter = $queryCoverageCompleteDuringFilter
    exact_wazuh_target_event_count_during_filter = if ($scenario) { @($scenario.event_plane.exact_matches).Count } else { $null }
    target_absent_from_csg_event_store_during_filter = $targetAbsentFromEventStore
    capture_gates_passed = $captureGatesPassed
    final_reconciliation_wait_deferred = [bool]$DeferFinalReconciliationWait
    target_reconciliation_history = $reconciliationHistory
    final_target_reconciliation = $finalReconciliation
    post_restore_query_window = $postRestoreQueryWindow
    post_restore_provider_queries = @($script:postRestoreQueries.ToArray())
    target_wazuh_event_ids_after_restore = $postRestoreTargetEventIds
    target_event_absent_after_restore = $eventAbsentAfterRestore
    distractor_event = if ($distractorEvidence) { $distractorEvidence } else { $null }
    distractor_same_host_same_type_different_object = $distractorDistinctFromTarget
    distractor_inside_final_reconciliation_window = $distractorInsideFinalWindow
    distractor_event_store_readback_verified = $distractorReadbackValid
    distractor_validation_applicable = $distractorApplicable
    paired_wrong_object_trial_passed = $pairedWrongObjectTrialPassed
    distractor_validation = if ($distractorApplicable) { $distractorValidation } else { "NOT_APPLICABLE" }
    target_event_present_during_filter = [bool]$targetEventPresentDuringFilter
    cleanup_verified = $cleanupVerified
    residual_study_tasks = $residualTasksFinal
    output_streams = [ordered]@{
        stdout_path = $stdoutPath
        stderr_path = $stderrPath
        stderr_excerpt = if (Test-Path -LiteralPath $stderrPath) { [string](Get-Content -LiteralPath $stderrPath -Raw) } else { "" }
    }
    error = $errorMessage
}
$result | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $resultPath -Encoding UTF8
if (($script:backupCreated -and -not $configRestored) -or -not $agentActiveFinal -or $residualTasksFinal.Count -gt 0) {
    throw "Safety failure: verify Wazuh restoration and task cleanup immediately. Result: $status"
}
Write-Output $status
