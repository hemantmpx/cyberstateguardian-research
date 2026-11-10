param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedAgentConfigSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedRunnerSha256,
    [Parameter(Mandatory = $true)]
    [string]$AssignmentPath,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [string]$CsgApiBase = 'http://192.168.64.1:8000',
    [string]$HostId = 'win11-arm-lab',
    [string]$ProbePython = 'C:\Program Files\CyberStateGuardian\Probe\venv\Scripts\python.exe',
    [string]$ProbeConfig = 'C:\Program Files\CyberStateGuardian\Probe\settings.json',
    [string]$RunnerPath = 'C:\CSG\run_windows_category_same_window_distractor_v12_frozen_v25.ps1'
)

$ErrorActionPreference = 'Stop'
$configPath = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$campaignPath = Join-Path $OutputDirectory 'campaign.json'
$preflightPath = Join-Path $OutputDirectory 'preflight.json'
$campaignId = 'scheduled-task-same-window-complete-distractor-campaign-v25'
$stopReason = $null
$trialResults = New-Object System.Collections.Generic.List[object]

if (Test-Path -LiteralPath $OutputDirectory) { throw "Refusing to overwrite $OutputDirectory" }
foreach ($path in @($configPath, $AssignmentPath, $ProbePython, $ProbeConfig, $RunnerPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file is missing: $path" }
}
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw 'Run from elevated Administrator PowerShell.' }

$assignments = Get-Content -LiteralPath $AssignmentPath -Raw | ConvertFrom-Json
if ($assignments.protocol_id -ne $campaignId -or @($assignments.trials).Count -ne 10) {
    throw 'Assignment file does not match the frozen ten-trial protocol.'
}
$allNames = @($assignments.trials | ForEach-Object { @($_.target, $_.distractor) })
if (@($allNames | Sort-Object -Unique).Count -ne 20) { throw 'Task assignments are not unique.' }
foreach ($assignment in $assignments.trials) {
    if ($assignment.target -notmatch '^CSGAPTTask[a-fA-F0-9]{10}$' -or
        $assignment.distractor -notmatch '^CSGAPTDis[a-fA-F0-9]{10}$') {
        throw "Invalid frozen task name in assignment $($assignment.trial)."
    }
}

$baselineHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
$runnerHash = (Get-FileHash -LiteralPath $RunnerPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($baselineHash -ne $ExpectedAgentConfigSha256.ToLowerInvariant()) {
    throw "Agent config does not match frozen hash: $baselineHash"
}
if ($runnerHash -ne $ExpectedRunnerSha256.ToLowerInvariant()) {
    throw "Runner does not match frozen hash: $runnerHash"
}
$settings = Get-Content -LiteralPath $ProbeConfig -Raw | ConvertFrom-Json
if ($settings.CSG_PROBE_HOST_ID -ne $HostId) { throw 'Probe config host ID mismatch.' }

function Get-ResidualStudyTasks {
    @(
        Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskName -like 'CSGAPTTask*' -or $_.TaskName -like 'CSGAPTDis*'
        } | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" }
    )
}

function Get-HealthSnapshot {
    $health = Invoke-RestMethod -Method Get -TimeoutSec 20 -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
    $agent = @($health.server_api.agents | Where-Object { $_.name -eq $HostId } | Select-Object -First 1)
    $service = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
    [ordered]@{
        captured_at_utc = [DateTime]::UtcNow.ToString('o')
        csg_api_healthy = [bool]$health.ok
        wazuh_api_healthy = [bool]$health.server_api.ok
        indexer_healthy = [bool]$health.indexer.ok
        agent_status = if ($agent.Count) { $agent[0].status } else { 'NOT_FOUND' }
        agent_version = if ($agent.Count) { $agent[0].version } else { $null }
        service_state = $service.State
        service_pid = [int]$service.ProcessId
    }
}

$preHealth = Get-HealthSnapshot
$residualBefore = @(Get-ResidualStudyTasks)
if ($residualBefore.Count -gt 0) { throw 'Residual study tasks exist before campaign.' }
if (-not $preHealth.csg_api_healthy -or -not $preHealth.wazuh_api_healthy -or
    -not $preHealth.indexer_healthy -or $preHealth.agent_status -ne 'active' -or
    $preHealth.service_state -ne 'Running') { throw 'CSG/Wazuh health preflight failed.' }

$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
[ordered]@{
    schema_version = 'csg-windows-distractor-campaign-preflight-v1'
    campaign_id = $campaignId
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    host_id = $HostId
    computer_name = $env:COMPUTERNAME
    windows_build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    processor_architecture = $env:PROCESSOR_ARCHITECTURE
    agent_config_sha256 = $baselineHash
    runner_sha256 = $runnerHash
    assignment_sha256 = (Get-FileHash -LiteralPath $AssignmentPath -Algorithm SHA256).Hash.ToLowerInvariant()
    health = $preHealth
    residual_tasks = $residualBefore
    trial_count = @($assignments.trials).Count
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $preflightPath -Encoding UTF8

foreach ($assignment in $assignments.trials) {
    $trialNumber = [int]$assignment.trial
    $trialDirectory = Join-Path $OutputDirectory ("trial-{0:D2}" -f $trialNumber)
    $runPath = Join-Path $trialDirectory 'run.json'
    $stdoutPath = Join-Path $trialDirectory 'runner.stdout.txt'
    $stderrPath = Join-Path $trialDirectory 'runner.stderr.txt'
    $null = New-Item -ItemType Directory -Path $trialDirectory -Force

    $beforeHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $beforeTasks = @(Get-ResidualStudyTasks)
    if ($beforeHash -ne $baselineHash -or $beforeTasks.Count -gt 0) {
        $stopReason = "Safety precondition failed before trial $trialNumber."
        break
    }
    $healthBefore = Get-HealthSnapshot
    if (-not $healthBefore.csg_api_healthy -or -not $healthBefore.wazuh_api_healthy -or
        -not $healthBefore.indexer_healthy -or $healthBefore.agent_status -ne 'active' -or
        $healthBefore.service_state -ne 'Running') {
        $stopReason = "Endpoint health failed before trial $trialNumber."
        break
    }

    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$RunnerPath`" " +
        "-CsgApiBase `"$CsgApiBase`" -HostId `"$HostId`" " +
        "-ProbePython `"$ProbePython`" -ProbeConfig `"$ProbeConfig`" " +
        "-WaitSeconds 60 -LocalEventWaitSeconds 10 " +
        "-OutputPath `"$runPath`" -ScheduledTaskName `"$($assignment.target)`" " +
        "-DistractorTaskName `"$($assignment.distractor)`" -ScenarioFilter scheduled_task"
    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -PassThru -Wait `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -WindowStyle Hidden

    $afterHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $afterTasks = @(Get-ResidualStudyTasks)
    $healthAfter = Get-HealthSnapshot
    $run = if (Test-Path -LiteralPath $runPath -PathType Leaf) {
        Get-Content -LiteralPath $runPath -Raw | ConvertFrom-Json
    } else { $null }
    $scenario = if ($run -and $run.scenarios) { @($run.scenarios | Select-Object -First 1)[0] } else { $null }
    $trialResult = [ordered]@{
        trial = $trialNumber
        target_task = [string]$assignment.target
        distractor_task = [string]$assignment.distractor
        started_at_utc = if ($run) { $run.started_at } else { $null }
        ended_at_utc = if ($run) { $run.ended_at } else { $null }
        runner_exit_code = [int]$process.ExitCode
        run_artifact_present = ($null -ne $run)
        runner_status = if ($run) { $run.status } else { 'MISSING' }
        runner_positive_control = if ($scenario) { [bool]$scenario.positive_control.passed } else { $false }
        runner_error = if ($scenario) { $scenario.action.error } else { 'run.json missing' }
        config_unchanged = ($afterHash -eq $baselineHash)
        config_sha256_after = $afterHash
        residual_tasks_after = $afterTasks
        cleanup_verified = ($afterTasks.Count -eq 0)
        health_before = $healthBefore
        health_after = $healthAfter
        raw_identity_audit_required = [bool]($scenario.state_plane.creation_delta_reconciliation_before_cleanup.raw_identity_audit_required)
    }
    $trialResult | ConvertTo-Json -Depth 12 | Set-Content `
        -LiteralPath (Join-Path $trialDirectory 'trial-status.json') -Encoding UTF8
    $trialResults.Add($trialResult)
    Write-Output ("CSG_V25_TRIAL|{0}|{1}|runner={2}|cleanup={3}|health={4}" -f `
        $trialNumber, $assignment.target, $trialResult.runner_positive_control, `
        $trialResult.cleanup_verified, $healthAfter.agent_status)

    if (-not $trialResult.config_unchanged -or -not $trialResult.cleanup_verified -or
        $healthAfter.agent_status -ne 'active' -or $healthAfter.service_state -ne 'Running') {
        $stopReason = "Safety postcondition failed after trial $trialNumber."
        break
    }
}

$campaign = [ordered]@{
    schema_version = 'csg-windows-same-host-distractor-campaign-v1'
    campaign_id = $campaignId
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
    frozen_assignment_count = @($assignments.trials).Count
    completed_trial_count = $trialResults.Count
    stopped_early = ($null -ne $stopReason)
    stop_reason = $stopReason
    config_baseline_sha256 = $baselineHash
    runner_sha256 = $runnerHash
    status = if ($null -ne $stopReason) { 'STOPPED_SAFETY_OR_PRECONDITION' } else { 'LIVE_RUNS_COMPLETE_RAW_IDENTITY_AUDIT_PENDING' }
    trials = @($trialResults)
    interpretation = 'Runner outputs are not publication outcomes. Raw Indexer identity audit and frozen protocol adjudication are required.'
}
$campaign | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $campaignPath -Encoding UTF8
Write-Output "CSG_V25_CAMPAIGN|$campaignPath|$($campaign.status)|$($trialResults.Count)/$(@($assignments.trials).Count)"
