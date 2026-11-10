param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ProtocolSha256,
    [string]$OutputDirectory = 'C:\CSG\research-campaign-20261012-scheduled-task-distractor-series-v2',
    [string]$CampaignId = 'csg-scheduled-task-distractor-series-20261012-v2',
    [string]$CsgApiBase = 'http://192.168.64.1:8000',
    [string]$HostId = 'win11-arm-lab',
    [string]$ControllerPath = 'C:\CSG\controller.ps1',
    [string]$PositiveRunnerPath = 'C:\CSG\positive-runner.ps1',
    [int]$Repetitions = 10,
    [int]$WaitSeconds = 90,
    [int]$EventTimeToleranceSeconds = 20
)

$ErrorActionPreference = 'Stop'
if ($Repetitions -lt 3 -or $Repetitions -gt 20) { throw 'Repetitions must be 3..20.' }
if ($WaitSeconds -lt 10 -or $WaitSeconds -gt 180) { throw 'WaitSeconds must be 10..180.' }
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw 'Run from elevated Administrator PowerShell.' }

$expectedControllerSha256 = '8da1cba640e0897ec26cf405fd95c9a0f386bc09bf4ca7442ea161dd2e26f142'
$expectedRunnerSha256 = '1b768e0b7b22bf7064fae0e91bf8ef22a46347c28a18a6f8fd4e957d58b597d2'
$expectedAgentConfigSha256 = '0e2eec247d4e645112f5dedc6f80e1713e2377f08ec2bbf7dc5e9cd4059ec3c1'
$agentConfigPath = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent\ossec.conf'
foreach ($path in @($ControllerPath, $PositiveRunnerPath, $agentConfigPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required frozen input is missing: $path" }
}
$controllerHash = (Get-FileHash -LiteralPath $ControllerPath -Algorithm SHA256).Hash.ToLowerInvariant()
$runnerHash = (Get-FileHash -LiteralPath $PositiveRunnerPath -Algorithm SHA256).Hash.ToLowerInvariant()
$agentConfigHash = (Get-FileHash -LiteralPath $agentConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($controllerHash -ne $expectedControllerSha256) { throw "Distractor controller hash mismatch: $controllerHash" }
if ($runnerHash -ne $expectedRunnerSha256) { throw "Positive runner hash mismatch: $runnerHash" }
if ($agentConfigHash -ne $expectedAgentConfigSha256) { throw "Wazuh config hash drift: $agentConfigHash" }

$config = [xml](Get-Content -LiteralPath $agentConfigPath -Raw)
$securityBlocks = @($config.SelectNodes('/ossec_config/localfile') | Where-Object {
    $location = $_.SelectSingleNode('location')
    $format = $_.SelectSingleNode('log_format')
    $location -and $format -and $location.InnerText -eq 'Security' -and $format.InnerText -eq 'eventchannel'
})
if ($securityBlocks.Count -ne 1) { throw "Expected one Security eventchannel subscription; found $($securityBlocks.Count)." }
$securityQuery = $securityBlocks[0].SelectSingleNode('query')
if ($securityQuery -and $securityQuery.InnerText -match 'EventID\s*!=\s*4698') {
    throw 'Security Event 4698 is excluded by the current Wazuh query.'
}

$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw "Refusing to overwrite existing campaign directory: $OutputDirectory" }
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$manifestPath = Join-Path $OutputDirectory 'campaign-manifest.json'
$healthUri = "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"

function Get-LabState {
    param([string]$Phase)
    $health = Invoke-RestMethod -Method Get -TimeoutSec 20 -Uri $healthUri
    $agent = @($health.server_api.agents | Where-Object { $_.name -eq $HostId } | Select-Object -First 1)
    $wazuh = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
    $sysmon = Get-CimInstance Win32_Service | Where-Object { $_.Name -in @('Sysmon64a', 'Sysmon64') } | Select-Object -First 1
    $residualTasks = @(
        Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.TaskName -like 'CSGAPTTask*' -or $_.TaskName -like 'CSGAPTDis*' } |
            ForEach-Object { "{0}{1}" -f $_.TaskPath, $_.TaskName }
    )
    [ordered]@{
        phase = $Phase
        captured_at_utc = [DateTime]::UtcNow.ToString('o')
        computer_name = $env:COMPUTERNAME
        windows_version = (Get-CimInstance Win32_OperatingSystem).Version
        windows_build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        processor_architecture = $env:PROCESSOR_ARCHITECTURE
        csg_api_healthy = [bool]$health.ok
        wazuh_server_api_healthy = [bool]$health.server_api.ok
        wazuh_indexer_healthy = [bool]$health.indexer.ok
        endpoint_agent = if ($agent.Count) { $agent[0] } else { $null }
        wazuh_service = [ordered]@{ state = $wazuh.State; pid = [int]$wazuh.ProcessId }
        sysmon_service = if ($sysmon) { [ordered]@{ name = $sysmon.Name; state = $sysmon.State; pid = [int]$sysmon.ProcessId } } else { $null }
        agent_config_sha256 = (Get-FileHash -LiteralPath $agentConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
        security_4698_allowed_by_query = $true
        residual_study_tasks = $residualTasks
    }
}

$initialState = Get-LabState -Phase 'preflight'
if (-not $initialState.csg_api_healthy -or -not $initialState.wazuh_server_api_healthy -or -not $initialState.wazuh_indexer_healthy) {
    throw 'Preflight failed: CSG, Wazuh manager API, or indexer is unhealthy.'
}
if (-not $initialState.endpoint_agent -or $initialState.endpoint_agent.status -ne 'active') { throw 'Preflight failed: endpoint agent is not active.' }
if ($initialState.wazuh_service.state -ne 'Running' -or -not $initialState.sysmon_service -or $initialState.sysmon_service.state -ne 'Running') {
    throw 'Preflight failed: Wazuh/Sysmon service state is not healthy.'
}
if ($initialState.residual_study_tasks.Count -gt 0) { throw 'Preflight failed: prior study task remains on the endpoint.' }

$manifest = [ordered]@{
    schema_version = 'csg-scheduled-task-distractor-series-v1'
    campaign_id = $CampaignId
    protocol_sha256 = $ProtocolSha256.ToLowerInvariant()
    controller_sha256 = $controllerHash
    positive_runner_sha256 = $runnerHash
    agent_config_sha256 = $agentConfigHash
    repetitions_planned = $Repetitions
    wait_seconds = $WaitSeconds
    event_time_tolerance_seconds = $EventTimeToleranceSeconds
    condition = 'complete_distractor'
    execution_kind = 'fixed_repetition_engineering_series_not_pooled_with_pilot_or_invalid_v1'
    endpoint = $HostId
    preflight = $initialState
    status = 'RUNNING'
    created_at_utc = [DateTime]::UtcNow.ToString('o')
    trials = @()
    postflight = $null
}
$trialEntries = New-Object System.Collections.Generic.List[object]

function Save-Manifest {
    $manifest.trials = @($trialEntries.ToArray())
    $manifest | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
}

Save-Manifest
for ($index = 1; $index -le $Repetitions; $index++) {
    $trialId = 'trial-{0:D2}' -f $index
    $trialDirectory = Join-Path $OutputDirectory $trialId
    $entry = [ordered]@{
        trial_id = $trialId
        status = 'RUNNING'
        started_at_utc = [DateTime]::UtcNow.ToString('o')
        ended_at_utc = $null
        result_status = $null
        target_task_name = $null
        distractor_task_name = $null
        target_event_id = $null
        distractor_event_id = $null
        target_reconciliation = $null
        cleanup_verified = $false
        failure = $null
    }
    $trialEntries.Add($entry)
    Save-Manifest
    Write-Output "Starting $trialId of $Repetitions"
    try {
        & $ControllerPath `
            -OutputDirectory $trialDirectory `
            -CampaignId "$CampaignId-$trialId" `
            -CsgApiBase $CsgApiBase `
            -HostId $HostId `
            -RunnerPath $PositiveRunnerPath `
            -WaitSeconds $WaitSeconds `
            -EventTimeToleranceSeconds $EventTimeToleranceSeconds 2>&1 |
            Tee-Object -FilePath (Join-Path $OutputDirectory "$trialId-controller.stdout.txt")
        $trialPath = Join-Path $trialDirectory 'trial.json'
        if (-not (Test-Path -LiteralPath $trialPath -PathType Leaf)) { throw 'Controller did not produce trial.json.' }
        $result = Get-Content -LiteralPath $trialPath -Raw | ConvertFrom-Json
        $entry.result_status = [string]$result.status
        $entry.target_task_name = $result.target_task_name
        $entry.distractor_task_name = $result.distractor_task_name
        $entry.target_event_id = @($result.target_reconciliation.exact_target_event_ids)
        $entry.distractor_event_id = $result.target_reconciliation.distractor_availability_ordering.distractor_event_id
        $entry.target_reconciliation = $result.target_reconciliation.status
        $entry.cleanup_verified = [bool]$result.cleanup_verified
        $entry.status = if ($result.status -eq 'PASS' -and $result.cleanup_verified) { 'PASS' } else { 'FAIL' }
        if ($entry.status -ne 'PASS') { $entry.failure = [string]$result.error }
    } catch {
        $entry.status = 'INVALID'
        $entry.failure = $_.Exception.Message
    }
    $entry.ended_at_utc = [DateTime]::UtcNow.ToString('o')
    Save-Manifest

    $afterTrial = Get-LabState -Phase "$trialId-postflight"
    if ($afterTrial.wazuh_service.state -ne 'Running' -or -not $afterTrial.endpoint_agent -or $afterTrial.endpoint_agent.status -ne 'active' -or $afterTrial.residual_study_tasks.Count -gt 0) {
        $manifest.status = 'ABORTED_UNSAFE_POSTFLIGHT'
        $manifest.postflight = $afterTrial
        Save-Manifest
        throw "Safety abort after $($trialId): endpoint collection did not restore cleanly."
    }
    Write-Output "$trialId recorded as $($entry.status); cleanup and endpoint health verified."
}

$manifest.postflight = Get-LabState -Phase 'campaign-postflight'
$manifest.completed_at_utc = [DateTime]::UtcNow.ToString('o')
$passed = @($manifest.trials | Where-Object { $_.status -eq 'PASS' }).Count
$manifest.status = if ($passed -eq $Repetitions) { 'ALL_TRIALS_PASS' } else { 'COMPLETED_WITH_FAILURES' }
Save-Manifest
Write-Output "Campaign $($manifest.status): $passed/$Repetitions trials passed."
