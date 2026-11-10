param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ProtocolSha256,
    [string]$CsgApiBase = 'http://192.168.64.1:8000',
    [string]$HostId = 'win11-arm-lab',
    [string]$OutputDirectory = 'C:\CSG\research-campaign-20261010-clean-suppression-followup-v2'
)

$ErrorActionPreference = 'Stop'
$drillPath = 'C:\CSG\run_service_drift_drill_windows-pilot-20261010-v2.ps1'
$controllerPath = 'C:\CSG\run_live_telemetry_campaign_windows.ps1'
$expectedDrillSha256 = 'bd8401455cf4b81ca16f65f99003a0270ae95436960406fd85f85de16fb8ace8'
$expectedControllerSha256 = 'd6203cc79975ae7b7adfc0aa52be8256cd1e6799ccbfada45a6b9fb5a8cfa596'
$agentConfigPath = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$beforePath = 'C:\CSG\research-clean-suppression-followup-v2-environment-before.json'
$afterPath = 'C:\CSG\research-clean-suppression-followup-v2-environment-after.json'

foreach ($file in @($drillPath, $controllerPath)) {
    if (-not (Test-Path -LiteralPath $file)) { throw "Required frozen script is missing: $file" }
    [void][scriptblock]::Create((Get-Content -LiteralPath $file -Raw))
}
$actualDrillSha256 = (Get-FileHash -LiteralPath $drillPath -Algorithm SHA256).Hash.ToLowerInvariant()
$actualControllerSha256 = (Get-FileHash -LiteralPath $controllerPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualDrillSha256 -ne $expectedDrillSha256) { throw "Drill hash mismatch: $actualDrillSha256" }
if ($actualControllerSha256 -ne $expectedControllerSha256) { throw "Controller hash mismatch: $actualControllerSha256" }

function Get-LabSnapshot {
    param([string]$Phase)
    $health = Invoke-RestMethod -TimeoutSec 15 -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
    $agent = @($health.agents | Where-Object { $_.name -eq $HostId } | Select-Object -First 1)
    $wazuh = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
    $task = Get-ScheduledTask -TaskName 'CyberStateGuardian Probe'
    [ordered]@{
        phase = $Phase
        captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        computer_name = $env:COMPUTERNAME
        windows_version = (Get-CimInstance Win32_OperatingSystem).Version
        windows_build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        processor_architecture = $env:PROCESSOR_ARCHITECTURE
        csg_api_healthy = [bool]$health.ok
        csg_state_provider = $health.sync.state_provider
        csg_event_provider = $health.sync.event_provider
        wazuh_endpoint_agent = if ($agent.Count) { $agent[0] } else { $null }
        wazuh_service = [ordered]@{ state = $wazuh.State; pid = [int]$wazuh.ProcessId }
        wazuh_agent_config_sha256 = (Get-FileHash -LiteralPath $agentConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
        probe_task = [ordered]@{ state = [string]$task.State; enabled = [bool]$task.Settings.Enabled }
        probe_task_last_run = (Get-ScheduledTaskInfo -TaskName 'CyberStateGuardian Probe' | Select-Object LastRunTime, LastTaskResult, NextRunTime)
        runtime_lookback_seconds = [int]$health.sync.lookback_seconds
        protocol_sha256 = $ProtocolSha256.ToLowerInvariant()
        drill_sha256 = $actualDrillSha256
        controller_sha256 = $actualControllerSha256
        residual_test_services = @(Get-CimInstance Win32_Service | Where-Object {
            $_.Name -like 'CSGResearch*' -or $_.Name -like 'CSGDistractor*'
        } | Select-Object Name, State, StartMode, PathName)
    }
}

$before = Get-LabSnapshot -Phase 'before'
if (-not $before.csg_api_healthy -or -not $before.wazuh_endpoint_agent -or $before.wazuh_endpoint_agent.status -ne 'active') {
    throw 'Preflight failed: CSG/Wazuh health or the target endpoint agent is not active.'
}
if ($before.runtime_lookback_seconds -ne 86400) { throw 'Preflight failed: configured event lookback differs from frozen protocol.' }
if ($before.wazuh_service.state -ne 'Running') { throw 'Preflight failed: WazuhSvc is not Running.' }
if (@($before.residual_test_services).Count -gt 0) { throw 'Preflight failed: pre-existing CSG research services would contaminate the trial.' }
$before | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $beforePath -Encoding UTF8

$controllerExitCode = $null
try {
    & $controllerPath `
        -DrillPath $drillPath `
        -CsgApiBase $CsgApiBase `
        -HostId $HostId `
        -Repetitions 3 `
        -TelemetryWaitSeconds 20 `
        -ProbeObservationTimeoutSeconds 30 `
        -ProbePollIntervalSeconds 1 `
        -LifecycleFinalizationWaitSeconds 75 `
        -CaptureDropFinalizationWaitSeconds 960 `
        -RecoveryWaitSeconds 120 `
        -ApiTimeoutSeconds 15 `
        -EventTimeToleranceSeconds 5 `
        -EventLookbackSeconds 86400 `
        -ProtocolSha256 $ProtocolSha256 `
        -OutputDirectory $OutputDirectory `
        -RandomSeed 530 `
        -ExperimentId 'csg-win-clean-suppression-followup-20261010-v2' `
        -ExecutionKind 'engineering_pilot_not_pooled' `
        -Conditions @('target_selective_drop_clean')
    $controllerExitCode = $LASTEXITCODE
}
finally {
    try {
        $after = Get-LabSnapshot -Phase 'after'
        $after.restoration_checks = [ordered]@{
            agent_config_hash_restored = ($after.wazuh_agent_config_sha256 -eq $before.wazuh_agent_config_sha256)
            wazuh_service_running = ($after.wazuh_service.state -eq 'Running')
            endpoint_agent_active = [bool]($after.wazuh_endpoint_agent -and $after.wazuh_endpoint_agent.status -eq 'active')
            probe_task_state_restored = ($after.probe_task.state -eq $before.probe_task.state)
            probe_task_enabled_restored = ($after.probe_task.enabled -eq $before.probe_task.enabled)
            no_residual_test_services = (@($after.residual_test_services).Count -eq 0)
        }
        $after | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $afterPath -Encoding UTF8
        Write-Output "ENVIRONMENT_AFTER $($after | ConvertTo-Json -Depth 8 -Compress)"
    }
    catch {
        Write-Warning "Could not capture complete postflight snapshot: $($_.Exception.Message)"
    }
}

if ($controllerExitCode -and $controllerExitCode -ne 0) { exit $controllerExitCode }
