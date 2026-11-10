param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ProtocolSha256,
    [switch]$CaptureOnly,
    [string]$CsgApiBase = 'http://192.168.64.1:8000',
    [string]$HostId = 'win11-arm-lab',
    [string]$OutputDirectory = 'C:\CSG\research-campaign-20261010-service-complete-positive-v1'
)

$ErrorActionPreference = 'Stop'
$drillPath = 'C:\CSG\run_service_drift_drill_windows-pilot-20261010-v2.ps1'
$controllerPath = 'C:\CSG\run_live_telemetry_campaign_windows.ps1'
$expectedDrillSha256 = 'bd8401455cf4b81ca16f65f99003a0270ae95436960406fd85f85de16fb8ace8'
$expectedControllerSha256 = 'd6203cc79975ae7b7adfc0aa52be8256cd1e6799ccbfada45a6b9fb5a8cfa596'
$agentConfigPath = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$beforePath = Join-Path $OutputDirectory 'environment-before.json'
$executionBeforePath = Join-Path $OutputDirectory 'environment-at-execution.json'
$afterPath = Join-Path $OutputDirectory 'environment-after.json'

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
    $managerAgent = @($health.server_api.agents | Where-Object { $_.manager } | Select-Object -First 1)
    $wazuh = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
    $task = Get-ScheduledTask -TaskName 'CyberStateGuardian Probe'
    $os = Get-CimInstance Win32_OperatingSystem
    $sysmon = Get-CimInstance Win32_Service | Where-Object { $_.Name -match '^Sysmon(64a|64)?$' } |
        Select-Object -First 1
    $sysmonExecutableMatch = [regex]::Match([string]$sysmon.PathName, '^\s*"([^"]+)"')
    $sysmonExecutable = if ($sysmonExecutableMatch.Success) {
        $sysmonExecutableMatch.Groups[1].Value
    } else {
        ([string]$sysmon.PathName -split '\s+', 2)[0].Trim('"')
    }
    $probeSettingsMatch = [regex]::Match([string]$task.Actions[0].Arguments, '--config\s+"([^"]+)"')
    $probeSettingsPath = if ($probeSettingsMatch.Success) { $probeSettingsMatch.Groups[1].Value } else { $null }
    $sysmonConfig = 'C:\CSG\sysmon-csg-lab.xml'
    $probeObservation = $null
    try {
        $probeObservation = Invoke-RestMethod -TimeoutSec 15 -Uri (
            "$($CsgApiBase.TrimEnd('/'))/api/hosts/$HostId/observations/latest"
        )
    } catch { }
    [ordered]@{
        captured_at = (Get-Date).ToUniversalTime().ToString('o')
        captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        phase = $Phase
        host_id = $HostId
        computer_name = $env:COMPUTERNAME
        windows_os_caption = $os.Caption
        windows_version = $os.Version
        windows_build = $os.BuildNumber
        windows_architecture = $env:PROCESSOR_ARCHITECTURE
        csg_wazuh_status = $health
        state_provider = $health.state_provider
        event_provider = $health.event_provider
        event_lookback_seconds = [int]$health.sync.lookback_seconds
        endpoint_agent = if ($agent.Count) { $agent[0] } else { $null }
        wazuh_agent_version = if ($agent.Count) { $agent[0].version } else { $null }
        wazuh_server_version = if ($managerAgent.Count) { $managerAgent[0].version } else { $null }
        wazuh_indexer_version = $health.indexer.version
        wazuh_service = [ordered]@{ state = $wazuh.State; pid = [int]$wazuh.ProcessId }
        wazuh_agent_config_sha256 = (Get-FileHash -LiteralPath $agentConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
        config_sha256 = [ordered]@{
            sysmon_value = if (Test-Path -LiteralPath $sysmonConfig) {
                (Get-FileHash -LiteralPath $sysmonConfig -Algorithm SHA256).Hash.ToLowerInvariant()
            } else { $null }
            wazuh_agent_value = (Get-FileHash -LiteralPath $agentConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        sysmon_service = if ($sysmon) { [ordered]@{ name = $sysmon.Name; state = $sysmon.State; path = $sysmon.PathName } } else { $null }
        sysmon_version = if (Test-Path -LiteralPath $sysmonExecutable) {
            (Get-Item -LiteralPath $sysmonExecutable).VersionInfo.ProductVersion
        } else { $null }
        sysmon_config_sha256 = if (Test-Path -LiteralPath $sysmonConfig) {
            (Get-FileHash -LiteralPath $sysmonConfig -Algorithm SHA256).Hash.ToLowerInvariant()
        } else { $null }
        probe_settings_path = $probeSettingsPath
        probe_settings_sha256 = if ($probeSettingsPath -and (Test-Path -LiteralPath $probeSettingsPath)) {
            (Get-FileHash -LiteralPath $probeSettingsPath -Algorithm SHA256).Hash.ToLowerInvariant()
        } else { $null }
        probe_task = [ordered]@{
            state = [string]$task.State
            enabled = [bool]$task.Settings.Enabled
            actions = @($task.Actions | ForEach-Object { [ordered]@{ execute = $_.Execute; arguments = $_.Arguments } })
        }
        probe_task_last_run = (Get-ScheduledTaskInfo -TaskName 'CyberStateGuardian Probe' |
            Select-Object LastRunTime, LastTaskResult, NextRunTime)
        latest_probe_observation = if ($probeObservation) {
            [ordered]@{
                observation_id = $probeObservation.observation_id
                observed_at = $probeObservation.observed_at
                service_status = $probeObservation.categories.service.status
                service_count = @($probeObservation.categories.service.items).Count
            }
        } else { $null }
        drill_sha256 = $actualDrillSha256
        controller_sha256 = $actualControllerSha256
        wrapper_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
        experiment_script_sha256 = [ordered]@{
            service_drift_drill = $actualDrillSha256
            campaign_controller = $actualControllerSha256
            service_complete_pilot_wrapper = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        protocol_sha256 = $ProtocolSha256.ToLowerInvariant()
        residual_test_services = @(Get-CimInstance Win32_Service | Where-Object {
            $_.Name -like 'CSGResearch*' -or $_.Name -like 'CSGDistractor*'
        } | Select-Object Name, State, StartMode, PathName)
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$before = Get-LabSnapshot -Phase 'before'
if (-not $before.csg_wazuh_status.ok -or -not $before.endpoint_agent -or $before.endpoint_agent.status -ne 'active') {
    throw 'Preflight failed: CSG/Wazuh health or the endpoint agent is not active.'
}
if ($before.state_provider -ne 'probe' -or $before.event_provider -ne 'wazuh') {
    throw 'Preflight failed: expected state_provider=probe and event_provider=wazuh.'
}
if ($before.event_lookback_seconds -ne 86400) { throw 'Preflight failed: event lookback differs from protocol.' }
if ($before.wazuh_service.state -ne 'Running') { throw 'Preflight failed: WazuhSvc is not Running.' }
if (@($before.residual_test_services).Count -gt 0) { throw 'Preflight failed: existing CSG test services would contaminate the run.' }
if ($CaptureOnly) {
    $before | ConvertTo-Json -Depth 18 | Set-Content -LiteralPath $beforePath -Encoding UTF8
    Write-Output "CAPTURE_ONLY_OK $beforePath"
    return
}
if (-not (Test-Path -LiteralPath $beforePath)) {
    throw 'Frozen environment-before.json is missing. Capture it and create source-freeze.json before execution.'
}
$frozenBefore = Get-Content -LiteralPath $beforePath -Raw | ConvertFrom-Json
if ($frozenBefore.protocol_sha256 -ne $ProtocolSha256.ToLowerInvariant()) {
    throw 'Frozen environment snapshot protocol hash differs from the requested campaign.'
}
foreach ($field in @(
    'host_id', 'windows_build', 'windows_architecture', 'state_provider', 'event_provider',
    'event_lookback_seconds', 'wazuh_agent_version', 'wazuh_server_version',
    'wazuh_indexer_version', 'sysmon_version', 'sysmon_config_sha256',
    'wazuh_agent_config_sha256', 'probe_settings_sha256', 'drill_sha256',
    'controller_sha256', 'wrapper_sha256'
)) {
    if ([string]$before.$field -ne [string]$frozenBefore.$field) {
        throw "Execution environment differs from frozen preflight field '$field'."
    }
}
$before | ConvertTo-Json -Depth 18 | Set-Content -LiteralPath $executionBeforePath -Encoding UTF8

$controllerExitCode = 0
try {
    & $controllerPath `
        -DrillPath $drillPath `
        -CsgApiBase $CsgApiBase `
        -HostId $HostId `
        -Repetitions 5 `
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
        -RandomSeed 8831 `
        -ExperimentId 'csg-win-service-complete-positive-20261010-v1' `
        -ExecutionKind 'engineering_pilot_not_pooled' `
        -Conditions @('complete')
}
finally {
    try {
        $after = Get-LabSnapshot -Phase 'after'
        $after.restoration_checks = [ordered]@{
            wazuh_agent_config_hash_unchanged = ($after.wazuh_agent_config_sha256 -eq $before.wazuh_agent_config_sha256)
            wazuh_service_running = ($after.wazuh_service.state -eq 'Running')
            endpoint_agent_active = [bool]($after.endpoint_agent -and $after.endpoint_agent.status -eq 'active')
            probe_task_state_unchanged = ($after.probe_task.state -eq $before.probe_task.state)
            probe_task_enabled_unchanged = ($after.probe_task.enabled -eq $before.probe_task.enabled)
            no_residual_test_services = (@($after.residual_test_services).Count -eq 0)
        }
        $after | ConvertTo-Json -Depth 18 | Set-Content -LiteralPath $afterPath -Encoding UTF8
    } catch {
        Write-Warning "Postflight capture failed: $($_.Exception.Message)"
    }
}
if ($controllerExitCode -ne 0) { exit $controllerExitCode }
