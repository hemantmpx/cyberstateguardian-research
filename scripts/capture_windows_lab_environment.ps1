param(
    [string]$OutputPath = "C:\CSG\research-lab-environment.json",
    [string]$CsgApiBase = "http://192.168.64.1:8000",
    [string]$HostId = "win11-arm-lab",
    [string]$ProbeRoot = "C:\CSG\probe",
    [string]$RunnerPath = "C:\CSG\run_windows_category_positive_controls.ps1",
    [string]$TelemetryConfigPath = "C:\CSG\configure_windows_research_telemetry.ps1"
)

$ErrorActionPreference = "Stop"
$agentConfig = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$sysmonConfig = "C:\CSG\sysmon-csg-lab.xml"
$health = Invoke-RestMethod -Method Get -DisableKeepAlive -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
$agent = @($health.server_api.agents | Where-Object { $_.name -eq $HostId } | Select-Object -First 1)
$os = Get-CimInstance Win32_OperatingSystem
$computer = Get-CimInstance Win32_ComputerSystem
$wazuhService = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
$sysmonService = Get-CimInstance Win32_Service | Where-Object { $_.Name -match '^Sysmon(64a|64)?$' } |
    Select-Object -First 1
$sysmonMatch = [regex]::Match([string]$sysmonService.PathName, '^\s*"([^"]+)"')
$sysmonExecutable = if ($sysmonMatch.Success) {
    $sysmonMatch.Groups[1].Value
} else {
    ([string]$sysmonService.PathName -split '\s+', 2)[0].Trim('"')
}
$agentDocument = [xml](Get-Content -LiteralPath $agentConfig -Raw)
$eventChannels = @($agentDocument.SelectNodes('/ossec_config/localfile/location') | ForEach-Object {
    $_.InnerText
})
$observation = $null
try {
    $observation = Invoke-RestMethod -Method Get -DisableKeepAlive -Uri (
        "$($CsgApiBase.TrimEnd('/'))/api/hosts/$HostId/observations/latest"
    )
} catch { }

$scriptHashes = [ordered]@{}
foreach ($entry in @(
    @{ name = 'windows_category_runner'; path = $RunnerPath },
    @{ name = 'windows_telemetry_configurator'; path = $TelemetryConfigPath },
    @{ name = 'probe_registry_collector'; path = (Join-Path $ProbeRoot 'cyberstateguardian_probe/collectors/registry.py') }
)) {
    if (Test-Path -LiteralPath $entry.path) {
        $scriptHashes[$entry.name] = (Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash
    }
}

$output = [ordered]@{
    captured_at = (Get-Date).ToUniversalTime().ToString('o')
    host_id = $HostId
    computer_name = $env:COMPUTERNAME
    windows_version = $os.Version
    windows_build = $os.BuildNumber
    windows_os_caption = $os.Caption
    windows_architecture = $computer.SystemType
    windows_processor_architecture = $env:PROCESSOR_ARCHITECTURE
    wazuh_agent_version = if ($agent.Count) { $agent[0].version } else { $null }
    wazuh_server_version = $health.server_api.version
    wazuh_indexer_version = $health.indexer.version
    sysmon_version = (Get-Item -LiteralPath $sysmonExecutable).VersionInfo.ProductVersion
    sysmon_config_sha256 = (Get-FileHash -LiteralPath $sysmonConfig -Algorithm SHA256).Hash
    wazuh_agent_config_sha256 = (Get-FileHash -LiteralPath $agentConfig -Algorithm SHA256).Hash
    config_sha256 = [ordered]@{
        sysmon_value = (Get-FileHash -LiteralPath $sysmonConfig -Algorithm SHA256).Hash
        wazuh_agent_value = (Get-FileHash -LiteralPath $agentConfig -Algorithm SHA256).Hash
    }
    experiment_script_sha256 = $scriptHashes
    windows_runner_sha256 = @{ run_windows_category_positive_controls = $scriptHashes.windows_category_runner }
    event_channels = $eventChannels
    wazuh_service = [ordered]@{ state = $wazuhService.State; process_id = [int]$wazuhService.ProcessId }
    sysmon_service = [ordered]@{ state = $sysmonService.State; process_id = [int]$sysmonService.ProcessId }
    endpoint_agent_status = if ($agent.Count) { $agent[0].status } else { 'NOT_REPORTED' }
    csg_wazuh_status = $health
    latest_probe_observation = if ($observation) {
        [ordered]@{
            observation_id = $observation.observation_id
            observed_at = $observation.observed_at
            scheduled_task_status = $observation.categories.scheduled_task.status
            scheduled_task_count = @($observation.categories.scheduled_task.items).Count
            registry_status = $observation.categories.registry.status
            registry_count = @($observation.categories.registry.items).Count
        }
    } else { $null }
}
$parent = Split-Path -Parent $OutputPath
if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$output | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
$output | ConvertTo-Json -Depth 8
