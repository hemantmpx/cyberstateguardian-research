param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedAgentConfigSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedRunnerSha256,
    [string]$CsgApiBase = "http://192.168.64.1:8000",
    [string]$HostId = "win11-arm-lab",
    [ValidateScript({ $_ -eq "" -or $_ -match '^CSGAPTTask[a-fA-F0-9]{10}$' })]
    [string]$TargetTaskName = "",
    [string]$RunnerPath = "C:\CSG\run_windows_category_positive_controls_v3.ps1",
    [string]$ProbePython = "C:\Program Files\CyberStateGuardian\Probe\venv\Scripts\python.exe",
    [string]$ProbeConfig = "C:\Program Files\CyberStateGuardian\Probe\settings.json",
    [string]$AgentConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf",
    [string]$OutputPath = "C:\CSG\scheduled-task-positive-preflight.json"
)

$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Preflight requires an elevated Administrator PowerShell session." }
foreach ($path in @($RunnerPath, $ProbePython, $ProbeConfig, $AgentConfigPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file missing: $path" }
}

$agentHash = (Get-FileHash -LiteralPath $AgentConfigPath -Algorithm SHA256).Hash.ToUpperInvariant()
$runnerHash = (Get-FileHash -LiteralPath $RunnerPath -Algorithm SHA256).Hash.ToUpperInvariant()
if ($agentHash -ne $ExpectedAgentConfigSha256.ToUpperInvariant()) { throw "Agent configuration hash drift: $agentHash" }
if ($runnerHash -ne $ExpectedRunnerSha256.ToUpperInvariant()) { throw "Runner hash mismatch: $runnerHash" }

$config = [xml](Get-Content -LiteralPath $AgentConfigPath -Raw)
$securityLocalFile = @($config.SelectNodes("/ossec_config/localfile") | Where-Object {
    $location = $_.SelectSingleNode("location")
    $format = $_.SelectSingleNode("log_format")
    $location -and $format -and $location.InnerText -eq "Security" -and $format.InnerText -eq "eventchannel"
})
if ($securityLocalFile.Count -ne 1) { throw "Expected exactly one Security eventchannel subscription." }
$securityQuery = $securityLocalFile[0].SelectSingleNode("query")
if (-not $securityQuery -or $securityQuery.InnerText -match 'EventID\s*!=\s*4698') {
    throw "Security Event ID 4698 is not eligible under the frozen endpoint filter."
}

$health = Invoke-RestMethod -Method Get -TimeoutSec 15 -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
$agent = @($health.server_api.agents | Where-Object { $_.name -eq $HostId } | Select-Object -First 1)
$services = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -in @("WazuhSvc", "Sysmon64a", "Sysmon64") })
$serviceStates = @{}
foreach ($service in $services) { $serviceStates[$service.Name] = $service.State }
$securityLog = Get-WinEvent -ListLog "Security" -ErrorAction Stop
$taskLog = Get-WinEvent -ListLog "Microsoft-Windows-TaskScheduler/Operational" -ErrorAction SilentlyContinue
$residualTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "CSGAPT*" })
$probeTask = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction SilentlyContinue
$targetTask = if ($TargetTaskName) {
    Get-ScheduledTask -TaskName $TargetTaskName -ErrorAction SilentlyContinue
} else { $null }
$operatingSystem = Get-CimInstance Win32_OperatingSystem
$wazuhService = $services | Where-Object { $_.Name -eq "WazuhSvc" } | Select-Object -First 1

$result = [ordered]@{
    captured_at_utc = [DateTime]::UtcNow.ToString("o")
    host_id = $HostId
    administrator = $isAdmin
    windows_build = $operatingSystem.BuildNumber
    architecture = $env:PROCESSOR_ARCHITECTURE
    agent_config_sha256 = $agentHash
    runner_sha256 = $runnerHash
    security_4698_included_by_filter = $true
    security_log_enabled = [bool]$securityLog.IsEnabled
    task_scheduler_operational_log_enabled = if ($taskLog) { [bool]$taskLog.IsEnabled } else { $false }
    services = $serviceStates
    csg_api_healthy = [bool]$health.ok
    wazuh_server_api_healthy = [bool]$health.server_api.ok
    wazuh_indexer_healthy = [bool]$health.indexer.ok
    endpoint_agent_status = if ($agent.Count) { $agent[0].status } else { "NOT_FOUND" }
    wazuh_service_state = if ($wazuhService) { $wazuhService.State } else { "NOT_FOUND" }
    wazuh_service_pid = if ($wazuhService) { [int]$wazuhService.ProcessId } else { 0 }
    probe_task_state = if ($probeTask) { [string]$probeTask.State } else { "MISSING" }
    probe_task_enabled = if ($probeTask) { [bool]$probeTask.Settings.Enabled } else { $false }
    target_task_name = $TargetTaskName
    target_absent = (-not $TargetTaskName -or $null -eq $targetTask)
    residual_csgapt_tasks = @($residualTasks | ForEach-Object { $_.TaskName })
    probe_python_path = $ProbePython
    probe_config_path = $ProbeConfig
    output_path = $OutputPath
}

if (-not $health.ok -or -not $health.server_api.ok -or -not $health.indexer.ok) { throw "CSG or Wazuh health preflight failed." }
if (-not $agent.Count -or $agent[0].status -ne "active") { throw "Wazuh endpoint agent is not active." }
if (-not $securityLog.IsEnabled) { throw "Windows Security event log is disabled." }
if ($serviceStates.WazuhSvc -ne "Running") { throw "WazuhSvc is not running." }
if (-not $serviceStates.ContainsKey("Sysmon64a") -and -not $serviceStates.ContainsKey("Sysmon64")) { throw "Sysmon service not found." }
if ($serviceStates.Sysmon64a -ne "Running" -and $serviceStates.Sysmon64 -ne "Running") { throw "Sysmon service is not running." }
if (-not $probeTask -or $probeTask.State -ne "Ready" -or -not $probeTask.Settings.Enabled) {
    throw "The CSG probe scheduled task is not enabled and Ready."
}
if ($TargetTaskName -and $targetTask) { throw "The assigned target scheduled task already exists." }
if ($residualTasks.Count -gt 0) { throw "Residual CSGAPT objects would contaminate the trial." }

$json = $result | ConvertTo-Json -Depth 8
$parent = Split-Path -Parent $OutputPath
if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
Set-Content -LiteralPath $OutputPath -Value $json -Encoding UTF8
$json
