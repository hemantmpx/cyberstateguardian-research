param(
    [string]$OutputPath = "C:\CSG\wazuh-source-coverage.json",
    [string]$HostId = "win11-arm-lab",
    [string]$AgentConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $AgentConfigPath)) {
    throw "Wazuh agent configuration not found: $AgentConfigPath"
}

$document = [xml](Get-Content -LiteralPath $AgentConfigPath -Raw)
$syscheck = $document.SelectSingleNode("/ossec_config/syscheck")
$os = Get-CimInstance Win32_OperatingSystem
$eventChannels = @($document.SelectNodes("/ossec_config/localfile") | Where-Object {
    $format = $_.SelectSingleNode("log_format")
    $format -and $format.InnerText -eq "eventchannel"
} | ForEach-Object {
    $location = $_.SelectSingleNode("location")
    $query = $_.SelectSingleNode("query")
    [ordered]@{
        channel = if ($location) { $location.InnerText } else { $null }
        query = if ($query) { ($query.InnerText -replace "\s+", " ").Trim() } else { $null }
    }
})
$registryPaths = @($document.SelectNodes("/ossec_config/syscheck/windows_registry") | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_.InnerText)
} | ForEach-Object {
    [ordered]@{
        path = $_.InnerText.Trim()
        architecture = if ($_.HasAttribute("arch")) { $_.GetAttribute("arch") } else { $null }
    }
})
$directoryPaths = @($document.SelectNodes("/ossec_config/syscheck/directories") | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_.InnerText)
} | ForEach-Object {
    $attributes = [ordered]@{}
    foreach ($attribute in $_.Attributes) { $attributes[$attribute.Name] = $attribute.Value }
    [ordered]@{ path = $_.InnerText.Trim(); attributes = $attributes }
})

$serviceRows = @(Get-CimInstance Win32_Service | Where-Object {
    $_.Name -match "^(WazuhSvc|Sysmon64a?|Sysmon)$"
} | ForEach-Object {
    [ordered]@{ name = $_.Name; state = $_.State; process_id = [int]$_.ProcessId }
})
$logNames = @(
    "Application",
    "Security",
    "System",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-TaskScheduler/Operational"
)
$windowsLogs = @($logNames | ForEach-Object {
    $log = Get-WinEvent -ListLog $_ -ErrorAction SilentlyContinue
    if ($log) {
        [ordered]@{ name = $log.LogName; enabled = [bool]$log.IsEnabled; record_count = $log.RecordCount }
    } else {
        [ordered]@{ name = $_; enabled = $false; record_count = $null }
    }
})

$registryPathText = @($registryPaths | ForEach-Object { $_.path })
$directoryPathText = @($directoryPaths | ForEach-Object { $_.path })
$channelNames = @($eventChannels | ForEach-Object { $_.channel })
$output = [ordered]@{
    schema_version = 2
    captured_at_utc = [DateTime]::UtcNow.ToString("o")
    logical_host_id = $HostId
    windows = [ordered]@{
        caption = $os.Caption
        version = $os.Version
        build = $os.BuildNumber
    }
    configuration = [ordered]@{
        assertion_scope = "On-disk agent configuration; loaded in-memory filters are not independently introspected."
        agent_config_path = $AgentConfigPath
        agent_config_sha256 = (Get-FileHash -LiteralPath $AgentConfigPath -Algorithm SHA256).Hash
        event_channels = $eventChannels
        subscribes_to_task_scheduler_operational = [bool]($channelNames -contains "Microsoft-Windows-TaskScheduler/Operational")
    }
    services = $serviceRows
    windows_event_logs = $windowsLogs
    fim = [ordered]@{
        disabled = if ($syscheck) { [string]$syscheck.SelectSingleNode("disabled").InnerText } else { $null }
        scan_frequency_seconds = if ($syscheck) { [int]$syscheck.SelectSingleNode("frequency").InnerText } else { $null }
        windows_audit_interval_seconds = if ($syscheck) { [int]$syscheck.SelectSingleNode("windows_audit_interval").InnerText } else { $null }
        windows_audit_interval_semantics = "Checks local audit policies and SACLs; it is not the periodic FIM scan interval."
        directory_paths = $directoryPaths
        registry_paths = $registryPaths
        explicitly_monitors_windows_tasks_directory = [bool]($directoryPathText -match "(^|[\\/])System32[\\/]Tasks[\\/]?$")
        monitors_services_registry_branch = [bool]($registryPathText -match "^HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services$")
        monitors_hklm_currentversion_run = [bool]($registryPathText -match "^HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run$")
        monitors_hklm_currentversion_runonce = [bool]($registryPathText -match "^HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce$")
        monitors_per_user_run = [bool]($registryPathText -match "^HKEY_USERS\\.*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run$")
    }
    limitations = @(
        "A running agent service does not prove a particular on-disk configuration was loaded without restart/runtime confirmation.",
        "A missing event at one query cutoff is not proof of permanent event loss.",
        "Alert-index absence and archive-index absence are separate checks."
    )
}

$json = $output | ConvertTo-Json -Depth 12
$parent = Split-Path -Parent $OutputPath
if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
Set-Content -LiteralPath $OutputPath -Value $json -Encoding UTF8
$json
