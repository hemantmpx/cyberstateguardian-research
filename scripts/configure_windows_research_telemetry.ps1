param(
    [ValidateSet("Apply", "Restore")]
    [string]$Mode = "Apply",
    [string]$SysmonConfigPath = "C:\CSG\sysmon-csg-lab.xml",
    [string]$CandidateSysmonConfigPath = "C:\CSG\sysmon-csg-lab.candidate.xml",
    [string]$WazuhConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf",
    [string]$OutputDirectory = "C:\CSG\instrumentation",
    [string]$RestoreRecordPath = "",
    [string]$CsgApiBase = "http://192.168.64.1:8000",
    [string]$HostId = "win11-arm-lab"
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this telemetry configuration from Administrator PowerShell."
    }
}

function Get-SysmonExecutable {
    $service = Get-CimInstance Win32_Service | Where-Object { $_.Name -match '^Sysmon(64a|64)?$' } |
        Select-Object -First 1
    if (-not $service) { throw "A Sysmon service was not found; install Sysmon before applying this profile." }
    $match = [regex]::Match([string]$service.PathName, '^\s*"([^"]+)"')
    if ($match.Success) { return $match.Groups[1].Value }
    return ([string]$service.PathName -split '\s+', 2)[0]
}

function Set-EventChannel {
    param([xml]$Document, [string]$Channel)
    $exists = @($Document.SelectNodes('/ossec_config/localfile/location') | Where-Object {
        $_.InnerText -eq $Channel
    }).Count -gt 0
    if ($exists) { return $false }
    $localFile = $Document.CreateElement('localfile')
    $location = $Document.CreateElement('location')
    $location.InnerText = $Channel
    $format = $Document.CreateElement('log_format')
    $format.InnerText = 'eventchannel'
    [void]$localFile.AppendChild($location)
    [void]$localFile.AppendChild($format)
    [void]$Document.DocumentElement.AppendChild($localFile)
    return $true
}

Assert-Administrator
$sysmonExe = Get-SysmonExecutable

if ($Mode -eq "Restore") {
    if (-not $RestoreRecordPath -or -not (Test-Path -LiteralPath $RestoreRecordPath)) {
        throw "Restore mode requires an existing -RestoreRecordPath."
    }
    $record = Get-Content -Raw -LiteralPath $RestoreRecordPath | ConvertFrom-Json
    Copy-Item -LiteralPath $record.backups.wazuh_config -Destination $record.paths.wazuh_config -Force
    Copy-Item -LiteralPath $record.backups.sysmon_config -Destination $record.paths.sysmon_config -Force
    & $sysmonExe -c $record.backups.sysmon_config
    if ($LASTEXITCODE -ne 0) { throw "Sysmon rejected the restored configuration (exit $LASTEXITCODE)." }
    $auditSwitch = if ($record.audit_policy.success_was_enabled) { "enable" } else { "disable" }
    & auditpol.exe /set /subcategory:'Other Object Access Events' "/success:$auditSwitch" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not restore the original successful audit policy state." }
    Restart-Service -Name WazuhSvc -Force
    $restore = [ordered]@{
        restored_at = (Get-Date).ToUniversalTime().ToString('o')
        source_record = (Resolve-Path -LiteralPath $RestoreRecordPath).Path
        wazuh_config_sha256 = (Get-FileHash -LiteralPath $record.paths.wazuh_config -Algorithm SHA256).Hash
        sysmon_config_sha256 = (Get-FileHash -LiteralPath $record.paths.sysmon_config -Algorithm SHA256).Hash
        audit_success_enabled = [bool]$record.audit_policy.success_was_enabled
        wazuh_service_status = [string](Get-Service WazuhSvc).Status
    }
    $restorePath = Join-Path (Split-Path -Parent $RestoreRecordPath) 'restore-verification.json'
    $restore | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $restorePath -Encoding UTF8
    $restore | ConvertTo-Json -Depth 8
    exit 0
}

if (-not (Test-Path -LiteralPath $CandidateSysmonConfigPath -PathType Leaf)) {
    throw "Candidate Sysmon configuration not found: $CandidateSysmonConfigPath"
}
if (-not (Test-Path -LiteralPath $WazuhConfigPath -PathType Leaf)) {
    throw "Wazuh agent configuration not found: $WazuhConfigPath"
}
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$runDirectory = Join-Path $OutputDirectory $runId
New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop | Out-Null
$wazuhBackup = Join-Path $runDirectory 'ossec.conf.before.xml'
$sysmonBackup = Join-Path $runDirectory 'sysmon-config.before.xml'
Copy-Item -LiteralPath $WazuhConfigPath -Destination $wazuhBackup
Copy-Item -LiteralPath $SysmonConfigPath -Destination $sysmonBackup
$candidateHash = (Get-FileHash -LiteralPath $CandidateSysmonConfigPath -Algorithm SHA256).Hash
$activeConfigHashBefore = (Get-FileHash -LiteralPath $sysmonBackup -Algorithm SHA256).Hash

$auditBefore = (& auditpol.exe /get /subcategory:'Other Object Access Events' /r 2>&1 | Out-String).Trim()
$auditSuccessWasEnabled = [bool]($auditBefore -match '(?im)Other Object Access Events.*Success')
$serviceBefore = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
$agentDocument = New-Object System.Xml.XmlDocument
$agentDocument.PreserveWhitespace = $true
$agentDocument.Load((Resolve-Path -LiteralPath $WazuhConfigPath).Path)
$addedChannels = @(
    foreach ($channel in @('Microsoft-Windows-Sysmon/Operational', 'Security')) {
        if (Set-EventChannel -Document $agentDocument -Channel $channel) { $channel }
    }
)
try {
    $temporaryConfig = "$WazuhConfigPath.csg-tmp"
    $agentDocument.Save($temporaryConfig)
    Move-Item -LiteralPath $temporaryConfig -Destination $WazuhConfigPath -Force
    & auditpol.exe /set /subcategory:'Other Object Access Events' /success:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not enable successful Other Object Access auditing.' }
    Copy-Item -LiteralPath $CandidateSysmonConfigPath -Destination $SysmonConfigPath -Force
    & $sysmonExe -c $SysmonConfigPath
    if ($LASTEXITCODE -ne 0) { throw "Sysmon rejected the research config (exit $LASTEXITCODE)." }
    Restart-Service -Name WazuhSvc -Force
} catch {
    Copy-Item -LiteralPath $wazuhBackup -Destination $WazuhConfigPath -Force
    Copy-Item -LiteralPath $sysmonBackup -Destination $SysmonConfigPath -Force
    & $sysmonExe -c $sysmonBackup | Out-Null
    $auditSwitch = if ($auditSuccessWasEnabled) { 'enable' } else { 'disable' }
    & auditpol.exe /set /subcategory:'Other Object Access Events' "/success:$auditSwitch" | Out-Null
    Restart-Service -Name WazuhSvc -Force -ErrorAction SilentlyContinue
    throw
}
Start-Sleep -Seconds 5
$serviceAfter = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
$auditAfter = (& auditpol.exe /get /subcategory:'Other Object Access Events' /r 2>&1 | Out-String).Trim()
$agentStatus = $null
$apiError = $null
try {
    $status = Invoke-RestMethod -Method Get -DisableKeepAlive -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
    $agentStatus = @($status.server_api.agents | Where-Object { $_.name -eq $HostId } |
        Select-Object -First 1).status
} catch {
    $apiError = $_.Exception.Message
}

$result = [ordered]@{
    schema_version = 'csg-windows-research-telemetry-config-v1'
    host_id = $HostId
    computer_name = $env:COMPUTERNAME
    applied_at = (Get-Date).ToUniversalTime().ToString('o')
    paths = [ordered]@{ wazuh_config = $WazuhConfigPath; sysmon_config = $SysmonConfigPath }
    backups = [ordered]@{ wazuh_config = $wazuhBackup; sysmon_config = $sysmonBackup }
    hashes = [ordered]@{
        wazuh_config_before = (Get-FileHash -LiteralPath $wazuhBackup -Algorithm SHA256).Hash
        wazuh_config_after = (Get-FileHash -LiteralPath $WazuhConfigPath -Algorithm SHA256).Hash
        sysmon_config_before = $activeConfigHashBefore
        sysmon_config_after = (Get-FileHash -LiteralPath $SysmonConfigPath -Algorithm SHA256).Hash
        sysmon_candidate = $candidateHash
    }
    event_channels_added = $addedChannels
    audit_policy = [ordered]@{
        subcategory = 'Other Object Access Events'
        success_was_enabled = $auditSuccessWasEnabled
        before = $auditBefore
        after = $auditAfter
    }
    wazuh_service = [ordered]@{
        before = [ordered]@{ status = [string]$serviceBefore.State; pid = [int]$serviceBefore.ProcessId }
        after = [ordered]@{ status = [string]$serviceAfter.State; pid = [int]$serviceAfter.ProcessId }
    }
    manager_agent_status = $agentStatus
    api_error = $apiError
    sysmon_executable = $sysmonExe
    sysmon_candidate_path = $CandidateSysmonConfigPath
    artifact_directory = $runDirectory
    restore_command = "powershell -ExecutionPolicy Bypass -File configure_windows_research_telemetry.ps1 -Mode Restore -RestoreRecordPath `"$(Join-Path $runDirectory 'configuration-change.json')`""
}
$recordPath = Join-Path $runDirectory 'configuration-change.json'
$result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $recordPath -Encoding UTF8
$result | ConvertTo-Json -Depth 12
