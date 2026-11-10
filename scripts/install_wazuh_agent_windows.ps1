param(
    [Parameter(Mandatory = $true)]
    [string] $WazuhManager,

    [string] $AgentName = $env:COMPUTERNAME,
    [string] $AgentGroup = "default",
    [string] $WazuhMsiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi",
    [string] $SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip",
    [string] $SysmonConfigPath = "",
    [switch] $SkipSysmon
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell prompt."
    }
}

function Install-WazuhAgent {
    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "Wazuh agent service already exists."
        return
    }

    $msiPath = Join-Path $env:TEMP "wazuh-agent.msi"
    Write-Host "Downloading Wazuh agent MSI..."
    Invoke-WebRequest -Uri $WazuhMsiUrl -OutFile $msiPath

    $arguments = @(
        "/i", "`"$msiPath`"",
        "/q",
        "WAZUH_MANAGER=`"$WazuhManager`"",
        "WAZUH_AGENT_NAME=`"$AgentName`"",
        "WAZUH_AGENT_GROUP=`"$AgentGroup`""
    ) -join " "

    Write-Host "Installing Wazuh agent..."
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Wazuh agent MSI failed with exit code $($process.ExitCode)."
    }
}

function Install-Sysmon {
    if ($SkipSysmon) {
        Write-Host "Skipping Sysmon installation."
        return
    }

    $workDir = Join-Path $env:TEMP "csg-sysmon"
    $zipPath = Join-Path $env:TEMP "Sysmon.zip"
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null

    Write-Host "Downloading Sysmon..."
    Invoke-WebRequest -Uri $SysmonUrl -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath $workDir -Force

    $candidates = @("Sysmon64a.exe", "Sysmon64.exe", "Sysmon.exe")
    $sysmonExe = $null
    foreach ($candidate in $candidates) {
        $path = Join-Path $workDir $candidate
        if (Test-Path $path) {
            $sysmonExe = $path
            break
        }
    }
    if (-not $sysmonExe) {
        throw "Could not find a Sysmon executable in $workDir."
    }

    if (-not $SysmonConfigPath) {
        $SysmonConfigPath = Join-Path $workDir "sysmon-csg-lab.xml"
        @"
<Sysmon schemaversion="4.82">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="include" />
    <NetworkConnect onmatch="include" />
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">\Software\Microsoft\Windows\CurrentVersion\Run\</TargetObject>
    </RegistryEvent>
  </EventFiltering>
</Sysmon>
"@ | Set-Content -Path $SysmonConfigPath -Encoding UTF8
    }

    $sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
    if ($sysmonService) {
        Write-Host "Updating Sysmon configuration..."
        & $sysmonExe -c $SysmonConfigPath
    }
    else {
        Write-Host "Installing Sysmon..."
        & $sysmonExe -accepteula -i $SysmonConfigPath
    }
}

function Enable-WazuhSysmonCollection {
    $configPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
    if (-not (Test-Path $configPath)) {
        throw "Wazuh agent config was not found at $configPath."
    }

    [xml]$document = Get-Content -Path $configPath -Raw
    $root = $document.SelectSingleNode('/ossec_config')
    if (-not $root) { throw "Could not parse the ossec_config root in $configPath." }

    $channelsChanged = $false
    foreach ($channel in @('Microsoft-Windows-Sysmon/Operational', 'Security')) {
        $configured = @($document.SelectNodes('/ossec_config/localfile/location') | Where-Object {
            $_.InnerText -eq $channel
        }).Count -gt 0
        if (-not $configured) {
            $channelsChanged = $true
            $localFile = $document.CreateElement('localfile')
            $location = $document.CreateElement('location')
            $location.InnerText = $channel
            $format = $document.CreateElement('log_format')
            $format.InnerText = 'eventchannel'
            [void]$localFile.AppendChild($location)
            [void]$localFile.AppendChild($format)
            [void]$root.AppendChild($localFile)
        }
    }

    if ($channelsChanged) {
        $backupPath = "$configPath.csg-$(Get-Date -Format yyyyMMddTHHmmss).bak"
        Copy-Item -Path $configPath -Destination $backupPath
        $temporaryPath = "$configPath.csg-tmp"
        $document.Save($temporaryPath)
        Move-Item -Path $temporaryPath -Destination $configPath -Force
        Write-Host "Backed up existing Wazuh agent config to $backupPath."
    }

    Write-Host 'Configured Wazuh Security and Sysmon event-channel collection.'
}

Assert-Administrator
Install-WazuhAgent
Install-Sysmon
Enable-WazuhSysmonCollection

Write-Host "Restarting Wazuh agent service to load event-channel configuration..."
$service = Get-Service -Name "WazuhSvc"
if ($service.Status -eq "Running") {
    Restart-Service -Name "WazuhSvc" -Force
} else {
    Start-Service -Name "WazuhSvc"
}
Write-Host "Done. Check the Wazuh dashboard Agents view for $AgentName."
