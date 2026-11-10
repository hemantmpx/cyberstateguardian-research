param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[0-9a-fA-F]{64}$')]
  [string]$ProtocolSha256,
  [Parameter(Mandatory = $true)]
  [string]$OutputDirectory,
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^S-1-5-21-(\d+-){3}\d+$')]
  [string]$InteractiveUserSid,
  [string]$HostId = "win11-arm-lab",
  [string]$CsgApiBase = "http://192.168.64.1:8000",
  [string]$ProbeConfig = "C:\CSG\probe-settings.json",
  [string]$AgentConfig = "C:\Program Files (x86)\ossec-agent\ossec.conf",
  [int]$FimFrequencySeconds = 60,
  [int]$RepetitionsPerCondition = 10,
  [int]$PositiveEventWaitSeconds = 75,
  [int]$LifecycleWaitSeconds = 75,
  [int]$ToleranceSeconds = 10,
  [int]$EventLookbackSeconds = 300,
  [int]$RandomSeed = 20261007
)

$ErrorActionPreference = "Stop"
if ($FimFrequencySeconds -lt 30) { throw "FIM frequency must be at least 30 seconds for this full-syscheck baseline." }
if ($RepetitionsPerCondition -lt 1 -or $RepetitionsPerCondition -gt 30) {
  throw "RepetitionsPerCondition must be between 1 and 30."
}
if (-not (Test-Path -LiteralPath $AgentConfig)) { throw "Wazuh agent config is missing." }
if (-not (Test-Path -LiteralPath $ProbeConfig)) { throw "CSG probe config is missing." }
if (Test-Path -LiteralPath $OutputDirectory) { throw "Refusing to overwrite output directory: $OutputDirectory" }
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Run this controller from Administrator PowerShell." }

function Save-Json([string]$Path, [object]$Value) {
  $temporaryPath = "$Path.tmp"
  $Value | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
  Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
}

$probeSettings = Get-Content -LiteralPath $ProbeConfig -Raw | ConvertFrom-Json
if ($probeSettings.CSG_PROBE_HOST_ID -ne $HostId) { throw "Probe config host ID mismatch." }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($sid -ne $InteractiveUserSid) {
  throw "Interactive user SID '$sid' does not match declared SID '$InteractiveUserSid'."
}
$runKey = "HKEY_USERS\$InteractiveUserSid\Software\Microsoft\Windows\CurrentVersion\Run"
$backupPath = Join-Path $OutputDirectory "ossec.conf.original.xml"
$candidatePath = Join-Path $OutputDirectory "ossec.conf.candidate.xml"
$campaignPath = Join-Path $OutputDirectory "campaign"
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
Copy-Item -LiteralPath $AgentConfig -Destination $backupPath
$originalHash = (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash.ToLowerInvariant()
$controllerHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$trialScript = Join-Path $PSScriptRoot "run_registry_reconciliation_trial_windows.ps1"
$campaignScript = Join-Path $PSScriptRoot "run_registry_reconciliation_campaign_windows.ps1"
if (-not (Test-Path -LiteralPath $trialScript) -or -not (Test-Path -LiteralPath $campaignScript)) {
  throw "Registry campaign scripts are missing beside this controller."
}
$trialHash = (Get-FileHash -LiteralPath $trialScript -Algorithm SHA256).Hash.ToLowerInvariant()
$campaignHash = (Get-FileHash -LiteralPath $campaignScript -Algorithm SHA256).Hash.ToLowerInvariant()
$startedAt = (Get-Date).ToUniversalTime()
$metricsPath = Join-Path $OutputDirectory "resource-samples.jsonl"
$monitorJob = $null
$manifest = [ordered]@{
  schema_version = "csg-wazuh-fim-matched-registry-campaign-v1"
  experiment_id = "CSG-wazuh-fim-matched-$($startedAt.ToString('yyyyMMddTHHmmssZ'))"
  status = "PREPARING"
  created_at = $startedAt.ToString("o")
  host_id = $HostId
  interactive_user_sid = $InteractiveUserSid
  exact_fim_registry_path = $runKey
  temporary_fim_frequency_seconds = $FimFrequencySeconds
  repetitions_per_condition = $RepetitionsPerCondition
  conditions = @("registry_complete", "registry_wrong_object", "registry_no_change")
  protocol_sha256 = $ProtocolSha256.ToLowerInvariant()
  controller_sha256 = $controllerHash
  campaign_controller_sha256 = $campaignHash
  trial_controller_sha256 = $trialHash
  original_agent_config_sha256 = $originalHash
  temporary_agent_config_sha256 = $null
  service_before = $null
  service_after_restore = $null
  resource_samples = "resource-samples.jsonl"
  restored_original_config = $false
  initial_restore_agent_status = $null
  restore_health_checks = @()
  agent_active_after_restore = $false
  campaign_directory = $campaignPath
}
Save-Json (Join-Path $OutputDirectory "fim-campaign-manifest.json") $manifest

try {
  $wazuhBefore = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
  if (-not $wazuhBefore -or $wazuhBefore.State -ne "Running") { throw "WazuhSvc must be running before the temporary config." }
  $manifest.service_before = [ordered]@{ state = [string]$wazuhBefore.State; pid = [int]$wazuhBefore.ProcessId }

  $xml = [System.Xml.XmlDocument]::new()
  $xml.PreserveWhitespace = $true
  $xml.Load($AgentConfig)
  $syscheck = $xml.SelectSingleNode("/ossec_config/syscheck")
  if (-not $syscheck) { throw "No syscheck section exists in the agent config." }
  $frequency = $syscheck.SelectSingleNode("frequency")
  if (-not $frequency) {
    $frequency = $xml.CreateElement("frequency")
    $syscheck.PrependChild($frequency) | Out-Null
  }
  $frequency.InnerText = [string]$FimFrequencySeconds
  $existing = @($syscheck.SelectNodes("windows_registry") | Where-Object {
    $_.InnerText.Trim().TrimEnd('\').Equals($runKey, [StringComparison]::OrdinalIgnoreCase)
  })
  if ($existing.Count -eq 0) {
    $registryNode = $xml.CreateElement("windows_registry")
    $registryNode.SetAttribute("arch", "both")
    $registryNode.InnerText = $runKey
    $syscheck.AppendChild($registryNode) | Out-Null
  }
  $xml.Save($candidatePath)
  $verify = [System.Xml.XmlDocument]::new()
  $verify.Load($candidatePath)
  if ($verify.SelectSingleNode("/ossec_config/syscheck/frequency").InnerText -ne [string]$FimFrequencySeconds) {
    throw "Candidate FIM frequency failed validation."
  }
  $verifiedRegistryPaths = @($verify.SelectNodes("/ossec_config/syscheck/windows_registry") | Where-Object {
    $_.InnerText.Trim().TrimEnd('\').Equals($runKey, [StringComparison]::OrdinalIgnoreCase)
  })
  if ($verifiedRegistryPaths.Count -eq 0) { throw "Candidate does not monitor the exact interactive-user Run key." }

  Copy-Item -LiteralPath $candidatePath -Destination $AgentConfig -Force
  $manifest.temporary_agent_config_sha256 = (Get-FileHash -LiteralPath $AgentConfig -Algorithm SHA256).Hash.ToLowerInvariant()
  $manifest.status = "TEMPORARY_CONFIG_APPLIED"
  Save-Json (Join-Path $OutputDirectory "fim-campaign-manifest.json") $manifest

  Restart-Service -Name WazuhSvc
  (Get-Service -Name WazuhSvc).WaitForStatus("Running", [TimeSpan]::FromSeconds(45))
  Start-Sleep -Seconds ($FimFrequencySeconds + 10)
  $health = Invoke-RestMethod -Method Get -TimeoutSec 30 -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
  $agent = @($health.agents | Where-Object { $_.name -eq $HostId }) | Select-Object -First 1
  if (-not $health.ok -or -not $agent -or $agent.status -ne "active") {
    throw "CSG/Wazuh status failed after temporary FIM config restart."
  }

  $monitorJob = Start-Job -ArgumentList $metricsPath -ScriptBlock {
    param($Path)
    while ($true) {
      $sampleTime = [DateTime]::UtcNow.ToString("o")
      $service = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
      $process = if ($service -and $service.ProcessId -gt 0) {
        Get-Process -Id $service.ProcessId -ErrorAction SilentlyContinue
      } else { $null }
      $os = Get-CimInstance Win32_OperatingSystem
      $sample = [ordered]@{
        sampled_at = $sampleTime
        wazuh_service_state = if ($service) { [string]$service.State } else { "MISSING" }
        wazuh_service_pid = if ($service) { [int]$service.ProcessId } else { 0 }
        process_cpu_seconds = if ($process) { [double]$process.CPU } else { $null }
        process_working_set_bytes = if ($process) { [long]$process.WorkingSet64 } else { $null }
        process_private_bytes = if ($process) { [long]$process.PrivateMemorySize64 } else { $null }
        available_physical_memory_bytes = [long]$os.FreePhysicalMemory * 1024
        total_visible_memory_bytes = [long]$os.TotalVisibleMemorySize * 1024
      }
      ($sample | ConvertTo-Json -Compress) | Add-Content -LiteralPath $Path -Encoding UTF8
      Start-Sleep -Seconds 15
    }
  }

  $manifest.status = "CAMPAIGN_RUNNING"
  Save-Json (Join-Path $OutputDirectory "fim-campaign-manifest.json") $manifest
  & $campaignScript `
    -TrialScript $trialScript `
    -CsgApiBase $CsgApiBase `
    -HostId $HostId `
    -ProbeConfig $ProbeConfig `
    -OutputDirectory $campaignPath `
    -ProtocolSha256 $ProtocolSha256 `
    -RepetitionsPerCondition $RepetitionsPerCondition `
    -RandomSeed $RandomSeed `
    -PositiveEventWaitSeconds $PositiveEventWaitSeconds `
    -LifecycleWaitSeconds $LifecycleWaitSeconds `
      -ToleranceSeconds $ToleranceSeconds `
      -EventLookbackSeconds $EventLookbackSeconds
  $campaignManifestPath = Join-Path $campaignPath "campaign-manifest.json"
  if (-not (Test-Path -LiteralPath $campaignManifestPath)) {
    throw "Registry campaign returned without writing its manifest."
  }
  $campaignResult = Get-Content -LiteralPath $campaignManifestPath -Raw | ConvertFrom-Json
  if ($campaignResult.status -notin @("COMPLETED", "COMPLETED_WITH_GAPS")) {
    throw "Registry campaign ended in unexpected status '$($campaignResult.status)'."
  }
  $manifest.campaign_status = $campaignResult.status
  $manifest.status = if ($campaignResult.status -eq "COMPLETED") {
    "CAMPAIGN_FINISHED"
  } else { "CAMPAIGN_FINISHED_WITH_GAPS" }
} catch {
  $manifest.status = "FAILED"
  $manifest.failure = $_.Exception.Message
  throw
} finally {
  if ($monitorJob) {
    Stop-Job -Job $monitorJob -ErrorAction SilentlyContinue
    Receive-Job -Job $monitorJob -ErrorAction SilentlyContinue | Out-Null
    Remove-Job -Job $monitorJob -Force -ErrorAction SilentlyContinue
  }
  try {
    if (Test-Path -LiteralPath $backupPath) {
      Copy-Item -LiteralPath $backupPath -Destination $AgentConfig -Force
      Restart-Service -Name WazuhSvc
      (Get-Service -Name WazuhSvc).WaitForStatus("Running", [TimeSpan]::FromSeconds(45))
      $restoredHash = (Get-FileHash -LiteralPath $AgentConfig -Algorithm SHA256).Hash.ToLowerInvariant()
      $wazuhAfter = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
      $manifest.restored_original_config = $restoredHash -eq $originalHash
      $manifest.service_after_restore = if ($wazuhAfter) {
        [ordered]@{ state = [string]$wazuhAfter.State; pid = [int]$wazuhAfter.ProcessId }
      } else { [ordered]@{ state = "MISSING"; pid = 0 } }
      $restoreDeadline = (Get-Date).AddSeconds(120)
      do {
        $healthCheck = [ordered]@{ checked_at = (Get-Date).ToUniversalTime().ToString("o"); api_ok = $false; agent_status = "unavailable" }
        try {
          $restoredHealth = Invoke-RestMethod -Method Get -TimeoutSec 15 -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
          $restoredAgent = @($restoredHealth.agents | Where-Object { $_.name -eq $HostId }) | Select-Object -First 1
          $healthCheck.api_ok = [bool]$restoredHealth.ok
          $healthCheck.agent_status = if ($restoredAgent) { [string]$restoredAgent.status } else { "not_reported" }
          if ($null -eq $manifest.initial_restore_agent_status) {
            $manifest.initial_restore_agent_status = $healthCheck.agent_status
          }
          $manifest.agent_active_after_restore = [bool]($restoredHealth.ok -and $restoredAgent -and $restoredAgent.status -eq "active")
        } catch {
          $healthCheck.agent_status = "health_request_failed"
        }
        $manifest.restore_health_checks += $healthCheck
        if (-not $manifest.agent_active_after_restore -and (Get-Date) -lt $restoreDeadline) {
          Start-Sleep -Seconds 5
        }
      } while (-not $manifest.agent_active_after_restore -and (Get-Date) -lt $restoreDeadline)
      if (-not $manifest.restored_original_config -or $manifest.service_after_restore.state -ne "Running" -or
          -not $manifest.agent_active_after_restore) {
        $manifest.status = "RESTORE_FAILED"
      } elseif ($manifest.status -ne "FAILED") {
        $manifest.status = if ($manifest.status -eq "CAMPAIGN_FINISHED_WITH_GAPS") {
          "COMPLETED_WITH_GAPS_RESTORED"
        } else { "COMPLETED_RESTORED" }
      }
    } else {
      $manifest.status = "RESTORE_BACKUP_MISSING"
    }
  } catch {
    $manifest.status = "RESTORE_FAILED"
    $manifest.restore_error = $_.Exception.Message
  }
  $manifest.completed_at = (Get-Date).ToUniversalTime().ToString("o")
  Save-Json (Join-Path $OutputDirectory "fim-campaign-manifest.json") $manifest
}

Write-Host "FIM campaign manifest: $(Join-Path $OutputDirectory 'fim-campaign-manifest.json')"
Write-Host "Status=$($manifest.status); original config restored=$($manifest.restored_original_config)"
if ($manifest.status -eq "RESTORE_FAILED") { throw "Original Wazuh config restoration failed; inspect manifest immediately." }
