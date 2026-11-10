param(
  [string]$DrillPath = "C:\CSG\run_windows_category_positive_controls.ps1",
  [string]$CsgApiBase = "http://192.168.64.1:8000",
  [string]$HostId = "win11-arm-lab",
  [string]$ProbePython = "python.exe",
  [string]$ProbeConfig = "C:\CSG\probe-settings.json",
  [int]$Repetitions = 10,
  [int]$WaitSeconds = 45,
  [int]$RandomSeed = 20261004,
  [string]$OutputDirectory = "C:\CSG\research\20261004-registry-positive-control-v1",
  [string]$CampaignLabel = "",
  [string]$ProtocolSha256 = "",
  [ValidateRange(180, 600)][int]$ReconciliationWaitSeconds = 300
)

$ErrorActionPreference = "Stop"
if ($Repetitions -lt 1 -or $Repetitions -gt 30) { throw "Repetitions must be between 1 and 30." }
if ($WaitSeconds -lt 10 -or $WaitSeconds -gt 180) { throw "WaitSeconds must be between 10 and 180." }
if (-not (Test-Path -LiteralPath $DrillPath)) { throw "Windows category runner is missing: $DrillPath" }
if (-not (Test-Path -LiteralPath $ProbeConfig)) { throw "Probe config is missing: $ProbeConfig" }
if (Test-Path -LiteralPath $OutputDirectory) { throw "Refusing to overwrite campaign directory: $OutputDirectory" }
if ([string]::IsNullOrWhiteSpace($CampaignLabel)) { $CampaignLabel = Split-Path -Leaf $OutputDirectory }
if ($CampaignLabel -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$') {
  throw "CampaignLabel must be a simple identifier of at most 100 characters."
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Run this controlled campaign from Administrator PowerShell." }

$probeSettings = (Get-Content -LiteralPath $ProbeConfig -Raw | ConvertFrom-Json)
if ($probeSettings.CSG_PROBE_HOST_ID -ne $HostId) {
  throw "Probe config host ID '$($probeSettings.CSG_PROBE_HOST_ID)' does not match '$HostId'."
}
$health = Invoke-RestMethod -Method Get -DisableKeepAlive -Uri "$CsgApiBase/api/wazuh/status"
$agent = @($health.agents | Where-Object { $_.name -eq $HostId }) | Select-Object -First 1
$wazuhService = Get-Service -Name WazuhSvc -ErrorAction Stop
$probeTask = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction Stop
$probeTaskEnabled = [bool]$probeTask.Settings.Enabled
if (-not $health.ok -or -not $agent -or $agent.status -ne "active" -or
    $wazuhService.Status -ne "Running" -or -not $probeTaskEnabled) {
  throw "Preflight failed: CSG/Wazuh, endpoint agent, WazuhSvc, and enabled CSG probe task are required."
}
$null = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop

function Get-OptionalHash([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Save-Json([string]$Path, [object]$Value) {
  $temporaryPath = "$Path.tmp"
  $Value | ConvertTo-Json -Depth 24 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
  Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
}

$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$wazuhCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='WazuhSvc'"
$sysmonServices = @(Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -match "Sysmon" })
$environment = [ordered]@{
  captured_at = (Get-Date).ToUniversalTime().ToString("o")
  host_id = $HostId
  hostname = $env:COMPUTERNAME
  user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  elevated = $isAdmin
  os_caption = $os.Caption
  os_version = $os.Version
  os_build = $os.BuildNumber
  powershell_version = $PSVersionTable.PSVersion.ToString()
  csg_api_base = $CsgApiBase
  csg_wazuh_health_ok = [bool]$health.ok
  wazuh_agent = [ordered]@{ status = $agent.status; version = $agent.version; service_status = [string]$wazuhService.Status; process_id = [int]$wazuhCim.ProcessId }
  sysmon_services = @($sysmonServices | ForEach-Object {
    [ordered]@{ name = [string]$_.Name; state = [string]$_.State; start_mode = [string]$_.StartMode; process_id = [int]$_.ProcessId }
  })
  probe_scheduled_task = [ordered]@{
    task_name = [string]$probeTask.TaskName
    state = [string]$probeTask.State
    enabled = $probeTaskEnabled
  }
  runner_sha256 = (Get-FileHash -LiteralPath $DrillPath -Algorithm SHA256).Hash.ToLowerInvariant()
  controller_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
  probe_config_sha256 = (Get-FileHash -LiteralPath $ProbeConfig -Algorithm SHA256).Hash.ToLowerInvariant()
  sysmon_config_sha256 = Get-OptionalHash "C:\CSG\sysmon-csg-lab.xml"
  wazuh_agent_config_sha256 = Get-OptionalHash "C:\Program Files (x86)\ossec-agent\ossec.conf"
  protocol_sha256 = $ProtocolSha256
}
Save-Json (Join-Path $OutputDirectory "pretrial-environment.json") $environment

$experimentId = "$CampaignLabel-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))"
$random = [System.Random]::new($RandomSeed)
$schedule = @(
  for ($index = 1; $index -le $Repetitions; $index++) {
    [pscustomobject]@{
      repetition = $index
      trial_id = "registry-positive-{0:D2}" -f $index
      condition = "registry_positive_control"
      status = "PENDING"
      started_at = $null
      ended_at = $null
      target_name = $null
      exact_wazuh_event_ids = @()
      post_trial_health = $null
      error = $null
    }
  }
)
$schedule = @($schedule | Sort-Object { $random.Next() })
$manifest = [ordered]@{
  schema_version = "csg-windows-registry-positive-campaign-v1"
  experiment_id = $experimentId
  execution_kind = "prospective_live_positive_control_pilot"
  status = "RUNNING"
  created_at = (Get-Date).ToUniversalTime().ToString("o")
  protocol_sha256 = $ProtocolSha256
  random_seed = $RandomSeed
  assigned_trials = $schedule.Count
  repetitions = $Repetitions
  condition = "controlled reversible HKCU Run-key persistence-like mutation; not an attack label"
  wait_seconds = $WaitSeconds
  reconciliation_wait_seconds = $ReconciliationWaitSeconds
  host_id = $HostId
  environment = "pretrial-environment.json"
  schedule = $schedule
}
$manifestPath = Join-Path $OutputDirectory "campaign-manifest.json"
Save-Json $manifestPath $manifest

$abortRemaining = $false
foreach ($entry in $schedule) {
  if ($abortRemaining) {
    $entry.status = "NOT_RUN_AFTER_PREVIOUS_TRIAL_FAILURE"
    continue
  }
  $trialDirectory = Join-Path $OutputDirectory $entry.trial_id
  $outputPath = Join-Path $trialDirectory "run.json"
  $null = New-Item -ItemType Directory -Path $trialDirectory -Force
  $entry.status = "RUNNING"
  $entry.started_at = (Get-Date).ToUniversalTime().ToString("o")
  Save-Json $manifestPath $manifest
  try {
    & $DrillPath `
      -CsgApiBase $CsgApiBase `
      -HostId $HostId `
      -ProbePython $ProbePython `
      -ProbeConfig $ProbeConfig `
      -WaitSeconds $WaitSeconds `
      -ReconciliationWaitSeconds $ReconciliationWaitSeconds `
      -ScenarioFilter "registry" `
      -OutputPath $outputPath
    if (-not (Test-Path -LiteralPath $outputPath)) { throw "Windows category runner did not create its run artifact." }
    $result = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
    $scenario = @($result.scenarios | Where-Object { $_.scenario_id -eq "registry-autorun-persistence" }) | Select-Object -First 1
    if (-not $scenario) { throw "Result did not contain the registry autorun scenario." }
    $entry.target_name = $scenario.object_name
    $entry.exact_wazuh_event_ids = @($scenario.event_plane.exact_matches | ForEach-Object { $_.event_id })
    $entry.status = if ($scenario.positive_control.passed) { "COMPLETED_PASS" } else { "COMPLETED_GAP" }
    if (-not $scenario.positive_control.passed) {
      $entry.error = "The frozen exact-target positive-control gate failed."
    }
  } catch {
    $entry.status = "FAILED"
    $entry.error = $_.Exception.Message
    $failure = [ordered]@{
      schema_version = "csg-registry-positive-trial-failure-v1"
      experiment_id = $experimentId
      trial_id = $entry.trial_id
      condition = $entry.condition
      host_id = $HostId
      started_at = $entry.started_at
      failed_at = (Get-Date).ToUniversalTime().ToString("o")
      failure_reason = $entry.error
      runner_progress = Join-Path $trialDirectory "progress.json"
      cleanup_status = "inspect retained progress and endpoint state"
    }
    Save-Json (Join-Path $trialDirectory "failure.json") $failure
  }
  try {
    $wazuhPost = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction Stop
    $sysmonPost = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.Name -match "^Sysmon" })
    $taskPost = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction SilentlyContinue
    $healthPost = Invoke-RestMethod -Method Get -DisableKeepAlive -TimeoutSec 30 -Uri "$CsgApiBase/api/wazuh/status"
    $agentPost = @($healthPost.agents | Where-Object { $_.name -eq $HostId }) | Select-Object -First 1
    $wazuhConfigPostHash = Get-OptionalHash "C:\Program Files (x86)\ossec-agent\ossec.conf"
    $probeConfigPostHash = Get-OptionalHash $ProbeConfig
    $sysmonConfigPostHash = Get-OptionalHash "C:\CSG\sysmon-csg-lab.xml"
    $entry.post_trial_health = [ordered]@{
      checked_at = (Get-Date).ToUniversalTime().ToString("o")
      wazuh_service = if ($wazuhPost) { [string]$wazuhPost.State } else { "MISSING" }
      wazuh_service_pid = if ($wazuhPost) { [int]$wazuhPost.ProcessId } else { 0 }
      endpoint_agent = if ($agentPost) { [string]$agentPost.status } else { "MISSING" }
      manager_indexer_healthy = [bool]$healthPost.ok
      sysmon_services_running = $sysmonPost.Count -gt 0 -and @($sysmonPost | Where-Object { $_.State -ne "Running" }).Count -eq 0
      probe_task_enabled = if ($taskPost) { [bool]$taskPost.Settings.Enabled } else { $null }
      wazuh_config_sha256 = $wazuhConfigPostHash
      probe_config_sha256 = $probeConfigPostHash
      sysmon_config_sha256 = $sysmonConfigPostHash
      configuration_unchanged = $wazuhConfigPostHash -eq $environment.wazuh_agent_config_sha256 -and
        $probeConfigPostHash -eq $environment.probe_config_sha256 -and
        $sysmonConfigPostHash -eq $environment.sysmon_config_sha256
      passed = [bool]($wazuhPost.State -eq "Running" -and [int]$wazuhPost.ProcessId -gt 0 -and
        $agentPost.status -eq "active" -and $healthPost.ok -and $sysmonPost.Count -gt 0 -and
        @($sysmonPost | Where-Object { $_.State -ne "Running" }).Count -eq 0 -and
        $taskPost -and [bool]$taskPost.Settings.Enabled -eq $probeTaskEnabled -and
        $wazuhConfigPostHash -eq $environment.wazuh_agent_config_sha256 -and
        $probeConfigPostHash -eq $environment.probe_config_sha256 -and
        $sysmonConfigPostHash -eq $environment.sysmon_config_sha256)
    }
    if (-not $entry.post_trial_health.passed) {
      $entry.status = "FAILED_POSTTRIAL_HEALTH"
      $entry.error = "Endpoint health or baseline configuration restoration check failed."
    }
  } catch {
    $entry.post_trial_health = [ordered]@{
      checked_at = (Get-Date).ToUniversalTime().ToString("o")
      passed = $false
      error = $_.Exception.Message
    }
    $entry.status = "FAILED_POSTTRIAL_HEALTH"
    $entry.error = $_.Exception.Message
  }
  $entry.ended_at = (Get-Date).ToUniversalTime().ToString("o")
  Save-Json $manifestPath $manifest
  if ($entry.status -ne "COMPLETED_PASS") { $abortRemaining = $true }
}

$finalWazuh = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction SilentlyContinue
$finalSysmon = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^Sysmon" })
$finalTask = Get-ScheduledTask -TaskName "CyberStateGuardian Probe" -ErrorAction SilentlyContinue
$finalHealth = $null
try { $finalHealth = Invoke-RestMethod -Method Get -TimeoutSec 30 -Uri "$CsgApiBase/api/wazuh/status" } catch { }
$finalAgent = if ($finalHealth) {
  @($finalHealth.agents | Where-Object { $_.name -eq $HostId } | Select-Object -First 1)[0]
} else { $null }
$finalSysmonConfigHash = Get-OptionalHash "C:\CSG\sysmon-csg-lab.xml"
$manifest.postflight = [ordered]@{
  checked_at = (Get-Date).ToUniversalTime().ToString("o")
  wazuh_service = if ($finalWazuh) { [string]$finalWazuh.State } else { "MISSING" }
  wazuh_service_pid = if ($finalWazuh) { [int]$finalWazuh.ProcessId } else { 0 }
  endpoint_health_ok = [bool]($finalHealth -and $finalHealth.ok)
  endpoint_agent_status = if ($finalAgent) { [string]$finalAgent.status } else { "MISSING" }
  sysmon_services_running = $finalSysmon.Count -gt 0 -and @($finalSysmon | Where-Object { $_.State -ne "Running" }).Count -eq 0
  sysmon_config_sha256 = $finalSysmonConfigHash
  probe_task_enabled = if ($finalTask) { [bool]$finalTask.Settings.Enabled } else { $null }
  wazuh_config_sha256 = Get-OptionalHash "C:\Program Files (x86)\ossec-agent\ossec.conf"
  probe_config_sha256 = Get-OptionalHash $ProbeConfig
  wazuh_config_restored = (Get-OptionalHash "C:\Program Files (x86)\ossec-agent\ossec.conf") -eq $environment.wazuh_agent_config_sha256
  probe_config_unchanged = (Get-OptionalHash $ProbeConfig) -eq $environment.probe_config_sha256
  postflight_valid = [bool]($finalWazuh.State -eq "Running" -and [int]$finalWazuh.ProcessId -gt 0 -and
    $finalHealth -and $finalHealth.ok -and $finalAgent.status -eq "active" -and $finalSysmon.Count -gt 0 -and
    @($finalSysmon | Where-Object { $_.State -ne "Running" }).Count -eq 0 -and
    $finalTask -and [bool]$finalTask.Settings.Enabled -eq $probeTaskEnabled -and
    (Get-OptionalHash "C:\Program Files (x86)\ossec-agent\ossec.conf") -eq $environment.wazuh_agent_config_sha256 -and
    (Get-OptionalHash $ProbeConfig) -eq $environment.probe_config_sha256 -and
    $finalSysmonConfigHash -eq $environment.sysmon_config_sha256)
}
$manifest.status = if (@($schedule | Where-Object { $_.status -ne "COMPLETED_PASS" }).Count -gt 0 -or
  -not $manifest.postflight.postflight_valid) {
  "COMPLETED_WITH_GAPS"
} else {
  "COMPLETED"
}
$manifest.completed_at = (Get-Date).ToUniversalTime().ToString("o")
Save-Json $manifestPath $manifest
Write-Host "Campaign manifest: $manifestPath"
Write-Host "Status: $($manifest.status); passed=$(@($schedule | Where-Object { $_.status -eq 'COMPLETED_PASS' }).Count)/$($schedule.Count)"
