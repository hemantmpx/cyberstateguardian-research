param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^CSGAPTTask[a-fA-F0-9]{10}$')]
  [string]$TargetTaskName,
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^CSGAPTDis[a-fA-F0-9]{10}$')]
  [string]$DistractorTaskName,
  [Parameter(Mandatory = $true)]
  [string]$OutputPath,
  [string]$CsgApiBase = "http://192.168.64.1:8000",
  [string]$HostId = "win11-arm-lab",
  [string]$ProbePython = "C:\Program Files\CyberStateGuardian\Probe\venv\Scripts\python.exe",
  [string]$ProbeConfig = "C:\Program Files\CyberStateGuardian\Probe\settings.json"
)

$ErrorActionPreference = "Stop"
if ($TargetTaskName -ieq $DistractorTaskName) {
  throw "Target and distractor names must be different."
}
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Run this controlled diagnostic from elevated Administrator PowerShell." }
foreach ($path in @($ProbePython, $ProbeConfig)) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file is missing: $path" }
}

function Normalize-TaskName {
  param([object]$Value)
  return ([string]$Value).Trim().Replace("\", "/").Trim("/").ToLowerInvariant()
}

function Test-TaskPresent {
  param([string]$Name)
  return $null -ne (Get-ScheduledTask -TaskName $Name -TaskPath "\" -ErrorAction SilentlyContinue)
}

function Invoke-ProbeAndReadObservation {
  & $ProbePython -m cyberstateguardian_probe.main --config $ProbeConfig --once
  if ($LASTEXITCODE -ne 0) { throw "Probe process returned exit code $LASTEXITCODE." }
  $observation = Invoke-RestMethod -Method Get -TimeoutSec 90 -Uri (
    "$($CsgApiBase.TrimEnd('/'))/api/hosts/$HostId/observations/latest"
  )
  if (-not $observation.observation_id) { throw "CSG API returned no latest probe observation." }
  return $observation
}

function Get-TaskRows {
  param([object]$Observation)
  $items = @($Observation.categories.scheduled_task.items)
  $wanted = @((Normalize-TaskName $TargetTaskName), (Normalize-TaskName $DistractorTaskName))
  return @($items | Where-Object {
    (Normalize-TaskName $_.task_name) -in $wanted
  } | ForEach-Object {
    [ordered]@{
      task_name = [string]$_.task_name
      enabled = [bool]$_.enabled
      principal = [string]$_.principal
      action_count = @($_.actions).Count
    }
  })
}

$OutputPath = [IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $OutputPath) { throw "Refusing to overwrite $OutputPath" }
$null = New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force
$startedAt = [DateTime]::UtcNow
$targetCreated = $false
$distractorCreated = $false
$result = [ordered]@{
  schema_version = "csg-task-pair-visibility-diagnostic-v1"
  diagnostic_id = "probe-scheduled-task-pair-visibility"
  host_id = $HostId
  started_at_utc = $startedAt.ToString("o")
  target_task_name = $TargetTaskName
  distractor_task_name = $DistractorTaskName
  wazuh_configuration_changed = $false
  baseline = $null
  windows_after_registration = $null
  shared_probe_observation = $null
  cleanup = $null
  error = $null
  status = "INCOMPLETE"
}
$exitCode = 0
try {
  if (Test-TaskPresent $TargetTaskName) { throw "Target task already exists; refusing to mutate it." }
  if (Test-TaskPresent $DistractorTaskName) { throw "Distractor task already exists; refusing to mutate it." }
  $baseline = Invoke-ProbeAndReadObservation
  $baselineItems = @($baseline.categories.scheduled_task.items)
  $baselineNames = @($baselineItems | ForEach-Object { Normalize-TaskName $_.task_name })
  if ((Normalize-TaskName $TargetTaskName) -in $baselineNames -or
      (Normalize-TaskName $DistractorTaskName) -in $baselineNames) {
    throw "Assigned task identity was already present in the fresh CSG baseline."
  }
  if ($baseline.categories.scheduled_task.status -ne "healthy") {
    throw "Baseline scheduled-task category is not healthy."
  }
  $result.baseline = [ordered]@{
    observation_id = $baseline.observation_id
    observed_at = $baseline.observed_at
    category_status = $baseline.categories.scheduled_task.status
    category_item_count = $baselineItems.Count
    assigned_tasks_absent = $true
  }

  $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c exit 0"
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(1)
  Register-ScheduledTask -TaskName $TargetTaskName -TaskPath "\" -Action $action `
    -Trigger $trigger -User "SYSTEM" -RunLevel Highest -Force | Out-Null
  $targetCreated = $true
  Register-ScheduledTask -TaskName $DistractorTaskName -TaskPath "\" -Action $action `
    -Trigger $trigger -User "SYSTEM" -RunLevel Highest -Force | Out-Null
  $distractorCreated = $true

  $windowsTasks = @(
    foreach ($name in @($TargetTaskName, $DistractorTaskName)) {
      $task = Get-ScheduledTask -TaskName $name -TaskPath "\" -ErrorAction Stop
      [ordered]@{ task_name = [string]$task.TaskPath + [string]$task.TaskName; state = [string]$task.State }
    }
  )
  $result.windows_after_registration = [ordered]@{
    target_present = Test-TaskPresent $TargetTaskName
    distractor_present = Test-TaskPresent $DistractorTaskName
    exact_tasks = $windowsTasks
  }
  $observation = Invoke-ProbeAndReadObservation
  $taskRows = @(Get-TaskRows -Observation $observation)
  $names = @($taskRows | ForEach-Object { Normalize-TaskName $_.task_name })
  $targetSeen = (Normalize-TaskName $TargetTaskName) -in $names
  $distractorSeen = (Normalize-TaskName $DistractorTaskName) -in $names
  $targetCount = @($names | Where-Object { $_ -eq (Normalize-TaskName $TargetTaskName) }).Count
  $distractorCount = @($names | Where-Object { $_ -eq (Normalize-TaskName $DistractorTaskName) }).Count
  $categoryHealthy = $observation.categories.scheduled_task.status -eq "healthy"
  $freshObservation = $observation.observation_id -ne $baseline.observation_id
  $result.shared_probe_observation = [ordered]@{
    observation_id = $observation.observation_id
    observed_at = $observation.observed_at
    collection_started_at = $observation.metadata.collection_started_at
    category_observed_at = $observation.categories.scheduled_task.observed_at
    category_status = $observation.categories.scheduled_task.status
    fresh_after_registration = $freshObservation
    category_item_count = @($observation.categories.scheduled_task.items).Count
    assigned_task_items = $taskRows
    target_exact_match_count = $targetCount
    distractor_exact_match_count = $distractorCount
    target_seen = $targetSeen
    distractor_seen = $distractorSeen
    both_seen_in_same_observation = ($freshObservation -and $categoryHealthy -and
      $targetCount -eq 1 -and $distractorCount -eq 1)
  }
  $result.status = if ($freshObservation -and $categoryHealthy -and
    $targetCount -eq 1 -and $distractorCount -eq 1) {
    "BOTH_TASKS_VISIBLE_IN_ONE_PROBE"
  } elseif ($targetSeen -or $distractorSeen) {
    "ONE_TASK_MISSING_FROM_PROBE"
  } else {
    "BOTH_TASKS_MISSING_FROM_PROBE"
  }
  if (-not ($targetSeen -and $distractorSeen)) { $exitCode = 2 }
} catch {
  $result.error = $_.Exception.Message
  $result.status = "DIAGNOSTIC_ERROR"
  $exitCode = 1
} finally {
  try {
    if ($targetCreated) {
      Unregister-ScheduledTask -TaskName $TargetTaskName -TaskPath "\" -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($distractorCreated) {
      Unregister-ScheduledTask -TaskName $DistractorTaskName -TaskPath "\" -Confirm:$false -ErrorAction SilentlyContinue
    }
    $result.cleanup = [ordered]@{
      target_absent = -not (Test-TaskPresent $TargetTaskName)
      distractor_absent = -not (Test-TaskPresent $DistractorTaskName)
      observation = $null
    }
    $cleanupObservation = Invoke-ProbeAndReadObservation
    $cleanupNames = @($cleanupObservation.categories.scheduled_task.items | ForEach-Object {
      Normalize-TaskName $_.task_name
    })
    $result.cleanup.observation = [ordered]@{
      observation_id = $cleanupObservation.observation_id
      observed_at = $cleanupObservation.observed_at
      target_seen = (Normalize-TaskName $TargetTaskName) -in $cleanupNames
      distractor_seen = (Normalize-TaskName $DistractorTaskName) -in $cleanupNames
    }
    $result.cleanup.target_absent = $result.cleanup.target_absent -and
      -not $result.cleanup.observation.target_seen
    $result.cleanup.distractor_absent = $result.cleanup.distractor_absent -and
      -not $result.cleanup.observation.distractor_seen
  } catch {
    $result.cleanup_error = $_.Exception.Message
    $exitCode = 1
  }
}
$result.completed_at_utc = [DateTime]::UtcNow.ToString("o")
$result.cleanup_verified = [bool]($result.cleanup.target_absent -and $result.cleanup.distractor_absent)
if (-not $result.cleanup_verified) { $exitCode = 1 }
$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Output ("Status: " + $result.status)
Write-Output ("Same probe contains both: " + $result.shared_probe_observation.both_seen_in_same_observation)
Write-Output ("Cleanup verified: " + $result.cleanup_verified)
Write-Output ("Result: " + $OutputPath)
exit $exitCode
