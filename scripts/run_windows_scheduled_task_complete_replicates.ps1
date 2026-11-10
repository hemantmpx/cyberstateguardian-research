param(
  [Parameter(Mandatory = $true)][string]$SchedulePath,
  [Parameter(Mandatory = $true)][string]$RunnerPath,
  [Parameter(Mandatory = $true)][string]$PreflightScriptPath,
  [Parameter(Mandatory = $true)][string]$OutputRoot,
  [Parameter(Mandatory = $true)][string]$ExpectedRunnerSha256,
  [Parameter(Mandatory = $true)][string]$ExpectedAgentConfigSha256,
  [string]$CsgApiBase = "http://192.168.64.1:8000",
  [string]$HostId = "win11-arm-lab",
  [string]$ProbePython = "C:\Program Files\CyberStateGuardian\Probe\venv\Scripts\python.exe",
  [string]$ProbeConfig = "C:\Program Files\CyberStateGuardian\Probe\settings.json",
  [int]$WaitSeconds = 60,
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Run the replicate controller from Administrator PowerShell." }
if ($WaitSeconds -lt 10 -or $WaitSeconds -gt 180) { throw "WaitSeconds must be between 10 and 180." }
foreach ($path in @($SchedulePath, $RunnerPath, $PreflightScriptPath, $ProbePython, $ProbeConfig)) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file missing: $path" }
}

$actualRunnerHash = (Get-FileHash -LiteralPath $RunnerPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualRunnerHash -ne $ExpectedRunnerSha256.ToLowerInvariant()) {
  throw "Runner hash mismatch: expected $ExpectedRunnerSha256, got $actualRunnerHash"
}
$schedule = Get-Content -LiteralPath $SchedulePath -Raw | ConvertFrom-Json
$trials = @($schedule.trials)
if ($schedule.schema_version -ne "csg-scheduled-task-complete-replicate-schedule-v1" -or
  $trials.Count -lt 1 -or $trials.Count -gt 50) {
  throw "Invalid or unsupported frozen trial schedule."
}
$names = @($trials | ForEach-Object { [string]$_.target_task_name })
$trialIds = @($trials | ForEach-Object { [string]$_.trial_id })
if (@($names | Where-Object { $_ -notmatch '^CSGAPTTask[a-fA-F0-9]{10}$' }).Count -gt 0 -or
  @($trialIds | Where-Object { $_ -notmatch '^trial-[0-9]{2}$' }).Count -gt 0 -or
  @($trialIds | Sort-Object -Unique).Count -ne $trialIds.Count -or
  @($names | Sort-Object -Unique).Count -ne $names.Count) {
  throw "Schedule requires unique trial-## IDs and unique CSGAPTTask names with ten hexadecimal characters."
}
if (-not $DryRun -and (Test-Path -LiteralPath $OutputRoot)) {
  throw "Refusing to overwrite existing campaign output: $OutputRoot"
}
if ($DryRun) {
  [ordered]@{
    status = "DRY_RUN_ONLY"
    trial_count = $trials.Count
    target_task_names = $names
    runner_sha256 = $actualRunnerHash
    wait_seconds = $WaitSeconds
  } | ConvertTo-Json -Depth 6
  exit 0
}

$null = New-Item -ItemType Directory -Path $OutputRoot -Force
$startedAt = [DateTime]::UtcNow.ToString("o")
$records = [System.Collections.Generic.List[object]]::new()
$campaignError = $null

function Invoke-EndpointPreflight {
  param([string]$TargetName, [string]$OutputPath, [string]$LogPath)
  & $PreflightScriptPath `
    -ExpectedAgentConfigSha256 $ExpectedAgentConfigSha256 `
    -ExpectedRunnerSha256 $ExpectedRunnerSha256 `
    -TargetTaskName $TargetName `
    -CsgApiBase $CsgApiBase `
    -HostId $HostId `
    -RunnerPath $RunnerPath `
    -ProbePython $ProbePython `
    -ProbeConfig $ProbeConfig `
    -OutputPath $OutputPath *> $LogPath
  if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
    throw "Preflight did not produce its JSON evidence: $OutputPath"
  }
  return (Get-Content -LiteralPath $OutputPath -Raw | ConvertFrom-Json)
}

foreach ($trial in $trials) {
  $trialStartedAt = [DateTime]::UtcNow.ToString("o")
  $trialRoot = Join-Path $OutputRoot ([string]$trial.trial_id)
  $preflightDir = Join-Path $trialRoot "preflight"
  $rawDir = Join-Path $trialRoot "windows-raw"
  $null = New-Item -ItemType Directory -Path $preflightDir -Force
  $null = New-Item -ItemType Directory -Path $rawDir -Force
  $preflight = $null
  $postflight = $null
  $run = $null
  $trialError = $null
  $runPath = Join-Path $rawDir "run.json"
  $runnerStdout = Join-Path $rawDir "runner.stdout.log"
  $runnerStderr = Join-Path $rawDir "runner.stderr.log"
  $runnerExitCode = $null

  try {
    $preflight = Invoke-EndpointPreflight `
      -TargetName ([string]$trial.target_task_name) `
      -OutputPath (Join-Path $preflightDir "windows-preflight.json") `
      -LogPath (Join-Path $preflightDir "preflight.log")
    if (-not $preflight.target_absent -or @($preflight.residual_csgapt_tasks).Count -ne 0) {
      throw "Target/residual-task preflight failed."
    }

    $runnerArguments = @(
      "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $RunnerPath,
      "-CsgApiBase", $CsgApiBase,
      "-HostId", $HostId,
      "-ProbePython", $ProbePython,
      "-ProbeConfig", $ProbeConfig,
      "-WaitSeconds", [string]$WaitSeconds,
      "-OutputPath", $runPath,
      "-ScheduledTaskName", [string]$trial.target_task_name,
      "-ScenarioFilter", "scheduled_task"
    )
    $argumentLine = ($runnerArguments | ForEach-Object {
      '"' + [string]$_ + '"'
    }) -join " "
    $runnerProcess = Start-Process `
      -FilePath (Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe") `
      -ArgumentList $argumentLine `
      -Wait -PassThru -NoNewWindow `
      -RedirectStandardOutput $runnerStdout `
      -RedirectStandardError $runnerStderr
    $runnerExitCode = [int]$runnerProcess.ExitCode
    if ($runnerExitCode -ne 0) { throw "Runner process exited with code $runnerExitCode." }
    if (Test-Path -LiteralPath $runPath -PathType Leaf) {
      $run = Get-Content -LiteralPath $runPath -Raw | ConvertFrom-Json
    } else {
      throw "Runner produced no final run.json; progress and log are retained."
    }

    $postflight = Invoke-EndpointPreflight `
      -TargetName ([string]$trial.target_task_name) `
      -OutputPath (Join-Path $trialRoot "postflight.json") `
      -LogPath (Join-Path $trialRoot "postflight.log")
    if (-not $postflight.target_absent -or @($postflight.residual_csgapt_tasks).Count -ne 0) {
      throw "Postflight found a residual study task."
    }
    if ($run.status -ne "ALL_REQUIRED_POSITIVE_CONTROLS_PASSED" -or
      $run.validation.passed_positive_controls -ne 1 -or
      -not $run.validation.all_positive_controls_passed) {
      throw "Frozen strict positive-control gate failed."
    }
  } catch {
    $trialError = $_.Exception.Message
    $campaignError = "Trial $($trial.trial_id): $trialError"
  }

  $records.Add([ordered]@{
    trial_id = [string]$trial.trial_id
    target_task_name = [string]$trial.target_task_name
    started_at_utc = $trialStartedAt
    ended_at_utc = [DateTime]::UtcNow.ToString("o")
    run_artifact = $runPath
    runner_status = if ($run) { $run.status } else { "NO_FINAL_RUN" }
    runner_exit_code = $runnerExitCode
    positive_control_passed = [bool]($run -and $run.validation.all_positive_controls_passed)
    preflight_target_absent = if ($preflight) { [bool]$preflight.target_absent } else { $false }
    postflight_target_absent = if ($postflight) { [bool]$postflight.target_absent } else { $null }
    cleanup_verified = [bool]($postflight -and $postflight.target_absent -and
      @($postflight.residual_csgapt_tasks).Count -eq 0)
    error = $trialError
  })

  if ($trialError) { break }
}

$passed = @($records | Where-Object {
  $_.positive_control_passed -and $_.preflight_target_absent -and
  $_.postflight_target_absent -and $_.cleanup_verified -and -not $_.error
})
$summary = [ordered]@{
  schema_version = "csg-scheduled-task-complete-replicate-campaign-v1"
  experiment_id = $schedule.experiment_id
  host_id = $HostId
  condition = "complete_telemetry_exact_target_positive_control"
  assigned_trial_count = $trials.Count
  attempted_trial_count = $records.Count
  passed_trial_count = $passed.Count
  campaign_status = if ($records.Count -eq $trials.Count -and $passed.Count -eq $trials.Count) {
    "ALL_ASSIGNED_TRIALS_PASSED"
  } else { "INCOMPLETE_OR_GATE_FAILURE" }
  started_at_utc = $startedAt
  ended_at_utc = [DateTime]::UtcNow.ToString("o")
  runner_sha256 = $actualRunnerHash
  agent_config_sha256 = $ExpectedAgentConfigSha256.ToLowerInvariant()
  reconciliation_grace_seconds = 180
  wait_seconds = $WaitSeconds
  error = $campaignError
  trials = @($records)
  interpretation = "Benign single-host positive-control repetitions; not attack-detection accuracy or cross-host reliability."
}
$summaryPath = Join-Path $OutputRoot "campaign-summary.json"
$summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
Write-Host "Campaign $($summary.campaign_status): $($passed.Count)/$($trials.Count) assigned trials passed; attempted $($records.Count)."
if ($summary.campaign_status -ne "ALL_ASSIGNED_TRIALS_PASSED") { exit 1 }
