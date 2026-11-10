param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [Parameter(Mandatory = $true)]
    [string]$CampaignId,
    [Parameter(Mandatory = $true)]
    [string]$ProtocolSha256,
    [string]$CsgApiBase = "http://192.168.64.1:8000",
    [string]$HostId = "win11-arm-lab",
    [string]$ProbePython = "C:\Program Files\CyberStateGuardian\Probe\venv\Scripts\python.exe",
    [string]$ProbeConfig = "C:\Program Files\CyberStateGuardian\Probe\settings.json",
    [string]$TrialController = "C:\CSG\run_windows_scheduled_task_complete_distractor_v3.ps1",
    [int]$Repetitions = 10,
    [int]$RandomSeed = 2026101104,
    [int]$WaitSeconds = 35,
    [int]$EventTimeToleranceSeconds = 20,
    [switch]$PreflightOnly
)

$ErrorActionPreference = "Stop"
if ($Repetitions -lt 1 -or $Repetitions -gt 30) { throw "Repetitions must be 1..30." }
if ($ProtocolSha256 -notmatch '^[A-Fa-f0-9]{64}$') { throw "ProtocolSha256 must be a SHA-256 digest." }
if ($CampaignId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,100}$') { throw "CampaignId is invalid." }
if ($WaitSeconds -lt 10 -or $WaitSeconds -gt 180) { throw "WaitSeconds must be 10..180." }
if ($EventTimeToleranceSeconds -lt 1 -or $EventTimeToleranceSeconds -gt 120) {
    throw "EventTimeToleranceSeconds must be 1..120."
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Run this controlled lab campaign from Administrator PowerShell." }
if (-not (Test-Path -LiteralPath $ProbePython -PathType Leaf)) { throw "Probe Python is missing." }
if (-not (Test-Path -LiteralPath $ProbeConfig -PathType Leaf)) { throw "Probe config is missing." }
if (-not (Test-Path -LiteralPath $TrialController -PathType Leaf)) { throw "Trial controller is missing." }

$settings = Get-Content -LiteralPath $ProbeConfig -Raw | ConvertFrom-Json
if ($settings.CSG_PROBE_HOST_ID -ne $HostId) { throw "Configured probe host ID does not match." }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw "Refusing to overwrite $OutputDirectory" }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$trialsDirectory = Join-Path $OutputDirectory "trials"
New-Item -ItemType Directory -Path $trialsDirectory -Force | Out-Null

function Get-WazuhProof {
    $service = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
    if ($null -eq $service) { throw "WazuhSvc is not installed." }
    return [ordered]@{
        name = $service.Name
        status = $service.State
        process_id = [int]$service.ProcessId
        start_mode = $service.StartMode
        captured_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    }
}

function Get-LabHealth {
    $wazuh = Get-WazuhProof
    if ($wazuh.status -ne "Running" -or $wazuh.process_id -le 0) {
        throw "WazuhSvc is not Running with a process ID."
    }
    $sysmon = Get-Service -Name Sysmon64a -ErrorAction Stop
    if ($sysmon.Status -ne "Running") { throw "Sysmon64a is not Running." }
    $latest = Invoke-RestMethod -Method Get -TimeoutSec 25 `
        -Uri "$($CsgApiBase.TrimEnd('/'))/api/hosts/$HostId/observations/latest"
    if (-not $latest.observation_id) { throw "CSG latest observation is missing an ID." }
    $taskSnapshot = $latest.categories.scheduled_task
    if ($null -eq $taskSnapshot -or $taskSnapshot.status -ne "healthy" -or -not $taskSnapshot.observed_at) {
        throw "Latest CSG observation has no healthy scheduled-task snapshot."
    }
    $taskSampleAt = [datetimeoffset]::Parse([string]$taskSnapshot.observed_at).UtcDateTime
    $taskSampleAge = ((Get-Date).ToUniversalTime() - $taskSampleAt).TotalSeconds
    if ($taskSampleAge -lt -5 -or $taskSampleAge -gt 300) {
        throw "Scheduled-task snapshot is outside the registered 0..300 second freshness bound."
    }
    $transitionStatus = Invoke-RestMethod -Method Get -TimeoutSec 25 `
        -Uri "$($CsgApiBase.TrimEnd('/'))/api/transition-capture/status?host_id=$HostId"
    $continuousTaskMonitorEnabled = [bool]$transitionStatus.categories.scheduled_task.enabled
    return [ordered]@{
        observed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        wazuh = $wazuh
        sysmon_status = [string]$sysmon.Status
        latest_observation_id = [string]$latest.observation_id
        latest_observation_at = [string]$latest.observed_at
        scheduled_task_snapshot_status = [string]$taskSnapshot.status
        scheduled_task_sample_at = [string]$taskSnapshot.observed_at
        scheduled_task_sample_age_seconds = [math]::Round($taskSampleAge, 3)
        scheduled_task_count = @($taskSnapshot.items).Count
        continuous_task_transition_monitor_enabled = $continuousTaskMonitorEnabled
    }
}

function Save-Manifest {
    $temporaryPath = "$manifestPath.tmp"
    $manifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
    Move-Item -LiteralPath $temporaryPath -Destination $manifestPath -Force
}

$sourceHash = (Get-FileHash -LiteralPath $MyInvocation.MyCommand.Path -Algorithm SHA256).Hash.ToLowerInvariant()
$controllerHash = (Get-FileHash -LiteralPath $TrialController -Algorithm SHA256).Hash.ToLowerInvariant()
$probeSettingsHash = (Get-FileHash -LiteralPath $ProbeConfig -Algorithm SHA256).Hash.ToLowerInvariant()
$beforeHealth = Get-LabHealth
$preexistingTasks = @(Get-ScheduledTask | Where-Object { $_.TaskName -like "CSGAPTTask*" -or $_.TaskName -like "CSGAPTDis*" })
if ($preexistingTasks.Count -gt 0) {
    throw "Refusing to begin: pre-existing CSGAPT lab tasks require review and cleanup."
}

$ids = 1..$Repetitions
$rng = New-Object System.Random($RandomSeed)
for ($index = $ids.Count - 1; $index -gt 0; $index--) {
    $swapIndex = $rng.Next($index + 1)
    $temporary = $ids[$index]
    $ids[$index] = $ids[$swapIndex]
    $ids[$swapIndex] = $temporary
}
$schedule = @(
    for ($position = 0; $position -lt $ids.Count; $position++) {
        [ordered]@{
            sequence = $position + 1
            trial_id = "task-complete-distractor-{0:D2}" -f $ids[$position]
            condition = "complete_distractor"
            status = "ASSIGNED"
            output_directory = Join-Path $trialsDirectory ("task-complete-distractor-{0:D2}" -f $ids[$position])
        }
    }
)
$manifestPath = Join-Path $OutputDirectory "campaign-manifest.json"
$manifest = [ordered]@{
    schema_version = "csg-scheduled-task-distractor-campaign-v3"
    campaign_id = $CampaignId
    strict_gate_version = "v2-store-readback-before-target-evaluation"
    campaign_controller_version = "v3-record-interrupted-assignment-on-exit"
    experiment_family = "scheduled_task_exact_object_matching"
    execution_kind = "live_windows_complete_telemetry_distractor_extension"
    status = "RUNNING"
    host_id = $HostId
    random_seed = $RandomSeed
    protocol_sha256 = $ProtocolSha256.ToLowerInvariant()
    campaign_runner_sha256 = $sourceHash
    trial_controller_sha256 = $controllerHash
    probe_settings_sha256 = $probeSettingsHash
    csg_api_base = $CsgApiBase
    windows = Get-CimInstance Win32_OperatingSystem | ForEach-Object {
        [ordered]@{ caption = $_.Caption; version = $_.Version; build = $_.BuildNumber; architecture = $_.OSArchitecture }
    }
    settings = [ordered]@{
        repetitions = $Repetitions
        random_seed = $RandomSeed
        wait_seconds = $WaitSeconds
        event_time_tolerance_seconds = $EventTimeToleranceSeconds
        condition = "complete_distractor"
        task_action = "cmd.exe /c exit 0"
        task_trigger = "one hour after creation; not expected to execute during the trial"
    }
    source_at_start = $beforeHealth
    planned_trials = @($schedule | ForEach-Object {
        [ordered]@{ sequence = $_.sequence; trial_id = $_.trial_id; condition = $_.condition }
    })
    trials = @($schedule)
    started_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    completed_at_utc = $null
    source_at_end = $null
    failure = $null
}
Save-Manifest
if ($PreflightOnly) {
    $manifest.status = "PREFLIGHT_ONLY_NO_MUTATIONS"
    $manifest.completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    Save-Manifest
    Write-Output "Preflight manifest: $manifestPath"
    Write-Output ("Preflight passed; assigned={0}; seed={1}" -f $schedule.Count, $RandomSeed)
    exit 0
}

$campaignFailure = $null
try {
    foreach ($entry in $schedule) {
        try {
            $health = Get-LabHealth
            $entry.status = "RUNNING"
            $entry.started_at_utc = (Get-Date).ToUniversalTime().ToString("o")
            $entry.pre_trial_health = $health
            Save-Manifest

            $stdout = Join-Path $entry.output_directory "controller.stdout.txt"
            $stderr = Join-Path $entry.output_directory "controller.stderr.txt"
            $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$TrialController`" " +
                "-OutputDirectory `"$($entry.output_directory)`" -CampaignId `"$CampaignId`" " +
                "-CsgApiBase `"$CsgApiBase`" -HostId `"$HostId`" -ProbePython `"$ProbePython`" " +
                "-ProbeConfig `"$ProbeConfig`" -WaitSeconds $WaitSeconds " +
                "-EventTimeToleranceSeconds $EventTimeToleranceSeconds"
            $child = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -PassThru -Wait `
                -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden
            $entry.controller_exit_code = [int]$child.ExitCode
            $trialPath = Join-Path $entry.output_directory "trial.json"
            if (Test-Path -LiteralPath $trialPath) {
                $trial = Get-Content -LiteralPath $trialPath -Raw | ConvertFrom-Json
                $entry.trial_status = $trial.status
                $entry.cleanup_verified = [bool]$trial.cleanup_verified
                $entry.target_task_name = $trial.target_task_name
                $entry.distractor_task_name = $trial.distractor_task_name
                $entry.condition_checks = $trial.condition_checks
                $entry.trial_artifact = $trialPath
                $checks = $trial.condition_checks
                $allChecks = $checks.target_positive_control_passed -and
                    $checks.distractor_event_ingested -and
                    $checks.same_host_and_event_class_different_object -and
                    $checks.distractor_event_inside_target_padded_window -and
                    $checks.both_objects_observed_in_one_probe_snapshot -and
                    $checks.target_consistent_with_only_target_evidence -and
                    $checks.distractor_available_before_target_evaluation -and
                    $checks.cleanup_verified -and $checks.wazuh_service_running_after_trial
                $entry.status = if ($trial.status -eq "PASS" -and $allChecks -and
                    $entry.controller_exit_code -eq 0) { "PASS" } else { "FAIL" }
            } else {
                $entry.status = "CONTROLLER_FAILED_NO_TRIAL_JSON"
            }
            $entry.ended_at_utc = (Get-Date).ToUniversalTime().ToString("o")
            $entry.post_trial_health = Get-LabHealth
            if ($entry.status -ne "PASS") {
                $entry.failure = "Trial did not pass every registered exact-object, health, and cleanup gate."
            }
            Save-Manifest
        } catch {
            $entry.status = "CONTROLLER_OR_HEALTH_FAILURE"
            $entry.failure = "line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
            $entry.ended_at_utc = (Get-Date).ToUniversalTime().ToString("o")
            $campaignFailure = $entry.failure
            Save-Manifest
            break
        }
    }
} finally {
    try { $manifest.source_at_end = Get-LabHealth } catch {
        $manifest.source_at_end = [ordered]@{ status = "UNAVAILABLE"; error = $_.Exception.Message }
        if (-not $campaignFailure) { $campaignFailure = "Final health check failed: $($_.Exception.Message)" }
    }
    foreach ($entry in $schedule) {
        if ($entry.status -eq "ASSIGNED") { $entry.status = "NOT_RUN_AFTER_FAILURE" }
        elseif ($entry.status -eq "RUNNING") {
            $entry.status = "INTERRUPTED_CONTROLLER_WITH_TRIAL_ARTIFACT_AUDIT_REQUIRED"
            $entry.ended_at_utc = (Get-Date).ToUniversalTime().ToString("o")
            $entry.failure = "Campaign controller exited before recording the child trial outcome; preserve and audit the child artifact and endpoint cleanup."
            if (-not $campaignFailure) {
                $campaignFailure = "Campaign controller exited while a child trial was marked RUNNING."
            }
        }
    }
    $manifest.failure = $campaignFailure
    $manifest.completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    $failed = @($schedule | Where-Object { $_.status -ne "PASS" }).Count
    $interrupted = @($schedule | Where-Object {
        $_.status -eq "INTERRUPTED_CONTROLLER_WITH_TRIAL_ARTIFACT_AUDIT_REQUIRED"
    }).Count -gt 0
    $manifest.status = if ($interrupted) { "INTERRUPTED_WITH_GAPS" } elseif ($failed -eq 0) {
        "COMPLETED"
    } elseif ($failed -eq $schedule.Count) {
        "FAILED"
    } else {
        "COMPLETED_WITH_GAPS"
    }
    Save-Manifest
}

Write-Output "Campaign manifest: $manifestPath"
Write-Output ("Status={0}; assigned={1}; passed={2}; failed_or_not_run={3}" -f `
    $manifest.status, $schedule.Count, @($schedule | Where-Object { $_.status -eq "PASS" }).Count, `
    @($schedule | Where-Object { $_.status -ne "PASS" }).Count)
if ($manifest.status -ne "COMPLETED") { exit 2 }
