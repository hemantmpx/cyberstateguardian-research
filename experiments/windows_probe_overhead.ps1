param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [int]$Pairs = 6,
    [int]$WarmupSeconds = 15,
    [int]$MeasureSeconds = 60,
    [int]$SampleSeconds = 5,
    [int]$Seed = 20261016,
    [switch]$BalancedOrder,
    [switch]$PreflightOnly
)

$ErrorActionPreference = 'Stop'
$taskName = 'CyberStateGuardian Probe'
$probePattern = '*C:\Program Files\CyberStateGuardian\Probe\settings.json*'
$samplePath = Join-Path $OutputDirectory 'samples.jsonl'
$metadataPath = Join-Path $OutputDirectory 'metadata.json'
$logPath = Join-Path $OutputDirectory 'execution.log'
$cpuCount = [Environment]::ProcessorCount
$initialTask = $null
$initialTaskRunning = $false
$initialTaskEnabled = $false
$wazuhInitiallyRunning = $false
$cleanup = [ordered]@{ attempted = $false; task_running = $null; task_enabled = $null; wazuh_running = $null; errors = @() }

function Write-Log([string]$Message) {
    $line = "$([DateTime]::UtcNow.ToString('o')) $Message"
    Add-Content -LiteralPath $logPath -Value $line -Encoding utf8
    Write-Output $line
}

function Get-ProbeProcesses {
    $matches = @(Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
        Where-Object { $_.CommandLine -and $_.CommandLine.Contains('cyberstateguardian_probe.main') -and $_.CommandLine.Contains($probePattern.Trim('*')) })
    $processes = @($matches | ForEach-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue })
    [pscustomobject]@{
        ids = @($matches | ForEach-Object { [int]$_.ProcessId })
        cpu_seconds = [double](($processes | Measure-Object -Property CPU -Sum).Sum)
        working_set_bytes = [long](($processes | Measure-Object -Property WorkingSet64 -Sum).Sum)
    }
}

function Get-WazuhProcesses {
    $matches = @(Get-CimInstance Win32_Process -Filter "Name LIKE 'wazuh%'" -ErrorAction SilentlyContinue)
    $processes = @($matches | ForEach-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue })
    [pscustomobject]@{
        ids = @($matches | ForEach-Object { [int]$_.ProcessId })
        cpu_seconds = [double](($processes | Measure-Object -Property CPU -Sum).Sum)
        working_set_bytes = [long](($processes | Measure-Object -Property WorkingSet64 -Sum).Sum)
    }
}

function Set-ProbeState([bool]$Running) {
    if ($Running) {
        $before = Get-ScheduledTask -TaskName $taskName
        if (-not $before.Settings.Enabled) { Enable-ScheduledTask -TaskName $taskName | Out-Null }
        if ($before.State.ToString() -ne 'Running') { Start-ScheduledTask -TaskName $taskName }
        $deadline = (Get-Date).AddSeconds(45)
        do {
            Start-Sleep -Seconds 1
            $state = (Get-ScheduledTask -TaskName $taskName).State.ToString()
            $probe = Get-ProbeProcesses
        } while ((($state -ne 'Running') -or ($probe.ids.Count -eq 0)) -and (Get-Date) -lt $deadline)
        if ($state -ne 'Running' -or $probe.ids.Count -eq 0) { throw 'Probe task/process did not become running within 45 seconds.' }
    } else {
        $before = Get-ScheduledTask -TaskName $taskName
        if ($before.Settings.Enabled) { Disable-ScheduledTask -TaskName $taskName | Out-Null }
        if ($before.State.ToString() -eq 'Running') { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
        $deadline = (Get-Date).AddSeconds(45)
        do {
            Start-Sleep -Seconds 1
            $state = (Get-ScheduledTask -TaskName $taskName).State.ToString()
            $probe = Get-ProbeProcesses
        } while ((($state -ne 'Disabled') -or ($probe.ids.Count -ne 0)) -and (Get-Date) -lt $deadline)
        if ($probe.ids.Count -ne 0) { throw 'Probe collector process remained after stopping its scheduled task; aborting without force-killing it.' }
    }
}

function Get-PhaseMeasurements([string]$PairId, [string]$Condition, [int]$Position) {
    $phaseStart = [DateTime]::UtcNow
    $watch = [Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Seconds $WarmupSeconds
    $previousProbe = Get-ProbeProcesses
    $previousWazuh = Get-WazuhProcesses
    $previousSeconds = $watch.Elapsed.TotalSeconds
    $plannedSamples = [Math]::Floor($MeasureSeconds / $SampleSeconds)

    for ($index = 1; $index -le $plannedSamples; $index++) {
        $targetSeconds = $WarmupSeconds + ($index * $SampleSeconds)
        $remaining = $targetSeconds - $watch.Elapsed.TotalSeconds
        if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int]($remaining * 1000)) }
        $observedAt = [DateTime]::UtcNow
        $elapsed = $watch.Elapsed.TotalSeconds
        $perf = Get-Counter -Counter @('\Processor(_Total)\% Processor Time', '\Memory\Available MBytes') -SampleInterval 1 -MaxSamples 1
        $processor = [double](($perf.CounterSamples | Where-Object { $_.Path -match '\\% Processor Time$' } | Select-Object -First 1).CookedValue)
        $availableMemory = [double](($perf.CounterSamples | Where-Object { $_.Path -match '\\Available MBytes$' } | Select-Object -First 1).CookedValue)
        $probe = Get-ProbeProcesses
        $wazuh = Get-WazuhProcesses
        $interval = $elapsed - $previousSeconds
        $probeCpuPct = $null
        if ($probe.ids.Count -gt 0 -and (Compare-Object $previousProbe.ids $probe.ids).Count -eq 0 -and $interval -gt 0) {
            $probeCpuPct = 100 * ($probe.cpu_seconds - $previousProbe.cpu_seconds) / ($interval * $cpuCount)
        }
        $wazuhCpuPct = $null
        if ($wazuh.ids.Count -gt 0 -and (Compare-Object $previousWazuh.ids $wazuh.ids).Count -eq 0 -and $interval -gt 0) {
            $wazuhCpuPct = 100 * ($wazuh.cpu_seconds - $previousWazuh.cpu_seconds) / ($interval * $cpuCount)
        }
        $task = Get-ScheduledTask -TaskName $taskName
        $service = Get-Service -Name WazuhSvc
        $row = [ordered]@{
            pair_id = $PairId
            order_position = $Position
            condition = $Condition
            sample_index = $index
            timestamp_utc = $observedAt.ToString('o')
            phase_elapsed_seconds = [Math]::Round($elapsed, 3)
            interval_seconds = [Math]::Round($interval, 3)
            host_cpu_percent = [Math]::Round($processor, 3)
            available_memory_mib = [Math]::Round($availableMemory, 2)
            probe_process_count = $probe.ids.Count
            probe_process_ids = $probe.ids
            probe_cpu_percent_of_host_capacity = if ($null -eq $probeCpuPct) { $null } else { [Math]::Round($probeCpuPct, 4) }
            probe_working_set_mib = [Math]::Round($probe.working_set_bytes / 1MB, 3)
            wazuh_process_count = $wazuh.ids.Count
            wazuh_cpu_percent_of_host_capacity = if ($null -eq $wazuhCpuPct) { $null } else { [Math]::Round($wazuhCpuPct, 4) }
            wazuh_working_set_mib = [Math]::Round($wazuh.working_set_bytes / 1MB, 3)
            probe_task_state = $task.State.ToString()
            wazuh_service_state = $service.Status.ToString()
        }
        ($row | ConvertTo-Json -Compress -Depth 5) | Add-Content -LiteralPath $samplePath -Encoding utf8
        if ($service.Status -ne 'Running') { throw 'WazuhSvc stopped during a measurement phase; aborting.' }
        if (($Condition -eq 'probe_on' -and $probe.ids.Count -eq 0) -or ($Condition -eq 'probe_off' -and $probe.ids.Count -ne 0)) {
            throw "Probe process condition was violated during $PairId/$Condition."
        }
        $previousProbe = $probe
        $previousWazuh = $wazuh
        $previousSeconds = $elapsed
    }
    [pscustomobject]@{ condition = $Condition; started_utc = $phaseStart.ToString('o'); ended_utc = [DateTime]::UtcNow.ToString('o'); samples = $plannedSamples }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
Set-Content -LiteralPath $logPath -Value '' -Encoding utf8
try {
    if ($Pairs -lt 2 -or $WarmupSeconds -lt 0 -or $MeasureSeconds -lt $SampleSeconds -or $SampleSeconds -lt 1) {
        throw 'Invalid design parameters: require at least two pairs and positive measurement/sample intervals.'
    }
    if (($MeasureSeconds % $SampleSeconds) -ne 0) { throw 'MeasureSeconds must divide evenly by SampleSeconds.' }
    if ($BalancedOrder -and (($Pairs % 2) -ne 0)) { throw 'BalancedOrder requires an even number of pairs.' }
    $initialTask = Get-ScheduledTask -TaskName $taskName
    $initialTaskRunning = $initialTask.State.ToString() -eq 'Running'
    $initialTaskEnabled = [bool]$initialTask.Settings.Enabled
    $wazuhInitiallyRunning = (Get-Service -Name WazuhSvc).Status -eq 'Running'
    if (-not $initialTaskRunning -or -not $initialTaskEnabled) { throw 'Precondition failed: probe task must begin enabled and running.' }
    if (-not $wazuhInitiallyRunning) { throw 'Precondition failed: WazuhSvc must begin running.' }
    if ((Get-ProbeProcesses).ids.Count -eq 0) { throw 'Precondition failed: exact CSG probe process signature was not found.' }
    $os = Get-CimInstance Win32_OperatingSystem
    $planRng = [Random]::new($Seed)
    $plan = @()
    $firstConditions = @()
    if ($BalancedOrder) {
        for ($i = 0; $i -lt ($Pairs / 2); $i++) { $firstConditions += 'probe_off' }
        for ($i = 0; $i -lt ($Pairs / 2); $i++) { $firstConditions += 'probe_on' }
        for ($i = $firstConditions.Count - 1; $i -gt 0; $i--) {
            $j = $planRng.Next(0, $i + 1)
            $temp = $firstConditions[$i]
            $firstConditions[$i] = $firstConditions[$j]
            $firstConditions[$j] = $temp
        }
    }
    for ($pair = 1; $pair -le $Pairs; $pair++) {
        if ($BalancedOrder) {
            $first = $firstConditions[$pair - 1]
        } else {
            $first = if ($planRng.Next(0, 2) -eq 0) { 'probe_off' } else { 'probe_on' }
        }
        $second = if ($first -eq 'probe_off') { 'probe_on' } else { 'probe_off' }
        $plan += [pscustomobject]@{ pair_id = ('pair-{0:D2}' -f $pair); order = @($first, $second) }
    }
    $metadata = [ordered]@{
        experiment_id = 'single-host-csg-probe-overhead-pilot'
        status = 'running'
        protocol_version = '1.0'
        started_utc = [DateTime]::UtcNow.ToString('o')
        seed = $Seed
        pairs = $Pairs
        warmup_seconds = $WarmupSeconds
        measurement_seconds_per_condition = $MeasureSeconds
        sample_period_seconds = $SampleSeconds
        randomization_method = if ($BalancedOrder) { 'seeded balanced sequence; equal first-condition counts' } else { 'seeded independent order per pair' }
        cpu_logical_processors = $cpuCount
        windows = [ordered]@{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber; architecture = $env:PROCESSOR_ARCHITECTURE; total_memory_mib = [Math]::Round($os.TotalVisibleMemorySize / 1024, 2) }
        probe_task_initial_state = $initialTask.State.ToString()
        probe_task_initial_enabled = $initialTaskEnabled
        probe_task_action = $initialTask.Actions | ForEach-Object { [ordered]@{ execute = $_.Execute; arguments = $_.Arguments; working_directory = $_.WorkingDirectory } }
        probe_script_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
        probe_settings_sha256 = (Get-FileHash -LiteralPath 'C:\Program Files\CyberStateGuardian\Probe\settings.json' -Algorithm SHA256).Hash
        probe_process_initial = (Get-ProbeProcesses).ids
        wazuh_service_initial_state = (Get-Service WazuhSvc).Status.ToString()
        wazuh_process_initial = (Get-WazuhProcesses).ids
        randomized_plan = $plan
        phases = @()
        cleanup = $cleanup
        limitations = @('One Windows 11 ARM VM; exploratory operational-overhead pilot only.', 'Paired blocks are the independent units; within-block samples are repeated measurements, not independent trials.', 'No service, task, registry, account, firewall, or security configuration mutations are performed.', 'Host CPU and available-memory differences can be affected by background workload; Wazuh remains enabled in both conditions.')
    }
    $metadata | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $metadataPath -Encoding utf8
    Write-Log "Starting overhead pilot. Plan is frozen in $metadataPath."
    if ($PreflightOnly) {
        Set-ProbeState $false
        Set-ProbeState $true
        $metadata.status = 'preflight_passed'
        Write-Log 'Preflight stop/start verified; no measurement samples collected.'
    } else {
        foreach ($block in $plan) {
            $position = 0
            foreach ($condition in $block.order) {
                $position++
                Set-ProbeState ($condition -eq 'probe_on')
                if ((Get-Service -Name WazuhSvc).Status -ne 'Running') { throw 'WazuhSvc is not running before a phase.' }
                $phase = Get-PhaseMeasurements -PairId $block.pair_id -Condition $condition -Position $position
                $metadata.phases += [pscustomobject]@{ pair_id = $block.pair_id; order_position = $position; condition = $condition; started_utc = $phase.started_utc; ended_utc = $phase.ended_utc; samples = $phase.samples }
                $metadata.status = 'running'
                $metadata | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $metadataPath -Encoding utf8
                Write-Log "Completed $($block.pair_id) position $position ($condition)."
            }
        }
        $metadata.status = 'completed'
    }
} catch {
    if ($metadata) { $metadata.status = 'failed'; $metadata.failure = $_.Exception.Message }
    Write-Log "ERROR: $($_.Exception.Message)"
} finally {
    $cleanup.attempted = $true
    try {
        if ($initialTaskEnabled -and $initialTaskRunning) { Set-ProbeState $true }
        elseif ($initialTaskEnabled) { Enable-ScheduledTask -TaskName $taskName | Out-Null }
        else { Disable-ScheduledTask -TaskName $taskName | Out-Null }
    } catch { $cleanup.errors += "Probe restoration: $($_.Exception.Message)" }
    try { $cleanup.task_running = (Get-ScheduledTask -TaskName $taskName).State.ToString() -eq 'Running' } catch { $cleanup.errors += "Probe status: $($_.Exception.Message)" }
    try { $cleanup.task_enabled = [bool](Get-ScheduledTask -TaskName $taskName).Settings.Enabled } catch { $cleanup.errors += "Probe enabled status: $($_.Exception.Message)" }
    try { $cleanup.wazuh_running = (Get-Service -Name WazuhSvc).Status -eq 'Running' } catch { $cleanup.errors += "Wazuh status: $($_.Exception.Message)" }
    if ($metadata) {
        $metadata.cleanup = $cleanup
        if ($cleanup.errors.Count -gt 0 -and $metadata.status -eq 'completed') { $metadata.status = 'completed_with_cleanup_error' }
        $metadata.ended_utc = [DateTime]::UtcNow.ToString('o')
        $metadata | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $metadataPath -Encoding utf8
    }
    Write-Log "Cleanup verified: probe_running=$($cleanup.task_running), probe_enabled=$($cleanup.task_enabled), wazuh_running=$($cleanup.wazuh_running)."
}
if ($metadata -and ($metadata.status -eq 'failed' -or $cleanup.errors.Count -gt 0 -or -not $cleanup.task_running -or -not $cleanup.task_enabled -or -not $cleanup.wazuh_running)) { exit 1 }
