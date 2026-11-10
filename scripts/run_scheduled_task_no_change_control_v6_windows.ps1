param(
    [Parameter(Mandatory = $true)] [string]$OutputDirectory,
    [Parameter(Mandatory = $true)] [string]$ProtocolPath,
    [Parameter(Mandatory = $true)] [string]$ProtocolSha256,
    [string]$CsgApiBase = "http://192.168.64.1:8000",
    [string]$HostId = "win11-arm-lab",
    [string]$ProbePython = "C:\Program Files\CyberStateGuardian\Probe\venv\Scripts\python.exe",
    [string]$ProbeConfig = "C:\Program Files\CyberStateGuardian\Probe\settings.json",
    [int]$Repetitions = 10,
    [int]$IntervalSeconds = 10,
    [int]$RandomSeed = 20261012
)

$ErrorActionPreference = "Stop"
if ($Repetitions -lt 1 -or $Repetitions -gt 10) { throw "Repetitions must be 1..10." }
if ($IntervalSeconds -lt 5 -or $IntervalSeconds -gt 30) { throw "IntervalSeconds must be 5..30." }
if ($ProtocolSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "ProtocolSha256 must be SHA-256." }
if (-not (Test-Path -LiteralPath $ProbePython)) { throw "Probe Python missing: $ProbePython" }
if (-not (Test-Path -LiteralPath $ProbeConfig)) { throw "Probe config missing: $ProbeConfig" }
if (-not (Test-Path -LiteralPath $ProtocolPath)) { throw "Frozen protocol missing: $ProtocolPath" }
if ((Get-FileHash -LiteralPath $ProtocolPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
    $ProtocolSha256.ToLowerInvariant()) { throw "Protocol hash does not match frozen value." }
if (Test-Path -LiteralPath $OutputDirectory) { throw "Refusing to overwrite $OutputDirectory" }
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) { throw "Run from elevated PowerShell." }

$probeSettings = Get-Content -LiteralPath $ProbeConfig -Raw | ConvertFrom-Json
if ($probeSettings.CSG_PROBE_HOST_ID -ne $HostId) { throw "Probe host ID mismatch." }
$scriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$probeConfigHash = (Get-FileHash -LiteralPath $ProbeConfig -Algorithm SHA256).Hash.ToLowerInvariant()

function Save-Json([string]$Path, [object]$Value) {
    $Value | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $Path -Encoding UTF8
}
function Invoke-Api([string]$Path) {
    $response = Invoke-RestMethod -Method Get -TimeoutSec 45 -Uri "$($CsgApiBase.TrimEnd('/'))$Path"
    if ($response -is [array]) {
        foreach ($item in $response) { $item }
    } else {
        $response
    }
}
function Invoke-Probe {
    & $ProbePython -m cyberstateguardian_probe.main --config $ProbeConfig --once
    if ($LASTEXITCODE -ne 0) { throw "Direct probe failed with exit code $LASTEXITCODE" }
    $value = Invoke-Api "/api/hosts/$HostId/observations/latest"
    if (-not $value -or $value.host_id -ne $HostId) { throw "Latest observation missing/wrong host." }
    return $value
}
function Get-HostHealth {
    $wazuh = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
    $sysmon = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -match '^Sysmon' })
    $status = Invoke-Api "/api/wazuh/status"
    $agent = @($status.agents | Where-Object { $_.name -eq $HostId } | Select-Object -First 1)[0]
    return [ordered]@{
        captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        api_ok = [bool]$status.ok
        wazuh_agent_status = if ($agent) { [string]$agent.status } else { 'MISSING' }
        wazuh_agent_version = if ($agent) { [string]$agent.version } else { $null }
        wazuh_service_state = if ($wazuh) { [string]$wazuh.State } else { 'MISSING' }
        wazuh_service_pid = if ($wazuh) { [int]$wazuh.ProcessId } else { 0 }
        sysmon_services = @($sysmon | ForEach-Object {
            [ordered]@{ name = $_.Name; state = [string]$_.State; process_id = [int]$_.ProcessId }
        })
    }
}
function Normalize-TaskName([object]$Value) {
    return ([string]$Value).Trim().TrimStart('\').ToLowerInvariant()
}
function Get-TaskNames([object]$Observation) {
    return @($Observation.categories.scheduled_task.items | ForEach-Object {
        Normalize-TaskName $_.task_name
    } | Sort-Object -Unique)
}
function Get-LocalCreateEvents([string]$Name, [datetime]$SinceLocal) {
    $found = @()
    foreach ($event in @(Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = 4698; StartTime = $SinceLocal
    } -ErrorAction SilentlyContinue)) {
        [xml]$xml = $event.ToXml()
        $field = @($xml.Event.EventData.Data | Where-Object {
            $_.Name -in @('TaskName', 'Task_Name')
        } | Select-Object -First 1)[0]
        if ($field -and (Normalize-TaskName $field.InnerText) -eq (Normalize-TaskName $Name)) {
            $found += [ordered]@{
                record_id = [long]$event.RecordId
                event_time_utc = $event.TimeCreated.ToUniversalTime().ToString('o')
                provider = [string]$event.ProviderName
                raw_xml = $event.ToXml()
            }
        }
    }
    return $found
}
function Test-HealthyTaskObservation([object]$Observation) {
    return ($Observation.categories.scheduled_task.status -eq 'healthy' -and
        $null -ne $Observation.categories.scheduled_task.observed_at)
}

$settings = Get-CimInstance Win32_OperatingSystem
$preHealth = Get-HostHealth
if (-not $preHealth.api_ok -or $preHealth.wazuh_agent_status -ne 'active' -or
    $preHealth.wazuh_service_state -ne 'Running' -or
    @($preHealth.sysmon_services | Where-Object state -eq 'Running').Count -eq 0) {
    throw "Preflight failed: CSG/Wazuh agent/services are not healthy."
}

$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$null = New-Item -ItemType Directory -Path (Join-Path $OutputDirectory 'trials') -Force
Copy-Item -LiteralPath $ProtocolPath -Destination (Join-Path $OutputDirectory 'PROTOCOL.md')
Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $OutputDirectory 'controller.ps1')
$environment = [ordered]@{
    captured_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    host_id = $HostId
    computer_name = $env:COMPUTERNAME
    os_caption = $settings.Caption
    os_version = $settings.Version
    os_build = $settings.BuildNumber
    powershell_version = $PSVersionTable.PSVersion.ToString()
    preflight_health = $preHealth
    protocol_sha256 = $ProtocolSha256.ToLowerInvariant()
    controller_sha256 = $scriptHash
    probe_config_sha256 = $probeConfigHash
    repetitions = $Repetitions
    interval_seconds = $IntervalSeconds
    random_seed = $RandomSeed
    mutation_policy = 'No task is created, modified, enabled, run, or deleted by this controller.'
}
Save-Json (Join-Path $OutputDirectory 'environment.json') $environment

$random = [System.Random]::new($RandomSeed)
$schedule = @(
    for ($i = 1; $i -le $Repetitions; $i++) {
        [ordered]@{
            trial_id = ('no-change-{0:D2}' -f $i)
            sentinel = ('CSGAPTNoChange{0}{1:D2}{2:X8}' -f $RandomSeed, $i, $random.Next())
            status = 'ASSIGNED'
        }
    }
)
$schedule = @($schedule | Sort-Object { $random.Next() })
$manifest = [ordered]@{
    schema_version = 'csg-scheduled-task-no-change-campaign-v1'
    campaign_id = "scheduled-task-no-change-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))"
    status = 'RUNNING'
    created_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    completed_at_utc = $null
    host_id = $HostId
    protocol_sha256 = $ProtocolSha256.ToLowerInvariant()
    controller_sha256 = $scriptHash
    random_seed = $RandomSeed
    interval_seconds = $IntervalSeconds
    assigned = $schedule
    trials = @()
}
$manifestPath = Join-Path $OutputDirectory 'campaign.json'
Save-Json $manifestPath $manifest

foreach ($assignment in $schedule) {
    $trialPath = Join-Path (Join-Path $OutputDirectory 'trials') "$($assignment.trial_id).json"
    $started = (Get-Date).ToUniversalTime()
    $trial = [ordered]@{
        trial_id = $assignment.trial_id
        sentinel_task_name = $assignment.sentinel
        condition = 'no_change'
        action_attempted = $false
        actions = @()
        started_at_utc = $started.ToString('o')
        pre_health = $null
        post_health = $null
        before_observation = $null
        after_observation = $null
        task_identity_changes = @()
        new_scheduled_task_deltas = @()
        new_scheduled_task_findings = @()
        exact_target_provider_events = @()
        exact_target_local_security_events = @()
        event_query = $null
        sentinel_absent_before = $false
        sentinel_absent_after = $false
        expected_target_event_status = 'NOT_APPLICABLE'
        status = 'FAILED'
        failure = $null
    }
    try {
        if (@(Get-ScheduledTask -TaskName $assignment.sentinel -TaskPath '\' -ErrorAction SilentlyContinue).Count -gt 0) {
            throw 'Seeded sentinel unexpectedly exists before trial.'
        }
        $trial.pre_health = Get-HostHealth
        if (-not $trial.pre_health.api_ok -or $trial.pre_health.wazuh_agent_status -ne 'active' -or
            $trial.pre_health.wazuh_service_state -ne 'Running' -or
            @($trial.pre_health.sysmon_services | Where-Object state -eq 'Running').Count -eq 0) {
            throw 'Pre-trial endpoint/CSG/Wazuh health gate failed.'
        }
        $before = Invoke-Probe
        if (-not (Test-HealthyTaskObservation $before)) { throw 'Before scheduled-task observation is unhealthy.' }
        $trial.sentinel_absent_before = @((Get-TaskNames $before) | Where-Object { $_ -eq (Normalize-TaskName $assignment.sentinel) }).Count -eq 0
        if (-not $trial.sentinel_absent_before) { throw 'Sentinel appears in before observation.' }
        $monitorStarted = (Get-Date).ToUniversalTime()
        $highWater = [long](Get-WinEvent -LogName Security -MaxEvents 1).RecordId
        $trial.before_observation = [ordered]@{
            observation_id = $before.observation_id
            observed_at = $before.observed_at
            category = $before.categories.scheduled_task
            task_identity_count = @(Get-TaskNames $before).Count
            task_names = Get-TaskNames $before
            security_log_high_water_record_id = $highWater
            interval_query_start_utc = $monitorStarted.ToString('o')
        }

        Start-Sleep -Seconds $IntervalSeconds
        $after = Invoke-Probe
        if (-not (Test-HealthyTaskObservation $after)) { throw 'After scheduled-task observation is unhealthy.' }
        $trial.sentinel_absent_after = @((Get-TaskNames $after) | Where-Object { $_ -eq (Normalize-TaskName $assignment.sentinel) }).Count -eq 0
        $createdAfter = [uri]::EscapeDataString($monitorStarted.ToString('o'))
        $afterDeltas = @(Invoke-Api "/api/hosts/$HostId/deltas?limit=500&created_after=$createdAfter&category=scheduled_task")
        $afterFindings = @(Invoke-Api "/api/findings?host_id=$HostId&limit=500&created_after=$createdAfter&category=scheduled_task")
        $beforeTaskNames = @(Get-TaskNames $before)
        $afterTaskNames = @(Get-TaskNames $after)
        $trial.task_identity_changes = @(
            Compare-Object -ReferenceObject $beforeTaskNames -DifferenceObject $afterTaskNames |
                ForEach-Object { [ordered]@{ task_name = $_.InputObject; side = $_.SideIndicator } }
        )
        $trial.new_scheduled_task_deltas = @($afterDeltas | Where-Object { $_.category -eq 'scheduled_task' })
        $trial.new_scheduled_task_findings = @($afterFindings | Where-Object { $_.category -eq 'scheduled_task' })

        $ended = (Get-Date).ToUniversalTime()
        $startIso = [uri]::EscapeDataString($started.AddSeconds(-2).ToString('o'))
        $endIso = [uri]::EscapeDataString($ended.AddSeconds(2).ToString('o'))
        $query = Invoke-Api "/api/hosts/$HostId/provider-event-observation?start=$startIso&end=$endIso"
        $targetKey = "scheduled_task:\$($assignment.sentinel.ToLowerInvariant())"
        $trial.exact_target_provider_events = @($query.events | Where-Object {
            $eventKey = if ($_.target) { [string]$_.target.key } else { '' }
            $_.normalized_type -eq 'scheduled_task_created' -and
            $eventKey -and (Normalize-TaskName $eventKey.Replace('scheduled_task:', '')) -eq
                (Normalize-TaskName $assignment.sentinel)
        })
        $trial.exact_target_local_security_events = @(Get-LocalCreateEvents -Name $assignment.sentinel `
            -SinceLocal $started.ToLocalTime())
        $trial.event_query = [ordered]@{
            query_start_utc = $started.AddSeconds(-2).ToString('o')
            query_end_utc = $ended.AddSeconds(2).ToString('o')
            query_complete = [bool]$query.query_complete
            coverage_status = [string]$query.coverage_status
            endpoint_collection_status = [string]$query.endpoint_collection_status
            transport_status = [string]$query.transport_status
            central_index_status = [string]$query.index_status
            retrieved_count = [int]$query.retrieved_count
            total_hits = [int]$query.total_hits
            error = $query.error
            raw_response = $query
        }
        $trial.after_observation = [ordered]@{
            observation_id = $after.observation_id
            observed_at = $after.observed_at
            category = $after.categories.scheduled_task
            task_identity_count = $afterTaskNames.Count
            task_names = $afterTaskNames
            interval_query_start_utc = $monitorStarted.ToString('o')
            interval_delta_ids = @($afterDeltas | ForEach-Object { [string]$_.delta_id })
            interval_finding_ids = @($afterFindings | ForEach-Object { [string]$_.finding_id })
        }
        $trial.post_health = Get-HostHealth
        $queryHealthy = $trial.event_query.query_complete -and
            $trial.event_query.coverage_status -eq 'COMPLETE' -and
            $trial.event_query.endpoint_collection_status -eq 'AVAILABLE' -and
            $trial.event_query.transport_status -eq 'AVAILABLE' -and
            $trial.event_query.central_index_status -eq 'AVAILABLE'
        $postHealthy = $trial.post_health.api_ok -and $trial.post_health.wazuh_agent_status -eq 'active' -and
            $trial.post_health.wazuh_service_state -eq 'Running' -and
            @($trial.post_health.sysmon_services | Where-Object state -eq 'Running').Count -gt 0
        $stableObservations = $before.observation_id -ne $after.observation_id -and
            @(Get-TaskNames $before).Count -eq $afterTaskNames.Count
        $noTargetEvidence = $trial.exact_target_provider_events.Count -eq 0 -and
            $trial.exact_target_local_security_events.Count -eq 0 -and
            @($afterDeltas | Where-Object object_key -eq $targetKey).Count -eq 0 -and
            @($afterFindings | Where-Object object_key -eq $targetKey).Count -eq 0
        $trial.gates = [ordered]@{
            healthy_before_and_after = [bool]($postHealthy -and $trial.pre_health.api_ok)
            healthy_probe_observations = [bool]((Test-HealthyTaskObservation $before) -and (Test-HealthyTaskObservation $after))
            sentinel_absent_locally_and_in_probe = [bool]($trial.sentinel_absent_before -and $trial.sentinel_absent_after -and
                @(Get-ScheduledTask -TaskName $assignment.sentinel -TaskPath '\' -ErrorAction SilentlyContinue).Count -eq 0)
            probe_identity_set_stable = [bool]($stableObservations -and $trial.task_identity_changes.Count -eq 0)
            complete_available_event_query = [bool]$queryHealthy
            no_exact_target_event_delta_or_finding = [bool]$noTargetEvidence
            no_new_scheduled_task_delta_or_finding = [bool]($trial.new_scheduled_task_deltas.Count -eq 0 -and
                $trial.new_scheduled_task_findings.Count -eq 0)
            interval_queries_below_limit = [bool]($afterDeltas.Count -lt 500 -and $afterFindings.Count -lt 500)
            no_endpoint_mutation = ($trial.action_attempted -eq $false -and $trial.actions.Count -eq 0)
        }
        $trial.status = if (@($trial.gates.Values | Where-Object { -not $_ }).Count -eq 0) { 'PASS' } else { 'FAIL' }
    } catch {
        $trial.failure = "line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    }
    $trial.ended_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    Save-Json $trialPath $trial
    $manifest.trials += [ordered]@{
        trial_id = $trial.trial_id
        sentinel_task_name = $trial.sentinel_task_name
        status = $trial.status
        artifact = "trials/$($assignment.trial_id).json"
        failure = $trial.failure
    }
    Save-Json $manifestPath $manifest
    if ($trial.post_health -and ($trial.post_health.wazuh_service_state -ne 'Running' -or
        $trial.post_health.wazuh_agent_status -ne 'active')) {
        foreach ($remaining in $schedule | Where-Object { $_.trial_id -notin $manifest.trials.trial_id }) {
            $manifest.trials += [ordered]@{
                trial_id = $remaining.trial_id
                sentinel_task_name = $remaining.sentinel
                status = 'NOT_RUN_AFTER_HEALTH_FAILURE'
                artifact = $null
                failure = 'Prespecified endpoint recovery stop rule.'
            }
        }
        Save-Json $manifestPath $manifest
        break
    }
}

$manifest.completed_at_utc = (Get-Date).ToUniversalTime().ToString('o')
$completed = @($manifest.trials | Where-Object status -in @('PASS', 'FAIL', 'FAILED')).Count
$failed = @($manifest.trials | Where-Object status -ne 'PASS').Count
$manifest.status = if ($completed -eq $Repetitions -and $failed -eq 0) { 'COMPLETED' } `
    elseif ($completed -eq $Repetitions) { 'COMPLETED_WITH_FAILURES' } else { 'INCOMPLETE' }
$manifest.pass_count = @($manifest.trials | Where-Object status -eq 'PASS').Count
$manifest.completed_count = $completed
$manifest.assigned_count = $Repetitions
$manifest.gap_count = $Repetitions - $completed
Save-Json $manifestPath $manifest
Write-Host "Campaign=$($manifest.campaign_id) Status=$($manifest.status) Pass=$($manifest.pass_count)/$Repetitions Gaps=$($manifest.gap_count)"
