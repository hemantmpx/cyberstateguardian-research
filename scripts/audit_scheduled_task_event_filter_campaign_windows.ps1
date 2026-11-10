param(
    [string]$CampaignDirectory = "C:\CSG\results\scheduled-task-eventid-filter-confirmatory-v2",
    [string]$CsgApiBase = "http://192.168.64.1:8000",
    [string]$HostId = "win11-arm-lab",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
$CampaignDirectory = [IO.Path]::GetFullPath($CampaignDirectory)
$manifestPath = Join-Path $CampaignDirectory "campaign-manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "Campaign manifest not found." }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if (@($manifest.trials).Count -ne 10) { throw "Expected exactly ten frozen assignments." }
if (-not $OutputPath) { $OutputPath = Join-Path $CampaignDirectory "post-run-audit.json" }
if (Test-Path -LiteralPath $OutputPath) { throw "Refusing to overwrite audit artifact: $OutputPath" }

$configPath = Join-Path ${env:ProgramFiles(x86)} "ossec-agent\ossec.conf"
$originalHash = "0e2eec247d4e645112f5dedc6f80e1713e2377f08ec2bbf7dc5e9cd4059ec3c1"

function Normalize-Text {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    return ([string]$Value).Trim().ToLowerInvariant().Replace("/", "\")
}

function Test-ExactTaskEvent {
    param([object]$Event, [string]$TaskName, [string]$ObjectKey)
    if ($Event.host_id -ne $HostId -or $Event.source -ne "wazuh" -or
        $Event.normalized_type -ne "scheduled_task_created") { return $false }
    $expectedName = Normalize-Text ("\" + $TaskName)
    $expectedKey = Normalize-Text $ObjectKey
    return (Normalize-Text $Event.target.key) -eq $expectedKey -or
        (Normalize-Text $Event.attributes.task_name) -eq $expectedName
}

function Get-ReconciliationHistory {
    param([string]$FindingId)
    if (-not $FindingId) { return @() }
    $response = Invoke-RestMethod -Method Get -TimeoutSec 45 -Uri (
        "$($CsgApiBase.TrimEnd('/'))/api/findings/$FindingId/reconciliations"
    )
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($response)) {
        if ($item -is [System.Array]) {
            foreach ($nested in $item) { if ($null -ne $nested) { $items.Add($nested) } }
        } elseif ($null -ne $item) {
            $items.Add($item)
        }
    }
    return @($items.ToArray())
}

$health = Invoke-RestMethod -Method Get -TimeoutSec 20 -Uri "$($CsgApiBase.TrimEnd('/'))/api/wazuh/status"
$agent = @($health.server_api.agents | Where-Object { $_.name -eq $HostId } | Select-Object -First 1)
$service = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
$auditTrials = New-Object System.Collections.Generic.List[object]

foreach ($assignment in @($manifest.trials)) {
    $trialDirectory = Join-Path $CampaignDirectory ("trial-{0:D2}" -f [int]$assignment.order)
    $runnerPath = Join-Path $trialDirectory "runner\run.json"
    $resultPath = Join-Path $trialDirectory "result.json"
    $trial = [ordered]@{
        assignment_id = $assignment.assignment_id
        campaign_controller_status = $assignment.status
        campaign_wrapper_status = $assignment.wrapper_status
        capture_gates_passed_at_campaign_time = $assignment.capture_gates_passed
        campaign_finding_id = $assignment.finding_id
        campaign_delta_id = $assignment.delta_id
        errors = @()
    }
    if (-not (Test-Path -LiteralPath $runnerPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        $trial.errors += "Missing runner or wrapper artifact."
        $auditTrials.Add($trial)
        continue
    }

    $runner = Get-Content -LiteralPath $runnerPath -Raw | ConvertFrom-Json
    $wrapper = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    $scenario = @($runner.scenarios | Where-Object { $_.kind -eq "scheduled_task" } | Select-Object -First 1)[0]
    $objectKey = [string]$scenario.expected_object_key
    $taskName = [string]$scenario.object_name
    $retrieval = $scenario.event_retrieval
    $trial.task_name = $taskName
    $trial.object_key = $objectKey
    $trial.local_4698_record_ids = @($scenario.local_source_evidence.exact_events |
        Where-Object { $_.event_id -eq 4698 -and $_.exact_identity_match } |
        ForEach-Object { $_.record_id })
    $rawAdds = @($scenario.deltas | Where-Object {
        $_.delta_type -eq "ADD" -and $_.object_key -eq $objectKey
    })
    $rawAddIds = @($rawAdds | ForEach-Object { $_.delta_id })
    $rawLinkedFindings = @($scenario.findings | Where-Object {
        $rawAddIds -contains $_.delta_id
    })
    $trial.raw_creation_add_delta_ids = $rawAddIds
    $trial.raw_creation_add_count = $rawAdds.Count
    $trial.raw_creation_finding_ids = @($rawLinkedFindings | ForEach-Object { $_.finding_id })
    $trial.raw_creation_finding_count = $rawLinkedFindings.Count
    $trial.state_observation_ids = [ordered]@{
        before = $scenario.state_plane.before_action_observation.observation_id
        after = $scenario.state_plane.after_action_observation.observation_id
        after_cleanup = $scenario.state_plane.after_cleanup_observation_id
    }
    $trial.action = $scenario.action
    $trial.post_restore_query_count = @($wrapper.post_restore_provider_queries).Count
    $trial.post_restore_target_event_ids = @($wrapper.target_wazuh_event_ids_after_restore)
    $trial.post_restore_queries_complete = [bool]$wrapper.target_event_absent_after_restore

    try {
        $start = [uri]::EscapeDataString([string]$retrieval.query_start)
        $end = [uri]::EscapeDataString([string]$retrieval.query_end)
        $observation = Invoke-RestMethod -Method Get -TimeoutSec 90 -Uri (
            "$($CsgApiBase.TrimEnd('/'))/api/hosts/$HostId/provider-event-observation?start=$start&end=$end"
        )
        $events = @($observation.events)
        $exact = @($events | Where-Object {
            Test-ExactTaskEvent -Event $_ -TaskName $taskName -ObjectKey $objectKey
        } | ForEach-Object {
            [ordered]@{
                event_id = $_.event_id
                event_time = $_.event_time
                host_id = $_.host_id
                source = $_.source
                normalized_type = $_.normalized_type
                target_key = $_.target.key
                task_name = $_.attributes.task_name
                source_reference = $_.source_reference
            }
        })
        $sameTypeCandidates = @($events | Where-Object {
            $_.host_id -eq $HostId -and $_.source -eq "wazuh" -and
            $_.normalized_type -eq "scheduled_task_created"
        } | ForEach-Object {
            [ordered]@{
                event_id = $_.event_id
                event_time = $_.event_time
                target_key = $_.target.key
                task_name = $_.attributes.task_name
            }
        })
        $trial.late_provider_requery = [ordered]@{
            queried_at_utc = [DateTime]::UtcNow.ToString("o")
            query_start = $retrieval.query_start
            query_end = $retrieval.query_end
            query_complete = [bool]$observation.query_complete
            coverage_status = $observation.coverage_status
            endpoint_collection_status = $observation.endpoint_collection_status
            transport_status = $observation.transport_status
            index_status = $observation.index_status
            retrieved_count = $observation.retrieved_count
            total_hits = $observation.total_hits
            candidate_scheduled_task_event_count = $sameTypeCandidates.Count
            same_type_candidates = $sameTypeCandidates
            exact_target_event_count = $exact.Count
            exact_target_events = $exact
        }
    } catch {
        $trial.errors += "Late provider query failed: $($_.Exception.GetType().Name): $($_.Exception.Message)"
    }

    try {
        $encoded = [uri]::EscapeDataString($objectKey)
        $deltas = @(Invoke-RestMethod -Method Get -TimeoutSec 30 -Uri (
            "$($CsgApiBase.TrimEnd('/'))/api/hosts/$HostId/deltas?limit=500&object_key=$encoded"
        ) | Where-Object { $_.object_key -eq $objectKey })
        $trial.current_deltas = @($deltas | ForEach-Object {
            [ordered]@{
                delta_id = $_.delta_id
                delta_type = $_.delta_type
                object_key = $_.object_key
                created_at = $_.created_at
                observation_window = $_.observation_window
                metadata = $_.metadata
            }
        })
        $trial.current_add_delta_count = @($deltas | Where-Object { $_.delta_type -eq "ADD" }).Count
        $trial.current_findings = @(
            foreach ($finding in $rawLinkedFindings) {
                $history = @(Get-ReconciliationHistory -FindingId $finding.finding_id)
                [ordered]@{
                    finding_id = $finding.finding_id
                    delta_id = $finding.delta_id
                    raw_finding = $finding
                    reconciliation_history = $history
                    latest_reconciliation = if ($history.Count) { $history[-1] } else { $null }
                }
            }
        )
        $trial.creation_add_finding_ids = @(
            $rawLinkedFindings | ForEach-Object { $_.finding_id }
        )
        $trial.creation_add_delta_present_in_api = @($deltas | Where-Object {
            $_.delta_type -eq "ADD" -and $rawAddIds -contains $_.delta_id
        }).Count -eq $rawAdds.Count -and $rawAdds.Count -gt 0
        $trial.current_add_delta_present = $trial.current_add_delta_count -gt 0
    } catch {
        $trial.errors += "Current CSG delta/finding audit failed: $($_.Exception.GetType().Name): $($_.Exception.Message)"
    }
    $auditTrials.Add($trial)
}

$configHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
$residualTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName -like "CSGAPTTask*" -or $_.TaskName -like "CSGAPTDis*"
} | ForEach-Object { "{0}{1}" -f $_.TaskPath, $_.TaskName })
$audit = [ordered]@{
    schema_version = "csg-scheduled-task-event-filter-post-run-audit-v1"
    captured_at_utc = [DateTime]::UtcNow.ToString("o")
    host_id = $HostId
    campaign_id = $manifest.campaign_id
    campaign_status_at_completion = $manifest.status
    campaign_started_at_utc = $manifest.started_at_utc
    campaign_ended_at_utc = $manifest.ended_at_utc
    campaign_manifest_sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    config_sha256_now = $configHash
    original_config_hash_matches = $configHash -eq $originalHash
    wazuh_service_state_now = $service.State
    endpoint_agent_status_now = if ($agent.Count) { $agent[0].status } else { "NOT_FOUND" }
    csg_api_healthy_now = [bool]$health.ok
    wazuh_server_api_healthy_now = [bool]$health.server_api.ok
    wazuh_indexer_healthy_now = [bool]$health.indexer.ok
    residual_study_tasks_now = $residualTasks
    trials = @($auditTrials.ToArray())
}
$audit | ConvertTo-Json -Depth 60 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Output ([ordered]@{
    output_path = $OutputPath
    status = $manifest.status
    trial_count = $auditTrials.Count
    exact_late_events = @($auditTrials | Where-Object {
        $_.late_provider_requery.exact_target_event_count -gt 0
    }).Count
    creation_add_missing = @($auditTrials | Where-Object { $_.current_add_delta_present -eq $false }).Count
    config_restored = $audit.original_config_hash_matches
    residual_tasks = $residualTasks.Count
} | ConvertTo-Json -Compress)
