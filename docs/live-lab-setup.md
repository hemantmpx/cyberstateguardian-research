# CyberStateGuardian Live Lab Setup

This guide turns the prototype into a live Mac + UTM Windows lab.

Previously verified on 2026-09-17: the Windows 11 ARM UTM VM was enrolled in Wazuh as
`win11-arm-lab`, Sysmon has been installed, and CSG has successfully synced Windows event data.
Updated October 3: the native probe is installed as a SYSTEM scheduled task, the private runtime
uses native state plus Wazuh alert and raw archive events, and an archive-backed exact registry
reconciliation has been re-evaluated. Repeated confirmatory trials and AI/human evaluation remain. See
[research validation](research-validation-protocol.md).

The additive Continuous State Transition Capture feature is documented separately in
[continuous-state-transition-capture.md](continuous-state-transition-capture.md). Its flags default
off; it must be enabled on both the CSG API and the Windows probe before transition upload is
accepted. The current Mac session has not run its PowerShell validation script on Windows.

## What Counts As Live

Live means:

- Docker Compose is running PostgreSQL, API, worker, and dashboard.
- A real Wazuh server/indexer/dashboard stack is running locally.
- A real Windows 11 ARM UTM VM enrolls as a Wazuh agent.
- Sysmon on the Windows VM sends process/network events through Wazuh.
- CSG uses direct native probe observations as authoritative state and Wazuh alerts plus optional
  raw archives as transient event telemetry; Wazuh inventory is cross-validation only.
- The current Windows research setup uses `CSG_WAZUH_ARCHIVE_INDEX_PATTERN=wazuh-archives-*`;
  Wazuh `logall_json` and Filebeat `archives.enabled` must both be enabled for unalerted events to
  reach the index. Monitor archive storage and retention during campaigns.
- For the independent-state research experiment, the native probe MUST send direct observations.
- The backend persists source observations, builds snapshots, emits deltas, creates findings, and
  deterministically correlates findings into incidents.
- The dashboard shows CSG API health, Wazuh central status, agent enrollment, snapshots, deltas,
  findings, correlated incidents, and experiment context from actual telemetry.

Synthetic scenario data is still useful for repeatable research tests, but it is not live telemetry.

## 1. Start Docker

Open Docker Desktop, then verify:

```bash
docker info
```

## 2. Create Local Lab Environment

Generate `.env` with local secrets:

```bash
python scripts/create_lab_env.py
```

The script does not print secrets. To rotate them:

```bash
python scripts/create_lab_env.py --force
```

## 3. Start The Stack

```bash
docker compose up -d --build
```

Verify:

```bash
python scripts/healthcheck.py --url http://localhost:8000/health
python scripts/live_lab_check.py --api-url http://localhost:8000/health --web-url http://localhost:3001
```

Open:

```text
http://localhost:3001
```

## 4. Start Wazuh

Start the Wazuh single-node stack:

```bash
python scripts/setup_wazuh_lab.py start
```

Verify Wazuh:

```bash
python scripts/wazuh_lab_check.py
```

Open:

```text
Wazuh dashboard: https://localhost:8443
CSG Wazuh status: http://localhost:8000/api/wazuh/status
```

The local Wazuh dashboard uses the default lab login from the Wazuh Docker stack:

```text
admin / SecretPassword
```

The private research `.env` uses the native probe for authoritative state and Wazuh for transient
events. Wazuh inventory remains a non-authoritative cross-validation source. CSG containers reach
Wazuh through Docker's host bridge:

```text
CSG_STATE_PROVIDER=probe
CSG_EVENT_PROVIDER=wazuh
CSG_STATE_CROSS_VALIDATION_ENABLED=true
CSG_WAZUH_API_URL=https://host.docker.internal:55000
CSG_WAZUH_INDEXER_URL=https://host.docker.internal:9200
CSG_WAZUH_DASHBOARD_URL=https://localhost:8443
CSG_WAZUH_VERIFY_SSL=false
```

Keep automatic Wazuh sync disabled until a Windows endpoint agent is enrolled and the target host
identifier is known:

```text
CSG_WAZUH_SYNC_ENABLED=false
CSG_WAZUH_SYNC_HOST_IDS=
```

For this lab, the enrolled Windows host identifier is `win11-arm-lab`. Automatic sync can use that
host name after manual provider sync proves the endpoint is reachable.

## 5. Optional Demo Seed

Seed synthetic demo findings only when you want dashboard sample data:

```bash
docker compose exec api csg-seed-demo
```

The seeded records are synthetic. They should not be mixed with live experiment results.

## 6. Enroll The Windows VM In Wazuh

Find a Mac IP or hostname reachable from the Windows VM. Examples:

```bash
ipconfig getifaddr en0
ipconfig getifaddr en1
```

For UTM NAT networking, prefer `192.168.64.1` when Windows can reach ports `1514` and `1515` on that
address. The Mac Wi-Fi/LAN address can also work, but it changes when the Mac moves to a different
network.

From elevated PowerShell inside the Windows VM, run the Wazuh helper:

```powershell
.\scripts\install_wazuh_agent_windows.ps1 -WazuhManager "<mac-reachable-address>" -AgentName "win11-arm-lab"
```

The helper installs the Wazuh agent, installs or updates Sysmon with `config/sysmon-csg-lab.xml`,
adds the Sysmon Operational event channel to the Wazuh agent config, and starts `WazuhSvc`.

Verify from the Mac:

```bash
curl http://localhost:8000/api/wazuh/status
```

Expected after enrollment:

- Wazuh reports an agent beyond manager `000`.
- The CSG dashboard Wazuh panel changes from `Central live` to `Live`.
- The Wazuh dashboard Agents view shows the Windows VM.

Current lab enrollment:

```text
host_id: win11-arm-lab
wazuh_agent_id: 001
typical_utm_vm_ip: 192.168.64.5
preferred_utm_manager_address: 192.168.64.1
```

Run a manual provider sync:

```bash
curl -X POST http://localhost:8000/api/hosts/<agent-id-or-name>/provider-sync
```

Then inspect:

```bash
curl http://localhost:8000/api/hosts/<agent-id-or-name>/state/latest
curl http://localhost:8000/api/hosts/<agent-id-or-name>/events
```

After this proves the agent identity, automatic sync can be enabled:

```text
CSG_WAZUH_SYNC_ENABLED=true
CSG_WAZUH_SYNC_HOST_IDS=<agent-id-or-name>
CSG_WAZUH_EVENT_LOOKBACK_SECONDS=900
```

Keep the automatic sync lookback bounded to 15 minutes for this lab. A 24-hour query on every
worker cycle repeatedly downloads and normalizes the full Wazuh archive and can delay
reconciliation; the Wazuh index retains its own longer history for explicit historical queries.
If measuring event arrivals delayed by more than 15 minutes, increase the lookback prospectively
and record it as a separate condition.

The general example retains a 30-second worker interval. The October 13 latency calibration used
10 seconds in the live lab `.env`; measured worker cycles still ranged from 13 to 40 seconds because
the interval is a sleep after each sync/processing pass, not an end-to-end cycle target. For a
timing experiment, freeze the interval and report observed cycle timestamps from worker logs.

Restart CSG after changing `.env`:

```bash
docker compose up -d --build api worker web
```

## 7. Native Probe Required For Independent-State Research

Find a Mac IP or hostname reachable from the Windows VM. Examples:

```bash
ipconfig getifaddr en0
ipconfig getifaddr en1
```

From Windows PowerShell, configure the probe. Replace the URL and token with your lab values:

```powershell
$env:CSG_PROBE_API_URL="http://<mac-reachable-address>:8000/api/probe/observations"
$env:CSG_PROBE_HOST_ID="win11-arm-lab"
$env:CSG_PROBE_HOST_ROLE="windows-target"
$env:CSG_PROBE_TOKEN="<CSG_LAB_SHARED_TOKEN from .env>"
$env:CSG_PROBE_INTERVAL_SECONDS="30"
```

Do not reuse an old Wi-Fi/LAN IP blindly. Re-check the Mac address before each lab run, or use the
UTM NAT host address `192.168.64.1` when it is reachable from Windows.

Install dependencies from a copy or clone of this repository:

```powershell
py -m pip install ./probe
```

Run one observation:

```powershell
py -m cyberstateguardian_probe.main --once
```

Use a machine-wide Python installation if installing the SYSTEM task. The installer creates a
dedicated virtual environment, checks installation exit codes and passes restricted JSON settings
to an absolute interpreter. SYSTEM execution has been verified on the lab VM; still verify a fresh
observation after each reinstall. A successful administrator upload is not proof of successful
SYSTEM collection. See
[current deployment and measurement commands](research-tooling.md).

The probe sends hostname, OS, architecture, and role metadata. The API registers or updates that host
automatically, so a separate `/api/hosts` pre-seed is not required.

Verify from the Mac:

```bash
curl http://localhost:8000/api/hosts/win11-arm-lab/observations/latest
curl http://localhost:8000/api/hosts/win11-arm-lab/state/latest
curl http://localhost:8000/api/hosts/win11-arm-lab/deltas
curl "http://localhost:8000/api/findings?host_id=win11-arm-lab"
```

### Optional Transition Capture Pilot

Transition capture is disabled unless enabled in both control plane and endpoint settings. To enable
only the service monitor for a controlled pilot, set these in the Mac `.env`:

```dotenv
CSG_TRANSITION_CAPTURE_ENABLED=true
CSG_TRANSITION_SERVICES_ENABLED=true
CSG_TRANSITION_PROCESSES_ENABLED=false
CSG_TRANSITION_REGISTRY_ENABLED=false
CSG_TRANSITION_TASKS_ENABLED=false
CSG_TRANSITION_PRIVILEGED_GROUPS_ENABLED=false
CSG_TRANSITION_LISTENERS_ENABLED=false
```

Recreate the API/worker so they load the flags:

```bash
docker compose up -d --build api worker
curl "http://localhost:8000/api/transition-capture/status?host_id=win11-arm-lab"
```

The Windows probe must be installed with the matching opt-in category. From an elevated PowerShell
copy of the repository, use the same reachable Mac API and existing lab token; never put the token
in a committed file or result artifact:

```powershell
.\probe\install_probe_windows.ps1 `
  -ApiUrl "http://<mac-reachable-address>:8000/api/probe/observations" `
  -HostId "win11-arm-lab" `
  -Token $Token `
  -PythonExe $PythonExe `
  -EnableTransitionCapture `
  -CaptureServices `
  -TransitionPollIntervalSeconds 5
```

The installer replaces the probe task/configuration, so verify a new direct-probe observation and
check that the status endpoint reports a healthy service-monitor baseline before changing anything.
The opt-in Windows runner creates one uniquely named, stopped dummy service, changes its start mode
Manual -> Automatic -> Manual, waits for the exact object-specific transition record after each
action, takes direct-probe endpoint snapshots, and checks the exact snapshot-bounded trajectory and
Wazuh evidence. It deletes only the service it created and saves a campaign folder on Windows:

```powershell
.\scripts\run_transition_capture_reverted_service_windows.ps1 -Repeat 1 -EvidenceWaitSeconds 30
```

Copy the completed per-campaign folder into a new, uniquely named directory under
`experiments/results/runs/20261004/` on the research workstation. Preserve incomplete trials. If an
intervening scheduled snapshot prevents the requested exact snapshot pair from being classified as
`REVERTED`, the validator must fail; do not relabel separate adjacent trajectories as one reversion.
This pilot checks the service category only. It does not validate all six monitors or imply
conference-grade capture reliability. See
[the full transition-capture design and limits](continuous-state-transition-capture.md).

## 8. Controlled Live Delta Drill

Preferred: use `scripts/run_service_drift_drill_windows.ps1` as described in the validation protocol.
It chooses a unique service name, refuses existing services, and cleans up only its own service.
The manual illustration below is for an isolated VM; confirm `CSGTestService` does not exist before
creating it and never delete a service that this experiment did not create.

After a successful direct-probe baseline, set `CSG_STATE_PROVIDER=probe`,
`CSG_EVENT_PROVIDER=wazuh`, and optionally `CSG_STATE_CROSS_VALIDATION_ENABLED=true` in `.env`.
Rebuild/recreate API and worker so the new configuration and migration are applied. Keep both the
probe host ID and Wazuh agent name as `win11-arm-lab`.

For Wazuh, sync once to establish baseline:

```bash
curl -X POST http://localhost:8000/api/hosts/<agent-id-or-name>/provider-sync
```

For the independent native state plane, run the probe once to establish baseline:

```powershell
py -m cyberstateguardian_probe.main --once
```

Create a lab-only service from an Administrator PowerShell:

```powershell
sc.exe create CSGTestService binPath= "C:\Windows\System32\cmd.exe /c exit 0" start= demand
```

Wait long enough for Wazuh inventory/alerts to update, then sync again:

```bash
curl -X POST http://localhost:8000/api/hosts/<agent-id-or-name>/provider-sync
```

For the independent native state plane, run the probe again:

```powershell
py -m cyberstateguardian_probe.main --once
```

The backend should create:

- one new snapshot
- one `service` `ADD` delta for `service:csgtestservice`
- one finding
- one persisted incident containing that finding
- reconciliation `CONSISTENT` if matching evidence exists, otherwise `PENDING_EVIDENCE` until the
  observation window plus grace closes; late imported evidence can revise a finalized result

Live findings are limited by `CSG_LIVE_FINDING_CATEGORIES`. The default focuses on low-change
security state (`service`, `listener`, `scheduled_task`, `privileged_group`, `registry`) so one-shot
probe process churn is retained as raw delta telemetry without flooding findings.

Clean up:

```powershell
sc.exe delete CSGTestService
py -m cyberstateguardian_probe.main --once
```

Then run one more Wazuh sync to capture cleanup:

```bash
curl -X POST http://localhost:8000/api/hosts/<agent-id-or-name>/provider-sync
```

Inspect the incident and preview its full AI context without calling a model:

```bash
curl http://localhost:8000/api/incidents
curl "http://localhost:8000/api/incidents/<incident-id>/ai-context?mode=full_context"
```

The previous A/B/C/D AI-context exporter is archived and is not the current study workflow. For the
active post-reconciliation response-assistance experiment, export the finding's bounded package,
prepare the three blinded conditions, and score only validated model guidance. Follow the exact
commands, reviewer boundaries, failure accounting, and human-scoring steps in
[`ai-response-assistance-methodology.md`](ai-response-assistance-methodology.md).

## 9. Run The Probe Continuously

After one-shot validation:

```powershell
py -m cyberstateguardian_probe.main
```

Stop with `Ctrl+C`.

## 10. Troubleshooting

If the Wazuh dashboard does not load:

- Confirm `python scripts/setup_wazuh_lab.py status` shows manager, indexer, and dashboard running.
- Confirm `python scripts/wazuh_lab_check.py` passes.
- Wait a minute after startup; Wazuh can need warm-up time before all services respond.

If `/api/wazuh/status` reports Wazuh down:

- Confirm `.env` has the Wazuh password values.
- Confirm CSG is using `https://host.docker.internal:55000` and
  `https://host.docker.internal:9200` when CSG runs in Docker on the Mac.
- Restart API/worker after environment changes.

If Wazuh central is live but endpoint agents are `0`:

- Only the built-in manager agent is enrolled.
- Run `scripts/install_wazuh_agent_windows.ps1` inside the Windows VM.
- Confirm Windows can reach the Mac address used for `-WazuhManager`.

If the Windows agent exists but shows `disconnected`:

- From elevated PowerShell, test the manager ports:

  ```powershell
  Test-NetConnection 192.168.64.1 -Port 1514
  Test-NetConnection 192.168.64.1 -Port 1515
  ```

- If those fail, test the current Mac Wi-Fi/LAN IP instead.
- Update the Wazuh manager address in `C:\Program Files (x86)\ossec-agent\ossec.conf` if needed.
- Restart the agent:

  ```powershell
  Restart-Service WazuhSvc
  ```

If the Windows probe cannot reach the Mac API:

- Confirm the Mac firewall allows inbound connections to port `8000`.
- Confirm the API container publishes `8000:8000`.
- Confirm the probe URL uses a Mac address reachable from UTM, not Windows `localhost`.
- Confirm `CSG_PROBE_TOKEN` matches `CSG_LAB_SHARED_TOKEN`.

If the dashboard shows `Registered only`:

- No live probe observation has been received for that host.
- Run the Windows probe with `--once`.

If the dashboard shows `Collector issue`:

- At least one collector returned `error` or `unavailable`.
- Check the latest observation endpoint for category-level messages.

## 11. What This Still Is Not

Previous records verified a Wazuh-backed endpoint. Fresh native-state proof, repeated live trials,
model trials, human scoring, and statistical evaluation remain. Proxmox/Kali automation is optional.
