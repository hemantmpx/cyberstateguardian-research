# Wazuh Live Lab

Date: 2026-09-14
Last updated: 2026-09-25

## Purpose

This document describes the real Wazuh-backed lab path for CyberStateGuardian. Wazuh now runs
locally as a central security telemetry stack. CSG uses Wazuh alerts as the transient event plane;
Wazuh inventory remains available for fallback and explicitly non-authoritative cross-validation.

The central stack and endpoint path are real. The Windows 11 ARM UTM VM has been enrolled as
`win11-arm-lab` with the Wazuh agent and Sysmon, and CSG can read and persist Wazuh-backed Windows
inventory and event data from that endpoint.

The September 22 live validation verified native probe snapshots plus Wazuh events in the private
`probe`/`wazuh` configuration. The September 24 readiness calibration additionally verified one
object-specific service transition with archived before/after state and exact Wazuh evidence. See
[validation protocol](research-validation-protocol.md) for repeated live conditions and AI
evaluation still to perform.

## Running Components

Wazuh stack:

- Wazuh manager: receives agent telemetry and exposes the Wazuh server API.
- Wazuh indexer: stores Wazuh alert and inventory indices.
- Wazuh dashboard: browser UI for Wazuh agents, alerts, and security views.

CyberStateGuardian stack:

- CSG API: exposes source-independent state, event, sync, and Wazuh status APIs.
- CSG worker: can periodically sync Wazuh hosts when configured.
- CSG dashboard: shows CSG health, Wazuh central status, Wazuh agent count, snapshots, deltas,
  findings, and correlated incidents.
- PostgreSQL: persists observations, snapshots, events, deltas, findings, incidents, assignment
  provenance, AI analyses, runs, and evidence.

## Access

Local browser/API URLs:

```text
CSG dashboard:   http://localhost:3001
CSG API:         http://localhost:8000
CSG Wazuh status http://localhost:8000/api/wazuh/status
Wazuh dashboard: https://localhost:8443
Wazuh API:       https://localhost:55000
Wazuh indexer:   https://localhost:9200
```

Wazuh dashboard lab login:

```text
admin / SecretPassword
```

CSG containers reach the local Wazuh stack through:

```text
CSG_WAZUH_API_URL=https://host.docker.internal:55000
CSG_WAZUH_INDEXER_URL=https://host.docker.internal:9200
```

## Setup Commands

Start Wazuh:

```bash
python scripts/setup_wazuh_lab.py start
```

Check Wazuh:

```bash
python scripts/wazuh_lab_check.py
```

Start or refresh CSG:

```bash
docker compose up -d --build
```

Check CSG's Wazuh view:

```bash
curl http://localhost:8000/api/wazuh/status
```

Stop Wazuh:

```bash
python scripts/setup_wazuh_lab.py stop
```

Remove Wazuh containers while keeping local files:

```bash
python scripts/setup_wazuh_lab.py down
```

## Implemented CSG Integration

`backend/csg/providers/wazuh.py` contains the live adapters:

- `WazuhClient` authenticates to the Wazuh server API with JWT and queries the Wazuh indexer.
- `WazuhStateProvider` builds CSG `StateSnapshot` records from Wazuh inventory indices.
- `WazuhEventProvider` builds CSG `NormalizedEvent` records from Wazuh alerts.

Inventory index families used by CSG:

- `wazuh-states-inventory-processes-*`
- `wazuh-states-inventory-ports-*`
- `wazuh-states-inventory-services-*`

Alert index family used by CSG:

- `wazuh-alerts-*`

CSG normalizes selected Windows/Wazuh events into research event types:

- Windows service installed events, including `7045`/`4697`, become `service_created`.
- Windows `7040` becomes `service_modified` (start-mode changes, not all service edits).
- Sysmon `13` becomes `registry_value_modified`; collection/filter coverage must be checked.
- Windows scheduled task events, including `4698`/`4702`, become task events.
- Windows privileged group membership events, including `4728`/`4732`/`4756`, become
  `privileged_group_member_added`.
- Sysmon process create event `1` becomes `process_start`.
- Sysmon network connection event `3`, and Windows Filtering Platform `5156`, become
  `network_activity`.

If Wazuh returns alerts that do not match one of those mappings, CSG still stores them as
`wazuh_alert` so the raw evidence path remains visible.

## Implemented APIs

Status:

```bash
curl http://localhost:8000/api/wazuh/status
```

Provider state without persisting (probe mode returns the latest stored native snapshot):

```bash
curl http://localhost:8000/api/hosts/<agent-id-or-name>/provider-state
```

Live provider events without persisting:

```bash
curl "http://localhost:8000/api/hosts/<agent-id-or-name>/provider-events?start=2026-09-14T00:00:00Z&end=2026-09-15T00:00:00Z"
```

Pull provider data into CSG persistence (probe mode imports events; it does not create inventory state):

```bash
curl -X POST http://localhost:8000/api/hosts/<agent-id-or-name>/provider-sync
```

Manual sync script:

```bash
docker compose exec api python scripts/sync_wazuh_once.py <agent-id-or-name>
```

## Windows VM Enrollment

Run inside the Windows 11 ARM UTM VM from elevated PowerShell:

```powershell
.\scripts\install_wazuh_agent_windows.ps1 -WazuhManager "<mac-reachable-address>" -AgentName "win11-arm-lab"
```

The helper script:

- downloads and installs the Wazuh Windows agent MSI
- sets the Wazuh manager address
- downloads Sysmon from Microsoft Sysinternals
- installs or updates Sysmon with `config/sysmon-csg-lab.xml`
- configures the Wazuh agent to read the Sysmon Operational channel
- starts the `WazuhSvc` service

After the Windows VM is enrolled, `/api/wazuh/status` should report at least one endpoint agent
beyond manager `000`.

Current lab enrollment:

```text
host_id: win11-arm-lab
wazuh_agent_id: 001
typical_utm_vm_ip: 192.168.64.5
preferred_utm_manager_address: 192.168.64.1
```

If the Wazuh dashboard shows the agent as disconnected after changing networks, re-check the manager
address from the Windows VM. In UTM NAT mode, `192.168.64.1` is usually more stable than the Mac Wi-Fi
address because Wi-Fi/LAN addresses change between networks.

## Honest Current Boundary

What is real now:

- Wazuh manager/indexer/dashboard run locally.
- CSG can authenticate to Wazuh API and indexer.
- The Windows VM is enrolled as `win11-arm-lab`.
- Sysmon is installed on the Windows VM and is configured for Wazuh collection.
- CSG can read real Wazuh inventory and alerts.
- CSG can persist Wazuh events and snapshots through provider sync.
- CSG reports category health honestly when endpoint inventory rows exist or are missing.
- The native probe is authoritative for the independent-state experiment, and Wazuh is the event
  comparison plane.
- One corrected complete service calibration passed exact identity, raw-state, and cleanup checks.

What remains to validate:

- A corrected 10 complete and 10 delayed-reconciliation rerun after the lifecycle-finalization fix;
  the earlier September 26 matrix is retained as acquisition evidence but is not a clean final
  reconciliation estimate.
- A measured telemetry-delay matrix using the new source-pause condition, plus a genuine event-loss
  experiment if the lab can remove events rather than buffer them.
- A genuine event-loss experiment, distractor controls, and positive controls for other endpoint
  categories.
- Independent human scoring for the current CSG-only/static-playbook/AI-response-assistance study,
  after a validated Ollama response exists, plus larger labeled correlation trials.

## Official References

- Wazuh Docker deployment: https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html
- Wazuh server API authentication: https://documentation.wazuh.com/current/user-manual/api/getting-started.html
- Wazuh indexer indices: https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html
- Wazuh Windows agent package: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html
- Microsoft Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
