# CyberStateGuardian

CyberStateGuardian is a computer-security research prototype for monitoring low-change,
high-value Windows systems through source-independent state, event, evidence, and experiment
models. The current build is Mac-first and Docker-portable: PostgreSQL, API, worker, and UI run
through Docker Compose, while the Windows probe remains native so it can observe the Windows host.

## Current Architecture

- `csg-api`: FastAPI backend with typed Pydantic models, SQLAlchemy repositories, Alembic migrations,
  probe ingestion, state/delta APIs, findings, experiments, and optional AI analyst explanations.
- `csg-worker`: same backend image, periodically processes state deltas that do not yet have
  findings.
- `csg-postgres`: PostgreSQL 16 with migration-driven schema creation.
- `csg-web`: Next.js analyst UI that reads backend APIs only.
- `.wazuh-lab/`: local checkout of the official Wazuh Docker single-node stack, created by
  `scripts/setup_wazuh_lab.py`.
- `probe/`: native Python Windows probe using `psutil` and PowerShell where practical.
- `experiments/`: deterministic synthetic fixtures, replayable scenarios, and result exports.

Wazuh is integrated as an event and inventory provider through its API and indexer. In the live
research setup, a native Windows probe independently observes endpoint state while Sysmon events
are collected through the Wazuh agent. CSG links observations and events by host, object identity,
event type, and bounded time, and retains reconciliation history. Wazuh remains the monitoring
platform; CSG does not replace it or treat an unexplained change as proof of an attack.

The empirical evaluation to date uses controlled, benign changes on one Windows 11 ARM64 VM. It
studies evidence attribution, collection visibility, reconciliation history, and timing. It does
not establish malicious-activity detection accuracy or cross-host generalization.

## Start on macOS

1. Copy the environment template:

   ```bash
   cp .env.example .env
   ```

2. Replace `POSTGRES_PASSWORD` and `CSG_LAB_SHARED_TOKEN` in `.env` for your lab.

3. Build and start the stack:

   ```bash
   docker compose up -d --build
   ```

4. Check the API:

   ```bash
   python scripts/healthcheck.py
   ```

5. Open the analyst UI:

   ```text
   http://localhost:3001
   ```

Stop the stack with:

```bash
docker compose down
```

Use `docker compose down -v` only when you intentionally want to remove the PostgreSQL volume.

## Local Development

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev,probe]"
ruff check .
pytest
```

Run migrations against the configured database:

```bash
alembic upgrade head
```

Run synthetic experiments:

```bash
python -m experiments.runner.run_scenarios
```

Prepare and check a live Mac lab:

```bash
python scripts/create_lab_env.py
docker compose up -d --build
python scripts/live_lab_check.py --api-url http://localhost:8000/health --web-url http://localhost:3001
```

Detailed live setup steps are in `docs/live-lab-setup.md`.

The research papers, experiment reports, and architecture diagrams are maintained outside the
public source-code snapshot. The setup guides above cover running the software.

## Wazuh Live Lab Quick Start

Start the Wazuh single-node stack:

```bash
python scripts/setup_wazuh_lab.py start
python scripts/wazuh_lab_check.py
```

Open:

```text
CSG dashboard:   http://localhost:3001
Wazuh dashboard: https://localhost:8443
CSG API status:  http://localhost:8000/api/wazuh/status
```

Use the credentials configured for your local Wazuh deployment. Do not commit passwords or local
`.env` files to the repository.

After the Windows VM is running, install the Wazuh agent and Sysmon from elevated PowerShell:

```powershell
.\scripts\install_wazuh_agent_windows.ps1 -WazuhManager "<mac-reachable-address>"
```

Then use the Wazuh agent ID or name with:

```bash
curl -X POST http://localhost:8000/api/hosts/<agent-id-or-name>/provider-sync
```

## Probe Quick Start

Install probe dependencies on the Windows target:

```powershell
py -m pip install -e .[probe]
```

Run one collection pass:

```powershell
py -m cyberstateguardian_probe.main --once
```

The probe sends normalized observations to `POST /api/probe/observations` using a bearer token.
Set `CSG_PROBE_API_URL`, `CSG_PROBE_HOST_ID`, `CSG_PROBE_HOST_ROLE`, and `CSG_PROBE_TOKEN` in the
Windows environment. The probe includes host identity metadata so the API can register the reporting
machine automatically.
For UTM, use the Mac address or hostname reachable from the Windows VM rather than assuming
`localhost` or a Docker-only hostname.

By default, live findings are created for low-change security categories:
`service`, `listener`, `scheduled_task`, `privileged_group`, and `registry`. Process deltas are still
stored as telemetry, but they do not become findings unless `CSG_LIVE_FINDING_CATEGORIES` includes
`process`.

## Research Integrity

- Synthetic fixtures are marked as synthetic and separate from live telemetry.
- Deterministic reconciliation, authorization, and risk scoring are not affected by AI output.
- Unexplained changes are visible findings, not automatic malicious verdicts.
- Every security artifact is keyed by `host_id`.
