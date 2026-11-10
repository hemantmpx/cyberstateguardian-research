# Mac to Proxmox Migration Plan

This project is designed so the Mac build becomes the Proxmox build without a rewrite.

## Preflight Audit

1. Confirm the repository has no hard-coded Mac paths:

   ```bash
   rg "/Users|host.docker.internal|Docker Desktop|localhost" backend probe config compose.yaml
   ```

   `localhost` is acceptable only for human-facing local examples, never required runtime wiring.

2. Confirm schema creation is migration-driven:

   ```bash
   alembic upgrade head
   ```

3. Confirm the container builds on the current architecture:

   ```bash
   docker compose build api worker web
   ```

4. For amd64 validation from Apple silicon, use Buildx when available:

   ```bash
   docker buildx build --platform linux/amd64 -f docker/backend.Dockerfile --load -t csg-api:amd64 .
   ```

## csg-dev Ubuntu Setup

1. Create the `csg-dev` Ubuntu VM.
2. Install Docker Engine, the Compose plugin, Git, and time synchronization.
3. Clone this repository.
4. Copy `.env.example` to `.env` and replace all placeholders.
5. Use Docker service names inside Compose and configured URLs for external systems.
6. Start the stack:

   ```bash
   docker compose up -d --build
   ```

7. Run migrations and health checks:

   ```bash
   docker compose exec api alembic upgrade head
   python scripts/healthcheck.py --url http://localhost:8000/health
   ```

## PostgreSQL Backup and Restore

Create a logical backup from the Mac stack:

```bash
docker compose exec postgres pg_dump -U csg cyberstateguardian > csg-backup.sql
```

Restore on `csg-dev`:

```bash
docker compose exec -T postgres psql -U csg cyberstateguardian < csg-backup.sql
```

For Docker named volumes, prefer logical backups for portability. Use raw volume migration only when
PostgreSQL versions and platform assumptions are intentionally controlled.

## Wazuh Migration

Wazuh is implemented in the Mac lab through the official Docker single-node deployment. When moving
to Proxmox, reuse the same CSG provider configuration and decide whether Wazuh stays Docker-based on
`csg-dev` or moves to a separate `csg-wazuh` VM.

The current Mac/UTM lab already has a Windows endpoint enrolled as `win11-arm-lab`. During Proxmox
migration, either re-enroll that endpoint against the Proxmox Wazuh manager or update the Windows
agent manager address and document the new agent ID/name/IP before running research trials.

Before switching the research run to a Proxmox Wazuh instance, inspect and document:

- Wazuh version.
- API authentication method.
- Index names.
- Syscollector/global-state fields.
- Windows/Sysmon event fields.
- Source scan timestamps and freshness behavior.
- Wazuh agent IDs/names/IPs used as CSG host identifiers.

The existing `WazuhStateProvider` and `WazuhEventProvider` should continue returning the same CSG
domain models. If the Proxmox Wazuh deployment has different fields, update only the Wazuh adapter
normalization and tests. Do not change state, diff, reconciliation, authorization, risk, experiment,
AI, or UI logic to fit a particular Wazuh deployment.

## Release Checklist

- `ruff check .` passes.
- `pytest` passes.
- `docker compose config` succeeds.
- `docker compose up -d --build` starts postgres, api, worker, and web.
- `/health` returns `status=ok`.
- `python -m experiments.runner.run_scenarios` exports JSON and CSV results.
- Provider config can be switched without code changes.
- `/api/wazuh/status` reports Wazuh API/indexer status without exposing secrets.
- Wazuh endpoint proof is run against an enrolled Windows agent, not the built-in manager agent.
- The controlled service drift drill is repeated after migration before claiming Proxmox results.
