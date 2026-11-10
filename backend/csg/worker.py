from __future__ import annotations

import asyncio
import logging
import os
import signal
import time

from csg.config import get_settings
from csg.db.repositories import CyberStateRepository
from csg.db.session import SessionLocal
from csg.services.live_pipeline import LivePipelineService
from csg.services.provider_sync import ProviderSyncService

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
LOGGER = logging.getLogger("csg.worker")
STOP = False


def _stop(_signum: int, _frame: object) -> None:
    global STOP
    STOP = True


def main() -> None:
    settings = get_settings()
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    LOGGER.info(
        "CyberStateGuardian worker started provider_state=%s provider_event=%s",
        settings.state_provider,
        settings.event_provider,
    )
    pipeline = LivePipelineService(settings)
    provider_sync = ProviderSyncService(settings)
    while not STOP:
        try:
            with SessionLocal() as session:
                repo = CyberStateRepository(session)
                if settings.wazuh_sync_enabled and settings.wazuh_sync_host_id_list:
                    for host_id in settings.wazuh_sync_host_id_list:
                        try:
                            sync_result = asyncio.run(provider_sync.sync_host(repo, host_id))
                            LOGGER.info(
                                "worker provider sync host=%s events=%s",
                                host_id,
                                len(sync_result.events),
                            )
                        except Exception:
                            session.rollback()
                            LOGGER.exception(
                                "provider sync failed host=%s; continuing local reconciliation",
                                host_id,
                            )
                result = pipeline.process_backlog(repo)
                LOGGER.info(
                    "worker cycle processed_deltas=%s created_findings=%s skipped=%s ignored=%s",
                    len(result.deltas),
                    len(result.findings),
                    result.skipped_existing_findings,
                    result.skipped_ignored_categories,
                )
        except Exception:
            LOGGER.exception("worker cycle failed; will retry")
        time.sleep(settings.worker_interval_seconds)
    LOGGER.info("CyberStateGuardian worker stopped")


if __name__ == "__main__":
    main()
