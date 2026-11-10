from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from csg.config import Settings
from csg.db.repositories import CyberStateRepository
from csg.db.session import SessionLocal
from csg.services.provider_sync import ProviderSyncService


async def sync(
    host_ids: list[str],
    state_provider: str = "probe",
) -> dict[str, object]:
    settings = Settings(CSG_STATE_PROVIDER=state_provider, CSG_EVENT_PROVIDER="wazuh")
    if not Path("/.dockerenv").exists():
        settings = settings.model_copy(
            update={
                "wazuh_api_url": host_side_url(settings.wazuh_api_url),
                "wazuh_indexer_url": host_side_url(settings.wazuh_indexer_url),
            }
        )
    with SessionLocal() as session:
        result = await ProviderSyncService(settings).sync_hosts(
            CyberStateRepository(session),
            host_ids,
        )
    return result.summary()


def host_side_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.hostname != "host.docker.internal":
        return url
    netloc = "localhost"
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def main() -> None:
    parser = argparse.ArgumentParser(description="Pull Wazuh inventory and alerts into CSG once.")
    parser.add_argument(
        "host_ids",
        nargs="+",
        help="Wazuh agent ID, Wazuh agent name, or agent IP visible in Wazuh.",
    )
    parser.add_argument(
        "--state-provider",
        choices=("probe", "wazuh"),
        default="probe",
        help="Use probe for the independent research state plane; wazuh is fallback mode.",
    )
    args = parser.parse_args()
    print(json.dumps(asyncio.run(sync(args.host_ids, args.state_provider)), indent=2))


if __name__ == "__main__":
    main()
