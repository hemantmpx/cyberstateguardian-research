from __future__ import annotations

from typing import Any

import httpx

from csg.config import Settings
from csg.providers.wazuh import WazuhClient, WazuhConfig

JsonDict = dict[str, Any]


class WazuhStatusService:
    def __init__(
        self,
        settings: Settings,
        client_factory: type[WazuhClient] = WazuhClient,
    ) -> None:
        self.settings = settings
        self.client_factory = client_factory

    async def status(self) -> JsonDict:
        config = WazuhConfig.from_settings(self.settings)
        result: JsonDict = {
            "enabled": self._provider_enabled(),
            "configured": bool(config.api_password and config.indexer_password),
            "ok": False,
            "state_provider": self.settings.state_provider,
            "event_provider": self.settings.event_provider,
            "api_url": config.api_url,
            "indexer_url": config.indexer_url,
            "dashboard_url": self.settings.wazuh_dashboard_url,
            "server_api": {"ok": False},
            "indexer": {"ok": False},
            "agent_count": 0,
            "endpoint_agent_count": 0,
            "agents": [],
            "sync": {
                "enabled": self.settings.wazuh_sync_enabled,
                "host_ids": self.settings.wazuh_sync_host_id_list,
                "lookback_seconds": self.settings.wazuh_event_lookback_seconds,
            },
            "warnings": [],
        }

        if not result["configured"]:
            result["warnings"].append(
                "Wazuh API/indexer passwords are not configured in the CSG environment."
            )
            return result

        async with self.client_factory(config) as client:
            result["indexer"] = await self._indexer_status(client)
            result["server_api"] = await self._server_api_status(client)

        agents = result["server_api"].get("agents", [])
        if isinstance(agents, list):
            result["agents"] = agents
            result["agent_count"] = len(agents)
            result["endpoint_agent_count"] = len(
                [agent for agent in agents if not agent.get("manager")]
            )

        result["ok"] = bool(result["server_api"].get("ok") and result["indexer"].get("ok"))
        if result["ok"] and result["endpoint_agent_count"] == 0:
            result["warnings"].append(
                "Only the built-in Wazuh manager agent is enrolled; "
                "the Windows VM agent is still pending."
            )
        if result["ok"] and not self.settings.wazuh_sync_enabled:
            result["warnings"].append(
                "Automatic Wazuh sync is disabled; use provider-sync manually "
                "or enable sync after Windows enrollment."
            )
        return result

    async def _indexer_status(self, client: WazuhClient) -> JsonDict:
        try:
            info = await client.indexer_get("/")
            return {
                "ok": True,
                "cluster_name": info.get("cluster_name"),
                "cluster_uuid": info.get("cluster_uuid"),
                "version": _nested_text(info, "version.number"),
            }
        except Exception as exc:
            return {"ok": False, "error": _error_text(exc)}

    async def _server_api_status(self, client: WazuhClient) -> JsonDict:
        try:
            agents = [_agent_summary(agent) for agent in await client.list_agents()]
            return {
                "ok": True,
                "agents": agents,
            }
        except Exception as exc:
            return {"ok": False, "error": _error_text(exc), "agents": []}

    def _provider_enabled(self) -> bool:
        return self.settings.state_provider == "wazuh" or self.settings.event_provider == "wazuh"


def _agent_summary(agent: JsonDict) -> JsonDict:
    agent_id = _text(agent.get("id"))
    os_info = agent.get("os") if isinstance(agent.get("os"), dict) else {}
    return _drop_empty(
        {
            "id": agent_id,
            "name": agent.get("name"),
            "ip": agent.get("ip"),
            "status": agent.get("status"),
            "version": agent.get("version"),
            "os": os_info.get("name") or os_info.get("platform"),
            "manager": agent_id == "000",
        }
    )


def _error_text(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}: {exc.response.reason_phrase}"
    return f"{type(exc).__name__}: {exc}"


def _nested_text(mapping: JsonDict, path: str) -> str | None:
    current: Any = mapping
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return _text(current) or None


def _drop_empty(mapping: JsonDict) -> JsonDict:
    return {key: value for key, value in mapping.items() if value not in (None, "", [], {})}


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""
