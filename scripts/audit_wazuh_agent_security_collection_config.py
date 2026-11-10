from __future__ import annotations

import argparse
import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote
from xml.etree import ElementTree

from csg.config import get_settings
from csg.providers.wazuh import WazuhClient, WazuhConfig


def security_blocks(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            location = str(node.get("channel") or node.get("location") or "").strip()
            if location.casefold() == "security":
                query = node.get("query")
                if isinstance(query, dict):
                    query = query.get("value")
                log_format = (
                    node.get("log_format") or node.get("logformat") or node.get("type")
                )
                if isinstance(log_format, dict):
                    log_format = log_format.get("value")
                found.append(
                    {
                        "location": location,
                        "log_format": log_format,
                        "query": query,
                        "only_future_events": node.get("only-future-events"),
                    }
                )
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)
        elif isinstance(node, str) and node.lstrip().startswith("<"):
            try:
                root = ElementTree.fromstring(node)
            except ElementTree.ParseError:
                return
            for block in root.iter():
                if block.tag.rsplit("}", 1)[-1] != "localfile":
                    continue
                fields = {
                    child.tag.rsplit("}", 1)[-1]: child.text
                    for child in block
                    if child.tag.rsplit("}", 1)[-1]
                    in {"location", "log_format", "query", "only-future-events"}
                }
                if str(fields.get("location", "")).strip().casefold() == "security":
                    found.append(fields)

    walk(value)
    return found


async def audit(agent_id: str, api_url: str | None) -> dict[str, Any]:
    settings = get_settings()
    if api_url:
        settings = settings.model_copy(update={"wazuh_api_url": api_url.rstrip("/")})
    config = WazuhConfig.from_settings(settings)
    async with WazuhClient(config) as client:
        agent_payload = await client.api_get(
            "/agents",
            params={"agents_list": agent_id, "select": "id,name,group,group_config_status"},
        )
        agents = agent_payload.get("data", {}).get("affected_items", [])
        if len(agents) != 1:
            raise RuntimeError(f"Expected one agent record for {agent_id}; received {len(agents)}")
        agent = agents[0]
        groups = [str(group) for group in agent.get("group", [])]

        active_payload = await client.api_get(
            f"/agents/{quote(agent_id, safe='')}/config/logcollector/localfile"
        )
        group_results = []
        for group in groups:
            payload = await client.api_get(
                f"/groups/{quote(group, safe='')}/configuration"
            )
            group_results.append(
                {
                    "group": group,
                    "api_error": payload.get("error"),
                    "response_keys": sorted(payload),
                    "data_keys": sorted(payload.get("data", {}))
                    if isinstance(payload.get("data"), dict)
                    else [],
                    "group_config_item_count": len(
                        payload.get("data", {}).get("affected_items", [])
                    ),
                    "security_localfile_blocks": security_blocks(payload),
                }
            )

    return {
        "schema_version": "csg-wazuh-agent-security-config-audit-v1",
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "agent": {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "groups": groups,
            "group_config_status": agent.get("group_config_status"),
        },
        "active_agent_security_localfile_blocks": security_blocks(active_payload),
        "central_group_security_localfile_blocks": group_results,
        "interpretation_note": (
            "This read-only API audit compares the agent-reported logcollector Security block "
            "with Security localfile blocks in its assigned centralized groups. It does not "
            "inspect the collector's in-memory subscription or prove event filtering."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit local and centralized Wazuh Security EventChannel configuration."
    )
    parser.add_argument("--agent-id", default="001")
    parser.add_argument("--api-url", help="Override CSG_WAZUH_API_URL")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = asyncio.run(audit(args.agent_id, args.api_url))
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
