from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import re
import sys
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from csg.config import get_settings
from csg.providers.wazuh import WazuhClient, WazuhConfig


def normalize_query(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def query_hash(value: str) -> str:
    return hashlib.sha256(normalize_query(value).encode("utf-8")).hexdigest()


def select_active_security_localfile_block(payload: dict[str, Any]) -> dict[str, Any]:
    blocks = payload.get("data", {}).get("localfile", [])
    security_blocks = [block for block in blocks if block.get("channel") == "Security"]
    if len(security_blocks) != 1:
        raise ValueError(
            f"Expected one active Security localfile block; found {len(security_blocks)}"
        )
    return security_blocks[0]


def write_audit_result(result: dict[str, Any], output: Path | None) -> None:
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_error_result(
    exc: Exception, *, agent_id: str, api_path: str, expected_query: str | None
) -> dict[str, Any]:
    response = getattr(exc, "response", None)
    response_detail: dict[str, Any] | None = None
    if response is not None:
        try:
            body = response.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            allowed_fields = ("title", "detail", "error", "remediation")
            response_detail = {key: body[key] for key in allowed_fields if key in body}

    return {
        "schema_version": "csg-wazuh-active-eventchannel-query-v1",
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "agent_id": agent_id,
        "active_config_api_path": api_path,
        "expected_query_sha256_normalized": (
            query_hash(expected_query) if expected_query is not None else None
        ),
        "matches_expected_query": False if expected_query is not None else None,
        "http_status_code": response.status_code if response is not None else None,
        "response_detail": response_detail,
        "error": f"{type(exc).__name__}: {exc}",
    }


async def inspect_active_query(
    *, agent_id: str, api_url: str | None, expected_query: str | None
) -> dict[str, Any]:
    settings = get_settings()
    if api_url:
        settings = settings.model_copy(update={"wazuh_api_url": api_url.rstrip("/")})
    config = WazuhConfig.from_settings(settings)
    api_path = f"/agents/{agent_id}/config/logcollector/localfile"
    async with WazuhClient(config) as client:
        payload = await client.api_get(api_path)

    active_block = select_active_security_localfile_block(payload)
    query = active_block.get("query", {})
    active_query = query.get("value", "") if isinstance(query, dict) else str(query)
    if not active_query:
        raise ValueError("Active Security localfile block has no query value")

    matches_expected = (
        normalize_query(active_query) == normalize_query(expected_query)
        if expected_query is not None
        else None
    )
    return {
        "schema_version": "csg-wazuh-active-eventchannel-query-v1",
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "agent_id": agent_id,
        "active_config_api_path": api_path,
        "channel": "Security",
        "api_error": payload.get("error"),
        "security_localfile_block_count": 1,
        "active_localfile_block": active_block,
        "active_query": active_query,
        "active_query_sha256_normalized": query_hash(active_query),
        "expected_query_sha256_normalized": (
            query_hash(expected_query) if expected_query is not None else None
        ),
        "matches_expected_query": matches_expected,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read and optionally verify an agent's active Wazuh EventChannel query."
    )
    parser.add_argument("--agent-id", default="001")
    parser.add_argument("--api-url", help="Override CSG_WAZUH_API_URL, e.g. https://192.168.64.1:55000")
    parser.add_argument(
        "--expected-query-base64",
        help=(
            "Expected XPath encoded as UTF-8 base64; the Windows pilot prints this "
            "before its gate."
        ),
    )
    parser.add_argument("--output", type=Path, help="Optional path for the JSON audit record.")
    return parser.parse_args()


async def async_main(args: argparse.Namespace) -> int:
    expected_query = None
    if args.expected_query_base64:
        try:
            expected_query = base64.b64decode(
                args.expected_query_base64, validate=True
            ).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("Expected query must be valid UTF-8 base64") from exc

    result = await inspect_active_query(
        agent_id=args.agent_id,
        api_url=args.api_url,
        expected_query=expected_query,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    write_audit_result(result, args.output)
    print(rendered)
    return 0 if result["matches_expected_query"] is not False else 2


def main() -> int:
    args = parse_args()
    try:
        return asyncio.run(async_main(args))
    except Exception as exc:
        expected_query = None
        if args.expected_query_base64:
            with suppress(ValueError, UnicodeDecodeError):
                expected_query = base64.b64decode(
                    args.expected_query_base64, validate=True
                ).decode("utf-8")
        api_path = f"/agents/{args.agent_id}/config/logcollector/localfile"
        result = build_error_result(
            exc,
            agent_id=args.agent_id,
            api_path=api_path,
            expected_query=expected_query,
        )
        write_audit_result(result, args.output)
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
