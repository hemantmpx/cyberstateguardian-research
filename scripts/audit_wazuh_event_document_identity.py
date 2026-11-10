from __future__ import annotations

import argparse
import asyncio
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from csg.config import get_settings
from csg.providers.wazuh import WazuhClient, WazuhConfig, _stable_windows_event_identity


def _field(source: dict[str, Any], *paths: tuple[str, ...]) -> Any:
    for path in paths:
        value: Any = source
        for part in path:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        if value is not None:
            return value
    return None


def _event_references(run: dict[str, Any]) -> list[dict[str, str]]:
    scenarios = run.get("scenarios") or []
    references: dict[tuple[str, str], dict[str, str]] = {}
    for scenario in scenarios:
        events = list((scenario.get("event_plane") or {}).get("exact_matches") or [])
        events.extend((scenario.get("distractor_evidence") or {}).get("provider_events") or [])
        for event in events:
            for reference in [event.get("source_reference"), *(
                (event.get("metadata") or {}).get("additional_source_references") or []
            )]:
                if not isinstance(reference, dict):
                    continue
                index = reference.get("index")
                document_id = reference.get("document_id")
                if index and document_id:
                    references[(str(index), str(document_id))] = {
                        "index": str(index),
                        "document_id": str(document_id),
                        "event_id": str(event.get("event_id") or ""),
                        "host_id": str(event.get("host_id") or ""),
                        "normalized_type": str(event.get("normalized_type") or ""),
                    }
    return list(references.values())


def _document_summary(reference: dict[str, str], source: dict[str, Any]) -> dict[str, Any]:
    system = _field(source, ("data", "win", "system"), ("win", "system")) or {}
    event_data = _field(source, ("data", "win", "eventdata"), ("win", "eventdata")) or {}
    agent = source.get("agent") if isinstance(source.get("agent"), dict) else {}
    identity = _stable_windows_event_identity(source)
    return {
        **reference,
        "source_kind": "wazuh_archive" if "archives" in reference["index"] else "wazuh_alert",
        "agent_id": agent.get("id"),
        "event_id_raw": _field(system, ("eventID",), ("eventId",)),
        "event_record_id": _field(
            system,
            ("eventRecordID",),
            ("eventRecordId",),
            ("eventrecordid",),
        ),
        "channel": system.get("channel"),
        "computer": system.get("computer"),
        "raw_task_name": _field(event_data, ("taskName",), ("TaskName",)),
        "event_timestamp": source.get("timestamp") or source.get("@timestamp"),
        "stable_windows_event_identity": list(identity) if identity else None,
    }


async def audit(args: argparse.Namespace) -> dict[str, Any]:
    run = json.loads(args.run_json.read_text(encoding="utf-8-sig"))
    settings = get_settings()
    updates: dict[str, Any] = {}
    if args.api_url:
        updates["wazuh_api_url"] = args.api_url.rstrip("/")
    if args.indexer_url:
        updates["wazuh_indexer_url"] = args.indexer_url.rstrip("/")
    if updates:
        settings = settings.model_copy(update=updates)
    config = WazuhConfig.from_settings(settings)

    documents: list[dict[str, Any]] = []
    async with WazuhClient(config) as client:
        for reference in _event_references(run):
            path = f"{reference['index']}/_doc/{reference['document_id']}"
            payload = await client.indexer_get(path)
            source = payload.get("_source")
            if not isinstance(source, dict):
                documents.append({**reference, "document_found": False})
                continue
            documents.append({"document_found": True, **_document_summary(reference, source)})

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for document in documents:
        identity = document.get("stable_windows_event_identity")
        if identity:
            groups[json.dumps(identity, separators=(",", ":"))].append(document)

    return {
        "schema_version": "csg-wazuh-raw-event-identity-audit-v1",
        "run_artifact": str(args.run_json),
        "raw_indexer_document_count": len(documents),
        "documents": documents,
        "stable_identity_groups": [
            {"identity": json.loads(identity), "documents": grouped}
            for identity, grouped in groups.items()
        ],
        "limitations": [
            "Reads selected fields only; does not archive full raw event payloads.",
            "Stable identity is the same helper used by the live Wazuh provider normalizer.",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit raw Wazuh Indexer documents referenced by a live CSG run."
    )
    parser.add_argument("--run-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--api-url", help="Override the Wazuh API URL")
    parser.add_argument("--indexer-url", help="Override the Wazuh Indexer URL")
    return parser.parse_args()


async def async_main(args: argparse.Namespace) -> int:
    result = await audit(args)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if all(item.get("document_found") for item in result["documents"]) else 2


def main() -> int:
    return asyncio.run(async_main(parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
