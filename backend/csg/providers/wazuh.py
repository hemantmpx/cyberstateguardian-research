from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PureWindowsPath
from time import perf_counter
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

import httpx

from csg.config import Settings
from csg.domain.models import (
    CategoryStatus,
    EventObservationResult,
    NormalizedEvent,
    StateObject,
    StateSnapshot,
    ensure_utc,
    utc_now,
)
from csg.state.normalize import normalize_attributes, stable_object_key

JsonDict = dict[str, Any]
CollectorState = Literal["healthy", "partial", "error", "unavailable"]


class WazuhConfigurationError(RuntimeError):
    pass


class WazuhProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class WazuhConfig:
    api_url: str
    indexer_url: str
    api_user: str
    api_password: str | None
    indexer_user: str
    indexer_password: str | None
    verify_ssl: bool = False
    alert_index_pattern: str = "wazuh-alerts-*"
    archive_index_pattern: str | None = None
    inventory_index_prefix: str = "wazuh-states-inventory"
    inventory_limit: int = 5000
    event_limit: int = 5000
    request_timeout_seconds: float = 20.0

    @classmethod
    def from_settings(cls, settings: Settings) -> WazuhConfig:
        return cls(
            api_url=settings.wazuh_api_url.rstrip("/"),
            indexer_url=settings.wazuh_indexer_url.rstrip("/"),
            api_user=settings.wazuh_api_user,
            api_password=_blank_to_none(settings.wazuh_api_password),
            indexer_user=settings.wazuh_indexer_user,
            indexer_password=_blank_to_none(settings.wazuh_indexer_password),
            verify_ssl=settings.wazuh_verify_ssl,
            alert_index_pattern=settings.wazuh_alert_index_pattern,
            archive_index_pattern=settings.wazuh_archive_index_pattern,
            inventory_index_prefix=settings.wazuh_inventory_index_prefix.rstrip("-"),
            inventory_limit=settings.wazuh_inventory_limit,
            event_limit=settings.wazuh_event_limit,
            request_timeout_seconds=settings.wazuh_request_timeout_seconds,
        )

    def require_api_password(self) -> str:
        if not self.api_password:
            raise WazuhConfigurationError(
                "CSG_WAZUH_API_PASSWORD is required when using the Wazuh server API."
            )
        return self.api_password

    def require_indexer_password(self) -> str:
        if not self.indexer_password:
            raise WazuhConfigurationError(
                "CSG_WAZUH_INDEXER_PASSWORD is required when using the Wazuh indexer API."
            )
        return self.indexer_password


class WazuhClient:
    def __init__(
        self,
        config: WazuhConfig,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self._client = httpx.AsyncClient(
            verify=config.verify_ssl,
            timeout=config.request_timeout_seconds,
            transport=transport,
        )
        self._token: str | None = None

    async def __aenter__(self) -> WazuhClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def api_token(self) -> str:
        if self._token is not None:
            return self._token
        response = await self._client.post(
            f"{self.config.api_url}/security/user/authenticate",
            params={"raw": "true"},
            auth=(self.config.api_user, self.config.require_api_password()),
        )
        response.raise_for_status()
        self._token = response.text.strip()
        if not self._token:
            raise WazuhProviderError("Wazuh server API returned an empty authentication token.")
        return self._token

    async def api_get(self, path: str, params: JsonDict | None = None) -> JsonDict:
        token = await self.api_token()
        response = await self._client.get(
            f"{self.config.api_url}/{path.lstrip('/')}",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        return _json_response(response)

    async def list_agents(self) -> list[JsonDict]:
        payload = await self.api_get("/agents", params={"limit": 1000})
        return _affected_items(payload)

    async def find_agent(self, host_id: str) -> JsonDict | None:
        for agent in await self.list_agents():
            if host_id in {
                _text(agent.get("id")),
                _text(agent.get("name")),
                _text(agent.get("ip")),
            }:
                return agent
        return None

    async def indexer_search(self, index_pattern: str, body: JsonDict) -> JsonDict:
        response = await self._client.post(
            f"{self.config.indexer_url}/{index_pattern}/_search",
            auth=(self.config.indexer_user, self.config.require_indexer_password()),
            json=body,
        )
        response.raise_for_status()
        return _json_response(response)

    async def indexer_get(self, path: str = "/") -> JsonDict:
        response = await self._client.get(
            f"{self.config.indexer_url}/{path.lstrip('/')}",
            auth=(self.config.indexer_user, self.config.require_indexer_password()),
        )
        response.raise_for_status()
        return _json_response(response)


class WazuhStateProvider:
    def __init__(
        self,
        config: WazuhConfig,
        client_factory: type[WazuhClient] = WazuhClient,
    ) -> None:
        self.config = config
        self.client_factory = client_factory

    @classmethod
    def from_settings(cls, settings: Settings) -> WazuhStateProvider:
        return cls(WazuhConfig.from_settings(settings))

    async def get_snapshot(self, host_id: str) -> StateSnapshot:
        observed_at = utc_now()
        statuses: list[CategoryStatus] = []
        objects: list[StateObject] = []
        agent: JsonDict | None = None

        async with self.client_factory(self.config) as client:
            for inventory in _STATE_INVENTORIES:
                try:
                    hits = await _inventory_hits(
                        client,
                        host_id=host_id,
                        inventory=inventory.index_name,
                        limit=self.config.inventory_limit,
                    )
                except httpx.HTTPStatusError as exc:
                    statuses.append(
                        _status(
                            inventory.category,
                            "unavailable" if exc.response.status_code == 404 else "error",
                            observed_at,
                            f"Wazuh inventory query failed: HTTP {exc.response.status_code}",
                        )
                    )
                    continue
                except Exception as exc:
                    statuses.append(
                        _status(
                            inventory.category,
                            "error",
                            observed_at,
                            f"Wazuh inventory query failed: {type(exc).__name__}: {exc}",
                        )
                    )
                    continue

                if not hits:
                    statuses.append(
                        _status(
                            inventory.category,
                            "partial",
                            observed_at,
                            "Wazuh query succeeded but no inventory rows matched this host.",
                        )
                    )
                    continue

                statuses.append(_status(inventory.category, "healthy", observed_at))
                for hit in hits:
                    source = _hit_source(hit)
                    agent = agent or _agent_metadata(source)
                    item = inventory.normalizer(source)
                    if not item:
                        continue
                    attributes = normalize_attributes(inventory.category, item)
                    objects.append(
                        StateObject(
                            category=inventory.category,
                            object_key=stable_object_key(inventory.category, attributes),
                            attributes=attributes,
                            source_timestamp=_timestamp_from_source(source, observed_at),
                            metadata={
                                "source": "wazuh",
                                "wazuh_index": hit.get("_index"),
                                "wazuh_document_id": hit.get("_id"),
                            },
                        )
                    )

        return StateSnapshot(
            host_id=host_id,
            built_at=observed_at,
            source="wazuh",
            category_statuses=statuses,
            objects=sorted(objects, key=lambda item: (item.category, item.object_key)),
            metadata={
                "host": _host_metadata(host_id, agent),
                "wazuh": {
                    "api_url": self.config.api_url,
                    "indexer_url": self.config.indexer_url,
                    "inventory_index_prefix": self.config.inventory_index_prefix,
                },
            },
        )


class WazuhEventProvider:
    def __init__(
        self,
        config: WazuhConfig,
        client_factory: type[WazuhClient] = WazuhClient,
    ) -> None:
        self.config = config
        self.client_factory = client_factory

    @classmethod
    def from_settings(cls, settings: Settings) -> WazuhEventProvider:
        return cls(WazuhConfig.from_settings(settings))

    async def get_events(
        self,
        host_id: str,
        start: datetime,
        end: datetime,
    ) -> EventObservationResult:
        start = ensure_utc(start)
        end = ensure_utc(end)
        query_started_at = utc_now()
        query_timer = perf_counter()
        async with self.client_factory(self.config) as client:
            endpoint_status_timer = perf_counter()
            endpoint_status = await _agent_collection_status(client, host_id)
            endpoint_status_duration = perf_counter() - endpoint_status_timer
            sources = [("wazuh_alert", self.config.alert_index_pattern, "@timestamp")]
            if self.config.archive_index_pattern:
                sources.append(("wazuh_archive", self.config.archive_index_pattern, "timestamp"))

            hits: list[JsonDict] = []
            source_results: JsonDict = {}
            pages = 0
            total_hits = 0
            all_queries_complete = True
            successful_sources = 0
            for source_kind, index_pattern, timestamp_field in sources:
                source_timer = perf_counter()
                try:
                    source_hits, source_retrieval = await _event_hits(
                        client,
                        host_id=host_id,
                        start=start,
                        end=end,
                        limit=self.config.event_limit,
                        index_pattern=index_pattern,
                        timestamp_field=timestamp_field,
                    )
                except Exception as exc:
                    all_queries_complete = False
                    source_results[source_kind] = {
                        "status": "UNAVAILABLE",
                        "index_pattern": index_pattern,
                        "error": f"{type(exc).__name__}: {exc}",
                        "duration_seconds": round(perf_counter() - source_timer, 6),
                    }
                    continue

                successful_sources += 1
                source_results[source_kind] = {
                    "status": "AVAILABLE" if source_retrieval["complete"] else "DEGRADED",
                    "index_pattern": index_pattern,
                    "timestamp_field": timestamp_field,
                    "duration_seconds": round(perf_counter() - source_timer, 6),
                    **source_retrieval,
                }
                all_queries_complete = all_queries_complete and bool(source_retrieval["complete"])
                pages += int(source_retrieval.get("pages") or 0)
                if source_retrieval.get("total_hits") is None:
                    total_hits = -1
                elif total_hits >= 0:
                    total_hits += int(source_retrieval["total_hits"])
                hits.extend({**hit, "_csg_source_kind": source_kind} for hit in source_hits)

        events = _normalize_and_deduplicate_event_hits(host_id, hits)
        all_sources_succeeded = successful_sources == len(sources)
        if all_sources_succeeded:
            index_status = "AVAILABLE" if all_queries_complete else "DEGRADED"
            transport_status = "AVAILABLE"
            coverage_status = "COMPLETE" if all_queries_complete else "PARTIAL"
        elif successful_sources:
            index_status = "DEGRADED"
            transport_status = "DEGRADED"
            coverage_status = "PARTIAL"
        else:
            index_status = "UNAVAILABLE"
            transport_status = "UNAVAILABLE"
            coverage_status = "UNAVAILABLE"

        retrieval = {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "query_started_at": query_started_at.isoformat(),
            "query_completed_at": utc_now().isoformat(),
            "duration_seconds": round(perf_counter() - query_timer, 6),
            "endpoint_status_duration_seconds": round(endpoint_status_duration, 6),
            "sources": source_results,
            "complete": all_queries_complete and all_sources_succeeded,
            "pages": pages,
            "returned_hits": len(hits),
            "normalized_events": len(events),
            "total_hits": None if total_hits < 0 else total_hits,
        }
        for event in events:
            event.metadata["retrieval"] = retrieval
            event.metadata["source_health"] = {
                "endpoint_collection_status": endpoint_status,
                "transport_status": transport_status,
                "index_status": index_status,
            }
        return EventObservationResult(
            events=sorted(events, key=lambda event: (event.event_time, event.event_id)),
            query_complete=bool(retrieval.get("complete")),
            endpoint_collection_status=endpoint_status,
            transport_status=transport_status,
            index_status=index_status,
            coverage_status=coverage_status,
            retrieval_pages=pages,
            retrieved_count=len(events),
            total_hits=retrieval.get("total_hits"),
            metadata={"retrieval": retrieval},
        )


async def _agent_collection_status(client: WazuhClient, host_id: str) -> str:
    find_agent = getattr(client, "find_agent", None)
    if find_agent is None:
        # Lightweight test transports and non-Wazuh providers do not expose agent health.
        return "AVAILABLE"
    try:
        agent = await find_agent(host_id)
    except Exception:
        return "UNKNOWN"
    if not agent:
        return "UNKNOWN"
    status = str(agent.get("status") or "").lower()
    if status == "active":
        return "AVAILABLE"
    if status in {"disconnected", "pending", "never_connected"}:
        return "DEGRADED"
    return "UNKNOWN"


@dataclass(frozen=True)
class InventoryMapping:
    index_name: str
    category: str
    normalizer: Any


_STATE_INVENTORIES = (
    InventoryMapping("processes", "process", lambda source: _normalize_process(source)),
    InventoryMapping("ports", "listener", lambda source: _normalize_port(source)),
    InventoryMapping("services", "service", lambda source: _normalize_service(source)),
)


async def _event_hits(
    client: WazuhClient,
    *,
    host_id: str,
    start: datetime,
    end: datetime,
    limit: int,
    index_pattern: str,
    timestamp_field: str,
) -> tuple[list[JsonDict], JsonDict]:
    """Retrieve all pages from one Wazuh event index and report search completeness."""
    hits: list[JsonDict] = []
    search_after: list[Any] | None = None
    total_hits: int | None = None
    pages = 0
    complete = False
    while pages < 100:
        body: JsonDict = {
            "size": limit,
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                timestamp_field: {
                                    "gte": start.isoformat(),
                                    "lte": end.isoformat(),
                                }
                            }
                        }
                    ],
                    "should": _host_match_clauses(host_id),
                    "minimum_should_match": 1,
                }
            },
            "sort": [
                {timestamp_field: {"order": "asc", "unmapped_type": "date"}},
                {"_id": {"order": "asc"}},
            ],
        }
        if search_after is not None:
            body["search_after"] = search_after
        payload = await client.indexer_search(index_pattern, body)
        page = _search_hits(payload)
        pages += 1
        if total_hits is None:
            total_hits = _total_hits(payload)
        hits.extend(page)
        if not page or len(page) < limit:
            complete = True
            break
        sort_values = page[-1].get("sort")
        if not isinstance(sort_values, list) or not sort_values:
            complete = total_hits is None or total_hits <= len(hits)
            break
        search_after = sort_values

    if pages >= 100 and not complete:
        complete = total_hits is not None and total_hits <= len(hits)
    return hits, {
        "complete": complete,
        "pages": pages,
        "returned_hits": len(hits),
        "total_hits": total_hits,
        "limit": limit,
    }


async def _inventory_hits(
    client: WazuhClient,
    host_id: str,
    inventory: str,
    limit: int,
) -> list[JsonDict]:
    body = {
        "size": limit,
        "query": {
            "bool": {
                "should": _host_match_clauses(host_id),
                "minimum_should_match": 1,
            }
        },
        "sort": [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
            {"scan.time": {"order": "desc", "unmapped_type": "date"}},
        ],
    }
    payload = await client.indexer_search(
        f"{client.config.inventory_index_prefix}-{inventory}-*",
        body,
    )
    return _search_hits(payload)


def _normalize_process(source: JsonDict) -> JsonDict | None:
    process = _dict_at(source, "process")
    pid = _first(source, "process.pid", "pid")
    name = _first(source, "process.name", "name")
    command = _first(source, "process.command_line", "process.cmd", "cmd", "argvs")
    executable = _first(source, "process.executable", "process.path", "path", "cmd")
    username = _first(
        source,
        "process.user.name",
        "user.name",
        "euser",
        "suser",
        "ruser",
    )

    if not any([pid, name, command, executable]):
        return None

    return _drop_empty(
        {
            "pid": pid,
            "ppid": _first(source, "process.parent.pid", "ppid"),
            "name": name or _basename(_text(executable)),
            "executable_path": executable,
            "command_line": command,
            "username": username,
            "create_time": _first(
                source,
                "process.start",
                "process.start_time",
                "start_time",
                "scan.time",
                "@timestamp",
            ),
            "state": _first(source, "process.state", "state"),
            "session": _first(source, "process.session", "session"),
            "agent_id": _first(source, "agent.id", "agent_id"),
            "raw_process": process or None,
        }
    )


def _normalize_port(source: JsonDict) -> JsonDict | None:
    local = _dict_at(source, "local")
    remote = _dict_at(source, "remote")
    port = _dict_at(source, "port")
    process = _dict_at(source, "process")

    local_port = _first(
        source,
        "network.transport_port",
        "destination.port",
        "local.port",
        "port.local_port",
        "port.source.port",
        "local_port",
    )
    protocol = _first(
        source,
        "network.transport",
        "network.protocol",
        "protocol",
        "transport",
        "port.protocol",
    )
    local_address = _first(
        source,
        "source.ip",
        "local.ip",
        "port.local_ip",
        "local_address",
        "address",
    )

    if not (local_port and protocol):
        return None

    return _drop_empty(
        {
            "protocol": protocol,
            "local_address": local_address or "0.0.0.0",
            "local_port": local_port,
            "remote_address": _first(source, "destination.ip", "remote.ip", "remote_address"),
            "remote_port": _first(source, "destination.port", "remote.port", "remote_port"),
            "status": _first(source, "port.state", "state"),
            "pid": _first(source, "process.pid", "pid"),
            "process_name": _first(source, "process.name", "process", "process_name"),
            "agent_id": _first(source, "agent.id", "agent_id"),
            "raw_local": local or None,
            "raw_remote": remote or None,
            "raw_port": port or None,
            "raw_process": process or None,
        }
    )


def _normalize_service(source: JsonDict) -> JsonDict | None:
    service = _dict_at(source, "service")
    service_name = _first(source, "service.name", "service_name", "name")
    if not service_name:
        return None

    return _drop_empty(
        {
            "service_name": service_name,
            "display_name": _first(source, "service.display_name", "display_name"),
            "status": _first(source, "service.state", "service.status", "status", "state"),
            "start_mode": _first(
                source,
                "service.start_type",
                "service.start_mode",
                "start_mode",
                "start_type",
            ),
            "binary_path": _first(
                source,
                "service.path",
                "service.binary_path",
                "binary_path",
                "path",
            ),
            "account": _first(source, "service.account", "account", "run_as"),
            "description": _first(source, "service.description", "description"),
            "agent_id": _first(source, "agent.id", "agent_id"),
            "raw_service": service or None,
        }
    )


def _normalized_event_from_alert(host_id: str, hit: JsonDict) -> NormalizedEvent:
    source = _hit_source(hit)
    windows_event_identity = _windows_event_identity(source)
    timestamp = _timestamp_from_source(source, utc_now())
    normalized_type = _event_type(source)
    attributes = _event_attributes(normalized_type, source)
    target = _event_target(normalized_type, attributes, source)
    actor = _event_actor(source)
    index_name = _text(hit.get("_index")) or "unknown"
    document_id = _text(hit.get("_id")) or _event_hash(source)

    return NormalizedEvent(
        event_id=f"wazuh-{uuid5(NAMESPACE_URL, f'{index_name}:{document_id}')}",
        host_id=host_id,
        event_time=timestamp,
        normalized_type=normalized_type,
        actor=actor,
        target=target,
        attributes=attributes,
        source="wazuh",
        source_reference={"index": index_name, "document_id": document_id},
        synthetic=False,
        metadata={
            "source_kind": hit.get("_csg_source_kind") or "wazuh_alert",
            "agent": source.get("agent") if isinstance(source.get("agent"), dict) else {},
            "decoder": source.get("decoder") if isinstance(source.get("decoder"), dict) else {},
            "location": source.get("location"),
            "rule": source.get("rule") if isinstance(source.get("rule"), dict) else {},
            **(
                {"windows_event_identity": windows_event_identity} if windows_event_identity else {}
            ),
        },
    )


def _normalize_and_deduplicate_event_hits(
    host_id: str,
    hits: list[JsonDict],
) -> list[NormalizedEvent]:
    """Keep alert enrichment while retaining archive provenance for duplicate Windows events."""
    events: list[NormalizedEvent] = []
    positions: dict[tuple[str, ...], int] = {}
    for hit in hits:
        event = _normalized_event_from_alert(host_id=host_id, hit=hit)
        identity = _stable_windows_event_identity(_hit_source(hit))
        if identity is None or identity not in positions:
            if identity is not None:
                positions[identity] = len(events)
            events.append(event)
            continue

        original = events[positions[identity]]
        references = original.metadata.setdefault("additional_source_references", [])
        reference = {
            "source_kind": event.metadata.get("source_kind"),
            **event.source_reference,
        }
        if reference not in references:
            references.append(reference)
    return events


def _windows_event_identity(source: JsonDict) -> JsonDict | None:
    agent_id = _text(_first(source, "agent.id", "agent_id"))
    channel = _text(
        _first(source, "data.win.system.channel", "win.system.channel", "win.system.channelName")
    ).lower()
    record_id = _text(
        _first(
            source,
            "data.win.system.eventRecordID",
            "data.win.system.eventRecordId",
            "win.system.eventRecordID",
            "win.system.eventRecordId",
            "event.record_id",
        )
    )
    event_code = _event_code(source)
    provider = _text(
        _first(source, "data.win.system.providerName", "win.system.providerName")
    ).lower()
    if not all((agent_id, channel, record_id, event_code)):
        return None
    return {
        "agent_id": agent_id,
        "channel": channel,
        "event_record_id": record_id,
        "event_code": event_code,
        "provider_name": provider,
    }


def _stable_windows_event_identity(source: JsonDict) -> tuple[str, ...] | None:
    identity = _windows_event_identity(source)
    return tuple(identity.values()) if identity else None


def _event_type(source: JsonDict) -> str:
    code = _event_code(source)
    provider = _text(
        _first(source, "data.win.system.providerName", "win.system.providerName")
    ).lower()
    groups = " ".join(_strings(_first(source, "rule.groups", "rule.groups.keyword"))).lower()

    if code in {"7045", "4697"}:
        return "service_created"
    if code == "7040":
        return "service_modified"
    if code == "5154" and "security-auditing" in provider:
        return "listener_created"
    if code == "4698":
        return "scheduled_task_created"
    if code == "4702":
        return "scheduled_task_modified"
    if code in {"4728", "4732", "4756"}:
        return "privileged_group_member_added"
    if code == "1" and ("sysmon" in provider or "sysmon" in groups):
        return "process_start"
    if code in {"3", "5156"} and ("sysmon" in provider or "sysmon" in groups or code == "5156"):
        return "network_activity"
    if code == "13" and ("sysmon" in provider or "sysmon" in groups):
        return "registry_value_modified"
    if "sysmon_event1" in groups or "sysmon event id 1" in groups:
        return "process_start"
    if "sysmon_event3" in groups or "sysmon event id 3" in groups:
        return "network_activity"
    return "wazuh_alert"


def _event_attributes(normalized_type: str, source: JsonDict) -> JsonDict:
    event_data = _event_data(source)
    event_code = _event_code(source)
    common = _drop_empty(
        {
            "event_code": event_code,
            "rule_id": _first(source, "rule.id"),
            "rule_level": _first(source, "rule.level"),
            "rule_description": _first(source, "rule.description"),
        }
    )

    if normalized_type == "listener_created":
        raw_protocol = _text(_first(event_data, "Protocol", "protocol"))
        protocol = {"6": "tcp", "17": "udp"}.get(raw_protocol, raw_protocol.lower())
        local_address = _first(event_data, "SourceAddress", "sourceAddress")
        raw_port = _text(_first(event_data, "SourcePort", "sourcePort"))
        local_port = int(raw_port) if raw_port.isdigit() and 0 < int(raw_port) <= 65535 else None
        application = _text(_first(event_data, "Application", "application"))
        return {
            **common,
            **_drop_empty(
                {
                    "protocol": protocol if protocol in {"tcp", "udp"} else None,
                    "local_address": local_address,
                    "local_port": local_port,
                    "process_id": _first(event_data, "ProcessId", "processId"),
                    "application": application,
                    "process_name": _basename(application),
                }
            ),
        }

    if normalized_type in {"service_created", "service_modified"}:
        return {
            **common,
            **_drop_empty(
                {
                    "service_name": _first(
                        event_data,
                        "ServiceName",
                        "serviceName",
                        "service_name",
                        "param4",
                    ),
                    "reported_service_name": _first(event_data, "param1"),
                    "display_name": _first(event_data, "DisplayName", "displayName"),
                    "binary_path": _first(event_data, "ImagePath", "imagePath", "param2"),
                    "service_type": _first(event_data, "ServiceType", "serviceType"),
                    "start_mode": _first(event_data, "StartType", "startType"),
                    "account": _first(event_data, "AccountName", "accountName"),
                    "old_start_mode": _first(event_data, "OldStartType", "oldStartType", "param2"),
                    "new_start_mode": _first(event_data, "NewStartType", "newStartType", "param3"),
                }
            ),
        }

    if normalized_type in {"scheduled_task_created", "scheduled_task_modified"}:
        return {
            **common,
            **_drop_empty(
                {
                    "task_name": _first(event_data, "TaskName", "taskName", "task_name"),
                    "task_content": _first(event_data, "TaskContent", "taskContent"),
                    "username": _first(event_data, "SubjectUserName", "UserName", "user"),
                }
            ),
        }

    if normalized_type == "privileged_group_member_added":
        group = _first(
            event_data,
            "TargetUserName",
            "targetUserName",
            "GroupName",
            "groupName",
            "group",
            "group_name",
        )
        member = _usable_event_identity(_first(event_data, "MemberName", "memberName", "member"))
        member_sid = _usable_event_identity(
            _first(event_data, "MemberSid", "memberSid", "member_sid")
        )
        return {
            **common,
            **_drop_empty(
                {
                    "group": group,
                    "member": member,
                    "member_sid": member_sid,
                    "username": _first(
                        event_data,
                        "SubjectUserName",
                        "subjectUserName",
                        "SubjectDomainName",
                        "subjectDomainName",
                    ),
                }
            ),
        }

    if normalized_type == "process_start":
        image = _first(
            event_data,
            "Image",
            "image",
            "NewProcessName",
            "ProcessName",
            "process.executable",
        )
        return {
            **common,
            **_drop_empty(
                {
                    "name": _first(event_data, "OriginalFileName", "Product", "ProcessName")
                    or _basename(_text(image)),
                    "executable_path": image,
                    "command_line": _first(
                        event_data,
                        "CommandLine",
                        "commandLine",
                        "ProcessCommandLine",
                    ),
                    "username": _first(event_data, "User", "SubjectUserName"),
                    "pid": _first(event_data, "ProcessId", "NewProcessId"),
                    "parent_path": _first(event_data, "ParentImage", "ParentProcessName"),
                    "parent_pid": _first(event_data, "ParentProcessId"),
                }
            ),
        }

    if normalized_type == "network_activity":
        protocol = _first(event_data, "Protocol", "protocol", "network.protocol")
        source_port = _first(
            event_data,
            "SourcePort",
            "sourcePort",
        )
        destination_port = _first(
            event_data,
            "DestinationPort",
            "destinationPort",
            "DestPort",
        )
        return {
            **common,
            **_drop_empty(
                {
                    "protocol": protocol,
                    "source_address": _first(
                        event_data,
                        "SourceIp",
                        "sourceIp",
                    ),
                    "source_port": source_port,
                    "destination_address": _first(
                        event_data,
                        "DestinationIp",
                        "destinationIp",
                        "DestAddress",
                    ),
                    "destination_port": destination_port,
                    "direction": "outbound",
                    "process_name": _basename(
                        _text(_first(event_data, "Image", "Application", "ProcessName"))
                    ),
                    "executable_path": _first(event_data, "Image", "Application", "ProcessName"),
                }
            ),
        }

    if normalized_type == "registry_value_modified":
        return {
            **common,
            **_drop_empty(
                {
                    "target_object": _first(event_data, "TargetObject", "targetObject"),
                    "details": _first(event_data, "Details", "details"),
                    "event_type": _first(event_data, "EventType", "eventType"),
                    "process_id": _first(event_data, "ProcessId", "processId"),
                    "image": _first(event_data, "Image", "image"),
                    "username": _first(event_data, "User", "user"),
                }
            ),
        }

    return {
        **common,
        **_drop_empty(
            {
                "description": _first(source, "rule.description"),
                "event_code": event_code,
                "location": source.get("location"),
            }
        ),
    }


def _event_target(normalized_type: str, attributes: JsonDict, source: JsonDict) -> JsonDict:
    if normalized_type in {"service_created", "service_modified"}:
        service_name = _text(attributes.get("service_name"))
        return _drop_empty(
            {
                "key": stable_object_key("service", {"service_name": service_name})
                if service_name
                else None,
                "service_name": service_name,
            }
        )

    if normalized_type == "registry_value_modified":
        target_object = _text(attributes.get("target_object"))
        normalized_key = target_object.replace("\\", "/").lower()
        while "//" in normalized_key:
            normalized_key = normalized_key.replace("//", "/")
        return _drop_empty(
            {
                "key": f"registry:{normalized_key}" if normalized_key else None,
                "target_object": target_object,
            }
        )

    if normalized_type in {"scheduled_task_created", "scheduled_task_modified"}:
        task_name = _text(attributes.get("task_name"))
        return _drop_empty(
            {
                "key": stable_object_key("scheduled_task", {"task_name": task_name})
                if task_name
                else None,
                "task_name": task_name,
            }
        )

    if normalized_type == "privileged_group_member_added":
        group = _text(attributes.get("group"))
        member = _text(attributes.get("member"))
        member_sid = _text(attributes.get("member_sid"))
        return _drop_empty(
            {
                "key": stable_object_key(
                    "privileged_group",
                    {"group": group, "member": member},
                )
                if group and member
                else None,
                "group": group,
                "member": member,
                "member_sid": member_sid,
            }
        )

    if normalized_type == "process_start":
        return _drop_empty(
            {
                "key": stable_object_key("process", attributes),
                "name": attributes.get("name"),
                "executable_path": attributes.get("executable_path"),
            }
        )

    if normalized_type == "listener_created":
        has_endpoint = all(
            attributes.get(key) for key in ("protocol", "local_address", "local_port")
        )
        return _drop_empty(
            {
                "key": stable_object_key("listener", attributes) if has_endpoint else None,
                "protocol": attributes.get("protocol"),
                "local_address": attributes.get("local_address"),
                "local_port": attributes.get("local_port"),
            }
        )

    if normalized_type == "network_activity":
        return _drop_empty(
            {
                "key": stable_object_key("listener", attributes)
                if attributes.get("protocol") and attributes.get("local_port")
                else None,
                "protocol": attributes.get("protocol"),
                "local_port": attributes.get("local_port"),
                "local_address": attributes.get("local_address"),
            }
        )

    return _drop_empty(
        {
            "description": _first(source, "rule.description"),
            "rule_id": _first(source, "rule.id"),
        }
    )


def _event_actor(source: JsonDict) -> JsonDict:
    event_data = _event_data(source)
    return _drop_empty(
        {
            "username": _first(
                event_data,
                "SubjectUserName",
                "User",
                "AccountName",
                "TargetUserName",
                "user",
            ),
            "domain": _first(event_data, "SubjectDomainName", "TargetDomainName", "domain"),
            "process": _first(event_data, "ParentImage", "ParentProcessName"),
        }
    )


def _event_data(source: JsonDict) -> JsonDict:
    for path in ("data.win.eventdata", "win.eventdata", "eventdata", "data.eventdata"):
        value = _first(source, path)
        if isinstance(value, dict):
            return value
    data = source.get("data")
    return data if isinstance(data, dict) else {}


def _event_code(source: JsonDict) -> str:
    return _text(
        _first(
            source,
            "data.win.system.eventID",
            "data.win.system.eventId",
            "data.win.system.event_id",
            "win.system.eventID",
            "win.system.event_id",
            "event.code",
            "event_id",
            "eventID",
        )
    )


def _host_match_clauses(host_id: str) -> list[JsonDict]:
    return [
        {"term": {"agent.id": host_id}},
        {"term": {"agent.id.keyword": host_id}},
        {"term": {"agent.name": host_id}},
        {"term": {"agent.name.keyword": host_id}},
        {"term": {"agent.ip": host_id}},
        {"term": {"agent.ip.keyword": host_id}},
        {"match": {"agent.name": host_id}},
    ]


def _status(
    category: str,
    state: CollectorState,
    observed_at: datetime,
    message: str | None = None,
) -> CategoryStatus:
    return CategoryStatus(
        category=category,
        status=state,
        source="wazuh",
        observed_at=observed_at,
        message=message,
    )


def _search_hits(payload: JsonDict) -> list[JsonDict]:
    hits = _first(payload, "hits.hits")
    return hits if isinstance(hits, list) else []


def _total_hits(payload: JsonDict) -> int | None:
    total = _first(payload, "hits.total")
    if isinstance(total, dict):
        total = total.get("value")
    try:
        return int(total) if total is not None else None
    except (TypeError, ValueError):
        return None


def _hit_source(hit: JsonDict) -> JsonDict:
    source = hit.get("_source")
    return source if isinstance(source, dict) else {}


def _affected_items(payload: JsonDict) -> list[JsonDict]:
    items = _first(payload, "data.affected_items")
    return items if isinstance(items, list) else []


def _agent_metadata(source: JsonDict) -> JsonDict:
    agent = source.get("agent")
    return agent if isinstance(agent, dict) else {}


def _host_metadata(host_id: str, agent: JsonDict | None) -> JsonDict:
    agent = agent or {}
    return _drop_empty(
        {
            "hostname": _first(agent, "name") or host_id,
            "role": "wazuh-agent",
            "os": _first(agent, "os.name", "os.platform", "os.type") or "unknown",
            "architecture": _first(agent, "architecture", "os.architecture") or "unknown",
            "wazuh_agent_id": _first(agent, "id"),
            "wazuh_agent_ip": _first(agent, "ip"),
            "wazuh_agent_status": _first(agent, "status"),
        }
    )


def _timestamp_from_source(source: JsonDict, fallback: datetime) -> datetime:
    value = _first(source, "@timestamp", "timestamp", "scan.time", "event.created")
    parsed = _parse_datetime(value)
    return parsed or ensure_utc(fallback)


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return ensure_utc(value)
    if isinstance(value, int | float):
        try:
            return ensure_utc(datetime.fromtimestamp(value, UTC))
        except (OverflowError, OSError, ValueError):
            return None
    text = _text(value)
    if not text:
        return None
    if text.isdigit():
        try:
            return ensure_utc(datetime.fromtimestamp(int(text), UTC))
        except (OverflowError, OSError, ValueError):
            return None
    try:
        return ensure_utc(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError:
        return None


def _first(mapping: JsonDict, *paths: str) -> Any:
    for path in paths:
        value = _get_path(mapping, path)
        if value not in (None, ""):
            return value
    return None


def _get_path(mapping: JsonDict, path: str) -> Any:
    if path in mapping:
        return mapping[path]
    current: Any = mapping
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _dict_at(mapping: JsonDict, path: str) -> JsonDict:
    value = _get_path(mapping, path)
    return value if isinstance(value, dict) else {}


def _json_response(response: httpx.Response) -> JsonDict:
    try:
        payload = response.json()
    except ValueError as exc:
        raise WazuhProviderError("Wazuh returned a non-JSON response.") from exc
    if not isinstance(payload, dict):
        raise WazuhProviderError("Wazuh returned a JSON value that was not an object.")
    return payload


def _strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return [_text(item) for item in value if _text(item)]
    text = _text(value)
    return [text] if text else []


def _drop_empty(mapping: JsonDict) -> JsonDict:
    return {key: value for key, value in mapping.items() if value not in (None, "", [], {})}


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _usable_event_identity(value: Any) -> str | None:
    text = _text(value)
    return text if text and text != "-" else None


def _blank_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _basename(value: str) -> str:
    if not value:
        return ""
    return PureWindowsPath(value.replace("/", "\\")).name


def _event_hash(source: JsonDict) -> str:
    parts: Iterable[str] = (
        _text(_first(source, "@timestamp", "timestamp")),
        _text(_first(source, "rule.id", "rule.description")),
        _text(_first(source, "agent.id", "agent.name")),
        repr(sorted(source.items())),
    )
    return str(uuid5(NAMESPACE_URL, "|".join(parts)))
