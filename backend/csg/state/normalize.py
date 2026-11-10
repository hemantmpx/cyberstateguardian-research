from __future__ import annotations

import re
from typing import Any


def normalize_string(value: Any) -> str:
    return str(value or "").strip()


def normalize_path(value: Any) -> str:
    text = normalize_string(value).replace("\\", "/")
    text = re.sub(r"/+", "/", text)
    return text.lower()


def normalize_username(value: Any) -> str:
    text = normalize_string(value).replace("\\", "/")
    return text.lower()


def normalize_registry_key(value: Any) -> str:
    text = normalize_path(value).removeprefix("registry:")
    for prefix, hive in (
        ("hkey_local_machine", "hklm"),
        ("hkey_current_user", "hkcu"),
        ("hkey_users", "hku"),
        ("hklm:", "hklm"),
        ("hkcu:", "hkcu"),
        ("hku:", "hku"),
    ):
        if text == prefix or text.startswith(prefix + "/"):
            text = hive + text[len(prefix) :]
            break
    return "registry:" + text


def normalize_protocol(value: Any) -> str:
    return normalize_string(value).lower()


def normalize_service_status(value: Any) -> str:
    return normalize_string(value).lower().replace(" ", "_")


def stable_process_key(item: dict[str, Any]) -> str:
    executable = normalize_path(item.get("executable_path") or item.get("exe") or item.get("path"))
    name = normalize_string(item.get("name")).lower()
    username = normalize_username(item.get("username"))
    create_time = normalize_string(item.get("create_time") or item.get("created_at"))
    identity = executable or name
    if create_time:
        return f"process:{identity}:{username}:{create_time}"
    ppid = normalize_string(item.get("ppid"))
    return f"process:{identity}:{username}:ppid:{ppid}"


def stable_listener_key(item: dict[str, Any]) -> str:
    protocol = normalize_protocol(item.get("protocol"))
    address = normalize_string(item.get("local_address") or item.get("address")).lower()
    port = normalize_string(item.get("local_port") or item.get("port"))
    return f"listener:{protocol}:{address}:{port}"


def stable_service_key(item: dict[str, Any]) -> str:
    service_name = normalize_string(item.get("service_name") or item.get("name")).lower()
    return f"service:{service_name}"


def stable_scheduled_task_key(item: dict[str, Any]) -> str:
    task_name = normalize_string(item.get("task_name") or item.get("name")).replace("/", "\\")
    task_name = re.sub(r"\\+", lambda _: "\\", task_name)
    if task_name and not task_name.startswith("\\"):
        task_name = f"\\{task_name}"
    task_name = task_name.lower()
    return f"scheduled_task:{task_name}"


def stable_privileged_group_key(item: dict[str, Any]) -> str:
    group = normalize_string(item.get("group") or item.get("group_name")).lower()
    member = normalize_username(item.get("member") or item.get("username"))
    return f"privileged_group:{group}:{member}"


def stable_object_key(category: str, item: dict[str, Any]) -> str:
    match category:
        case "process":
            return stable_process_key(item)
        case "listener":
            return stable_listener_key(item)
        case "service":
            return stable_service_key(item)
        case "scheduled_task":
            return stable_scheduled_task_key(item)
        case "privileged_group":
            return stable_privileged_group_key(item)
        case "registry":
            return normalize_registry_key(item.get("object_key") or item.get("name"))
        case _:
            existing = item.get("object_key")
            if existing:
                return normalize_string(existing).lower()
            name = normalize_string(item.get("name") or item.get("id")).lower()
            return f"{category}:{name}"


def normalize_attributes(category: str, item: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(item)
    if "username" in normalized:
        normalized["username"] = normalize_username(normalized["username"])
    if "user" in normalized:
        normalized["user"] = normalize_username(normalized["user"])
    for key in ("executable_path", "binary_path", "path", "exe"):
        if key in normalized and normalized[key]:
            normalized[key] = normalize_path(normalized[key])
    if "protocol" in normalized:
        normalized["protocol"] = normalize_protocol(normalized["protocol"])
    if "status" in normalized and category == "service":
        normalized["status"] = normalize_service_status(normalized["status"])
    if "start_mode" in normalized:
        normalized["start_mode"] = normalize_service_status(normalized["start_mode"])
    return {key: _normalize_value(value) for key, value in sorted(normalized.items())}


def comparable_attributes(
    attributes: dict[str, Any], category: str | None = None
) -> dict[str, Any]:
    ignored = {"pid", "ppid", "last_seen", "collection_order"}
    if category == "service":
        # Win32_Service.State is runtime status, not persistent configuration.
        ignored.add("status")
    return {key: _normalize_value(value) for key, value in attributes.items() if key not in ignored}


def _normalize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _normalize_value(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return sorted((_normalize_value(item) for item in value), key=repr)
    return value
