from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from csg.domain.enums import AuthorizationStatus, DeltaType
from csg.domain.models import MaintenanceWindow, StateDelta, ensure_utc


@dataclass(frozen=True)
class AuthorizationDecision:
    status: AuthorizationStatus
    reason: str
    matched_rule: dict[str, Any] | None = None


class AuthorizationService:
    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self.config = self._load_config(config_path)

    def evaluate_delta(self, delta: StateDelta) -> AuthorizationDecision:
        host_config = self.config.get("hosts", {}).get(delta.host_id, {})
        object_key = delta.object_key
        category = delta.category
        when = ensure_utc(delta.created_at)

        for item in host_config.get("violating_objects", []):
            if item.get("category") == category and item.get("object_key") == object_key:
                return AuthorizationDecision(
                    AuthorizationStatus.VIOLATION,
                    item.get("reason", "object conflicts with authorized state"),
                    item,
                )

        expected_section = self._expected_section(category)
        for item in host_config.get(expected_section, []):
            if item.get("object_key") == object_key:
                operation = delta.delta_type.value
                allowed_operations = {
                    str(value).upper()
                    for value in item.get("allowed_operations", ["ADD", "MODIFY", "REMOVE"])
                }
                if operation not in allowed_operations:
                    return AuthorizationDecision(
                        AuthorizationStatus.VIOLATION,
                        f"{operation} is not authorized for {object_key}",
                        item,
                    )
                expected_attributes = item.get("attributes") or {}
                if expected_attributes and not self._attributes_match(delta, expected_attributes):
                    return AuthorizationDecision(
                        AuthorizationStatus.VIOLATION,
                        f"{object_key} attributes do not match the authorized baseline",
                        item,
                    )
                return AuthorizationDecision(
                    AuthorizationStatus.EXPECTED,
                    (
                        f"{object_key} matches the authorized baseline transition"
                        if expected_attributes
                        else f"{object_key} is present in authorized baseline"
                    ),
                    item,
                )

        for item in host_config.get("approved_changes", []):
            if item.get("category") != category or item.get("object_key") != object_key:
                continue
            if self._within(when, item.get("valid_from"), item.get("valid_until")):
                if not self._attributes_match(
                    delta,
                    item.get("allowed_after") or item.get("attributes") or {},
                ):
                    return AuthorizationDecision(
                        AuthorizationStatus.VIOLATION,
                        "approved change does not authorize the observed attributes",
                        item,
                    )
                return AuthorizationDecision(
                    AuthorizationStatus.APPROVED_CHANGE,
                    item.get("reason", "change is approved for this time window"),
                    item,
                )

        for item in host_config.get("maintenance_windows", []):
            window = MaintenanceWindow(
                window_id=item["window_id"],
                host_id=delta.host_id,
                valid_from=item["valid_from"],
                valid_until=item["valid_until"],
                categories=item.get("categories", []),
                object_keys=item.get("object_keys", []),
                reason=item["reason"],
            )
            if window.contains(when, category, object_key):
                return AuthorizationDecision(
                    AuthorizationStatus.APPROVED_CHANGE,
                    window.reason,
                    item,
                )

        if category == "privileged_group":
            return AuthorizationDecision(
                AuthorizationStatus.VIOLATION,
                "privileged group change is not approved",
                {"category": category, "object_key": object_key},
            )

        return AuthorizationDecision(
            AuthorizationStatus.UNKNOWN,
            "no matching expected object, approved change, or maintenance window",
            None,
        )

    @staticmethod
    def _within(when, valid_from: str | None, valid_until: str | None) -> bool:
        if not valid_from or not valid_until:
            return False
        start = _parse_datetime(valid_from)
        end = _parse_datetime(valid_until)
        return start <= when <= end

    @staticmethod
    def _expected_section(category: str) -> str:
        return {
            "service": "expected_services",
            "listener": "expected_listeners",
            "process": "expected_processes",
        }.get(category, "expected_objects")

    @staticmethod
    def _attributes_match(delta: StateDelta, expected: dict[str, Any]) -> bool:
        observed = delta.after.attributes if delta.after else {}
        before = delta.before.attributes if delta.before else {}
        for key, expected_value in expected.items():
            if key == "allowed_modified_fields":
                continue
            if observed.get(key) != expected_value:
                return False
        if delta.delta_type != DeltaType.MODIFY:
            return True
        allowed_fields = expected.get("allowed_modified_fields")
        if not allowed_fields:
            return True
        changed_fields = {
            key
            for key in set(before) | set(observed)
            if before.get(key) != observed.get(key)
        }
        return changed_fields.issubset(set(allowed_fields))

    @staticmethod
    def _load_config(config_path: Path) -> dict[str, Any]:
        if not config_path.exists():
            return {"hosts": {}}
        with config_path.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle) or {}
        return loaded


def _parse_datetime(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return ensure_utc(value)
    return ensure_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
