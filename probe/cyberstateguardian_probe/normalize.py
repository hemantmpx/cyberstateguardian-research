from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def normalize_path(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().replace("\\", "/")
    return text.lower() or None


def normalize_username(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().replace("\\", "/").lower()
    return text or None


def clean_dict(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value is not None}
