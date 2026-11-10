from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cyberstateguardian_probe.normalize import clean_dict, normalize_path, normalize_username


def collect_processes() -> dict[str, Any]:
    try:
        import psutil
    except ImportError as exc:
        return _error("psutil is not installed", exc)

    rows: list[dict[str, Any]] = []
    failures = 0
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "username", "create_time"]):
        try:
            info = proc.info
            create_time = info.get("create_time")
            create_iso = (
                datetime.fromtimestamp(float(create_time), tz=UTC).isoformat()
                if create_time
                else None
            )
            rows.append(
                clean_dict(
                    {
                        "pid": info.get("pid"),
                        "ppid": info.get("ppid"),
                        "name": info.get("name"),
                        "executable_path": normalize_path(info.get("exe")),
                        "username": normalize_username(info.get("username")),
                        "create_time": create_iso,
                    },
                ),
            )
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            failures += 1
    status = "partial" if failures else "healthy"
    return {
        "category": "process",
        "status": status,
        "items": rows,
        "message": f"{failures} process records could not be read" if failures else None,
    }


def _error(message: str, exc: Exception) -> dict[str, Any]:
    return {
        "category": "process",
        "status": "error",
        "items": [],
        "message": f"{message}: {type(exc).__name__}",
    }
