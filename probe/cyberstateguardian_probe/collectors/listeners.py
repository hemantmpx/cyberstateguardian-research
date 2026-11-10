from __future__ import annotations

from typing import Any


def collect_listeners() -> dict[str, Any]:
    try:
        import psutil
    except ImportError as exc:
        return _error("psutil is not installed", exc)

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied as exc:
        return _error("listener collection requires elevated permissions on this OS", exc)
    except OSError as exc:
        return _error("listener collection failed", exc)

    rows: list[dict[str, Any]] = []
    failures = 0
    for conn in connections:
        if getattr(conn, "status", None) != psutil.CONN_LISTEN:
            continue
        try:
            process_name = None
            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    failures += 1
            laddr = conn.laddr
            rows.append(
                {
                    "protocol": "tcp",
                    "local_address": getattr(laddr, "ip", None) or laddr[0],
                    "local_port": getattr(laddr, "port", None) or laddr[1],
                    "pid": conn.pid,
                    "process_name": process_name,
                },
            )
        except (IndexError, TypeError):
            failures += 1
    status = "partial" if failures else "healthy"
    return {
        "category": "listener",
        "status": status,
        "items": rows,
        "message": f"{failures} listener records were incomplete" if failures else None,
    }


def _error(message: str, exc: Exception) -> dict[str, Any]:
    return {
        "category": "listener",
        "status": "error",
        "items": [],
        "message": f"{message}: {type(exc).__name__}",
    }
