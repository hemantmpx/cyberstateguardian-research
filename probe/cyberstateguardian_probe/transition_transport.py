from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

LOGGER = logging.getLogger("csg.probe.transitions.transport")


def transition_endpoint(observation_url: str) -> str:
    parts = urlsplit(observation_url)
    path = parts.path.rstrip("/")
    if path.endswith("/observations"):
        path = path[: -len("observations")] + "transitions"
    else:
        path = path + "/transitions"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))


class DurableTransitionTransport:
    """Append-first JSONL spool; network failure never removes queued transition batches."""

    def __init__(
        self,
        *,
        api_url: str,
        token: str,
        spool_path: Path,
        max_spool_bytes: int,
        timeout_seconds: float,
        max_retries: int,
    ) -> None:
        self.api_url = api_url
        self.token = token
        self.spool_path = spool_path
        self.max_spool_bytes = max_spool_bytes
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.metrics: dict[str, int | float] = {
            "batches_spooled": 0,
            "batches_sent": 0,
            "bytes_spooled": 0,
            "bytes_sent": 0,
            "spool_full_batches": 0,
            "upload_failures": 0,
            "queue_depth": 0,
        }

    def start(self) -> None:
        self.spool_path.parent.mkdir(parents=True, exist_ok=True)
        if self._thread and self._thread.is_alive():
            return
        if self.spool_path.exists():
            with self.spool_path.open("rb") as handle:
                self.metrics["queue_depth"] = sum(1 for _ in handle)
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._worker, name="csg-transition-uploader", daemon=True
        )
        self._thread.start()
        if self.metrics["queue_depth"]:
            self._wake.set()

    def submit(self, payload: dict[str, Any]) -> bool:
        encoded = (json.dumps(payload, separators=(",", ":"), allow_nan=False) + "\n").encode(
            "utf-8"
        )
        with self._lock:
            current_size = self.spool_path.stat().st_size if self.spool_path.exists() else 0
            if current_size + len(encoded) > self.max_spool_bytes:
                self.metrics["spool_full_batches"] += 1
                LOGGER.error(
                    "transition spool full; batch not accepted path=%s size=%s limit=%s",
                    self.spool_path,
                    current_size,
                    self.max_spool_bytes,
                )
                return False
            with self.spool_path.open("ab") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            self.metrics["batches_spooled"] += 1
            self.metrics["bytes_spooled"] += len(encoded)
            self.metrics["queue_depth"] = int(self.metrics["queue_depth"]) + 1
        self._wake.set()
        return True

    def stop(self, timeout_seconds: float = 10.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout_seconds)

    def _worker(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(1.0)
            self._wake.clear()
            self.flush_one()
        while self.flush_one():
            pass

    def flush_one(self) -> bool:
        with self._lock:
            if not self.spool_path.exists():
                return False
            content = self.spool_path.read_bytes()
            first, separator, rest = content.partition(b"\n")
            if not separator:
                LOGGER.error("incomplete transition spool line retained for recovery")
                return False
        try:
            payload = json.loads(first)
        except (UnicodeDecodeError, json.JSONDecodeError):
            LOGGER.exception("invalid transition spool record retained path=%s", self.spool_path)
            return False
        if not self._send(payload, len(first) + 1):
            return False
        with self._lock:
            current = self.spool_path.read_bytes() if self.spool_path.exists() else b""
            current_first, current_separator, current_rest = current.partition(b"\n")
            if not current_separator or current_first != first:
                LOGGER.error("transition spool head changed unexpectedly; retaining queued data")
                return False
            temporary = self.spool_path.with_suffix(self.spool_path.suffix + ".tmp")
            with temporary.open("wb") as handle:
                handle.write(current_rest)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.spool_path)
            self.metrics["queue_depth"] = max(0, int(self.metrics["queue_depth"]) - 1)
        return bool(rest)

    def _send(self, payload: dict[str, Any], body_bytes: int) -> bool:
        try:
            import requests
        except ImportError:
            LOGGER.error("requests is not installed; transition batch remains spooled")
            return False
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        body = json.dumps(payload, allow_nan=False).encode("utf-8")
        for attempt in range(1, self.max_retries + 1):
            try:
                response = requests.post(
                    self.api_url,
                    data=body,
                    headers=headers,
                    timeout=self.timeout_seconds,
                )
                if response.ok:
                    self.metrics["batches_sent"] += 1
                    self.metrics["bytes_sent"] += body_bytes
                    return True
                LOGGER.warning(
                    "transition upload failed status=%s response=%s",
                    response.status_code,
                    response.text,
                )
            except requests.RequestException as exc:
                LOGGER.warning("transition upload attempt %s failed: %s", attempt, exc)
            if attempt < self.max_retries:
                time.sleep(min(attempt, 5))
        self.metrics["upload_failures"] += 1
        return False
