from __future__ import annotations

import json
import logging
import time
from collections import deque
from typing import Any

LOGGER = logging.getLogger("csg.probe.transport")


class QueuedTransport:
    def __init__(
        self,
        api_url: str,
        token: str,
        timeout_seconds: float,
        max_queue_size: int,
        max_retries: int,
    ) -> None:
        self.api_url = api_url
        self.token = token
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.queue: deque[dict[str, Any]] = deque(maxlen=max_queue_size)
        self.metrics = {
            "attempts": 0,
            "request_body_bytes_attempted": 0,
            "successful_uploads": 0,
            "request_wall_seconds": 0.0,
            "dropped_observations": 0,
        }

    def send_or_queue(self, payload: dict[str, Any]) -> bool:
        if len(self.queue) == self.queue.maxlen:
            self.metrics["dropped_observations"] += 1
            LOGGER.warning("probe queue full; oldest observation will be dropped")
        self.queue.append(payload)
        return self.flush()

    def flush(self) -> bool:
        all_sent = True
        while self.queue:
            payload = self.queue[0]
            if not self._send_with_retries(payload):
                all_sent = False
                break
            self.queue.popleft()
        return all_sent

    def _send_with_retries(self, payload: dict[str, Any]) -> bool:
        try:
            import requests
        except ImportError:
            LOGGER.error("requests is not installed; cannot send probe observations")
            return False

        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        body = json.dumps(payload, allow_nan=False).encode("utf-8")
        for attempt in range(1, self.max_retries + 1):
            started = time.perf_counter()
            self.metrics["attempts"] += 1
            self.metrics["request_body_bytes_attempted"] += len(body)
            try:
                response = requests.post(
                    self.api_url,
                    data=body,
                    headers=headers,
                    timeout=self.timeout_seconds,
                )
                if response.ok:
                    self.metrics["successful_uploads"] += 1
                    return True
                LOGGER.warning(
                    "probe post failed status=%s body=%s", response.status_code, response.text
                )
            except requests.RequestException as exc:
                LOGGER.warning("probe post attempt %s failed: %s", attempt, exc)
            finally:
                self.metrics["request_wall_seconds"] += time.perf_counter() - started
                LOGGER.info("probe transport counters=%s", self.metrics)
            time.sleep(min(attempt, 5))
        return False
