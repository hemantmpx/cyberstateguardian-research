from __future__ import annotations

import argparse
import json
import logging
import platform
import signal
import socket
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from cyberstateguardian_probe.collectors import (
    collect_listeners,
    collect_privileged_groups,
    collect_processes,
    collect_registry_security_state,
    collect_scheduled_tasks,
    collect_services,
)
from cyberstateguardian_probe.config import ProbeSettings
from cyberstateguardian_probe.normalize import utc_now_iso
from cyberstateguardian_probe.transition_capture import TransitionCaptureManager
from cyberstateguardian_probe.transition_transport import (
    DurableTransitionTransport,
    transition_endpoint,
)
from cyberstateguardian_probe.transport import QueuedTransport

LOGGER = logging.getLogger("csg.probe")
STOP = False


def _stop(_signum: int, _frame: object) -> None:
    global STOP
    STOP = True


def host_identity(settings: ProbeSettings) -> dict[str, str]:
    system = platform.system() or "unknown"
    release = platform.release() or ""
    os_name = " ".join(part for part in [system, release] if part).strip() or "unknown"
    return {
        "hostname": settings.hostname or socket.gethostname() or settings.host_id,
        "role": settings.host_role,
        "os": os_name,
        "platform": platform.platform(),
        "architecture": platform.machine() or "unknown",
    }


def collect_observation(settings: ProbeSettings) -> dict[str, Any]:
    observed_at = utc_now_iso()
    started = time.perf_counter()
    collectors = {
        "process": collect_processes,
        "listener": collect_listeners,
        "service": collect_services,
        "scheduled_task": collect_scheduled_tasks,
        "privileged_group": collect_privileged_groups,
        "registry": collect_registry_security_state,
    }
    categories = {}
    durations = {}
    for name, collector in collectors.items():
        category_start = time.perf_counter()
        categories[name] = {**collector(), "observed_at": utc_now_iso()}
        durations[name] = time.perf_counter() - category_start
    return {
        "observation_id": str(uuid4()),
        "host_id": settings.host_id,
        "observed_at": utc_now_iso(),
        "source": "direct_probe",
        "categories": categories,
        "metadata": {
            "probe": "cyberstateguardian_probe",
            "schema_version": "2",
            "host": host_identity(settings),
            "collection_started_at": observed_at,
            "collection_wall_seconds": time.perf_counter() - started,
            "collector_wall_seconds": durations,
        },
    }


def run_once(settings: ProbeSettings, *, measurements: dict | None = None) -> bool:
    transport = QueuedTransport(
        api_url=settings.api_url,
        token=settings.token,
        timeout_seconds=settings.timeout_seconds,
        max_queue_size=settings.max_queue_size,
        max_retries=settings.max_retries,
    )
    payload = collect_observation(settings)
    success = transport.send_or_queue(payload)
    if measurements is not None:
        measurements.update(
            {
                "transport": dict(transport.metrics),
                "collection_wall_seconds": payload["metadata"]["collection_wall_seconds"],
                "collector_wall_seconds": payload["metadata"]["collector_wall_seconds"],
            }
        )
    return success


def run_loop(settings: ProbeSettings) -> None:
    transport = QueuedTransport(
        api_url=settings.api_url,
        token=settings.token,
        timeout_seconds=settings.timeout_seconds,
        max_queue_size=settings.max_queue_size,
        max_retries=settings.max_retries,
    )
    transitions = None
    if any(settings.transition_enabled_categories.values()):
        transition_transport = DurableTransitionTransport(
            api_url=settings.transition_api_url or transition_endpoint(settings.api_url),
            token=settings.token,
            spool_path=settings.transition_spool_path,
            max_spool_bytes=settings.transition_spool_max_bytes,
            timeout_seconds=settings.timeout_seconds,
            max_retries=settings.max_retries,
        )
        transition_transport.start()

        def submit_transition_batch(payload: dict[str, Any]) -> bool:
            spool_bytes = (
                settings.transition_spool_path.stat().st_size
                if settings.transition_spool_path.exists()
                else 0
            )
            for health in payload.get("monitor_health", []):
                health.setdefault("metrics", {}).update(
                    {
                        "transition_spool_bytes_before_batch": spool_bytes,
                        "transition_spool_queue_depth_before_batch": transition_transport.metrics[
                            "queue_depth"
                        ],
                        "transition_spool_upload_failures": transition_transport.metrics[
                            "upload_failures"
                        ],
                        "transition_spool_full_batches": transition_transport.metrics[
                            "spool_full_batches"
                        ],
                    }
                )
            return transition_transport.submit(payload)

        transitions = TransitionCaptureManager(settings, submit_transition_batch)
        transitions.start()
    try:
        while not STOP:
            transport.send_or_queue(collect_observation(settings))
            time.sleep(settings.interval_seconds)
    finally:
        if transitions:
            transitions.stop()
            transition_transport.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberStateGuardian native Windows probe")
    parser.add_argument("--once", action="store_true", help="collect and post one observation")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--config", type=Path, help="JSON settings overriding environment values")
    parser.add_argument(
        "--measurements", type=Path, help="Measure one collection/upload; requires --once"
    )
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level)
    overrides = json.loads(args.config.read_text(encoding="utf-8-sig")) if args.config else {}
    settings = ProbeSettings(**overrides)
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    if args.once:
        if args.measurements:
            from cyberstateguardian_probe.measurements import ResourceMonitor

            measurements = {}
            with ResourceMonitor() as monitor:
                success = run_once(settings, measurements=measurements)
            args.measurements.parent.mkdir(parents=True, exist_ok=True)
            args.measurements.write_text(
                json.dumps(
                    {**monitor.result(), **measurements, "upload_success": success}, indent=2
                )
            )
        else:
            success = run_once(settings)
        raise SystemExit(0 if success else 1)
    if args.measurements:
        parser.error("--measurements requires --once")
    LOGGER.info("starting CyberStateGuardian probe host_id=%s", settings.host_id)
    run_loop(settings)


if __name__ == "__main__":
    main()
