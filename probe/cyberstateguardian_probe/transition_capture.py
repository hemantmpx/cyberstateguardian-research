from __future__ import annotations

import json
import logging
import platform
import subprocess
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from typing import Any, Protocol
from uuid import NAMESPACE_URL, uuid5

from cyberstateguardian_probe import collectors
from cyberstateguardian_probe.config import ProbeSettings
from cyberstateguardian_probe.normalize import clean_dict, normalize_path, normalize_username

LOGGER = logging.getLogger("csg.probe.transitions")
TransitionBatchSubmitter = Callable[[dict[str, Any]], bool]


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _object_key(category: str, item: dict[str, Any]) -> str:
    if category == "process":
        executable = normalize_path(
            item.get("executable_path") or item.get("exe") or item.get("path")
        )
        name = str(item.get("name") or "").strip().lower()
        username = normalize_username(item.get("username")) or ""
        created = str(item.get("create_time") or item.get("created_at") or "").strip()
        identity = executable or name
        if created:
            return f"process:{identity}:{username}:{created}"
        return f"process:{identity}:{username}:ppid:{item.get('ppid') or ''}"
    if category == "listener":
        protocol = str(item.get("protocol") or "").strip().lower()
        address = str(item.get("local_address") or item.get("address") or "").strip().lower()
        port = str(item.get("local_port") or item.get("port") or "").strip()
        return f"listener:{protocol}:{address}:{port}"
    if category == "service":
        return f"service:{str(item.get('service_name') or item.get('name') or '').strip().lower()}"
    if category == "scheduled_task":
        return (
            f"scheduled_task:{str(item.get('task_name') or item.get('name') or '').strip().lower()}"
        )
    if category == "privileged_group":
        group = str(item.get("group") or item.get("group_name") or "").strip().lower()
        member = normalize_username(item.get("member") or item.get("username")) or ""
        return f"privileged_group:{group}:{member}"
    if category == "registry":
        key = str(item.get("object_key") or item.get("name") or "").strip().replace("\\", "/")
        key = "/".join(part for part in key.split("/") if part).lower()
        key = key.removeprefix("registry:")
        for prefix, hive in (
            ("hkey_local_machine", "hklm"),
            ("hkey_current_user", "hkcu"),
            ("hkey_users", "hku"),
            ("hklm:", "hklm"),
            ("hkcu:", "hkcu"),
            ("hku:", "hku"),
        ):
            if key == prefix or key.startswith(prefix + "/"):
                key = hive + key[len(prefix) :]
                break
        return f"registry:{key}"
    return str(item.get("object_key") or item.get("name") or "").strip().lower()


def _changed_fields(before: dict[str, Any] | None, after: dict[str, Any] | None) -> list[str]:
    if before is None or after is None:
        return ["$object"]
    keys = before.keys() | after.keys()
    return sorted(key for key in keys if before.get(key) != after.get(key))


def _probe_resource_metrics() -> dict[str, Any]:
    try:
        import psutil

        process = psutil.Process()
        cpu = process.cpu_times()
        return {
            "probe_cpu_seconds_total": cpu.user + cpu.system,
            "probe_memory_rss_bytes": process.memory_info().rss,
            "probe_thread_count": process.num_threads(),
            "resource_scope": "whole_probe_process_not_per_monitor",
        }
    except (ImportError, OSError):
        return {"resource_metrics_status": "unavailable"}


def _event_type(category: str, operation: str, before: dict | None, after: dict | None) -> str:
    if category == "service":
        if operation == "CREATE":
            return "SERVICE_CREATED"
        if operation == "REMOVE":
            return "SERVICE_DELETED"
        changed = set(_changed_fields(before, after))
        if changed == {"status"}:
            return "SERVICE_RUNTIME_STATUS_CHANGED"
        if "start_mode" in changed:
            return "SERVICE_START_MODE_CHANGED"
        if "binary_path" in changed:
            return "SERVICE_BINARY_PATH_CHANGED"
        if "account" in changed:
            return "SERVICE_ACCOUNT_CHANGED"
        return "SERVICE_CONFIG_MODIFIED"
    if category == "scheduled_task":
        return {"CREATE": "TASK_CREATED", "REMOVE": "TASK_DELETED"}.get(operation, "TASK_MODIFIED")
    if category == "registry":
        return {
            "CREATE": "REGISTRY_VALUE_CREATED",
            "REMOVE": "REGISTRY_VALUE_REMOVED",
        }.get(operation, "REGISTRY_VALUE_MODIFIED")
    if category == "privileged_group":
        return "PRIVILEGED_MEMBER_ADDED" if operation == "CREATE" else "PRIVILEGED_MEMBER_REMOVED"
    if category == "listener":
        return "LISTENER_OPENED" if operation == "CREATE" else "LISTENER_CLOSED"
    if category == "process":
        return "PROCESS_START" if operation == "CREATE" else "PROCESS_EXIT"
    return operation


class TransitionMonitor(Protocol):
    category: str

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def health_payload(self) -> dict[str, Any]: ...

    def record_start_failure(self, error: Exception) -> None: ...


class CategoryPollingMonitor:
    """Poll one CSG state family; failures affect only that category's coverage."""

    COLLECTORS = {
        "listener": "collect_listeners",
        "service": "collect_services",
        "scheduled_task": "collect_scheduled_tasks",
        "privileged_group": "collect_privileged_groups",
        "registry": "collect_registry_security_state",
    }

    def __init__(
        self,
        *,
        host_id: str,
        category: str,
        interval_seconds: float,
        submit: TransitionBatchSubmitter,
    ) -> None:
        self.host_id = host_id
        self.category = category
        self.interval_seconds = interval_seconds
        self.submit = submit
        self.monitor_id = f"{category}-scoped-poll"
        self.started_at = _now()
        self.coverage_start: datetime | None = None
        self.coverage_end: datetime | None = None
        self.last_heartbeat = 0.0
        self.last_sample: datetime | None = None
        self.states: dict[str, dict[str, Any]] = {}
        self.status = "UNKNOWN"
        self.message: str | None = None
        self.sequence = 0
        self.records_emitted = 0
        self.bytes_emitted = 0
        self.last_poll_duration_ms = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name=f"csg-transition-{self.category}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(max(2.0, self.interval_seconds + 1.0))

    def record_start_failure(self, error: Exception) -> None:
        self.status = "OFFLINE"
        self.message = f"monitor failed to start: {type(error).__name__}: {error}"
        self._emit([], force_health=True)

    def _run(self) -> None:
        while not self._stop.is_set():
            started = time.perf_counter()
            try:
                self._sample()
            except Exception as exc:
                LOGGER.exception("transition monitor failed category=%s", self.category)
                self.status = "DEGRADED"
                self.message = f"{type(exc).__name__}: {exc}"
                self._emit([], force_health=True)
            self._stop.wait(max(0.0, self.interval_seconds - (time.perf_counter() - started)))

    def _sample(self) -> None:
        poll_started = time.perf_counter()
        collector = getattr(collectors, self.COLLECTORS[self.category])
        result = collector()
        now = _now()
        self.last_poll_duration_ms = (time.perf_counter() - poll_started) * 1000
        self.coverage_end = now
        if result.get("status") not in {"healthy", "partial"}:
            self.status = "DEGRADED"
            self.message = (
                result.get("message") or "category collector did not provide usable state"
            )
            self._emit([], force_health=True)
            return
        current: dict[str, dict[str, Any]] = {}
        for item in result.get("items", []):
            key = _object_key(self.category, item)
            if key:
                current[key] = item
        prior_sample = self.last_sample
        if self.coverage_start is None:
            self.coverage_start = now
        if self.last_sample is None:
            self.states = current
            self.last_sample = now
            self.status = "HEALTHY" if result.get("status") == "healthy" else "PARTIAL"
            self.message = result.get("message")
            self._emit([], force_health=True)
            return

        records = []
        for key in sorted(self.states.keys() | current.keys()):
            before = self.states.get(key)
            after = current.get(key)
            operation = "CREATE" if before is None else "REMOVE" if after is None else "MODIFY"
            if before is not None and after is not None and _canonical(before) == _canonical(after):
                continue
            fields = _changed_fields(before, after)
            records.append(
                self._record(
                    key,
                    operation,
                    before,
                    after,
                    fields,
                    prior_sample or now,
                    now,
                )
            )
        self.states = current
        self.last_sample = now
        self.records_emitted += len(records)
        self.bytes_emitted += sum(len(_canonical(record).encode("utf-8")) for record in records)
        self.status = "HEALTHY" if result.get("status") == "healthy" else "PARTIAL"
        self.message = result.get("message")
        self._emit(
            records, force_health=bool(records) or time.monotonic() - self.last_heartbeat > 30
        )

    def _record(
        self,
        object_key: str,
        operation: str,
        before: dict | None,
        after: dict | None,
        fields: list[str],
        window_start: datetime,
        observed_at: datetime,
    ) -> dict[str, Any]:
        self.sequence += 1
        transition_type = _event_type(self.category, operation, before, after)
        identity = "|".join(
            (
                self.host_id,
                self.category,
                object_key,
                transition_type,
                _iso(window_start),
                _iso(observed_at),
                _canonical(before),
                _canonical(after),
            )
        )
        return {
            "transition_id": str(uuid5(NAMESPACE_URL, identity)),
            "host_id": self.host_id,
            "category": self.category,
            "object_key": object_key,
            "transition_type": transition_type,
            "observed_at": _iso(observed_at),
            "window_start": _iso(window_start),
            "window_end": _iso(observed_at),
            "old_state": before,
            "new_state": after,
            "changed_fields": fields,
            "source": "direct_probe",
            "capture_method": f"category_scoped_poll:{self.interval_seconds:g}s",
            "collector_health": self.status,
            "sequence_number": self.sequence,
            "raw_metadata": {
                "monitor_id": self.monitor_id,
                "poll_interval_seconds": self.interval_seconds,
            },
        }

    def _emit(self, records: list[dict], *, force_health: bool = False) -> None:
        health = [self.health_payload()] if force_health else []
        if records or health:
            try:
                accepted = self.submit(
                    {"host_id": self.host_id, "records": records, "monitor_health": health}
                )
            except Exception as exc:
                accepted = False
                self.message = f"transition spool failed: {type(exc).__name__}: {exc}"
            if not accepted:
                self.status = "DEGRADED"
                self.message = (
                    self.message or "transition spool rejected batch; coverage may be lost"
                )
            elif health:
                self.last_heartbeat = time.monotonic()

    def health_payload(self) -> dict[str, Any]:
        now = _now()
        return {
            "host_id": self.host_id,
            "category": self.category,
            "monitor_id": self.monitor_id,
            "status": self.status,
            "capture_method": f"category_scoped_poll:{self.interval_seconds:g}s",
            "started_at": _iso(self.started_at),
            "observed_at": _iso(now),
            "last_heartbeat_at": _iso(now),
            "coverage_start": _iso(self.coverage_start) if self.coverage_start else None,
            "coverage_end": _iso(self.coverage_end) if self.coverage_end else None,
            "baseline_established": self.last_sample is not None,
            "metrics": {
                "sequence_number": self.sequence,
                "transition_records_total": self.records_emitted,
                "transition_bytes_total": self.bytes_emitted,
                "transition_records_per_minute": self.records_emitted
                / max(1 / 60, (now - self.started_at).total_seconds() / 60),
                "last_poll_duration_ms": self.last_poll_duration_ms,
                **_probe_resource_metrics(),
            },
            "message": self.message,
        }


class WindowsProcessLifecycleMonitor:
    """Consume Windows WMI process-start/stop indications without table polling."""

    category = "process"
    _POWERSHELL = r"""
$ErrorActionPreference = 'Stop'
Register-WmiEvent `
  -Query 'SELECT * FROM Win32_ProcessStartTrace' `
  -SourceIdentifier 'CSGStart' | Out-Null
Register-WmiEvent `
  -Query 'SELECT * FROM Win32_ProcessStopTrace' `
  -SourceIdentifier 'CSGStop' | Out-Null
$ready = [ordered]@{
  kind = 'READY'
  source_time = [DateTime]::UtcNow.ToString('o')
}
[Console]::Out.WriteLine(($ready | ConvertTo-Json -Compress))
while ($true) {
  $eventRecord = Wait-Event -Timeout 2
  if ($null -eq $eventRecord) { continue }
  $item = $eventRecord.SourceEventArgs.NewEvent
  $kind = if ($eventRecord.SourceIdentifier -eq 'CSGStart') {
    'PROCESS_START'
  } else { 'PROCESS_EXIT' }
  $sourceTime = if ($item.TIME_CREATED) {
    [DateTime]::FromFileTimeUtc([int64]$item.TIME_CREATED).ToString('o')
  } else { [DateTime]::UtcNow.ToString('o') }
  $value = [ordered]@{
    kind = $kind
    pid = [int]$item.ProcessID
    ppid = [int]$item.ParentProcessID
    name = [string]$item.ProcessName
    source_time = $sourceTime
  }
  [Console]::Out.WriteLine(($value | ConvertTo-Json -Compress))
  Remove-Event -EventIdentifier $eventRecord.EventIdentifier
}
"""

    def __init__(
        self,
        *,
        host_id: str,
        submit: TransitionBatchSubmitter,
        include_patterns: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
    ) -> None:
        self.host_id = host_id
        self.submit = submit
        self.include_patterns = [item.lower() for item in include_patterns or []]
        self.exclude_patterns = [item.lower() for item in exclude_patterns or []]
        self.monitor_id = "windows-wmi-process-lifecycle"
        self.started_at = _now()
        self.coverage_start: datetime | None = None
        self.coverage_end: datetime | None = None
        self.status = "UNKNOWN"
        self.message: str | None = None
        self.sequence = 0
        self.filtered_transition_count = 0
        self.duplicate_notification_count = 0
        self.records_emitted = 0
        self.payload_bytes_generated = 0
        self.capture_latency_total_ms = 0.0
        self.capture_latency_max_ms = 0.0
        self._recent_events: set[tuple[str, int, str]] = set()
        self._recent_event_order: deque[tuple[str, int, str]] = deque(maxlen=10_000)
        self.processes: dict[int, dict[str, Any]] = {}
        self.process_keys: dict[int, str] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._heartbeat_thread: threading.Thread | None = None
        self._process: subprocess.Popen | None = None

    def start(self) -> None:
        if platform.system().lower() != "windows":
            self.status = "OFFLINE"
            self.message = "Windows WMI process indications are unavailable on this platform"
            self._emit([], force_health=True)
            return
        self.started_at = _now()
        try:
            self._process = subprocess.Popen(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", self._POWERSHELL],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self._thread = threading.Thread(
                target=self._read_events,
                name="csg-transition-process-wmi",
                daemon=True,
            )
            self._thread.start()
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat,
                name="csg-transition-process-health",
                daemon=True,
            )
            self._heartbeat_thread.start()
            self._emit([], force_health=True)
        except Exception as exc:
            self.status = "OFFLINE"
            self.message = f"{type(exc).__name__}: {exc}"
            self._emit([], force_health=True)

    def stop(self) -> None:
        self._stop.set()
        if self._process and self._process.poll() is None:
            self._process.terminate()
        if self._thread:
            self._thread.join(3.0)
        if self._heartbeat_thread:
            self._heartbeat_thread.join(2.0)
        self.status = "OFFLINE"
        self.message = "monitor stopped; transitions during shutdown are not covered"
        self._emit([], force_health=True)

    def _heartbeat(self) -> None:
        while not self._stop.wait(30.0):
            if self.status == "UNKNOWN" and (_now() - self.started_at).total_seconds() > 30:
                self.status = "DEGRADED"
                self.message = "WMI process listener has not reported readiness"
            self._emit([], force_health=True)

    def record_start_failure(self, error: Exception) -> None:
        self.status = "OFFLINE"
        self.message = f"monitor failed to start: {type(error).__name__}: {error}"
        self._emit([], force_health=True)

    def _establish_baseline(self) -> None:
        baseline = collectors.collect_processes()
        for row in baseline.get("items", []):
            pid = row.get("pid")
            if pid is not None:
                self.processes[int(pid)] = row
                self.process_keys[int(pid)] = _object_key("process", row)
        if baseline.get("status") not in {"healthy", "partial"}:
            self.status = "PARTIAL"
            self.message = baseline.get("message") or "process baseline was incomplete"

    def _read_events(self) -> None:
        assert self._process and self._process.stdout
        try:
            for line in self._process.stdout:
                if self._stop.is_set():
                    return
                try:
                    event = json.loads(line)
                    if event.get("kind") == "READY":
                        self._establish_baseline()
                        self.coverage_start = _now()
                        if self.status != "PARTIAL":
                            self.status = "HEALTHY"
                            self.message = None
                        self._emit([], force_health=True)
                    else:
                        self._handle(event)
                except (ValueError, TypeError, KeyError) as exc:
                    LOGGER.warning("invalid WMI process indication: %s", exc)
                    self.status = "PARTIAL"
                    self.message = f"malformed process indication: {type(exc).__name__}"
                    self._emit([], force_health=True)
            if not self._stop.is_set():
                self.status = "OFFLINE"
                self.message = f"WMI listener exited with code {self._process.poll()}"
                self._emit([], force_health=True)
        except OSError as exc:
            self.status = "DEGRADED"
            self.message = f"WMI event stream read failed: {exc}"
            self._emit([], force_health=True)

    def _handle(self, event: dict[str, Any]) -> None:
        pid = int(event["pid"])
        observed_at = _parse_timestamp(event.get("source_time")) or _now()
        if self.coverage_start and observed_at < self.coverage_start:
            return
        kind = str(event["kind"])
        fingerprint = (kind, pid, str(event.get("source_time") or ""))
        if fingerprint in self._recent_events:
            self.duplicate_notification_count += 1
            return
        if kind == "PROCESS_START":
            state = self._read_process(pid)
            if state is None:
                self.status = "PARTIAL"
                self.message = f"could not enrich process start PID {pid}; no transition fabricated"
                self._emit([], force_health=True)
                return
            self.processes[pid] = state
            self.process_keys[pid] = _object_key("process", state)
            if not self._included(state):
                self.filtered_transition_count += 1
                self._remember_event(fingerprint)
                return
            record = self._record(
                self.process_keys[pid], "PROCESS_START", None, state, event, observed_at
            )
        else:
            state = self.processes.pop(pid, None)
            key = self.process_keys.pop(pid, None)
            if state is None or key is None:
                self.status = "PARTIAL"
                self.message = f"process exit PID {pid} had no retained start/baseline state"
                self._emit([], force_health=True)
                return
            if not self._included(state):
                self.filtered_transition_count += 1
                self._remember_event(fingerprint)
                return
            record = self._record(key, "PROCESS_EXIT", state, None, event, observed_at)
        self.coverage_end = observed_at
        self.status = "HEALTHY"
        self.message = None
        self._remember_event(fingerprint)
        self._emit([record], force_health=False)

    def _remember_event(self, fingerprint: tuple[str, int, str]) -> None:
        if len(self._recent_event_order) == self._recent_event_order.maxlen:
            self._recent_events.discard(self._recent_event_order[0])
        self._recent_event_order.append(fingerprint)
        self._recent_events.add(fingerprint)

    def _included(self, state: dict[str, Any]) -> bool:
        subject = [
            str(state.get("name") or "").lower(),
            str(state.get("executable_path") or "").lower(),
        ]
        if self.include_patterns and not any(
            fnmatchcase(value, pattern) for value in subject for pattern in self.include_patterns
        ):
            return False
        return not any(
            fnmatchcase(value, pattern) for value in subject for pattern in self.exclude_patterns
        )

    @staticmethod
    def _read_process(pid: int) -> dict[str, Any] | None:
        from datetime import datetime

        import psutil

        for _ in range(4):
            try:
                process = psutil.Process(pid)
                created = process.create_time()
                return clean_dict(
                    {
                        "pid": pid,
                        "ppid": process.ppid(),
                        "name": process.name(),
                        "executable_path": normalize_path(process.exe()),
                        "username": normalize_username(process.username()),
                        "create_time": datetime.fromtimestamp(created, tz=UTC).isoformat(),
                    }
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                time.sleep(0.05)
        return None

    def _record(
        self,
        object_key: str,
        transition_type: str,
        before: dict | None,
        after: dict | None,
        event: dict,
        observed_at: datetime,
    ) -> dict[str, Any]:
        self.sequence += 1
        transition_id = str(
            uuid5(
                NAMESPACE_URL,
                "|".join(
                    (
                        self.host_id,
                        object_key,
                        transition_type,
                        str(event.get("source_time")),
                    )
                ),
            )
        )
        captured_at = _now()
        latency_ms = max(0.0, (captured_at - observed_at).total_seconds() * 1000)
        self.capture_latency_total_ms += latency_ms
        self.capture_latency_max_ms = max(self.capture_latency_max_ms, latency_ms)
        self.records_emitted += 1
        return {
            "transition_id": transition_id,
            "host_id": self.host_id,
            "category": "process",
            "object_key": object_key,
            "transition_type": transition_type,
            "observed_at": _iso(observed_at),
            "window_start": _iso(observed_at),
            "window_end": _iso(observed_at),
            "old_state": before,
            "new_state": after,
            "changed_fields": _changed_fields(before, after),
            "source": "direct_probe",
            "capture_method": "windows_wmi_process_start_stop_trace",
            "collector_health": self.status,
            "sequence_number": self.sequence,
            "raw_metadata": {
                "monitor_id": self.monitor_id,
                "wmi_source_time": event.get("source_time"),
                "process_id": event.get("pid"),
                "parent_process_id": event.get("ppid"),
                "image_name": event.get("name"),
                "captured_at": _iso(captured_at),
                "capture_latency_ms": latency_ms,
            },
        }

    def _emit(self, records: list[dict], *, force_health: bool) -> None:
        self.payload_bytes_generated += sum(
            len(_canonical(record).encode("utf-8")) for record in records
        )
        health = [self.health_payload()] if force_health else []
        if records or health:
            try:
                accepted = self.submit(
                    {"host_id": self.host_id, "records": records, "monitor_health": health}
                )
            except Exception as exc:
                accepted = False
                self.message = f"transition spool failed: {type(exc).__name__}: {exc}"
            if not accepted:
                self.status = "DEGRADED"
                self.message = (
                    self.message or "transition spool rejected batch; coverage may be lost"
                )

    def health_payload(self) -> dict[str, Any]:
        now = _now()
        return {
            "host_id": self.host_id,
            "category": "process",
            "monitor_id": self.monitor_id,
            "status": self.status,
            "capture_method": "windows_wmi_process_start_stop_trace",
            "started_at": _iso(self.started_at),
            "observed_at": _iso(now),
            "last_heartbeat_at": _iso(now),
            "coverage_start": _iso(self.coverage_start) if self.coverage_start else None,
            "coverage_end": _iso(self.coverage_end) if self.coverage_end else None,
            "baseline_established": self.coverage_start is not None,
            "restart_count": 0,
            "metrics": {
                "sequence_number": self.sequence,
                "transition_records_total": self.records_emitted,
                "transition_records_per_minute": self.records_emitted
                / max(1 / 60, (now - self.started_at).total_seconds() / 60),
                "retained_process_baseline": len(self.processes),
                "filtered_transition_count": self.filtered_transition_count,
                "duplicate_notification_count": self.duplicate_notification_count,
                "transition_payload_bytes_generated": self.payload_bytes_generated,
                "capture_latency_max_ms": self.capture_latency_max_ms,
                "capture_latency_mean_ms": self.capture_latency_total_ms / max(1, self.sequence),
                "include_patterns": self.include_patterns,
                "exclude_patterns": self.exclude_patterns,
                **_probe_resource_metrics(),
            },
            "message": self.message,
        }


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


class TransitionCaptureManager:
    def __init__(self, settings: ProbeSettings, submit: TransitionBatchSubmitter) -> None:
        self.settings = settings
        self.submit = submit
        self.monitors: list[TransitionMonitor] = []
        self._construct_monitors()

    def _construct_monitors(self) -> None:
        for category, enabled in self.settings.transition_enabled_categories.items():
            if not enabled:
                continue
            monitor: TransitionMonitor
            if category == "process":
                monitor = WindowsProcessLifecycleMonitor(
                    host_id=self.settings.host_id,
                    submit=self.submit,
                    include_patterns=self.settings.transition_process_include_patterns,
                    exclude_patterns=self.settings.transition_process_exclude_patterns,
                )
            else:
                monitor = CategoryPollingMonitor(
                    host_id=self.settings.host_id,
                    category=category,
                    interval_seconds=self.settings.transition_poll_interval_seconds,
                    submit=self.submit,
                )
            self.monitors.append(monitor)

    def start(self) -> None:
        for monitor in self.monitors:
            try:
                monitor.start()
            except Exception as exc:
                LOGGER.exception("could not start transition monitor category=%s", monitor.category)
                monitor.record_start_failure(exc)

    def stop(self) -> None:
        for monitor in self.monitors:
            try:
                monitor.stop()
            except Exception:
                LOGGER.exception("could not stop transition monitor category=%s", monitor.category)

    def health(self) -> list[dict[str, Any]]:
        return [monitor.health_payload() for monitor in self.monitors]
