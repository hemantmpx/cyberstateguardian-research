from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ProbeSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    api_url: str = Field(
        default="http://replace-with-mac-reachable-host:8000/api/probe/observations",
        validation_alias="CSG_PROBE_API_URL",
    )
    host_id: str = Field(default="win-lab-01", validation_alias="CSG_PROBE_HOST_ID")
    hostname: str | None = Field(default=None, validation_alias="CSG_PROBE_HOSTNAME")
    host_role: str = Field(default="windows-target", validation_alias="CSG_PROBE_HOST_ROLE")
    token: str = Field(default="replace-with-lab-token", validation_alias="CSG_PROBE_TOKEN")
    interval_seconds: int = Field(default=30, validation_alias="CSG_PROBE_INTERVAL_SECONDS")
    timeout_seconds: float = Field(default=5.0, validation_alias="CSG_PROBE_TIMEOUT_SECONDS")
    max_queue_size: int = Field(default=50, validation_alias="CSG_PROBE_MAX_QUEUE_SIZE")
    max_retries: int = Field(default=3, validation_alias="CSG_PROBE_MAX_RETRIES")
    transition_capture_enabled: bool = Field(
        default=False,
        validation_alias="CSG_TRANSITION_CAPTURE_ENABLED",
    )
    transition_processes_enabled: bool = Field(
        default=False,
        validation_alias="CSG_TRANSITION_PROCESSES_ENABLED",
    )
    transition_services_enabled: bool = Field(
        default=False,
        validation_alias="CSG_TRANSITION_SERVICES_ENABLED",
    )
    transition_registry_enabled: bool = Field(
        default=False,
        validation_alias="CSG_TRANSITION_REGISTRY_ENABLED",
    )
    transition_tasks_enabled: bool = Field(
        default=False,
        validation_alias="CSG_TRANSITION_TASKS_ENABLED",
    )
    transition_privileged_groups_enabled: bool = Field(
        default=False,
        validation_alias="CSG_TRANSITION_PRIVILEGED_GROUPS_ENABLED",
    )
    transition_listeners_enabled: bool = Field(
        default=False,
        validation_alias="CSG_TRANSITION_LISTENERS_ENABLED",
    )
    transition_poll_interval_seconds: float = Field(
        default=5.0,
        ge=1.0,
        le=3600.0,
        validation_alias="CSG_TRANSITION_POLL_INTERVAL_SECONDS",
    )
    transition_spool_path: Path = Field(
        default=Path.home() / ".csg" / "transition-spool.jsonl",
        validation_alias="CSG_TRANSITION_SPOOL_PATH",
    )
    transition_spool_max_bytes: int = Field(
        default=100 * 1024 * 1024,
        ge=1024,
        validation_alias="CSG_TRANSITION_SPOOL_MAX_BYTES",
    )
    transition_api_url: str | None = Field(
        default=None,
        validation_alias="CSG_TRANSITION_API_URL",
    )
    transition_process_include_patterns: list[str] = Field(
        default_factory=list,
        validation_alias="CSG_TRANSITION_PROCESS_INCLUDE_PATTERNS",
    )
    transition_process_exclude_patterns: list[str] = Field(
        default_factory=list,
        validation_alias="CSG_TRANSITION_PROCESS_EXCLUDE_PATTERNS",
    )

    @property
    def transition_enabled_categories(self) -> dict[str, bool]:
        enabled = {
            "process": self.transition_processes_enabled,
            "service": self.transition_services_enabled,
            "registry": self.transition_registry_enabled,
            "scheduled_task": self.transition_tasks_enabled,
            "privileged_group": self.transition_privileged_groups_enabled,
            "listener": self.transition_listeners_enabled,
        }
        return {
            category: self.transition_capture_enabled and category_enabled
            for category, category_enabled in enabled.items()
        }
