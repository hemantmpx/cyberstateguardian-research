from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "CyberStateGuardian"
    app_env: str = "development"
    log_level: str = "INFO"

    database_url: str = Field(
        default="sqlite:///./cyberstateguardian.db",
        validation_alias="DATABASE_URL",
    )
    api_host: str = Field(default="0.0.0.0", validation_alias="CSG_API_HOST")
    api_port: int = Field(default=8000, validation_alias="CSG_API_PORT")
    lab_shared_token: str = Field(
        default="replace-with-lab-token",
        validation_alias="CSG_LAB_SHARED_TOKEN",
    )

    state_provider: str = Field(default="fixture", validation_alias="CSG_STATE_PROVIDER")
    event_provider: str = Field(default="fixture", validation_alias="CSG_EVENT_PROVIDER")
    state_fixture_name: str = Field(default="baseline", validation_alias="CSG_STATE_FIXTURE_NAME")
    event_fixture_set: str = Field(default="all", validation_alias="CSG_EVENT_FIXTURE_SET")
    observation_window_seconds: int = Field(
        default=900,
        validation_alias="CSG_OBSERVATION_WINDOW_SECONDS",
    )
    event_time_tolerance_seconds: int = Field(
        default=20,
        validation_alias="CSG_EVENT_TIME_TOLERANCE_SECONDS",
    )
    reconciliation_grace_seconds: int = Field(
        default=60,
        validation_alias="CSG_RECONCILIATION_GRACE_SECONDS",
    )
    pipeline_on_ingest: bool = Field(default=True, validation_alias="CSG_PIPELINE_ON_INGEST")
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
    worker_interval_seconds: int = Field(default=30, validation_alias="CSG_WORKER_INTERVAL_SECONDS")
    worker_batch_size: int = Field(default=100, validation_alias="CSG_WORKER_BATCH_SIZE")
    live_finding_categories: str = Field(
        default="service,listener,scheduled_task,privileged_group,registry",
        validation_alias="CSG_LIVE_FINDING_CATEGORIES",
    )
    incident_correlation_window_seconds: int = Field(
        default=3600,
        validation_alias="CSG_INCIDENT_CORRELATION_WINDOW_SECONDS",
    )
    incident_temporal_only_window_seconds: int = Field(
        default=900,
        validation_alias="CSG_INCIDENT_TEMPORAL_ONLY_WINDOW_SECONDS",
    )
    incident_correlation_min_score: int = Field(
        default=40,
        validation_alias="CSG_INCIDENT_CORRELATION_MIN_SCORE",
    )

    wazuh_api_url: str = Field(
        default="https://localhost:55000",
        validation_alias="CSG_WAZUH_API_URL",
    )
    wazuh_indexer_url: str = Field(
        default="https://localhost:9200",
        validation_alias="CSG_WAZUH_INDEXER_URL",
    )
    wazuh_dashboard_url: str = Field(
        default="https://localhost:8443",
        validation_alias="CSG_WAZUH_DASHBOARD_URL",
    )
    wazuh_api_user: str = Field(default="wazuh", validation_alias="CSG_WAZUH_API_USER")
    wazuh_api_password: str | None = Field(
        default=None,
        validation_alias="CSG_WAZUH_API_PASSWORD",
    )
    wazuh_indexer_user: str = Field(
        default="admin",
        validation_alias="CSG_WAZUH_INDEXER_USER",
    )
    wazuh_indexer_password: str | None = Field(
        default=None,
        validation_alias="CSG_WAZUH_INDEXER_PASSWORD",
    )
    wazuh_verify_ssl: bool = Field(default=False, validation_alias="CSG_WAZUH_VERIFY_SSL")
    wazuh_alert_index_pattern: str = Field(
        default="wazuh-alerts-*",
        validation_alias="CSG_WAZUH_ALERT_INDEX_PATTERN",
    )
    wazuh_archive_index_pattern: str | None = Field(
        default=None,
        validation_alias="CSG_WAZUH_ARCHIVE_INDEX_PATTERN",
    )
    wazuh_inventory_index_prefix: str = Field(
        default="wazuh-states-inventory",
        validation_alias="CSG_WAZUH_INVENTORY_INDEX_PREFIX",
    )
    wazuh_inventory_limit: int = Field(
        default=5000,
        validation_alias="CSG_WAZUH_INVENTORY_LIMIT",
    )
    wazuh_event_limit: int = Field(default=5000, validation_alias="CSG_WAZUH_EVENT_LIMIT")
    wazuh_request_timeout_seconds: float = Field(
        default=20.0,
        validation_alias="CSG_WAZUH_REQUEST_TIMEOUT_SECONDS",
    )
    wazuh_sync_enabled: bool = Field(
        default=False,
        validation_alias="CSG_WAZUH_SYNC_ENABLED",
    )
    wazuh_sync_host_ids: str = Field(default="", validation_alias="CSG_WAZUH_SYNC_HOST_IDS")
    wazuh_event_lookback_seconds: int = Field(
        default=3600,
        validation_alias="CSG_WAZUH_EVENT_LOOKBACK_SECONDS",
    )
    state_cross_validation_enabled: bool = Field(
        default=True,
        validation_alias="CSG_STATE_CROSS_VALIDATION_ENABLED",
    )

    providers_config_path: Path = Field(
        default=Path("config/providers.example.yaml"),
        validation_alias="CSG_PROVIDERS_CONFIG_PATH",
    )
    authorized_state_path: Path = Field(
        default=Path("config/authorized-state.example.yaml"),
        validation_alias="CSG_AUTHORIZED_STATE_PATH",
    )
    risk_rules_path: Path = Field(
        default=Path("config/risk-rules.yaml"),
        validation_alias="CSG_RISK_RULES_PATH",
    )
    fixture_state_dir: Path = Field(
        default=Path("experiments/fixtures/state"),
        validation_alias="CSG_FIXTURE_STATE_DIR",
    )
    fixture_event_dir: Path = Field(
        default=Path("experiments/fixtures/events"),
        validation_alias="CSG_FIXTURE_EVENT_DIR",
    )

    ai_enabled: bool = Field(default=False, validation_alias="CSG_AI_ENABLED")
    ai_provider: str = Field(default="openai", validation_alias="CSG_AI_PROVIDER")
    openai_api_key: str | None = Field(default=None, validation_alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-5-mini", validation_alias="CSG_OPENAI_MODEL")
    ollama_base_url: str = Field(
        default="http://127.0.0.1:11434",
        validation_alias="CSG_OLLAMA_BASE_URL",
    )
    ollama_model: str = Field(default="llama3.1:8b", validation_alias="CSG_OLLAMA_MODEL")
    ollama_timeout_seconds: float = Field(
        default=180.0,
        validation_alias="CSG_OLLAMA_TIMEOUT_SECONDS",
    )
    ollama_num_predict: int = Field(default=2600, validation_alias="CSG_OLLAMA_NUM_PREDICT")
    ollama_num_ctx: int = Field(default=16384, validation_alias="CSG_OLLAMA_NUM_CTX")
    ai_context_window_seconds: int = Field(
        default=900,
        validation_alias="CSG_AI_CONTEXT_WINDOW_SECONDS",
    )
    ai_context_max_events: int = Field(default=100, validation_alias="CSG_AI_CONTEXT_MAX_EVENTS")
    ai_context_related_limit: int = Field(
        default=25,
        validation_alias="CSG_AI_CONTEXT_RELATED_LIMIT",
    )
    ai_context_expansion_windows: str = Field(
        default="900,3600,21600,86400",
        validation_alias="CSG_AI_CONTEXT_EXPANSION_WINDOWS",
    )
    ai_context_min_relevant_events: int = Field(
        default=3,
        validation_alias="CSG_AI_CONTEXT_MIN_RELEVANT_EVENTS",
    )
    ai_store_responses: bool = Field(default=False, validation_alias="CSG_AI_STORE_RESPONSES")

    def resolve_path(self, value: Path) -> Path:
        return value if value.is_absolute() else repo_root() / value

    @property
    def live_finding_category_set(self) -> set[str]:
        return {
            category.strip()
            for category in self.live_finding_categories.split(",")
            if category.strip()
        }

    @property
    def transition_enabled_category_set(self) -> set[str]:
        categories = {
            "process": self.transition_processes_enabled,
            "service": self.transition_services_enabled,
            "registry": self.transition_registry_enabled,
            "scheduled_task": self.transition_tasks_enabled,
            "privileged_group": self.transition_privileged_groups_enabled,
            "listener": self.transition_listeners_enabled,
        }
        return {
            category
            for category, enabled in categories.items()
            if self.transition_capture_enabled and enabled
        }

    @property
    def wazuh_sync_host_id_list(self) -> list[str]:
        return [
            host_id.strip() for host_id in self.wazuh_sync_host_ids.split(",") if host_id.strip()
        ]

    @property
    def ai_context_expansion_window_list(self) -> list[int]:
        windows = sorted(
            {
                int(value.strip())
                for value in self.ai_context_expansion_windows.split(",")
                if value.strip() and int(value.strip()) > 0
            }
        )
        return windows or [self.ai_context_window_seconds]


@lru_cache
def get_settings() -> Settings:
    return Settings()
