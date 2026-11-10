from __future__ import annotations

from csg.config import Settings, get_settings
from csg.providers.base import EventProvider, ProviderRegistry, StateProvider
from csg.providers.fixture_events import FixtureEventProvider
from csg.providers.probe_state import FixtureStateProvider
from csg.providers.wazuh import WazuhEventProvider, WazuhStateProvider


def default_registry(settings: Settings | None = None) -> ProviderRegistry:
    settings = settings or get_settings()
    registry = ProviderRegistry()
    registry.register_state(
        "fixture",
        lambda: FixtureStateProvider(
            fixture_dir=settings.resolve_path(settings.fixture_state_dir),
            fixture_name=settings.state_fixture_name,
        ),
    )
    registry.register_events(
        "fixture",
        lambda: FixtureEventProvider(
            fixture_dir=settings.resolve_path(settings.fixture_event_dir),
            fixture_set=settings.event_fixture_set,
        ),
    )
    registry.register_state("wazuh", lambda: WazuhStateProvider.from_settings(settings))
    registry.register_events("wazuh", lambda: WazuhEventProvider.from_settings(settings))
    return registry


def build_state_provider(settings: Settings | None = None) -> StateProvider:
    settings = settings or get_settings()
    return default_registry(settings).state(settings.state_provider)


def build_event_provider(settings: Settings | None = None) -> EventProvider:
    settings = settings or get_settings()
    return default_registry(settings).events(settings.event_provider)
