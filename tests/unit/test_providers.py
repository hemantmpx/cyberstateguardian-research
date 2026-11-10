from __future__ import annotations

from datetime import UTC, datetime

import pytest
from tests.conftest import ROOT

from csg.providers.base import ProviderRegistry
from csg.providers.fixture_events import FixtureEventProvider
from csg.providers.probe_state import FixtureStateProvider


@pytest.mark.asyncio
async def test_fixture_state_provider_returns_normalized_snapshot() -> None:
    provider = FixtureStateProvider(ROOT / "experiments/fixtures/state", "baseline")
    snapshot = await provider.get_snapshot("win-lab-01")
    assert snapshot.source == "synthetic_fixture"
    assert {item.category for item in snapshot.objects} >= {"service", "listener"}


@pytest.mark.asyncio
async def test_fixture_event_provider_filters_by_host_and_window() -> None:
    provider = FixtureEventProvider(ROOT / "experiments/fixtures/events", "svc-create-consistent")
    events = await provider.get_events(
        "win-lab-01",
        datetime(2026, 9, 13, 20, 14, tzinfo=UTC),
        datetime(2026, 9, 13, 20, 15, tzinfo=UTC),
    )
    assert [event.event_id for event in events] == ["evt-service-001"]


def test_provider_registry_swaps_implementations() -> None:
    registry = ProviderRegistry()
    registry.register_state(
        "fixture", lambda: FixtureStateProvider(ROOT / "experiments/fixtures/state")
    )
    provider = registry.state("fixture")
    assert provider is not None
