from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Protocol

from csg.domain.models import EventObservationResult, NormalizedEvent, StateSnapshot


class StateProvider(Protocol):
    async def get_snapshot(self, host_id: str) -> StateSnapshot: ...


class EventProvider(Protocol):
    async def get_events(
        self,
        host_id: str,
        start: datetime,
        end: datetime,
    ) -> EventObservationResult | list[NormalizedEvent]: ...


StateProviderFactory = Callable[[], StateProvider]
EventProviderFactory = Callable[[], EventProvider]


class ProviderRegistry:
    def __init__(self) -> None:
        self._state: dict[str, StateProviderFactory] = {}
        self._events: dict[str, EventProviderFactory] = {}

    def register_state(self, provider_type: str, factory: StateProviderFactory) -> None:
        self._state[provider_type] = factory

    def register_events(self, provider_type: str, factory: EventProviderFactory) -> None:
        self._events[provider_type] = factory

    def state(self, provider_type: str) -> StateProvider:
        try:
            return self._state[provider_type]()
        except KeyError as exc:
            raise ValueError(f"unknown state provider: {provider_type}") from exc

    def events(self, provider_type: str) -> EventProvider:
        try:
            return self._events[provider_type]()
        except KeyError as exc:
            raise ValueError(f"unknown event provider: {provider_type}") from exc


async def maybe_await[T](value: T | Awaitable[T]) -> T:
    if hasattr(value, "__await__"):
        return await value  # type: ignore[no-any-return]
    return value
