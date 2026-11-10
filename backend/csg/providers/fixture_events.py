from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from csg.domain.models import NormalizedEvent, ensure_utc


class FixtureEventProvider:
    def __init__(self, fixture_dir: Path, fixture_set: str = "all") -> None:
        self.fixture_dir = fixture_dir
        self.fixture_set = fixture_set

    async def get_events(
        self,
        host_id: str,
        start: datetime,
        end: datetime,
    ) -> list[NormalizedEvent]:
        start = ensure_utc(start)
        end = ensure_utc(end)
        events = [
            event
            for event in self._load_events()
            if event.host_id == host_id and start <= event.event_time <= end
        ]
        return sorted(events, key=lambda event: (event.event_time, event.event_id))

    def _load_events(self) -> list[NormalizedEvent]:
        paths = self._paths()
        events: list[NormalizedEvent] = []
        for path in paths:
            with path.open("r", encoding="utf-8") as handle:
                payload: Any = json.load(handle)
            rows = payload if isinstance(payload, list) else payload.get("events", [payload])
            events.extend(NormalizedEvent.model_validate(row) for row in rows)
        return events

    def _paths(self) -> list[Path]:
        if self.fixture_set == "all":
            return sorted(self.fixture_dir.glob("*.json"))
        candidate = self.fixture_dir / f"{self.fixture_set}.json"
        if not candidate.exists():
            raise FileNotFoundError(f"event fixture set not found: {candidate}")
        return [candidate]
