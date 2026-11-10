from __future__ import annotations

import json
from pathlib import Path

from csg.domain.models import StateSnapshot


class FixtureStateProvider:
    def __init__(self, fixture_dir: Path, fixture_name: str = "baseline") -> None:
        self.fixture_dir = fixture_dir
        self.fixture_name = fixture_name

    async def get_snapshot(self, host_id: str) -> StateSnapshot:
        path = self._resolve_fixture(host_id)
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        snapshot = StateSnapshot.model_validate(data)
        if snapshot.host_id != host_id:
            raise ValueError(f"fixture {path} belongs to host {snapshot.host_id}, not {host_id}")
        return snapshot

    def _resolve_fixture(self, host_id: str) -> Path:
        candidates = [
            self.fixture_dir / f"{self.fixture_name}.json",
            self.fixture_dir / f"{host_id}.{self.fixture_name}.json",
            self.fixture_dir / f"{host_id}.json",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        raise FileNotFoundError(
            f"no state fixture found for host={host_id} name={self.fixture_name}"
        )


class ProbeStateProvider:
    """Adapter placeholder for persisted direct-probe observations.

    The concrete snapshot construction lives in StateBuilder so the provider returns the same
    source-independent StateSnapshot model as fixtures and Wazuh providers.
    """

    def __init__(self, latest_snapshot: StateSnapshot | None = None) -> None:
        self.latest_snapshot = latest_snapshot

    async def get_snapshot(self, host_id: str) -> StateSnapshot:
        if self.latest_snapshot is None or self.latest_snapshot.host_id != host_id:
            raise ValueError("no direct-probe snapshot is available for host")
        return self.latest_snapshot
