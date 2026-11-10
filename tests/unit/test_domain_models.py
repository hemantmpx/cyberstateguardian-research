from __future__ import annotations

from datetime import UTC, datetime

from tests.conftest import ROOT, load_json

from csg.domain.enums import ReconciliationStatus
from csg.domain.models import Host, StateSnapshot


def test_host_defaults_are_utc() -> None:
    host = Host(
        host_id="win-lab-01",
        hostname="win11-arm-lab",
        role="windows-target",
        os="windows-11",
        architecture="arm64",
    )
    assert host.created_at.tzinfo == UTC
    assert host.enabled is True


def test_state_fixture_validates_and_normalizes_utc() -> None:
    snapshot = StateSnapshot.model_validate(
        load_json(ROOT / "experiments/fixtures/state/baseline.json")
    )
    assert snapshot.host_id == "win-lab-01"
    assert snapshot.built_at.tzinfo == UTC
    assert snapshot.status_for("service") is not None


def test_reconciliation_enum_values_are_stable() -> None:
    assert ReconciliationStatus.CONSISTENT.value == "CONSISTENT"
    assert datetime.fromisoformat("2026-09-13T20:00:00+00:00").tzinfo is not None
