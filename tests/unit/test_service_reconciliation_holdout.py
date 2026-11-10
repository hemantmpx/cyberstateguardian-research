from __future__ import annotations

import pytest
from experiments.analyze_service_reconciliation_holdout import (
    _event_occurrence_key,
    _probe_schedule_isolated,
    _source_kind,
    _wilson,
)


def test_alert_and_archive_copies_are_distinguished_but_same_occurrence() -> None:
    base = {
        "host_id": "win11-arm-lab",
        "normalized_type": "service_created",
        "event_time": "2026-10-05T12:00:00Z",
        "target_key": "service:csgresearchabc",
        "attributes": {"event_code": "7045"},
    }
    alert = {
        **base,
        "metadata": {"source_kind": "wazuh_alert"},
        "source_reference": {"index": "wazuh-alerts-4.x-2026.10.05"},
    }
    archive = {
        **base,
        "metadata": {"source_kind": "wazuh_archive"},
        "source_reference": {"index": "wazuh-archives-4.x-2026.10.05"},
    }

    assert _source_kind(alert) == "wazuh_alert"
    assert _source_kind(archive) == "wazuh_archive"
    assert _event_occurrence_key(alert) == _event_occurrence_key(archive)


def test_source_kind_falls_back_to_index_and_keeps_unknown_explicit() -> None:
    assert _source_kind({"source_reference": {"index": "wazuh-alerts-4.x"}}) == "wazuh_alert"
    assert _source_kind({"source_reference": {"index": "custom-events"}}) == "unknown"


def test_wilson_interval_reports_numerator_and_denominator() -> None:
    result = _wilson(10, 10)
    assert result["successes"] == 10
    assert result["total"] == 10
    assert result["rate"] == 1.0
    assert result["ci95"] == pytest.approx([0.7224672001371107, 1.0])
    assert _wilson(0, 0)["rate"] is None


def test_probe_schedule_isolation_requires_disable_and_restore_proof() -> None:
    assert _probe_schedule_isolated(
        {
            "enabled_before": True,
            "enabled_during_trial": False,
            "enabled_after": True,
        }
    )
    assert _probe_schedule_isolated({"status": "not_installed"})
    assert not _probe_schedule_isolated(
        {
            "enabled_before": True,
            "enabled_during_trial": True,
            "enabled_after": True,
        }
    )
