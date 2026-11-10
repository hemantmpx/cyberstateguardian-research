from __future__ import annotations

import unittest
from datetime import UTC, datetime

from analyze_v90_v91_identity_ablation import qualifies_for_naive_match, wilson


class IdentityAblationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.start = datetime(2026, 10, 16, 3, 0, tzinfo=UTC)
        self.end = datetime(2026, 10, 16, 3, 1, tzinfo=UTC)
        self.event = {
            "host_id": "win11-arm-lab",
            "normalized_type": "service_modified",
            "event_time": "2026-10-16T03:00:30Z",
            "target_key": "service:other-service",
            "attributes": {"event_code": "7040", "rule_id": "61104"},
        }

    def test_host_type_rule_time_match_ignores_wrong_object_identity(self) -> None:
        self.assertTrue(
            qualifies_for_naive_match(
                self.event,
                host_id="win11-arm-lab",
                window_start=self.start,
                window_end=self.end,
            )
        )

    def test_rejects_wrong_host(self) -> None:
        self.assertFalse(
            qualifies_for_naive_match(
                self.event,
                host_id="other-host",
                window_start=self.start,
                window_end=self.end,
            )
        )

    def test_rejects_wrong_event_class(self) -> None:
        event = {**self.event, "normalized_type": "service_created"}
        self.assertFalse(
            qualifies_for_naive_match(
                event,
                host_id="win11-arm-lab",
                window_start=self.start,
                window_end=self.end,
            )
        )

    def test_rejects_event_outside_frozen_tolerance(self) -> None:
        event = {**self.event, "event_time": "2026-10-16T03:02:00Z"}
        self.assertFalse(
            qualifies_for_naive_match(
                event,
                host_id="win11-arm-lab",
                window_start=self.start,
                window_end=self.end,
            )
        )

    def test_wilson_interval(self) -> None:
        self.assertEqual(wilson(20, 20), [0.8389, 1.0])
        self.assertEqual(wilson(0, 20), [0.0, 0.1611])


if __name__ == "__main__":
    unittest.main()
