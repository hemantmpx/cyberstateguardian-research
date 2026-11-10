"""Validate a live Windows-APT-style reproduction without overstating its scope."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

Json = dict[str, Any]


def load(path: Path) -> Json:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def identity(value: Any) -> str:
    text = str(value or "").strip().lower().replace("\\", "/")
    text = re.sub(r"/+", "/", text)
    return text.replace(":/", "/")


def event_matches(scenario: Json, event: Json) -> bool:
    expected_key = identity(scenario.get("expected_object_key"))
    target_key = identity((event.get("target") or {}).get("key"))
    if target_key == expected_key:
        return True
    attrs = event.get("attributes") or {}
    kind = scenario.get("kind")
    if kind == "service":
        return (
            str(attrs.get("service_name") or "").lower()
            == str(scenario.get("object_name") or "").lower()
        )
    if kind == "scheduled_task":
        return identity(attrs.get("task_name")) == identity("\\" + str(scenario.get("object_name")))
    if kind == "registry":
        return identity(attrs.get("target_object")) == expected_key
    return False


def _tri_state(condition: bool | None, detail: str) -> Json:
    """Represent evidence checks without treating an empty result as proof."""
    if condition is None:
        return {"status": "NOT_APPLICABLE", "passed": None, "detail": detail}
    return {
        "status": "PASS" if condition else "FAIL",
        "passed": condition,
        "detail": detail,
    }


def validate(payload: Json) -> Json:
    checks: list[Json] = []
    scenarios = payload.get("scenarios")
    checks.append(
        {
            "name": "schema",
            "passed": payload.get("schema_version")
            in {
                "csg-windows-apt-live-reproduction-v1",
                "csg-windows-apt-inspired-live-validation-v2",
            },
        }
    )
    checks.append(
        {"name": "explicit_non_replication", "passed": payload.get("exact_replication") is False}
    )
    checks.append(
        {"name": "scenario_count", "passed": isinstance(scenarios, list) and len(scenarios) == 4}
    )

    identities: list[str] = []
    evidence_ids: list[str] = []
    scenario_results: list[Json] = []
    for scenario in scenarios if isinstance(scenarios, list) else []:
        state = scenario.get("state_plane") or {}
        event_plane = scenario.get("event_plane") or {}
        events = event_plane.get("exact_matches") or []
        key = identity(scenario.get("expected_object_key"))
        identities.append(key)
        host_id = payload.get("environment", {}).get("host_id")
        query_completed = event_plane.get("query_completed", True)
        event_present = bool(events)
        event_required = bool(
            scenario.get("event_presence_required")
            or event_plane.get("event_presence_required")
            or scenario.get("expected_event_type") == "service_created"
        )
        identity_checks = {
            "same_host": _tri_state(
                all(event.get("host_id") == host_id for event in events)
                if event_present
                else None,
                "every returned event belongs to the recorded host"
                if event_present
                else "no exact event was returned",
            ),
            "expected_event_type": _tri_state(
                all(
                    event.get("normalized_type") == scenario.get("expected_event_type")
                    for event in events
                )
                if event_present
                else None,
                "every returned event has the expected normalized type"
                if event_present
                else "no exact event was returned",
            ),
            "exact_object_identity": _tri_state(
                all(event_matches(scenario, event) for event in events)
                if event_present
                else None,
                "every returned event names the exact state object"
                if event_present
                else "no exact event was returned",
            ),
        }
        required_checks = [
            state.get("source") == "direct_probe",
            bool(state.get("after_action_observed")),
            state.get("cleanup_removed_from_probe") is True,
            event_plane.get("source") == "wazuh",
            query_completed is True,
            (event_present if event_required else True),
            *[check["passed"] is not False for check in identity_checks.values()],
        ]
        event_ids = [str(event.get("event_id")) for event in events if event.get("event_id")]
        evidence_ids.extend(event_ids)
        scenario_results.append(
            {
                "scenario_id": scenario.get("scenario_id"),
                "object_key": scenario.get("expected_object_key"),
                "state_observed": bool(state.get("after_action_observed")),
                "exact_wazuh_event_count": len(events),
                "event_presence": "PRESENT" if event_present else "ABSENT",
                "event_presence_required": event_required,
                "finding_count": len(scenario.get("findings") or []),
                "reconciliation_statuses": sorted(
                    {
                        str((finding.get("reconciliation") or {}).get("status"))
                        for finding in scenario.get("findings") or []
                    }
                ),
                "cleanup_completed": scenario.get("action", {}).get("cleanup_completed") is True,
                "passed": all(required_checks),
                "checks": {
                    "direct_probe_source": _tri_state(
                        state.get("source") == "direct_probe",
                        "state was collected by the native probe",
                    ),
                    "direct_probe_observed_object": _tri_state(
                        bool(state.get("after_action_observed")),
                        "the expected object appeared in the post-action probe snapshot",
                    ),
                    "cleanup_removed_object": _tri_state(
                        state.get("cleanup_removed_from_probe") is True,
                        "the object was absent from the cleanup probe snapshot",
                    ),
                    "wazuh_source": _tri_state(
                        event_plane.get("source") == "wazuh",
                        "the event query used Wazuh",
                    ),
                    "retrieval_query_completed": _tri_state(
                        query_completed is True,
                        "the central event query completed",
                    ),
                    "exact_event_present": _tri_state(
                        event_present if event_required else None,
                        "an exact event is required for this positive-control scenario"
                        if event_required
                        else "event availability is being measured, not asserted",
                    ),
                    **identity_checks,
                },
            }
        )

    checks.append({"name": "unique_object_keys", "passed": len(identities) == len(set(identities))})
    checks.append(
        {"name": "no_reused_exact_wazuh_ids", "passed": len(evidence_ids) == len(set(evidence_ids))}
    )
    checks.append(
        {"name": "scenario_integrity", "passed": all(row["passed"] for row in scenario_results)}
    )
    return {
        "schema_version": "csg-windows-apt-live-reproduction-validation-v2",
        "passed": all(check["passed"] for check in checks),
        "campaign_id": payload.get("campaign_id"),
        "checks": checks,
        "scenario_results": scenario_results,
        "interpretation": (
            "Validation proves record integrity and strict identity checks. It does not claim "
            "that a missing Wazuh event was permanently lost."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = validate(load(args.path))
    output = args.output or args.path.with_name("validation.json")
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
