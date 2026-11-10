"""Evaluate semantic normalization and bounded evidence retrieval on Windows-APT 2025."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from experiments.datasets.windows_apt_2025.loader import iter_dataset, load_scenario_manifest

SEMANTIC_TYPES = {
    "process_start",
    "registry_value_modified",
    "service_created",
    "service_modified",
    "scheduled_task_created",
    "scheduled_task_modified",
    "privileged_group_member_added",
    "network_activity",
}

IDENTITY_FIELDS = {
    "process_start": ("process_guid", "process_id", "process_name"),
    "registry_value_modified": ("target_object",),
    "service_created": ("service_name", "target_object"),
    "service_modified": ("service_name", "target_object"),
    "scheduled_task_created": ("task_name", "target_object"),
    "scheduled_task_modified": ("task_name", "target_object"),
    "privileged_group_member_added": ("group_name", "member_name", "member_sid"),
    "network_activity": ("source_address", "destination_address", "destination_port"),
}


def evaluate_dataset(archive: Path, *, host_id: str | None = None) -> dict[str, Any]:
    type_counts: Counter[str] = Counter()
    agent_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    attribute_presence: Counter[str] = Counter()
    identity_counts: Counter[str] = Counter()
    total = 0

    for event in iter_dataset(archive, host_id=host_id):
        total += 1
        type_counts[event.normalized_type] += 1
        agent = str(event.metadata.get("agent_name") or "unknown")
        agent_counts[agent or "unknown"] += 1
        host_counts[event.host_id] += 1
        attrs = event.attributes
        if any(attrs.get(key) for key in ("process_name", "process_guid", "process_id")):
            attribute_presence["process_context"] += 1
        if any(
            attrs.get(key) for key in ("source_address", "destination_address", "destination_port")
        ):
            attribute_presence["network_context"] += 1
        if attrs.get("target_object"):
            attribute_presence["registry_context"] += 1
        if attrs.get("service_name"):
            attribute_presence["service_context"] += 1
        if attrs.get("task_name"):
            attribute_presence["scheduled_task_context"] += 1
        required = IDENTITY_FIELDS.get(event.normalized_type)
        if required and any(attrs.get(field) for field in required):
            identity_counts[event.normalized_type] += 1

    manifest = load_scenario_manifest(archive)
    semantic_count = sum(type_counts[item] for item in SEMANTIC_TYPES)
    generic_count = type_counts["dataset_event"]
    identified_semantic_count = sum(identity_counts.values())
    return {
        "schema_version": "csg-windows-apt-evaluation-v2",
        "dataset": {
            "archive": str(archive),
            "dataset_id": "b8fmtzvpy8",
            "revision": 3,
            "host_identity_policy": (
                "one distinct CSG dataset host per original Wazuh agent ID and name"
                if host_id is None
                else f"explicit host override: {host_id}"
            ),
            "event_count": total,
            "scenario_count": len(manifest),
            "distinct_source_agent_count": len(agent_counts),
            "distinct_dataset_host_count": len(host_counts),
            "agents": sorted(agent_counts),
        },
        "normalization": {
            "counts_by_type": dict(sorted(type_counts.items())),
            "semantic_event_types": sorted(SEMANTIC_TYPES),
            "semantic_events": semantic_count,
            "generic_dataset_events": generic_count,
            "semantic_normalization_rate": round(semantic_count / total, 6) if total else None,
            "generic_event_rate": round(generic_count / total, 6) if total else None,
            "semantic_events_with_target_identity": identified_semantic_count,
            "target_identity_coverage_rate": (
                round(identified_semantic_count / semantic_count, 6) if semantic_count else None
            ),
            "target_identity_by_event_type": {
                event_type: {
                    "semantic_events": type_counts[event_type],
                    "with_target_identity": identity_counts[event_type],
                    "coverage_rate": (
                        round(identity_counts[event_type] / type_counts[event_type], 6)
                        if type_counts[event_type]
                        else None
                    ),
                }
                for event_type in sorted(SEMANTIC_TYPES)
            },
        },
        "context_attributes": {
            key: {"count": value, "rate": round(value / total, 6) if total else None}
            for key, value in sorted(attribute_presence.items())
        },
        "agent_distribution": dict(sorted(agent_counts.items())),
        "dataset_host_distribution": dict(sorted(host_counts.items())),
        "interpretation": {
            "generic_events_are_not_silently_dropped": True,
            "generic_events_remain_available_as_dataset_event": True,
            "scenario_manifest_is_catalogue_only": True,
            "field_presence_is_not_counted_as_context": True,
            "limitation": (
                "The archive does not provide a trusted row-level scenario label for every event. "
                "These are normalization and target-identity coverage measures, not attack "
                "detection accuracy or validated scenario retrieval."
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Windows-APT CSG normalization coverage")
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = evaluate_dataset(args.archive)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
