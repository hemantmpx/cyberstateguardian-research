from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def source_key(reference: dict[str, Any]) -> str:
    index = str(reference.get("index", "")).casefold()
    document_id = str(reference.get("document_id", "")).casefold()
    return f"{index}|{document_id}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Supplementally compare v49 controller references with full CSG API metadata."
    )
    parser.add_argument("--trial-dir", type=Path, required=True)
    args = parser.parse_args()
    trial_dir = args.trial_dir.resolve()
    controller_path = trial_dir / "windows-raw" / "trial-02" / "result.json"
    readback_path = trial_dir / "postrun" / "csg-event-store-raw-readback.json"
    controller = json.loads(controller_path.read_text(encoding="utf-8-sig"))
    rows = json.loads(readback_path.read_text(encoding="utf-8"))
    validation = controller["distractor_event_store_readback_validation"]
    local_event = controller["distractor_event"]["local_windows_event"]
    expected_provider_keys = set(validation["provider_source_reference_keys"])
    actual_references: list[dict[str, Any]] = []
    for row in rows:
        if row.get("source_reference"):
            actual_references.append(row["source_reference"])
        actual_references.extend(row.get("metadata", {}).get("additional_source_references", []))
    actual_keys = {source_key(reference) for reference in actual_references}

    checks = {
        "original_controller_result_remains_incomplete": controller.get("status")
        == "INCOMPLETE_OR_INVALID",
        "one_canonical_csg_event_returned": len(rows) == 1,
        "canonical_event_id_matches_controller_readback": len(rows) == 1
        and rows[0].get("event_id") in validation.get("readback_event_ids", []),
        "host_and_normalized_type_match": len(rows) == 1
        and rows[0].get("host_id") == controller.get("host_id")
        and rows[0].get("normalized_type") == "scheduled_task_created",
        "object_identity_is_exact_distractor": len(rows) == 1
        and rows[0].get("target", {}).get("key", "").casefold()
        == controller["distractor_event"]["object_key"].casefold(),
        "physical_windows_event_identity_matches_local_4698": len(rows) == 1
        and str(
            rows[0].get("metadata", {}).get("windows_event_identity", {}).get("event_record_id")
        )
        == str(local_event.get("record_id"))
        and str(rows[0].get("metadata", {}).get("windows_event_identity", {}).get("event_code"))
        == str(local_event.get("event_id")),
        "alert_and_archive_refs_match_provider": actual_keys == expected_provider_keys
        and len(actual_keys) == 2,
        "target_final_reconciliation_remains_unexplained_without_citations": controller.get(
            "final_target_reconciliation", {}
        ).get("status")
        == "UNEXPLAINED"
        and controller.get("final_target_reconciliation", {}).get("matched_evidence_ids") == [],
    }
    result = {
        "schema_version": "csg-v49-supplemental-provenance-audit-v1",
        "audited_at_utc": datetime.now(UTC).isoformat(),
        "evidence_class": "POSTRUN_READ_ONLY_CORROBORATION_NOT_A_CONTROLLER_PASS",
        "controller_trial_status": controller.get("status"),
        "controller_trial_is_promoted": False,
        "readback_artifact_sha256": hashlib.sha256(readback_path.read_bytes()).hexdigest(),
        "provider_source_reference_keys": sorted(expected_provider_keys),
        "csg_store_source_reference_keys": sorted(actual_keys),
        "canonical_csg_event_id": rows[0].get("event_id") if len(rows) == 1 else None,
        "checks": checks,
        "passed": all(checks.values()),
        "interpretation": (
            "The CSG store retains the alert and archive references in event metadata. "
            "The frozen v14 runner's readback projection omitted that metadata, causing the "
            "controller's strict provenance check to fail. This supplemental query does not "
            "rewrite or promote the original controller disposition."
        ),
    }
    output_path = trial_dir / "postrun" / "provenance-audit.json"
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
