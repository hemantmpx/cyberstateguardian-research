from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized(value: Any) -> str:
    text = str(value or "").strip().lower().replace("\\", "/")
    while "//" in text:
        text = text.replace("//", "/")
    return text.replace(":/", "/")


def wilson(successes: int, total: int) -> list[float] | None:
    if total == 0:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    radius = z * ((p * (1 - p) / total + z * z / (4 * total * total)) ** 0.5) / denominator
    return [round(max(0, center - radius), 4), round(min(1, center + radius), 4)]


def strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)] if value else []


def audit(root: Path, output: Path) -> dict[str, Any]:
    campaign_dir = root / "campaign"
    manifest_path = campaign_dir / "campaign-manifest.json"
    manifest = read_json(manifest_path)
    assignments = manifest.get("schedule", [])
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})

    expected_repetitions = int(manifest.get("repetitions", len(assignments)))
    check("ten_assignments_frozen", len(assignments) == expected_repetitions == 10,
          f"assignments={len(assignments)}; declared={expected_repetitions}")
    check("controller_campaign_completed", manifest.get("status") == "COMPLETED",
          f"status={manifest.get('status')}")

    preflight_path = campaign_dir / "pretrial-environment.json"
    preflight = read_json(preflight_path) if preflight_path.exists() else {}
    agent = preflight.get("wazuh_agent", {})
    sysmon_services = preflight.get("sysmon_services", [])
    probe_task = preflight.get("probe_scheduled_task", {})
    check("preflight_host_matches", preflight.get("host_id") == manifest.get("host_id"),
          f"preflight_host={preflight.get('host_id')}; campaign_host={manifest.get('host_id')}")
    check("preflight_wazuh_running", agent.get("service_status") == "Running",
          f"state={agent.get('service_status')}")
    check("preflight_agent_active", agent.get("status") == "active",
          f"status={agent.get('status')}")
    check("preflight_sysmon_running", bool(sysmon_services)
          and all(item.get("state") == "Running" for item in sysmon_services),
          f"services={[(item.get('name'), item.get('state')) for item in sysmon_services]}")
    check("preflight_probe_task_enabled", probe_task.get("enabled") is True,
          f"enabled={probe_task.get('enabled')}; state={probe_task.get('state')}")
    check("preflight_csg_wazuh_health", preflight.get("csg_wazuh_health_ok") is True,
          f"health_ok={preflight.get('csg_wazuh_health_ok')}")

    rows: list[dict[str, Any]] = []
    all_names: list[str] = []
    event_owners: dict[tuple[str, ...], str] = {}
    for assignment in assignments:
        trial_id = str(assignment.get("trial_id", "missing-trial-id"))
        run_path = campaign_dir / trial_id / "run.json"
        if not run_path.exists():
            rows.append({"trial_id": trial_id, "controller_status": assignment.get("status"),
                         "raw_artifact": "missing", "audit_pass": False,
                         "failed_checks": "raw_artifact_exists"})
            check(f"{trial_id}_raw_artifact_exists", False, str(run_path))
            continue

        record = read_json(run_path)
        scenarios = [item for item in record.get("scenarios", [])
                     if item.get("scenario_id") == "registry-autorun-persistence"]
        scenario = scenarios[0] if len(scenarios) == 1 else {}
        state = scenario.get("state_plane", {})
        before = state.get("before_action_observation", {})
        after = state.get("after_action_observation", {})
        after_cleanup = state.get("after_cleanup_observation", {})
        target_key = normalized(scenario.get("expected_object_key"))
        target_name = str(scenario.get("object_name", ""))
        all_names.append(target_name)
        before_items = before.get("target_items", [])
        after_items = after.get("target_items", [])
        cleanup_items = after_cleanup.get("target_items", [])
        cleanup_category_status = after_cleanup.get("category_status")
        state_ok = (
            state.get("target_absent_before_action") is True
            and not before_items
            and len(after_items) == 1
            and normalized(after_items[0].get("object_key")) == target_key
            and cleanup_category_status == "healthy"
            and not cleanup_items
            and state.get("cleanup_removed_from_probe") is True
        )

        local = scenario.get("local_source_evidence", {})
        local_events = [event for event in local.get("exact_events", [])
                        if event.get("exact_identity_match") is True
                        and int(event.get("event_id", 0)) == 13
                        and normalized(event.get("event_data", {}).get("TargetObject"))
                        == target_key.removeprefix("registry:")]
        local_ok = local.get("query_status") == "COMPLETE" and bool(local_events)
        local_records = {
            (str(event.get("record_id")), str(event.get("event_id")),
             normalized(event.get("provider")), normalized(event.get("log_name")))
            for event in local_events
        }

        event_plane = scenario.get("event_plane", {})
        exact_events = [event for event in event_plane.get("exact_matches", [])
                        if event.get("host_id") == manifest.get("host_id")
                        and event.get("source") == "wazuh"
                        and event.get("normalized_type") == "registry_value_modified"
                        and normalized(event.get("target", {}).get("key")) == target_key]
        physical_ids = {
            (str(event.get("windows_event_identity", {}).get("event_record_id")),
             str(event.get("windows_event_identity", {}).get("event_code")),
             normalized(event.get("windows_event_identity", {}).get("provider_name")),
             normalized(event.get("windows_event_identity", {}).get("channel")))
            for event in exact_events
            if event.get("windows_event_identity")
        }
        physical_ok = bool(local_records) and len(local_records) == 1 and len(physical_ids) == 1
        if physical_ok:
            local_record = next(iter(local_records))
            physical_record = next(iter(physical_ids))
            physical_ok = (local_record[0] == physical_record[0]
                           and local_record[1] == physical_record[1]
                           and local_record[2] == physical_record[2]
                           and local_record[3] == physical_record[3])
        event_ok = event_plane.get("query_complete") is True and bool(exact_events) and physical_ok

        reconciliation = scenario.get("csg_reconciliation", {})
        matched_ids = set(strings(reconciliation.get("matched_evidence_ids")))
        exact_ids = {str(event.get("event_id")) for event in exact_events}
        reconciliation_ok = (
            reconciliation.get("status") == "CONSISTENT"
            and reconciliation.get("finalized") is True
            and reconciliation.get("matched_only_exact_target_events") is True
            and bool(matched_ids)
            and matched_ids <= exact_ids
        )
        cleanup_ok = scenario.get("action", {}).get("cleanup_completed") is True
        controller_gate = scenario.get("positive_control", {}).get("passed") is True
        health = assignment.get("post_trial_health") or {}
        health_ok = health.get("passed") is True
        checks_for_trial = {
            "single_registry_scenario": len(scenarios) == 1,
            "unique_target_name": bool(target_name),
            "native_absent_present_absent": state_ok,
            "local_sysmon_event_13_exact": local_ok,
            "wazuh_event_exact_physical_identity": event_ok,
            "finalized_consistent_exact_citation": reconciliation_ok,
            "cleanup_confirmed": cleanup_ok,
            "runner_positive_gate": controller_gate,
            "post_trial_health_and_hashes": health_ok,
        }
        evidence_outcome_pass = all(
            checks_for_trial[name]
            for name in (
                "single_registry_scenario",
                "unique_target_name",
                "native_absent_present_absent",
                "local_sysmon_event_13_exact",
                "wazuh_event_exact_physical_identity",
                "finalized_consistent_exact_citation",
                "cleanup_confirmed",
                "runner_positive_gate",
            )
        )
        for name, passed in checks_for_trial.items():
            check(f"{trial_id}_{name}", passed,
                  f"name={target_name}; controller={assignment.get('status')}; "
                  f"wazuh_records={len(exact_events)}; physical_records={len(physical_ids)}")
        row_pass = all(checks_for_trial.values())
        rows.append({
            "trial_id": trial_id,
            "controller_status": assignment.get("status"),
            "target_name": target_name,
            "target_object_key": scenario.get("expected_object_key"),
            "state_absent_present_absent": state_ok,
            "local_sysmon_exact_count": len(local_events),
            "wazuh_exact_document_count": len(exact_events),
            "wazuh_distinct_physical_event_count": len(physical_ids),
            "reconciliation_status": reconciliation.get("status"),
            "reconciliation_finalized": reconciliation.get("finalized"),
            "matched_evidence_ids": ";".join(sorted(matched_ids)),
            "cleanup_confirmed": cleanup_ok,
            "cleanup_category_status": cleanup_category_status,
            "cleanup_target_item_count": len(cleanup_items),
            "post_trial_health": health_ok,
            "evidence_outcome_pass": evidence_outcome_pass,
            "audit_pass": row_pass,
            "failed_checks": ";".join(key for key, value in checks_for_trial.items() if not value),
            "raw_artifact": str(run_path.relative_to(root)),
        })
        for identity in physical_ids:
            prior = event_owners.setdefault(identity, trial_id)
            check(f"{trial_id}_physical_event_not_reused", prior == trial_id,
                  f"physical_identity={identity}; first_trial={prior}")

    raw_rows = [row for row in rows if row.get("raw_artifact") != "missing"]
    valid_outcomes = sum(bool(row.get("evidence_outcome_pass")) for row in raw_rows)
    fully_validated_trials = sum(bool(row.get("audit_pass")) for row in raw_rows)
    raw_trial_count = len(raw_rows)
    count_ok = len(assignments) == expected_repetitions
    names_unique = len(all_names) == len(set(all_names)) and all(all_names)
    postflight = manifest.get("postflight", {})
    postflight_ok = postflight.get("postflight_valid") is True
    check("trial_name_unique_across_run", names_unique,
          f"names={len(all_names)}; unique={len(set(all_names))}")
    check("final_postflight_valid", postflight_ok,
          f"postflight_valid={postflight.get('postflight_valid')}")
    campaign_complete = (
        manifest.get("status") == "COMPLETED"
        and count_ok
        and raw_trial_count == expected_repetitions
        and fully_validated_trials == expected_repetitions
        and all(item.get("status") == "COMPLETED_PASS" for item in assignments)
        and names_unique
        and postflight_ok
    )
    audit_valid = campaign_complete and all(item["passed"] for item in checks)
    audit_record = {
        "schema_version": "csg-registry-positive-campaign-audit-v1",
        "experiment_id": manifest.get("experiment_id"),
        "audited_at_utc": datetime.now(UTC).isoformat(),
        "audit_script_sha256": sha256(Path(__file__).resolve()),
        "audit_valid": audit_valid,
        "campaign_complete": campaign_complete,
        "controller_status": manifest.get("status"),
        "host_id": manifest.get("host_id"),
        "planned_trials": expected_repetitions,
        "scheduled_assignments": len(assignments),
        "raw_trials": raw_trial_count,
        "independently_valid_evidence_outcomes": valid_outcomes,
        "fully_validated_trials": fully_validated_trials,
        "evidence_outcome_rate": valid_outcomes / raw_trial_count if raw_trial_count else None,
        "evidence_outcome_wilson_95_ci": wilson(valid_outcomes, raw_trial_count),
        "checks_passed": sum(item["passed"] for item in checks),
        "checks_total": len(checks),
        "checks": checks,
        "trial_summary": rows,
        "interpretation": (
            "A positive-control result for one benign registry state category on one Windows host; "
            "not attack-detection efficacy or general event-loss resilience."
        ),
    }

    output.mkdir(parents=True, exist_ok=False)
    (output / "audit.json").write_text(json.dumps(audit_record, indent=2) + "\n", encoding="utf-8")
    if rows:
        with (output / "trial-summary.csv").open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    catalog = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and output not in path.parents:
            catalog.append({"path": str(path.relative_to(root)), "sha256": sha256(path),
                            "size_bytes": path.stat().st_size})
    catalog.append({"path": str(Path(__file__).resolve()),
                    "sha256": sha256(Path(__file__).resolve()),
                    "size_bytes": Path(__file__).stat().st_size,
                    "scope": "independent audit implementation"})
    (output / "artifact-manifest.json").write_text(
        json.dumps(
            {"schema_version": "csg-artifact-manifest-v1", "entries": catalog}, indent=2
        )
        + "\n",
        encoding="utf-8",
    )
    return audit_record


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Independently audit a CSG registry positive-control campaign"
    )
    parser.add_argument("run_root", type=Path)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.run_root.resolve(), args.output_directory.resolve())
    print(json.dumps({key: result[key] for key in (
        "audit_valid", "campaign_complete", "controller_status", "planned_trials",
        "scheduled_assignments", "raw_trials", "independently_valid_evidence_outcomes",
        "fully_validated_trials",
        "evidence_outcome_rate", "evidence_outcome_wilson_95_ci",
        "checks_passed", "checks_total",
    )}, indent=2))


if __name__ == "__main__":
    main()
