from __future__ import annotations

from csg.domain.enums import DeltaType
from csg.domain.models import Finding, StateDelta

_MAPPINGS = {
    "service": {
        "technique_id": "T1543.003",
        "technique": "Create or Modify System Process: Windows Service",
        "url": "https://attack.mitre.org/techniques/T1543/003/",
    },
    "scheduled_task": {
        "technique_id": "T1053.005",
        "technique": "Scheduled Task/Job: Scheduled Task",
        "url": "https://attack.mitre.org/techniques/T1053/005/",
    },
    "privileged_group": {
        "technique_id": "T1098.007",
        "technique": "Account Manipulation: Additional Local or Domain Groups",
        "url": "https://attack.mitre.org/techniques/T1098/007/",
    },
    "registry": {
        "technique_id": "T1112",
        "technique": "Modify Registry",
        "url": "https://attack.mitre.org/techniques/T1112/",
    },
}


def attack_context_for(
    finding: Finding,
    state_delta: StateDelta | None,
) -> dict[str, object] | None:
    mapping = _MAPPINGS.get(finding.category)
    if mapping is None:
        return None
    selected = dict(mapping)
    if (
        finding.category == "registry"
        and "currentversion/run" in (finding.object_key or "").replace("\\", "/").lower()
    ):
        selected = {
            "technique_id": "T1547.001",
            "technique": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            "url": "https://attack.mitre.org/techniques/T1547/001/",
        }

    delta_type = state_delta.delta_type if state_delta else None
    confidence = "medium"
    rationale = "category-level behavioral candidate"
    if finding.category in {"service", "scheduled_task", "privileged_group"} and delta_type in {
        DeltaType.ADD,
        DeltaType.MODIFY,
    }:
        confidence = "high"
        rationale = f"deterministic {finding.category} {delta_type.value} state transition"

    return {
        "framework": "MITRE ATT&CK Enterprise",
        **selected,
        "mapping_status": "candidate_enrichment",
        "confidence": confidence,
        "rationale": rationale,
        "analyst_validation_required": True,
        "mapping_version": "csg-attack-candidates-2026-09-20",
        "source_reviewed_at": "2026-09-20",
    }
