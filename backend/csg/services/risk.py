from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from csg.domain.enums import AuthorizationStatus, DeltaType, ReconciliationStatus, Severity
from csg.domain.models import ReconciliationResult, RiskComponent, RiskScore, StateDelta


class RiskEngine:
    def __init__(self, rules_path: Path) -> None:
        self.rules_path = rules_path
        self.config = self._load_rules(rules_path)

    def score_delta(
        self,
        delta: StateDelta,
        reconciliation: ReconciliationResult,
        authorization_status: AuthorizationStatus,
    ) -> RiskScore:
        components: list[RiskComponent] = []

        if delta.category == "service" and delta.delta_type == DeltaType.ADD:
            components.append(self._component("new_service"))
        if delta.category == "service" and delta.delta_type == DeltaType.MODIFY:
            components.append(self._component("modified_service"))
        if delta.category == "listener" and delta.delta_type == DeltaType.ADD:
            components.append(self._component("new_listener"))
        if delta.category == "privileged_group":
            components.append(self._component("privileged_change"))
        if delta.category == "scheduled_task":
            components.append(self._component("scheduled_task"))

        if authorization_status == AuthorizationStatus.VIOLATION:
            components.append(self._component("authorization_violation"))
        elif authorization_status == AuthorizationStatus.UNKNOWN:
            components.append(self._component("unknown_authorization"))
        elif authorization_status == AuthorizationStatus.APPROVED_CHANGE:
            components.append(self._component("approved_change"))
        elif authorization_status == AuthorizationStatus.EXPECTED:
            components.append(self._component("expected_object"))

        semantics = reconciliation.metadata.get("reconciliation_semantics")
        if semantics == "UNCORROBORATED_HEALTHY":
            components.append(self._component("unexplained_telemetry"))
        elif semantics == "UNCORROBORATED_DEGRADED":
            components.append(self._component("degraded_event_source"))
        elif reconciliation.status == ReconciliationStatus.UNEXPLAINED:
            components.append(self._component("unexplained_telemetry"))
        elif reconciliation.status == ReconciliationStatus.PARTIALLY_EXPLAINED:
            components.append(self._component("partial_explanation"))

        source_quality = delta.source_quality.get("current", {})
        if source_quality.get("status") not in {None, "healthy", "partial"}:
            components.append(self._component("stale_source_quality"))

        total = max(0, sum(component.points for component in components))
        return RiskScore(
            total=total,
            severity=self._severity(total),
            components=components,
            rules_version=str(self.config.get("version", "unknown")),
        )

    def score_transient(
        self,
        reconciliation: ReconciliationResult,
        authorization_status: AuthorizationStatus = AuthorizationStatus.UNKNOWN,
    ) -> RiskScore:
        components = [self._component("unknown_authorization")]
        if reconciliation.status == ReconciliationStatus.UNEXPLAINED:
            components.append(self._component("unexplained_telemetry"))
        total = max(0, sum(component.points for component in components))
        return RiskScore(
            total=total,
            severity=self._severity(total),
            components=components,
            rules_version=str(self.config.get("version", "unknown")),
        )

    def _component(self, rule_name: str) -> RiskComponent:
        rule = self.config.get("rules", {}).get(rule_name, {})
        return RiskComponent(
            rule_name=rule_name,
            points=int(rule.get("points", 0)),
            explanation=rule.get("explanation", f"risk rule {rule_name}"),
        )

    def _severity(self, total: int) -> Severity:
        for name, bounds in self.config.get("bands", {}).items():
            low, high = bounds
            if int(low) <= total <= int(high):
                return Severity(name)
        return Severity.CRITICAL

    @staticmethod
    def _load_rules(rules_path: Path) -> dict[str, Any]:
        with rules_path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
