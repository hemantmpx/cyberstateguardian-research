"""initial schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-09-13 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "hosts",
        sa.Column("host_id", sa.String(length=128), primary_key=True),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=128), nullable=False),
        sa.Column("os", sa.String(length=128), nullable=False),
        sa.Column("architecture", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "source_observations",
        sa.Column("observation_id", sa.String(length=36), primary_key=True),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("categories", sa.JSON(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index("ix_source_observations_host_id", "source_observations", ["host_id"])
    op.create_index("ix_source_observations_observed_at", "source_observations", ["observed_at"])

    op.create_table(
        "state_snapshots",
        sa.Column("snapshot_id", sa.String(length=36), primary_key=True),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("built_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("category_statuses", sa.JSON(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index("ix_state_snapshots_host_id", "state_snapshots", ["host_id"])
    op.create_index("ix_state_snapshots_built_at", "state_snapshots", ["built_at"])

    op.create_table(
        "state_objects",
        sa.Column("object_id", sa.String(length=36), primary_key=True),
        sa.Column(
            "snapshot_id",
            sa.String(length=36),
            sa.ForeignKey("state_snapshots.snapshot_id"),
            nullable=False,
        ),
        sa.Column("host_id", sa.String(length=128), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("object_key", sa.String(length=512), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("source_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index("ix_state_objects_snapshot_id", "state_objects", ["snapshot_id"])
    op.create_index("ix_state_objects_host_id", "state_objects", ["host_id"])
    op.create_index("ix_state_objects_category", "state_objects", ["category"])
    op.create_index("ix_state_objects_object_key", "state_objects", ["object_key"])
    op.create_index("ix_state_objects_source_timestamp", "state_objects", ["source_timestamp"])
    op.create_index(
        "ix_state_objects_host_category_key",
        "state_objects",
        ["host_id", "category", "object_key"],
    )

    op.create_table(
        "state_deltas",
        sa.Column("delta_id", sa.String(length=36), primary_key=True),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("object_key", sa.String(length=512), nullable=False),
        sa.Column("delta_type", sa.String(length=16), nullable=False),
        sa.Column("before", sa.JSON(), nullable=True),
        sa.Column("after", sa.JSON(), nullable=True),
        sa.Column("source_quality", sa.JSON(), nullable=False),
        sa.Column("observation_window", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index("ix_state_deltas_host_id", "state_deltas", ["host_id"])
    op.create_index("ix_state_deltas_category", "state_deltas", ["category"])
    op.create_index("ix_state_deltas_object_key", "state_deltas", ["object_key"])
    op.create_index("ix_state_deltas_delta_type", "state_deltas", ["delta_type"])
    op.create_index("ix_state_deltas_created_at", "state_deltas", ["created_at"])
    op.create_index("ix_deltas_host_created", "state_deltas", ["host_id", "created_at"])

    op.create_table(
        "normalized_events",
        sa.Column("event_id", sa.String(length=128), primary_key=True),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("normalized_type", sa.String(length=128), nullable=False),
        sa.Column("actor", sa.JSON(), nullable=False),
        sa.Column("target", sa.JSON(), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("source_reference", sa.JSON(), nullable=False),
        sa.Column("synthetic", sa.Boolean(), nullable=False),
        sa.Column("scenario_id", sa.String(length=128), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index("ix_normalized_events_host_id", "normalized_events", ["host_id"])
    op.create_index("ix_normalized_events_event_time", "normalized_events", ["event_time"])
    op.create_index(
        "ix_normalized_events_normalized_type", "normalized_events", ["normalized_type"]
    )
    op.create_index("ix_normalized_events_source", "normalized_events", ["source"])
    op.create_index("ix_normalized_events_scenario_id", "normalized_events", ["scenario_id"])
    op.create_index("ix_events_host_time", "normalized_events", ["host_id", "event_time"])

    op.create_table(
        "transient_observations",
        sa.Column("transient_id", sa.String(length=36), primary_key=True),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("event_id", sa.String(length=128), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("normalized_type", sa.String(length=128), nullable=False),
        sa.Column("actor", sa.JSON(), nullable=False),
        sa.Column("target", sa.JSON(), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index("ix_transient_observations_host_id", "transient_observations", ["host_id"])
    op.create_index("ix_transient_observations_event_id", "transient_observations", ["event_id"])
    op.create_index(
        "ix_transient_observations_event_time", "transient_observations", ["event_time"]
    )
    op.create_index(
        "ix_transient_observations_normalized_type",
        "transient_observations",
        ["normalized_type"],
    )
    op.create_index(
        "ix_transient_observations_created_at", "transient_observations", ["created_at"]
    )

    op.create_table(
        "evidence_items",
        sa.Column("evidence_id", sa.String(length=128), primary_key=True),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("evidence_type", sa.String(length=128), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
        sa.Column("source_reference", sa.JSON(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index("ix_evidence_items_host_id", "evidence_items", ["host_id"])
    op.create_index("ix_evidence_items_evidence_type", "evidence_items", ["evidence_type"])
    op.create_index("ix_evidence_items_timestamp", "evidence_items", ["timestamp"])

    op.create_table(
        "reconciliation_results",
        sa.Column("reconciliation_id", sa.String(length=36), primary_key=True),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("matched_evidence_ids", sa.JSON(), nullable=False),
        sa.Column("match_reasons", sa.JSON(), nullable=False),
        sa.Column("missing_expected_evidence_types", sa.JSON(), nullable=False),
        sa.Column("observation_window", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index("ix_reconciliation_results_host_id", "reconciliation_results", ["host_id"])
    op.create_index("ix_reconciliation_results_status", "reconciliation_results", ["status"])
    op.create_index(
        "ix_reconciliation_results_created_at", "reconciliation_results", ["created_at"]
    )

    op.create_table(
        "findings",
        sa.Column("finding_id", sa.String(length=36), primary_key=True),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("observation_kind", sa.String(length=32), nullable=False),
        sa.Column("delta_id", sa.String(length=36), nullable=True),
        sa.Column("transient_id", sa.String(length=36), nullable=True),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("object_key", sa.String(length=512), nullable=True),
        sa.Column("reconciliation", sa.JSON(), nullable=False),
        sa.Column("authorization_status", sa.String(length=32), nullable=False),
        sa.Column("authorization_reason", sa.Text(), nullable=False),
        sa.Column("risk", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index("ix_findings_host_id", "findings", ["host_id"])
    op.create_index("ix_findings_observation_kind", "findings", ["observation_kind"])
    op.create_index("ix_findings_delta_id", "findings", ["delta_id"])
    op.create_index("ix_findings_transient_id", "findings", ["transient_id"])
    op.create_index("ix_findings_category", "findings", ["category"])
    op.create_index("ix_findings_object_key", "findings", ["object_key"])
    op.create_index("ix_findings_authorization_status", "findings", ["authorization_status"])
    op.create_index("ix_findings_created_at", "findings", ["created_at"])
    op.create_index("ix_findings_host_created", "findings", ["host_id", "created_at"])

    op.create_table(
        "authorized_objects",
        sa.Column("authorization_id", sa.String(length=36), primary_key=True),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("object_key", sa.String(length=512), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index("ix_authorized_objects_host_id", "authorized_objects", ["host_id"])
    op.create_index("ix_authorized_objects_category", "authorized_objects", ["category"])
    op.create_index("ix_authorized_objects_object_key", "authorized_objects", ["object_key"])

    op.create_table(
        "maintenance_windows",
        sa.Column("window_id", sa.String(length=128), primary_key=True),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("categories", sa.JSON(), nullable=False),
        sa.Column("object_keys", sa.JSON(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
    )
    op.create_index("ix_maintenance_windows_host_id", "maintenance_windows", ["host_id"])
    op.create_index("ix_maintenance_windows_valid_from", "maintenance_windows", ["valid_from"])
    op.create_index("ix_maintenance_windows_valid_until", "maintenance_windows", ["valid_until"])

    op.create_table(
        "experiment_scenarios",
        sa.Column("scenario_id", sa.String(length=128), primary_key=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("classification", sa.String(length=64), nullable=False),
        sa.Column("initial_state_fixture", sa.String(length=255), nullable=False),
        sa.Column("resulting_state_fixture", sa.String(length=255), nullable=True),
        sa.Column("event_fixture_set", sa.String(length=255), nullable=False),
        sa.Column("expected_deltas", sa.JSON(), nullable=False),
        sa.Column("expected_reconciliation", sa.String(length=32), nullable=False),
        sa.Column("ground_truth_notes", sa.Text(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )

    op.create_table(
        "experiment_runs",
        sa.Column("run_id", sa.String(length=36), primary_key=True),
        sa.Column("scenario_id", sa.String(length=128), nullable=False),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("ground_truth_classification", sa.String(length=64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider_configuration", sa.JSON(), nullable=False),
        sa.Column("expected_observations", sa.JSON(), nullable=False),
        sa.Column("actual_observations", sa.JSON(), nullable=False),
        sa.Column("reconciliation_result", sa.JSON(), nullable=False),
        sa.Column("risk_score", sa.JSON(), nullable=False),
        sa.Column("detection_timestamps", sa.JSON(), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("metrics", sa.JSON(), nullable=False),
    )
    op.create_index("ix_experiment_runs_scenario_id", "experiment_runs", ["scenario_id"])
    op.create_index("ix_experiment_runs_host_id", "experiment_runs", ["host_id"])
    op.create_index("ix_experiment_runs_started_at", "experiment_runs", ["started_at"])
    op.create_index("ix_experiment_runs_ended_at", "experiment_runs", ["ended_at"])

    op.create_table(
        "ai_analyses",
        sa.Column("analysis_id", sa.String(length=36), primary_key=True),
        sa.Column(
            "finding_id", sa.String(length=36), sa.ForeignKey("findings.finding_id"), nullable=False
        ),
        sa.Column("prompt_version", sa.String(length=64), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("response_json", sa.JSON(), nullable=True),
        sa.Column("validation_errors", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ai_analyses_finding_id", "ai_analyses", ["finding_id"])
    op.create_index("ix_ai_analyses_created_at", "ai_analyses", ["created_at"])


def downgrade() -> None:
    op.drop_table("ai_analyses")
    op.drop_table("experiment_runs")
    op.drop_table("experiment_scenarios")
    op.drop_table("maintenance_windows")
    op.drop_table("authorized_objects")
    op.drop_table("findings")
    op.drop_table("reconciliation_results")
    op.drop_table("evidence_items")
    op.drop_table("transient_observations")
    op.drop_table("normalized_events")
    op.drop_table("state_deltas")
    op.drop_table("state_objects")
    op.drop_table("state_snapshots")
    op.drop_table("source_observations")
    op.drop_table("hosts")
