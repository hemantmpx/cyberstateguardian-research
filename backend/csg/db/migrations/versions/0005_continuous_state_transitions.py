"""additive continuous state-transition storage

Revision ID: 0005_state_transitions
Revises: 0004_unique_finding_per_delta
Create Date: 2026-10-04 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_state_transitions"
down_revision: str | None = "0004_unique_finding_per_delta"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "state_transition_records",
        sa.Column("transition_id", sa.String(length=36), primary_key=True),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("object_key", sa.String(length=512), nullable=False),
        sa.Column("transition_type", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("old_state", sa.JSON(), nullable=True),
        sa.Column("new_state", sa.JSON(), nullable=True),
        sa.Column("changed_fields", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("capture_method", sa.String(length=128), nullable=False),
        sa.Column("collector_health", sa.String(length=16), nullable=False),
        sa.Column(
            "snapshot_before_id",
            sa.String(length=36),
            sa.ForeignKey("state_snapshots.snapshot_id"),
            nullable=True,
        ),
        sa.Column(
            "snapshot_after_id",
            sa.String(length=36),
            sa.ForeignKey("state_snapshots.snapshot_id"),
            nullable=True,
        ),
        sa.Column(
            "delta_id", sa.String(length=36), sa.ForeignKey("state_deltas.delta_id"), nullable=True
        ),
        sa.Column("sequence_number", sa.Integer(), nullable=True),
        sa.Column("raw_metadata", sa.JSON(), nullable=False),
    )
    op.create_index("ix_state_transition_records_host_id", "state_transition_records", ["host_id"])
    op.create_index(
        "ix_state_transition_records_category", "state_transition_records", ["category"]
    )
    op.create_index(
        "ix_state_transition_records_object_key", "state_transition_records", ["object_key"]
    )
    op.create_index(
        "ix_state_transition_records_transition_type",
        "state_transition_records",
        ["transition_type"],
    )
    op.create_index(
        "ix_state_transition_records_observed_at", "state_transition_records", ["observed_at"]
    )
    op.create_index(
        "ix_state_transition_records_received_at", "state_transition_records", ["received_at"]
    )
    op.create_index(
        "ix_state_transition_records_collector_health",
        "state_transition_records",
        ["collector_health"],
    )
    op.create_index(
        "ix_state_transition_records_delta_id", "state_transition_records", ["delta_id"]
    )
    op.create_index(
        "ix_transitions_host_observed", "state_transition_records", ["host_id", "observed_at"]
    )
    op.create_index(
        "ix_transitions_host_object_time",
        "state_transition_records",
        ["host_id", "category", "object_key", "observed_at"],
    )

    op.create_table(
        "transition_monitor_health",
        sa.Column("health_id", sa.String(length=36), primary_key=True),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("monitor_id", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("capture_method", sa.String(length=128), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("coverage_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("coverage_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("baseline_established", sa.Boolean(), nullable=False),
        sa.Column("restart_count", sa.Integer(), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_transition_monitor_health_host_id", "transition_monitor_health", ["host_id"]
    )
    op.create_index(
        "ix_transition_monitor_health_category", "transition_monitor_health", ["category"]
    )
    op.create_index(
        "ix_transition_monitor_health_monitor_id", "transition_monitor_health", ["monitor_id"]
    )
    op.create_index("ix_transition_monitor_health_status", "transition_monitor_health", ["status"])
    op.create_index(
        "ix_transition_monitor_health_observed_at", "transition_monitor_health", ["observed_at"]
    )
    op.create_index(
        "ix_transition_health_host_category_time",
        "transition_monitor_health",
        ["host_id", "category", "observed_at"],
    )

    op.create_table(
        "transition_reconciliations",
        sa.Column("reconciliation_id", sa.String(length=36), primary_key=True),
        sa.Column(
            "transition_id",
            sa.String(length=36),
            sa.ForeignKey("state_transition_records.transition_id"),
            nullable=False,
        ),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("matched_evidence_ids", sa.JSON(), nullable=False),
        sa.Column("match_reasons", sa.JSON(), nullable=False),
        sa.Column("missing_expected_evidence_types", sa.JSON(), nullable=False),
        sa.Column("observation_window", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("finalized", sa.Boolean(), nullable=False),
        sa.Column("finalized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("supersedes_reconciliation_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_transition_reconciliations_transition_id",
        "transition_reconciliations",
        ["transition_id"],
    )
    op.create_index(
        "ix_transition_reconciliations_host_id", "transition_reconciliations", ["host_id"]
    )
    op.create_index(
        "ix_transition_reconciliations_status", "transition_reconciliations", ["status"]
    )
    op.create_index(
        "ix_transition_reconciliations_finalized", "transition_reconciliations", ["finalized"]
    )
    op.create_index(
        "ix_transition_reconciliations_supersedes_reconciliation_id",
        "transition_reconciliations",
        ["supersedes_reconciliation_id"],
    )
    op.create_index(
        "ix_transition_reconciliations_created_at", "transition_reconciliations", ["created_at"]
    )


def downgrade() -> None:
    op.drop_table("transition_reconciliations")
    op.drop_table("transition_monitor_health")
    op.drop_table("state_transition_records")
