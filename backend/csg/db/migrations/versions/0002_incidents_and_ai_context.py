"""persist incidents and AI context lineage

Revision ID: 0002_incidents_ai
Revises: 0001_initial_schema
Create Date: 2026-09-17 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_incidents_ai"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(length=36), primary_key=True),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("context_version", sa.Integer(), nullable=False),
        sa.Column("categories", sa.JSON(), nullable=False),
        sa.Column("object_keys", sa.JSON(), nullable=False),
        sa.Column("entity_keys", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
    )
    op.create_index("ix_incidents_host_id", "incidents", ["host_id"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_started_at", "incidents", ["started_at"])
    op.create_index("ix_incidents_last_activity_at", "incidents", ["last_activity_at"])
    op.create_index("ix_incidents_created_at", "incidents", ["created_at"])
    op.create_index("ix_incidents_updated_at", "incidents", ["updated_at"])
    op.create_index(
        "ix_incidents_host_activity",
        "incidents",
        ["host_id", "last_activity_at"],
    )

    op.create_table(
        "incident_findings",
        sa.Column(
            "incident_id",
            sa.String(length=36),
            sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "finding_id",
            sa.String(length=36),
            sa.ForeignKey("findings.finding_id", ondelete="CASCADE"),
            primary_key=True,
            unique=True,
        ),
        sa.Column("assignment_score", sa.Integer(), nullable=False),
        sa.Column("assignment_reasons", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incident_findings_finding_id", "incident_findings", ["finding_id"])
    op.create_index("ix_incident_findings_created_at", "incident_findings", ["created_at"])

    with op.batch_alter_table("ai_analyses") as batch_op:
        batch_op.add_column(sa.Column("incident_id", sa.String(length=36), nullable=True))
        batch_op.add_column(
            sa.Column("context_version", sa.Integer(), nullable=False, server_default="1")
        )
        batch_op.add_column(
            sa.Column(
                "context_mode",
                sa.String(length=32),
                nullable=False,
                server_default="full_context",
            )
        )
        batch_op.add_column(sa.Column("evidence_package_hash", sa.String(length=64)))
        batch_op.add_column(sa.Column("parent_analysis_id", sa.String(length=36)))
        batch_op.add_column(
            sa.Column("metadata_json", sa.JSON(), nullable=False, server_default="{}")
        )
        batch_op.create_foreign_key(
            "fk_ai_analyses_incident_id_incidents",
            "incidents",
            ["incident_id"],
            ["incident_id"],
        )
        batch_op.create_index("ix_ai_analyses_incident_id", ["incident_id"])
        batch_op.create_index("ix_ai_analyses_evidence_package_hash", ["evidence_package_hash"])
        batch_op.create_index("ix_ai_analyses_parent_analysis_id", ["parent_analysis_id"])


def downgrade() -> None:
    with op.batch_alter_table("ai_analyses") as batch_op:
        batch_op.drop_index("ix_ai_analyses_parent_analysis_id")
        batch_op.drop_index("ix_ai_analyses_evidence_package_hash")
        batch_op.drop_index("ix_ai_analyses_incident_id")
        batch_op.drop_constraint("fk_ai_analyses_incident_id_incidents", type_="foreignkey")
        batch_op.drop_column("metadata_json")
        batch_op.drop_column("parent_analysis_id")
        batch_op.drop_column("evidence_package_hash")
        batch_op.drop_column("context_mode")
        batch_op.drop_column("context_version")
        batch_op.drop_column("incident_id")

    op.drop_table("incident_findings")
    op.drop_index("ix_incidents_host_activity", table_name="incidents")
    op.drop_table("incidents")
