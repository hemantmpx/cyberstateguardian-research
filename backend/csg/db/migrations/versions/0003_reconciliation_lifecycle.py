"""versioned reconciliation lifecycle

Revision ID: 0003_reconciliation_lifecycle
Revises: 0002_incidents_ai
Create Date: 2026-09-20 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_reconciliation_lifecycle"
down_revision: str | None = "0002_incidents_ai"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("reconciliation_results") as batch_op:
        batch_op.add_column(sa.Column("delta_id", sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column("finding_id", sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column("version", sa.Integer(), nullable=False, server_default="1"))
        batch_op.add_column(
            sa.Column("finalized", sa.Boolean(), nullable=False, server_default=sa.true())
        )
        batch_op.add_column(sa.Column("finalized_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(
            sa.Column("supersedes_reconciliation_id", sa.String(length=36), nullable=True)
        )
        batch_op.create_index("ix_reconciliation_results_delta_id", ["delta_id"])
        batch_op.create_index("ix_reconciliation_results_finding_id", ["finding_id"])
        batch_op.create_index("ix_reconciliation_results_finalized", ["finalized"])
        batch_op.create_index(
            "ix_reconciliation_results_supersedes_reconciliation_id",
            ["supersedes_reconciliation_id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("reconciliation_results") as batch_op:
        batch_op.drop_index("ix_reconciliation_results_supersedes_reconciliation_id")
        batch_op.drop_index("ix_reconciliation_results_finalized")
        batch_op.drop_index("ix_reconciliation_results_finding_id")
        batch_op.drop_index("ix_reconciliation_results_delta_id")
        batch_op.drop_column("supersedes_reconciliation_id")
        batch_op.drop_column("finalized_at")
        batch_op.drop_column("finalized")
        batch_op.drop_column("version")
        batch_op.drop_column("finding_id")
        batch_op.drop_column("delta_id")
