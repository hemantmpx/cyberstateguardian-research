"""add idempotency key for newly created delta findings

Revision ID: 0004_unique_finding_per_delta
Revises: 0003_reconciliation_lifecycle
Create Date: 2026-10-01 00:00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_unique_finding_per_delta"
down_revision: str | None = "0003_reconciliation_lifecycle"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("delta_idempotency_key", sa.String(length=36), nullable=True),
    )
    op.create_index(
        "uq_findings_delta_idempotency_key",
        "findings",
        ["delta_idempotency_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_findings_delta_idempotency_key", table_name="findings")
    op.drop_column("findings", "delta_idempotency_key")
