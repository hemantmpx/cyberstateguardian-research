"""persist direct-probe snapshot ingestion order

Revision ID: 0006_probe_ingestion_order
Revises: 0005_state_transitions
Create Date: 2026-10-12 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_probe_ingestion_order"
down_revision: str | None = "0005_state_transitions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "state_snapshots",
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_state_snapshots_host_source_ingested",
        "state_snapshots",
        ["host_id", "source", "ingested_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_state_snapshots_host_source_ingested", table_name="state_snapshots")
    op.drop_column("state_snapshots", "ingested_at")
