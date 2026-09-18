"""Add per-scan module options

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-18

Module options (port selection, discovery ports) are stored as one JSON column
rather than a column per option, so adding a module option in a later
checkpoint does not require a schema change.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.add_column(
            sa.Column(
                "module_options_json",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("module_options_json")
