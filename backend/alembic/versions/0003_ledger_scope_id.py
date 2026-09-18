"""Attach ledger entries to the scope that decided them

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-18

A target refused at creation time never becomes a scan, so its denial had no
scan to hang from and was invisible per-scan - yet PRD 10.4 expects a refused
public address to be visible as denied. Recording the scope profile that made
the decision gives every refusal a home, including the ones that stopped a
scan from existing at all.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scan_ledger") as batch:
        batch.add_column(sa.Column("scope_id", sa.String(length=36), nullable=True))
    op.create_index("ix_scan_ledger_scope_id", "scan_ledger", ["scope_id"])
    op.create_index("ix_ledger_decision", "scan_ledger", ["decision"])


def downgrade() -> None:
    op.drop_index("ix_ledger_decision", table_name="scan_ledger")
    op.drop_index("ix_scan_ledger_scope_id", table_name="scan_ledger")
    with op.batch_alter_table("scan_ledger") as batch:
        batch.drop_column("scope_id")
