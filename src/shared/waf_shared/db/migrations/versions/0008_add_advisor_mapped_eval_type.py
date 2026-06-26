"""Add advisor_mapped to evaluation_type enum.

Revision ID: 0008
Revises: 0007
Create Date: 2026-06-26

evaluation_type was created in 0003 with only ('deterministic', 'llm', 'hybrid').
The advisor_mapped value was added to the migration source but any database
initialised from an earlier image never received it.  This migration adds it
idempotently so that existing deployments are repaired without needing a
volume wipe.

ALTER TYPE … ADD VALUE is non-transactional in PostgreSQL and cannot run
inside a transaction block.  Alembic's connection.execute() runs in
autocommit mode for DDL, so no special handling is required beyond using
execute_if to short-circuit on databases that don't need the change.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# ---------------------------------------------------------------------------
# Alembic revision identifiers
# ---------------------------------------------------------------------------
revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ADD VALUE IF NOT EXISTS is idempotent — safe to run against databases
    # that already have the value (e.g. a fresh clone from the patched 0003).
    op.execute(
        sa.text("ALTER TYPE evaluation_type ADD VALUE IF NOT EXISTS 'advisor_mapped'")
    )


def downgrade() -> None:
    # PostgreSQL does not support removing individual enum values.
    # A downgrade would require recreating the type, which risks data loss.
    # Leave this as a no-op; manual intervention is required if needed.
    pass
