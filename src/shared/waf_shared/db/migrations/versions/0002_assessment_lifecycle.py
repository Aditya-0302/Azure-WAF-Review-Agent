"""Assessment lifecycle tables — assessments, assessment_batches, assessment_resources.

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-17

Zero-downtime impact: CREATE TABLE only; no existing traffic on these tables.

asyncpg compatibility: every op.execute() contains exactly one SQL statement.
"""

from __future__ import annotations

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ── Enum types ────────────────────────────────────────────────────────────
    op.execute("""
        CREATE TYPE assessment_status AS ENUM (
            'pending', 'preparing', 'extracting', 'reasoning',
            'reporting', 'completed', 'partial_failure', 'cancelled', 'failed'
        )
    """)
    op.execute("""
        CREATE TYPE batch_status AS ENUM (
            'pending', 'in_progress', 'completed', 'failed', 'dead_lettered'
        )
    """)

    # ── assessments ───────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE assessments (
            id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id                 UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
            idempotency_key           TEXT NOT NULL,
            status                    assessment_status NOT NULL DEFAULT 'pending',
            subscription_ids          UUID[] NOT NULL,
            pillar_filter             TEXT[],
            tag_filter                JSONB,
            requested_by_oid          UUID NOT NULL,
            total_batches             INTEGER,
            completed_batches         INTEGER NOT NULL DEFAULT 0,
            cancellation_requested_at TIMESTAMPTZ,
            created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (tenant_id, idempotency_key)
        )
    """)
    op.execute("CREATE INDEX idx_assessments_tenant_id ON assessments(tenant_id)")
    op.execute("""
        CREATE INDEX idx_assessments_status ON assessments(status)
            WHERE status NOT IN ('completed', 'failed', 'cancelled')
    """)
    op.execute("CREATE INDEX idx_assessments_created_at ON assessments(tenant_id, created_at DESC)")

    # ── assessment_batches ────────────────────────────────────────────────────
    # tenant_id is denormalised here (not FK-constrained) for query performance;
    # referential integrity is enforced via assessment_id → assessments.
    op.execute("""
        CREATE TABLE assessment_batches (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            assessment_id   UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            tenant_id       UUID NOT NULL,
            batch_index     INTEGER NOT NULL,
            subscription_id UUID NOT NULL,
            status          batch_status NOT NULL DEFAULT 'pending',
            resource_ids    TEXT[] NOT NULL DEFAULT '{}',
            error_detail    TEXT,
            started_at      TIMESTAMPTZ,
            completed_at    TIMESTAMPTZ,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (assessment_id, batch_index)
        )
    """)
    op.execute("CREATE INDEX idx_batches_assessment_id ON assessment_batches(assessment_id)")
    op.execute("""
        CREATE INDEX idx_batches_tenant_status ON assessment_batches(tenant_id, status)
            WHERE status NOT IN ('completed', 'dead_lettered')
    """)

    # ── assessment_resources ──────────────────────────────────────────────────
    # tenant_id is denormalised for query performance (same reasoning as batches).
    op.execute("""
        CREATE TABLE assessment_resources (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            assessment_id   UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            batch_id        UUID NOT NULL REFERENCES assessment_batches(id) ON DELETE CASCADE,
            tenant_id       UUID NOT NULL,
            resource_id     TEXT NOT NULL,
            resource_type   TEXT NOT NULL,
            location        TEXT NOT NULL,
            subscription_id UUID NOT NULL,
            resource_group  TEXT NOT NULL,
            raw_properties  JSONB NOT NULL DEFAULT '{}',
            extracted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (assessment_id, resource_id)
        )
    """)
    op.execute("CREATE INDEX idx_resources_assessment_id ON assessment_resources(assessment_id)")
    op.execute("CREATE INDEX idx_resources_resource_type ON assessment_resources(resource_type)")

    # ── Row-Level Security ────────────────────────────────────────────────────
    op.execute("ALTER TABLE assessments ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE assessment_batches ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE assessment_resources ENABLE ROW LEVEL SECURITY")

    op.execute("""
        CREATE POLICY tenant_isolation_policy ON assessments
            USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    """)
    op.execute("""
        CREATE POLICY tenant_isolation_policy ON assessment_batches
            USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    """)
    op.execute("""
        CREATE POLICY tenant_isolation_policy ON assessment_resources
            USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    """)


def downgrade() -> None:
    # Drop in reverse FK dependency order.
    op.execute("DROP TABLE IF EXISTS assessment_resources")
    op.execute("DROP TABLE IF EXISTS assessment_batches")
    op.execute("DROP TABLE IF EXISTS assessments")
    op.execute("DROP TYPE IF EXISTS batch_status")
    op.execute("DROP TYPE IF EXISTS assessment_status")
