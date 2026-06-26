"""Assessment reports and webhook delivery tables.

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-17

Zero-downtime impact:
  - CREATE TABLE only; no modifications to existing tables.
  - assessment_reports has RLS to ensure tenant isolation.
  - tenant_webhook_endpoints stores only the KV secret name, never the secret value.
  - webhook_deliveries is an append-only audit log (no updates).

asyncpg compatibility: every op.execute() contains exactly one SQL statement.

Design notes:
  - tenant_webhook_endpoints.tenant_id has no FK to tenants to allow the
    webhook config to survive tenant soft-deletion.
  - webhook_deliveries has no FK constraints on tenant_id or assessment_id
    to preserve the audit trail even after cascade deletes upstream.
"""

from __future__ import annotations

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ── assessment_reports ────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE assessment_reports (
            id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            assessment_id  UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            tenant_id      UUID NOT NULL,
            xlsx_blob_path TEXT NOT NULL,
            pdf_blob_path  TEXT NOT NULL,
            summary        JSONB NOT NULL,
            generated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute(
        "CREATE INDEX idx_assessment_reports_assessment_id ON assessment_reports(assessment_id)"
    )
    op.execute("CREATE INDEX idx_assessment_reports_tenant_id ON assessment_reports(tenant_id)")
    op.execute("ALTER TABLE assessment_reports ENABLE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY tenant_isolation_policy ON assessment_reports
            USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    """)

    # ── tenant_webhook_endpoints ──────────────────────────────────────────────
    # One row per tenant.  HMAC secret is in Key Vault; only the KV secret name
    # lives in this table.
    op.execute("""
        CREATE TABLE tenant_webhook_endpoints (
            id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id      UUID NOT NULL UNIQUE,
            webhook_url    TEXT NOT NULL,
            secret_kv_name TEXT NOT NULL,
            is_active      BOOLEAN NOT NULL DEFAULT TRUE,
            created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    # ── webhook_deliveries ────────────────────────────────────────────────────
    # Append-only audit log: one row per delivery attempt.
    op.execute("""
        CREATE TABLE webhook_deliveries (
            id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id     UUID NOT NULL,
            assessment_id UUID NOT NULL,
            webhook_url   TEXT NOT NULL,
            attempt       INTEGER NOT NULL,
            status_code   INTEGER,
            success       BOOLEAN NOT NULL,
            error_detail  TEXT,
            delivered_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("""
        CREATE INDEX idx_webhook_deliveries_assessment
            ON webhook_deliveries(tenant_id, assessment_id)
    """)


def downgrade() -> None:
    # Drop in reverse dependency order.  assessment_reports has a FK to
    # assessments (ON DELETE CASCADE), but we drop it explicitly here so the
    # downgrade is self-contained and does not rely on cascade behaviour.
    op.execute("DROP TABLE IF EXISTS webhook_deliveries")
    op.execute("DROP TABLE IF EXISTS tenant_webhook_endpoints")
    op.execute("DROP TABLE IF EXISTS assessment_reports")
