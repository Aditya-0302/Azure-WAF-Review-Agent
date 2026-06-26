"""Core schema — tenants, tenant_users, tenant_quotas, subscription_credentials.

Revision ID: 0001
Revises:
Create Date: 2026-06-17

Zero-downtime impact: CREATE TABLE statements with no existing traffic; safe.

asyncpg compatibility: every op.execute() contains exactly one SQL statement.
asyncpg uses the PostgreSQL extended query protocol, which rejects multi-statement
strings.  Each DDL operation is therefore issued as a separate call.
"""

from __future__ import annotations

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ── Extensions ────────────────────────────────────────────────────────────
    # gen_random_uuid() is built-in from PostgreSQL 13+; pgcrypto is retained
    # for any application-level crypto helpers.  Both are on Azure Database for
    # PostgreSQL Flexible Server's allowed-extensions list.
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')

    # ── Enum types ────────────────────────────────────────────────────────────
    op.execute(
        "CREATE TYPE plan_tier AS ENUM ('standard', 'premium', 'enterprise')"
    )
    op.execute(
        "CREATE TYPE user_role AS ENUM ('tenant_admin', 'tenant_viewer', 'platform_admin')"
    )
    op.execute("""
        CREATE TYPE credential_health AS ENUM (
            'healthy', 'expiring_soon', 'expired', 'invalid', 'unchecked'
        )
    """)

    # ── tenants ───────────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE tenants (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            slug            TEXT NOT NULL UNIQUE,
            display_name    TEXT NOT NULL,
            azure_tenant_id UUID NOT NULL,
            plan_tier       plan_tier NOT NULL DEFAULT 'standard',
            is_active       BOOLEAN NOT NULL DEFAULT TRUE,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    # ── tenant_users ──────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE tenant_users (
            id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            entra_oid   UUID NOT NULL,
            role        user_role NOT NULL,
            is_active   BOOLEAN NOT NULL DEFAULT TRUE,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (tenant_id, entra_oid)
        )
    """)
    op.execute("CREATE INDEX idx_tenant_users_entra_oid ON tenant_users(entra_oid)")
    op.execute("CREATE INDEX idx_tenant_users_tenant_id ON tenant_users(tenant_id)")

    # ── tenant_quotas ─────────────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE tenant_quotas (
            tenant_id                        UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
            max_concurrent_assessments       INTEGER NOT NULL DEFAULT 3,
            max_monthly_assessments          INTEGER NOT NULL DEFAULT 20,
            max_subscriptions_per_assessment INTEGER NOT NULL DEFAULT 10,
            max_resources_per_assessment     INTEGER NOT NULL DEFAULT 5000,
            updated_at                       TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    # ── subscription_credentials ──────────────────────────────────────────────
    op.execute("""
        CREATE TABLE subscription_credentials (
            id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id            UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            subscription_id      UUID NOT NULL,
            display_name         TEXT NOT NULL,
            keyvault_secret_name TEXT NOT NULL,
            health               credential_health NOT NULL DEFAULT 'unchecked',
            expires_at           TIMESTAMPTZ,
            last_health_check_at TIMESTAMPTZ,
            created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (tenant_id, subscription_id)
        )
    """)
    op.execute(
        "CREATE INDEX idx_credentials_tenant_id ON subscription_credentials(tenant_id)"
    )
    op.execute("""
        CREATE INDEX idx_credentials_health ON subscription_credentials(health)
            WHERE health IN ('expiring_soon', 'expired')
    """)

    # ── Row-Level Security ────────────────────────────────────────────────────
    # Defense-in-depth: primary tenant isolation is enforced by application-layer
    # WHERE tenant_id = $N clauses.  RLS is a secondary guard.
    op.execute("ALTER TABLE tenant_users ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tenant_quotas ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE subscription_credentials ENABLE ROW LEVEL SECURITY")

    op.execute("""
        CREATE POLICY tenant_isolation_policy ON tenant_users
            USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    """)
    op.execute("""
        CREATE POLICY tenant_isolation_policy ON tenant_quotas
            USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    """)
    op.execute("""
        CREATE POLICY tenant_isolation_policy ON subscription_credentials
            USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    """)


def downgrade() -> None:
    # Drop in reverse FK dependency order.  Policies and indexes are dropped
    # automatically by PostgreSQL when their tables are dropped.
    op.execute("DROP TABLE IF EXISTS subscription_credentials")
    op.execute("DROP TABLE IF EXISTS tenant_quotas")
    op.execute("DROP TABLE IF EXISTS tenant_users")
    op.execute("DROP TABLE IF EXISTS tenants")
    op.execute("DROP TYPE IF EXISTS credential_health")
    op.execute("DROP TYPE IF EXISTS user_role")
    op.execute("DROP TYPE IF EXISTS plan_tier")
