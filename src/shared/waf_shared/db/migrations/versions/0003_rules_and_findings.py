"""WAF rules and assessment findings tables.

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-17

Zero-downtime impact: CREATE TABLE only; no existing traffic.
The condition_dsl column is JSONB (not TEXT python_expression) — no eval() needed.

asyncpg compatibility: every op.execute() contains exactly one SQL statement.
"""

from __future__ import annotations

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ── Enum types ────────────────────────────────────────────────────────────
    op.execute("""
        CREATE TYPE pillar AS ENUM (
            'reliability', 'security', 'cost_optimization',
            'operational_excellence', 'performance_efficiency'
        )
    """)
    op.execute(
        "CREATE TYPE evaluation_type AS ENUM ('deterministic', 'llm', 'hybrid', 'advisor_mapped')"
    )
    op.execute(
        "CREATE TYPE finding_status AS ENUM ('open', 'acknowledged', 'resolved', 'suppressed')"
    )
    op.execute(
        "CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'informational')"
    )

    # ── waf_rules ─────────────────────────────────────────────────────────────
    # RLS is intentionally NOT applied to waf_rules — rules are shared across
    # all tenants and are managed exclusively by platform administrators.
    op.execute("""
        CREATE TABLE waf_rules (
            id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            rule_id             TEXT NOT NULL UNIQUE,
            pillar              pillar NOT NULL,
            resource_types      TEXT[] NOT NULL,
            evaluation_type     evaluation_type NOT NULL,
            condition_dsl       JSONB,
            prompt_template_ref TEXT,
            severity            severity NOT NULL,
            title               TEXT NOT NULL,
            description         TEXT NOT NULL,
            recommendation      TEXT NOT NULL,
            is_active           BOOLEAN NOT NULL DEFAULT TRUE,
            version             INTEGER NOT NULL DEFAULT 1,
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT chk_dsl_or_prompt CHECK (
                condition_dsl IS NOT NULL OR prompt_template_ref IS NOT NULL
            )
        )
    """)
    # Partial index: only index active rules to keep the index small and fast.
    op.execute("CREATE INDEX idx_rules_pillar ON waf_rules(pillar) WHERE is_active")
    # Partial GIN index on the TEXT[] array column for containment queries.
    op.execute(
        "CREATE INDEX idx_rules_resource_types ON waf_rules USING GIN(resource_types) WHERE is_active"
    )

    # ── assessment_findings ───────────────────────────────────────────────────
    # rule_id references waf_rules(rule_id) — a non-PK unique column.
    # PostgreSQL allows FK references to any UNIQUE-constrained column.
    # tenant_id is denormalised for query performance (no FK constraint).
    op.execute("""
        CREATE TABLE assessment_findings (
            id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            assessment_id    UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            batch_id         UUID NOT NULL REFERENCES assessment_batches(id) ON DELETE CASCADE,
            tenant_id        UUID NOT NULL,
            rule_id          TEXT NOT NULL REFERENCES waf_rules(rule_id) ON DELETE RESTRICT,
            resource_id      TEXT NOT NULL,
            resource_type    TEXT NOT NULL,
            status           finding_status NOT NULL DEFAULT 'open',
            severity         severity NOT NULL,
            pillar           pillar NOT NULL,
            confidence_score NUMERIC(4,3) NOT NULL CHECK (confidence_score BETWEEN 0 AND 1),
            title            TEXT NOT NULL,
            recommendation   TEXT NOT NULL,
            evidence         JSONB NOT NULL DEFAULT '{}',
            evaluation_type  evaluation_type NOT NULL,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX idx_findings_assessment_id ON assessment_findings(assessment_id)")
    op.execute("CREATE INDEX idx_findings_tenant_pillar ON assessment_findings(tenant_id, pillar)")
    op.execute("CREATE INDEX idx_findings_severity ON assessment_findings(severity)")
    op.execute("CREATE INDEX idx_findings_resource_id ON assessment_findings(resource_id)")

    # ── Row-Level Security ────────────────────────────────────────────────────
    op.execute("ALTER TABLE assessment_findings ENABLE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY tenant_isolation_policy ON assessment_findings
            USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    """)


def downgrade() -> None:
    # Drop findings first: FK references waf_rules(rule_id) ON DELETE RESTRICT
    # would block waf_rules drop if findings still exist.
    op.execute("DROP TABLE IF EXISTS assessment_findings")
    op.execute("DROP TABLE IF EXISTS waf_rules")
    op.execute("DROP TYPE IF EXISTS severity")
    op.execute("DROP TYPE IF EXISTS finding_status")
    op.execute("DROP TYPE IF EXISTS evaluation_type")
    op.execute("DROP TYPE IF EXISTS pillar")
