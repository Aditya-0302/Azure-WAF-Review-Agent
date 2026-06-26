"""Add WAF catalog enrichment columns to assessment_findings.

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-22

Adds three JSONB columns to assessment_findings that persist the WAF control
enrichment produced by the Reasoning Agent at finding creation time:
  - waf_codes:     ["SE-07", "SE-12"]
  - waf_titles:    ["Protect application secrets", "Define and test BCDR procedures"]
  - microsoft_urls: ["https://learn.microsoft.com/..."]

All columns default to an empty JSONB array so existing rows remain valid
without a backfill migration.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assessment_findings",
        sa.Column(
            "waf_codes",
            JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )

    op.add_column(
        "assessment_findings",
        sa.Column(
            "waf_titles",
            JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )

    op.add_column(
        "assessment_findings",
        sa.Column(
            "microsoft_urls",
            JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )

    op.create_index(
        "idx_findings_waf_codes",
        "assessment_findings",
        [sa.text("waf_codes jsonb_path_ops")],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index("idx_findings_waf_codes", table_name="assessment_findings")

    op.drop_column("assessment_findings", "microsoft_urls")

    op.drop_column("assessment_findings", "waf_titles")

    op.drop_column("assessment_findings", "waf_codes")
