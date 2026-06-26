"""Add human review framework tables.

Revision ID: 0007
Revises: 0006
Create Date: 2026-06-22

Implements the Human Review Framework for the four WAF controls that cannot be
objectively assessed via Azure APIs:
  SE-10 — Adversarial testing
  OE-03 — Software planning management
  OE-04 — Continuous integration
  CO-09 — Personnel time optimisation

New PostgreSQL enums:
  review_status    — pending | in_progress | completed | not_assessed
  compliance_status — compliant | partially_compliant | non_compliant | not_assessed

New table:
  human_review_assessments — one row per (tenant, assessment, control_code)

All JSONB columns (answers, evidence_refs) default to empty arrays so that
existing assessment rows are unaffected by this migration.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from sqlalchemy.dialects.postgresql import JSONB

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

# Defined once at module level; create_type=False ensures op.create_table()
# never emits CREATE TYPE — enum creation is handled explicitly below.
review_status_enum = PgEnum(
    "pending",
    "in_progress",
    "completed",
    "not_assessed",
    name="review_status",
    create_type=False,
)

compliance_status_enum = PgEnum(
    "compliant",
    "partially_compliant",
    "non_compliant",
    "not_assessed",
    name="compliance_status",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    review_status_enum.create(bind, checkfirst=True)
    compliance_status_enum.create(bind, checkfirst=True)

    op.create_table(
        "human_review_assessments",
        sa.Column(
            "id",
            sa.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "tenant_id",
            sa.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "assessment_id",
            sa.UUID(as_uuid=True),
            sa.ForeignKey("assessments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("control_code", sa.Text, nullable=False),
        sa.Column("pillar", sa.Text, nullable=False),
        sa.Column("reviewer_oid", sa.Text, nullable=False),
        sa.Column(
            "status",
            review_status_enum,
            nullable=False,
            server_default="pending",
        ),
        sa.Column(
            "compliance_status",
            compliance_status_enum,
            nullable=False,
            server_default="not_assessed",
        ),
        sa.Column(
            "score",
            sa.SmallInteger,
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "answers",
            JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "evidence_refs",
            JSONB,
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("comments", sa.Text, nullable=True),
        sa.Column(
            "reviewed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    op.create_unique_constraint(
        "uidx_human_review_assessment_control",
        "human_review_assessments",
        ["tenant_id", "assessment_id", "control_code"],
    )

    op.create_index(
        "idx_human_review_tenant_assessment",
        "human_review_assessments",
        ["tenant_id", "assessment_id"],
    )

    op.create_index(
        "idx_human_review_status",
        "human_review_assessments",
        ["status"],
        postgresql_where=sa.text("status != 'completed'"),
    )

    op.create_index(
        "idx_human_review_control_code",
        "human_review_assessments",
        ["control_code"],
    )

    op.create_index(
        "idx_human_review_answers",
        "human_review_assessments",
        [sa.text("answers jsonb_path_ops")],
        postgresql_using="gin",
    )

    op.create_index(
        "idx_human_review_evidence_refs",
        "human_review_assessments",
        [sa.text("evidence_refs jsonb_path_ops")],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index("idx_human_review_evidence_refs", table_name="human_review_assessments")
    op.drop_index("idx_human_review_answers", table_name="human_review_assessments")
    op.drop_index("idx_human_review_control_code", table_name="human_review_assessments")
    op.drop_index("idx_human_review_status", table_name="human_review_assessments")
    op.drop_index("idx_human_review_tenant_assessment", table_name="human_review_assessments")
    op.drop_constraint(
        "uidx_human_review_assessment_control",
        "human_review_assessments",
        type_="unique",
    )
    op.drop_table("human_review_assessments")
    bind = op.get_bind()
    compliance_status_enum.drop(bind, checkfirst=True)
    review_status_enum.drop(bind, checkfirst=True)
