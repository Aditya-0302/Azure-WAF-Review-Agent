"""SQLAlchemy model for waf_rules (Alembic target only)."""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from waf_shared.db.models.base import Base, TimestampMixin

_pillar = sa.Enum(
    "reliability", "security", "cost_optimization",
    "operational_excellence", "performance_efficiency",
    name="pillar",
    create_type=False,
)
_evaluation_type = sa.Enum(
    "deterministic", "llm", "hybrid",
    name="evaluation_type",
    create_type=False,
)
_severity = sa.Enum(
    "critical", "high", "medium", "low", "informational",
    name="severity",
    create_type=False,
)


class WafRuleORM(Base, TimestampMixin):
    __tablename__ = "waf_rules"
    __table_args__ = (
        sa.CheckConstraint(
            "condition_dsl IS NOT NULL OR prompt_template_ref IS NOT NULL",
            name="chk_dsl_or_prompt",
        ),
        sa.Index("idx_rules_pillar", "pillar", postgresql_where=sa.text("is_active")),
        sa.Index(
            "idx_rules_resource_types",
            "resource_types",
            postgresql_using="gin",
            postgresql_where=sa.text("is_active"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=sa.text("gen_random_uuid()"),
    )
    rule_id: Mapped[str] = mapped_column(sa.Text, nullable=False, unique=True)
    pillar: Mapped[str] = mapped_column(_pillar, nullable=False)
    resource_types: Mapped[list[str]] = mapped_column(ARRAY(sa.Text), nullable=False)
    evaluation_type: Mapped[str] = mapped_column(_evaluation_type, nullable=False)
    condition_dsl: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    prompt_template_ref: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    severity: Mapped[str] = mapped_column(_severity, nullable=False)
    title: Mapped[str] = mapped_column(sa.Text, nullable=False)
    description: Mapped[str] = mapped_column(sa.Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(sa.Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default=sa.true()
    )
    version: Mapped[int] = mapped_column(sa.Integer, nullable=False, server_default="1")
