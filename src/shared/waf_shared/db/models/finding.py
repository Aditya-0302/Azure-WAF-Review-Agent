"""SQLAlchemy model for assessment_findings (Alembic target only)."""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from waf_shared.db.models.base import Base

_finding_status = sa.Enum(
    "open",
    "acknowledged",
    "resolved",
    "suppressed",
    name="finding_status",
    create_type=False,
)
_severity = sa.Enum(
    "critical",
    "high",
    "medium",
    "low",
    "informational",
    name="severity",
    create_type=False,
)
_pillar = sa.Enum(
    "reliability",
    "security",
    "cost_optimization",
    "operational_excellence",
    "performance_efficiency",
    name="pillar",
    create_type=False,
)
_evaluation_type = sa.Enum(
    "deterministic",
    "llm",
    "hybrid",
    name="evaluation_type",
    create_type=False,
)


class AssessmentFindingORM(Base):
    __tablename__ = "assessment_findings"
    __table_args__ = (
        sa.Index("idx_findings_assessment_id", "assessment_id"),
        sa.Index("idx_findings_tenant_pillar", "tenant_id", "pillar"),
        sa.Index("idx_findings_severity", "severity"),
        sa.Index("idx_findings_resource_id", "resource_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=sa.text("gen_random_uuid()"),
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        sa.ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
    )
    batch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        sa.ForeignKey("assessment_batches.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    rule_id: Mapped[str] = mapped_column(
        sa.Text,
        sa.ForeignKey("waf_rules.rule_id", ondelete="RESTRICT"),
        nullable=False,
    )
    resource_id: Mapped[str] = mapped_column(sa.Text, nullable=False)
    resource_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(_finding_status, nullable=False, server_default="open")
    severity: Mapped[str] = mapped_column(_severity, nullable=False)
    pillar: Mapped[str] = mapped_column(_pillar, nullable=False)
    confidence_score: Mapped[float] = mapped_column(
        sa.Numeric(4, 3),
        sa.CheckConstraint("confidence_score BETWEEN 0 AND 1"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(sa.Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(sa.Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=sa.text("'{}'"))
    evaluation_type: Mapped[str] = mapped_column(_evaluation_type, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
    )
    waf_codes: Mapped[list] = mapped_column(
        JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")
    )
    waf_titles: Mapped[list] = mapped_column(
        JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")
    )
    microsoft_urls: Mapped[list] = mapped_column(
        JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")
    )
