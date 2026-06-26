"""SQLAlchemy ORM model for human_review_assessments.

Used ONLY by Alembic for schema diffing (autogenerate).
All runtime database access uses asyncpg directly via HumanReviewRepository.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from waf_shared.db.models.base import Base, TimestampMixin


class HumanReviewAssessmentORM(Base, TimestampMixin):
    __tablename__ = "human_review_assessments"
    __table_args__ = (
        sa.UniqueConstraint(
            "tenant_id",
            "assessment_id",
            "control_code",
            name="uidx_human_review_assessment_control",
        ),
        sa.Index("idx_human_review_tenant_assessment", "tenant_id", "assessment_id"),
        sa.Index("idx_human_review_status", "status"),
        sa.Index("idx_human_review_control_code", "control_code"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True),
        primary_key=True,
        server_default=sa.text("gen_random_uuid()"),
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True),
        sa.ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True),
        sa.ForeignKey("assessments.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_code: Mapped[str] = mapped_column(sa.Text, nullable=False)
    pillar: Mapped[str] = mapped_column(sa.Text, nullable=False)
    reviewer_oid: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(
        sa.Enum(
            "pending",
            "in_progress",
            "completed",
            "not_assessed",
            name="review_status",
        ),
        nullable=False,
        server_default="pending",
    )
    compliance_status: Mapped[str] = mapped_column(
        sa.Enum(
            "compliant",
            "partially_compliant",
            "non_compliant",
            "not_assessed",
            name="compliance_status",
        ),
        nullable=False,
        server_default="not_assessed",
    )
    score: Mapped[int] = mapped_column(
        sa.SmallInteger,
        nullable=False,
        server_default="0",
    )
    answers: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        server_default=sa.text("'[]'::jsonb"),
    )
    evidence_refs: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        server_default=sa.text("'[]'::jsonb"),
    )
    comments: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=True,
    )
