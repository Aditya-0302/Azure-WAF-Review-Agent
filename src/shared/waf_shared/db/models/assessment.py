"""SQLAlchemy models for assessment lifecycle tables (Alembic target only)."""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from waf_shared.db.models.base import Base, TimestampMixin

_assessment_status = sa.Enum(
    "pending", "preparing", "extracting", "reasoning",
    "reporting", "completed", "partial_failure", "cancelled", "failed",
    name="assessment_status",
    create_type=False,
)
_batch_status = sa.Enum(
    "pending", "in_progress", "completed", "failed", "dead_lettered",
    name="batch_status",
    create_type=False,
)


class AssessmentORM(Base, TimestampMixin):
    __tablename__ = "assessments"
    __table_args__ = (
        sa.UniqueConstraint("tenant_id", "idempotency_key"),
        sa.Index("idx_assessments_tenant_id", "tenant_id"),
        sa.Index(
            "idx_assessments_status",
            "status",
            postgresql_where=sa.text("status NOT IN ('completed', 'failed', 'cancelled')"),
        ),
        sa.Index("idx_assessments_created_at", "tenant_id", sa.desc(sa.text("created_at"))),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=sa.text("gen_random_uuid()"),
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
    )
    idempotency_key: Mapped[str] = mapped_column(sa.Text, nullable=False)
    status: Mapped[str] = mapped_column(
        _assessment_status, nullable=False, server_default="pending"
    )
    subscription_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False
    )
    pillar_filter: Mapped[list[str] | None] = mapped_column(ARRAY(sa.Text), nullable=True)
    tag_filter: Mapped[dict | None] = mapped_column(sa.JSON, nullable=True)
    requested_by_oid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    total_batches: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    completed_batches: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default="0"
    )
    cancellation_requested_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )


class AssessmentBatchORM(Base):
    __tablename__ = "assessment_batches"
    __table_args__ = (
        sa.UniqueConstraint("assessment_id", "batch_index"),
        sa.Index("idx_batches_assessment_id", "assessment_id"),
        sa.Index(
            "idx_batches_tenant_status",
            "tenant_id", "status",
            postgresql_where=sa.text("status NOT IN ('completed', 'dead_lettered')"),
        ),
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
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    batch_index: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    subscription_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(_batch_status, nullable=False, server_default="pending")
    resource_ids: Mapped[list[str]] = mapped_column(
        ARRAY(sa.Text), nullable=False, server_default=sa.text("'{}'")
    )
    error_detail: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
    )


class AssessmentResourceORM(Base):
    __tablename__ = "assessment_resources"
    __table_args__ = (
        sa.UniqueConstraint("assessment_id", "resource_id"),
        sa.Index("idx_resources_assessment_id", "assessment_id"),
        sa.Index("idx_resources_resource_type", "resource_type"),
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
    resource_id: Mapped[str] = mapped_column(sa.Text, nullable=False)
    resource_type: Mapped[str] = mapped_column(sa.Text, nullable=False)
    location: Mapped[str] = mapped_column(sa.Text, nullable=False)
    subscription_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    resource_group: Mapped[str] = mapped_column(sa.Text, nullable=False)
    raw_properties: Mapped[dict] = mapped_column(
        sa.JSON, nullable=False, server_default=sa.text("'{}'")
    )
    extracted_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
    )
