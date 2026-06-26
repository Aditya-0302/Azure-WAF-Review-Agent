"""SQLAlchemy models for tenant-related tables (Alembic target only)."""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from waf_shared.db.models.base import Base, TimestampMixin

_plan_tier = sa.Enum(
    "standard", "premium", "enterprise",
    name="plan_tier",
    create_type=False,
)
_user_role = sa.Enum(
    "tenant_admin", "tenant_viewer", "platform_admin",
    name="user_role",
    create_type=False,
)


class TenantORM(Base, TimestampMixin):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=sa.text("gen_random_uuid()"),
    )
    slug: Mapped[str] = mapped_column(sa.Text, nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    azure_tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    plan_tier: Mapped[str] = mapped_column(_plan_tier, nullable=False, server_default="standard")
    is_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, server_default=sa.true())


class TenantUserORM(Base):
    __tablename__ = "tenant_users"
    __table_args__ = (
        sa.UniqueConstraint("tenant_id", "entra_oid"),
        sa.Index("idx_tenant_users_entra_oid", "entra_oid"),
        sa.Index("idx_tenant_users_tenant_id", "tenant_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=sa.text("gen_random_uuid()"),
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        sa.ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    entra_oid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    role: Mapped[str] = mapped_column(_user_role, nullable=False)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, server_default=sa.true())
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        nullable=False,
    )


class TenantQuotaORM(Base):
    __tablename__ = "tenant_quotas"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        sa.ForeignKey("tenants.id", ondelete="CASCADE"),
        primary_key=True,
    )
    max_concurrent_assessments: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default="3"
    )
    max_monthly_assessments: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default="20"
    )
    max_subscriptions_per_assessment: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default="10"
    )
    max_resources_per_assessment: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, server_default="5000"
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
        nullable=False,
    )
