"""SQLAlchemy model for subscription_credentials (Alembic target only)."""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from waf_shared.db.models.base import Base, TimestampMixin

_credential_health = sa.Enum(
    "healthy", "expiring_soon", "expired", "invalid", "unchecked",
    name="credential_health",
    create_type=False,
)


class SubscriptionCredentialORM(Base, TimestampMixin):
    __tablename__ = "subscription_credentials"
    __table_args__ = (
        sa.UniqueConstraint("tenant_id", "subscription_id"),
        sa.Index("idx_credentials_tenant_id", "tenant_id"),
        sa.Index(
            "idx_credentials_health",
            "health",
            postgresql_where=sa.text("health IN ('expiring_soon', 'expired')"),
        ),
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
    subscription_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    display_name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    keyvault_secret_name: Mapped[str] = mapped_column(sa.Text, nullable=False)
    health: Mapped[str] = mapped_column(
        _credential_health, nullable=False, server_default="unchecked"
    )
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    last_health_check_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
