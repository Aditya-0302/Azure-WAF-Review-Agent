"""Tenant domain models."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator


class PlanTier(StrEnum):
    STANDARD = "standard"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"


class UserRole(StrEnum):
    TENANT_ADMIN = "tenant_admin"
    TENANT_VIEWER = "tenant_viewer"
    PLATFORM_ADMIN = "platform_admin"


class Tenant(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    slug: str
    display_name: str
    azure_tenant_id: uuid.UUID
    plan_tier: PlanTier
    is_active: bool
    created_at: datetime
    updated_at: datetime

    @field_validator("slug")
    @classmethod
    def slug_must_be_lowercase_alphanumeric(cls, v: str) -> str:
        if not v.replace("-", "").isalnum() or v != v.lower():
            raise ValueError("slug must be lowercase alphanumeric with hyphens only")
        return v


class TenantUser(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    entra_oid: uuid.UUID
    role: UserRole
    is_active: bool
    created_at: datetime


class TenantQuota(BaseModel):
    model_config = ConfigDict(frozen=True)

    tenant_id: uuid.UUID
    max_concurrent_assessments: int
    max_monthly_assessments: int
    max_subscriptions_per_assessment: int
    max_resources_per_assessment: int
    updated_at: datetime

    @field_validator(
        "max_concurrent_assessments",
        "max_monthly_assessments",
        "max_subscriptions_per_assessment",
        "max_resources_per_assessment",
    )
    @classmethod
    def must_be_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("quota limits must be positive integers")
        return v
