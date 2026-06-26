"""Subscription credential domain models."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class CredentialHealth(StrEnum):
    HEALTHY = "healthy"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    INVALID = "invalid"
    UNCHECKED = "unchecked"


class SubscriptionCredential(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    subscription_id: uuid.UUID
    display_name: str
    keyvault_secret_name: str
    health: CredentialHealth
    expires_at: datetime | None
    last_health_check_at: datetime | None
    created_at: datetime
    updated_at: datetime
