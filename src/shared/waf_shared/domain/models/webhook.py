"""Webhook domain models."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TenantWebhookEndpoint(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    webhook_url: str
    secret_kv_name: str
    is_active: bool
    created_at: datetime
    updated_at: datetime


class WebhookDelivery(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    assessment_id: uuid.UUID
    webhook_url: str
    attempt: int
    status_code: int | None
    success: bool
    error_detail: str | None
    delivered_at: datetime
