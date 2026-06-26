"""WebhookRepository — tenant webhook endpoints and delivery audit log."""

from __future__ import annotations

import uuid
from datetime import datetime

import asyncpg

from waf_shared.db.pool import DatabasePool
from waf_shared.db.repository import BaseRepository
from waf_shared.domain.models.webhook import TenantWebhookEndpoint, WebhookDelivery

_ENDPOINT_COLS = (
    "id, tenant_id, webhook_url, secret_kv_name, is_active, created_at, updated_at"
)
_DELIVERY_COLS = (
    "id, tenant_id, assessment_id, webhook_url, attempt, "
    "status_code, success, error_detail, delivered_at"
)


def _row_to_endpoint(row: asyncpg.Record) -> TenantWebhookEndpoint:  # type: ignore[type-arg]
    return TenantWebhookEndpoint(
        id=row["id"],
        tenant_id=row["tenant_id"],
        webhook_url=row["webhook_url"],
        secret_kv_name=row["secret_kv_name"],
        is_active=row["is_active"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_delivery(row: asyncpg.Record) -> WebhookDelivery:  # type: ignore[type-arg]
    return WebhookDelivery(
        id=row["id"],
        tenant_id=row["tenant_id"],
        assessment_id=row["assessment_id"],
        webhook_url=row["webhook_url"],
        attempt=row["attempt"],
        status_code=row["status_code"],
        success=row["success"],
        error_detail=row["error_detail"],
        delivered_at=row["delivered_at"],
    )


class WebhookRepository(BaseRepository):
    def __init__(
        self,
        pool: DatabasePool | None = None,
        *,
        conn: asyncpg.Connection | None = None,  # type: ignore[type-arg]
        uow_tenant_id: uuid.UUID | None = None,
    ) -> None:
        super().__init__(pool=pool, conn=conn, uow_tenant_id=uow_tenant_id)

    # ── Webhook endpoints ─────────────────────────────────────────────────────

    async def get_endpoint_by_tenant(
        self,
        tenant_id: uuid.UUID,
    ) -> TenantWebhookEndpoint | None:
        row = await self._fetch_system_one(
            f"SELECT {_ENDPOINT_COLS} FROM tenant_webhook_endpoints "
            "WHERE tenant_id = $1 AND is_active = TRUE",
            tenant_id,
        )
        return _row_to_endpoint(row) if row else None

    async def upsert_endpoint(
        self,
        endpoint: TenantWebhookEndpoint,
    ) -> TenantWebhookEndpoint:
        row = await self._write_system_one(
            f"""
            INSERT INTO tenant_webhook_endpoints (
                id, tenant_id, webhook_url, secret_kv_name, is_active
            ) VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id) DO UPDATE
                SET webhook_url     = EXCLUDED.webhook_url,
                    secret_kv_name  = EXCLUDED.secret_kv_name,
                    is_active       = EXCLUDED.is_active,
                    updated_at      = NOW()
            RETURNING {_ENDPOINT_COLS}
            """,
            endpoint.id,
            endpoint.tenant_id,
            endpoint.webhook_url,
            endpoint.secret_kv_name,
            endpoint.is_active,
        )
        return _row_to_endpoint(row)  # type: ignore[arg-type]

    async def deactivate_endpoint(self, tenant_id: uuid.UUID) -> None:
        await self._execute_system(
            "UPDATE tenant_webhook_endpoints "
            "SET is_active = FALSE, updated_at = NOW() "
            "WHERE tenant_id = $1",
            tenant_id,
        )

    # ── Delivery log ──────────────────────────────────────────────────────────

    async def record_delivery(self, delivery: WebhookDelivery) -> WebhookDelivery:
        row = await self._write_system_one(
            f"""
            INSERT INTO webhook_deliveries (
                id, tenant_id, assessment_id, webhook_url,
                attempt, status_code, success, error_detail, delivered_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING {_DELIVERY_COLS}
            """,
            delivery.id,
            delivery.tenant_id,
            delivery.assessment_id,
            delivery.webhook_url,
            delivery.attempt,
            delivery.status_code,
            delivery.success,
            delivery.error_detail,
            delivery.delivered_at,
        )
        return _row_to_delivery(row)  # type: ignore[arg-type]

    async def list_deliveries(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> list[WebhookDelivery]:
        rows = await self._fetch_system(
            f"SELECT {_DELIVERY_COLS} FROM webhook_deliveries "
            "WHERE tenant_id = $1 AND assessment_id = $2 "
            "ORDER BY attempt ASC",
            tenant_id,
            assessment_id,
        )
        return [_row_to_delivery(r) for r in rows]
