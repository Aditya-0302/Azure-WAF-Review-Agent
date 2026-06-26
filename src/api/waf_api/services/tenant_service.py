"""TenantService — read-access to tenant data for request-scoped operations."""

from __future__ import annotations

import uuid

from waf_shared.db.pool import DatabasePool
from waf_shared.db.repositories.tenant_repository import TenantRepository
from waf_shared.domain.errors.domain_errors import TenantNotFoundError
from waf_shared.domain.models.tenant import Tenant, TenantUser
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-api", version="0.1.0")


class TenantService:
    def __init__(self, pool: DatabasePool) -> None:
        self._repo = TenantRepository(pool=pool)

    async def get_by_id(self, tenant_id: uuid.UUID) -> Tenant:
        tenant = await self._repo.get_by_id(tenant_id)
        if tenant is None:
            raise TenantNotFoundError(tenant_id)
        return tenant

    async def get_by_azure_tenant_id(self, azure_tenant_id: uuid.UUID) -> Tenant:
        tenant = await self._repo.get_by_azure_tenant_id(azure_tenant_id)
        if tenant is None:
            raise TenantNotFoundError(azure_tenant_id)
        return tenant

    async def get_user_by_oid(
        self,
        tenant_id: uuid.UUID,
        entra_oid: uuid.UUID,
    ) -> TenantUser | None:
        return await self._repo.get_user_by_oid(tenant_id, entra_oid)
