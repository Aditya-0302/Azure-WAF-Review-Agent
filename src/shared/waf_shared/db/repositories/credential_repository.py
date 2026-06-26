"""CredentialRepository — subscription credential CRUD.

subscription_credentials has RLS; all tenant-scoped queries use _read / _write
which set SET LOCAL app.current_tenant_id.

list_expiring is system-scoped (platform health-check sweep) and therefore uses
_fetch_system without a tenant filter.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import asyncpg

from waf_shared.db.pool import DatabasePool
from waf_shared.db.repository import BaseRepository
from waf_shared.domain.errors.domain_errors import CredentialNotFoundError
from waf_shared.domain.models.credential import CredentialHealth, SubscriptionCredential
from waf_shared.domain.repositories.i_credential_repository import ICredentialRepository

_COLS = (
    "id, tenant_id, subscription_id, display_name, keyvault_secret_name, "
    "health, expires_at, last_health_check_at, created_at, updated_at"
)


def _row_to_credential(row: asyncpg.Record) -> SubscriptionCredential:  # type: ignore[type-arg]
    return SubscriptionCredential(
        id=row["id"],
        tenant_id=row["tenant_id"],
        subscription_id=row["subscription_id"],
        display_name=row["display_name"],
        keyvault_secret_name=row["keyvault_secret_name"],
        health=CredentialHealth(row["health"]),
        expires_at=row["expires_at"],
        last_health_check_at=row["last_health_check_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class CredentialRepository(BaseRepository, ICredentialRepository):
    def __init__(
        self,
        pool: DatabasePool | None = None,
        *,
        conn: asyncpg.Connection | None = None,  # type: ignore[type-arg]
        uow_tenant_id: uuid.UUID | None = None,
    ) -> None:
        super().__init__(pool=pool, conn=conn, uow_tenant_id=uow_tenant_id)

    # ── Reads ─────────────────────────────────────────────────────────────────

    async def get_by_id(
        self,
        tenant_id: uuid.UUID,
        credential_id: uuid.UUID,
    ) -> SubscriptionCredential | None:
        row = await self._read_one(
            f"SELECT {_COLS} FROM subscription_credentials "
            f"WHERE tenant_id = $1 AND id = $2",
            tenant_id,
            tenant_id, credential_id,
        )
        return _row_to_credential(row) if row else None

    async def get_by_subscription(
        self,
        tenant_id: uuid.UUID,
        subscription_id: uuid.UUID,
    ) -> SubscriptionCredential | None:
        row = await self._read_one(
            f"SELECT {_COLS} FROM subscription_credentials "
            f"WHERE tenant_id = $1 AND subscription_id = $2",
            tenant_id,
            tenant_id, subscription_id,
        )
        return _row_to_credential(row) if row else None

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
    ) -> list[SubscriptionCredential]:
        if cursor is None:
            rows = await self._read(
                f"SELECT {_COLS} FROM subscription_credentials "
                f"WHERE tenant_id = $1 ORDER BY id LIMIT $2",
                tenant_id,
                tenant_id, limit,
            )
        else:
            rows = await self._read(
                f"SELECT {_COLS} FROM subscription_credentials "
                f"WHERE tenant_id = $1 AND id > $2 ORDER BY id LIMIT $3",
                tenant_id,
                tenant_id, cursor, limit,
            )
        return [_row_to_credential(r) for r in rows]

    async def list_expiring(
        self,
        before: datetime,
        limit: int = 100,
    ) -> list[SubscriptionCredential]:
        """Return credentials expiring before `before` across ALL tenants.

        SECURITY: Bypasses tenant isolation (no tenant_id filter).
        MUST only be called from the platform-level credential health-check
        CronJob (waf_shared/jobs/credential_health_check.py).
        MUST NOT be wired into any API router or tenant-scoped service.
        """
        rows = await self._fetch_system(
            f"SELECT {_COLS} FROM subscription_credentials "
            f"WHERE expires_at IS NOT NULL AND expires_at < $1 "
            f"AND health != $2::credential_health "
            f"ORDER BY expires_at LIMIT $3",
            before,
            CredentialHealth.EXPIRED.value,
            limit,
        )
        return [_row_to_credential(r) for r in rows]

    async def count_by_health(
        self, tenant_id: uuid.UUID
    ) -> dict[str, int]:
        rows = await self._read(
            "SELECT health, COUNT(*) AS n "
            "FROM subscription_credentials WHERE tenant_id = $1 GROUP BY health",
            tenant_id,
            tenant_id,
        )
        return {r["health"]: int(r["n"]) for r in rows}

    # ── Writes ────────────────────────────────────────────────────────────────

    async def create(
        self, credential: SubscriptionCredential
    ) -> SubscriptionCredential:
        row = await self._write_one(
            f"INSERT INTO subscription_credentials "
            f"(id, tenant_id, subscription_id, display_name, keyvault_secret_name, "
            f" health, expires_at, last_health_check_at, created_at, updated_at) "
            f"VALUES ($1, $2, $3, $4, $5, $6::credential_health, $7, $8, $9, $10) "
            f"RETURNING {_COLS}",
            credential.tenant_id,
            credential.id,
            credential.tenant_id,
            credential.subscription_id,
            credential.display_name,
            credential.keyvault_secret_name,
            credential.health.value,
            credential.expires_at,
            credential.last_health_check_at,
            credential.created_at,
            credential.updated_at,
        )
        if row is None:
            raise CredentialNotFoundError(credential.id, credential.tenant_id)
        return _row_to_credential(row)

    async def update_health(
        self,
        tenant_id: uuid.UUID,
        credential_id: uuid.UUID,
        health: CredentialHealth,
        expires_at: datetime | None,
        last_health_check_at: datetime,
    ) -> SubscriptionCredential:
        row = await self._write_one(
            f"UPDATE subscription_credentials "
            f"SET health = $3::credential_health, "
            f"    expires_at = $4, "
            f"    last_health_check_at = $5, "
            f"    updated_at = NOW() "
            f"WHERE tenant_id = $1 AND id = $2 "
            f"RETURNING {_COLS}",
            tenant_id,
            tenant_id, credential_id, health.value, expires_at, last_health_check_at,
        )
        if row is None:
            raise CredentialNotFoundError(credential_id, tenant_id)
        return _row_to_credential(row)

    async def delete(
        self,
        tenant_id: uuid.UUID,
        credential_id: uuid.UUID,
    ) -> None:
        await self._write(
            "DELETE FROM subscription_credentials "
            "WHERE tenant_id = $1 AND id = $2",
            tenant_id,
            tenant_id, credential_id,
        )
