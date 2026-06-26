"""Credential lifecycle service — registration, health, deletion.

Wraps CredentialRepository + AuthenticationService so that routers don't need
to interact with either directly.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from waf_shared.auth.auth_service import AuthenticationService
from waf_shared.db.pool import DatabasePool
from waf_shared.db.repositories.credential_repository import CredentialRepository
from waf_shared.domain.errors.domain_errors import CredentialNotFoundError
from waf_shared.domain.models.credential import CredentialHealth, SubscriptionCredential
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-api", version="0.1.0")

_EXPIRY_LOOKAHEAD_DAYS = 30


class CredentialService:
    def __init__(
        self,
        pool: DatabasePool,
        auth_service: AuthenticationService,
    ) -> None:
        self._pool = pool
        self._auth = auth_service

    def _repo(self) -> CredentialRepository:
        return CredentialRepository(pool=self._pool)

    # ── Registration ──────────────────────────────────────────────────────────

    async def register(
        self,
        tenant_id: uuid.UUID,
        subscription_id: uuid.UUID,
        display_name: str,
        keyvault_secret_name: str,
    ) -> SubscriptionCredential:
        """Persist a new subscription credential record in UNCHECKED state."""
        now = datetime.now(UTC)
        cred = SubscriptionCredential(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            subscription_id=subscription_id,
            display_name=display_name,
            keyvault_secret_name=keyvault_secret_name,
            health=CredentialHealth.UNCHECKED,
            expires_at=None,
            last_health_check_at=None,
            created_at=now,
            updated_at=now,
        )
        result = await self._repo().create(cred)
        _logger.info(
            "credential.registered",
            tenant_id=str(tenant_id),
            subscription_id=str(subscription_id),
            credential_id=str(result.id),
        )
        return result

    # ── Health checks ─────────────────────────────────────────────────────────

    async def check_health(
        self,
        tenant_id: uuid.UUID,
        credential_id: uuid.UUID,
    ) -> SubscriptionCredential:
        """Validate the credential against Azure and persist the result."""
        repo = self._repo()
        cred = await repo.get_by_id(tenant_id, credential_id)
        if cred is None:
            raise CredentialNotFoundError(credential_id, tenant_id)

        health = await self._auth.validate_subscription_credential(
            subscription_id=cred.subscription_id,
            keyvault_secret_name=cred.keyvault_secret_name,
        )

        updated = await repo.update_health(
            tenant_id=tenant_id,
            credential_id=credential_id,
            health=health,
            expires_at=cred.expires_at,
            last_health_check_at=datetime.now(UTC),
        )
        _logger.info(
            "credential.health.checked",
            tenant_id=str(tenant_id),
            credential_id=str(credential_id),
            health=health.value,
        )
        return updated

    async def sweep_expiring(self) -> list[SubscriptionCredential]:
        """Platform-wide sweep: return all credentials expiring within 30 days."""
        before = datetime.now(UTC) + timedelta(days=_EXPIRY_LOOKAHEAD_DAYS)
        expiring = await self._repo().list_expiring(before=before)
        if expiring:
            _logger.warning(
                "credential.expiry.sweep",
                count=len(expiring),
                lookahead_days=_EXPIRY_LOOKAHEAD_DAYS,
            )
        return expiring

    # ── Retrieval ─────────────────────────────────────────────────────────────

    async def get(
        self,
        tenant_id: uuid.UUID,
        credential_id: uuid.UUID,
    ) -> SubscriptionCredential:
        cred = await self._repo().get_by_id(tenant_id, credential_id)
        if cred is None:
            raise CredentialNotFoundError(credential_id, tenant_id)
        return cred

    async def list(
        self,
        tenant_id: uuid.UUID,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
    ) -> list[SubscriptionCredential]:
        return await self._repo().list_by_tenant(
            tenant_id, limit=limit, cursor=cursor
        )

    async def count_by_health(
        self, tenant_id: uuid.UUID
    ) -> dict[str, int]:
        return await self._repo().count_by_health(tenant_id)

    # ── Deletion ──────────────────────────────────────────────────────────────

    async def delete(
        self,
        tenant_id: uuid.UUID,
        credential_id: uuid.UUID,
    ) -> None:
        repo = self._repo()
        cred = await repo.get_by_id(tenant_id, credential_id)
        if cred is None:
            raise CredentialNotFoundError(credential_id, tenant_id)

        await repo.delete(tenant_id, credential_id)
        await self._auth.refresh_subscription_credential(cred.subscription_id)
        _logger.info(
            "credential.deleted",
            tenant_id=str(tenant_id),
            credential_id=str(credential_id),
            subscription_id=str(cred.subscription_id),
        )

    # ── Rotation support ──────────────────────────────────────────────────────

    async def rotate(
        self,
        tenant_id: uuid.UUID,
        credential_id: uuid.UUID,
    ) -> SubscriptionCredential:
        """Evict cached credential and immediately re-validate from Key Vault."""
        repo = self._repo()
        cred = await repo.get_by_id(tenant_id, credential_id)
        if cred is None:
            raise CredentialNotFoundError(credential_id, tenant_id)

        await self._auth.refresh_subscription_credential(cred.subscription_id)
        return await self.check_health(tenant_id, credential_id)
