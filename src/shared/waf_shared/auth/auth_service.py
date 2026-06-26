"""Authentication service — orchestrates credential acquisition and validation.

Consumers should call this service rather than interacting with providers
directly. Provides:
  - Platform token acquisition (ARM, Key Vault, Graph)
  - Customer subscription credential retrieval
  - Credential health validation (attempt token acquisition → health enum)
  - Cache invalidation (force re-read from Key Vault after rotation)
"""

from __future__ import annotations

import uuid

from azure.core.credentials_async import AsyncTokenCredential

from waf_shared.auth.credential_provider import CrossTenantCredentialProvider
from waf_shared.auth.token_provider import TokenProvider
from waf_shared.domain.errors.infrastructure_errors import (
    CredentialUnavailableError,
    CrossTenantAuthError,
)
from waf_shared.domain.models.credential import CredentialHealth
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-shared", version="0.1.0")

_ARM_SCOPE = "https://management.azure.com/.default"


class AuthenticationService:
    """High-level authentication operations used by the service layer."""

    def __init__(
        self,
        token_provider: TokenProvider,
        cross_tenant_provider: CrossTenantCredentialProvider,
    ) -> None:
        self._tokens = token_provider
        self._cross_tenant = cross_tenant_provider

    # ── Subscription credentials ──────────────────────────────────────────────

    async def get_subscription_credential(
        self,
        subscription_id: uuid.UUID,
        keyvault_secret_name: str,
    ) -> AsyncTokenCredential:
        """Return an async credential scoped to a customer subscription."""
        return await self._cross_tenant.get_credential_for_subscription(
            subscription_id=subscription_id,
            keyvault_secret_name=keyvault_secret_name,
        )

    async def validate_subscription_credential(
        self,
        subscription_id: uuid.UUID,
        keyvault_secret_name: str,
    ) -> CredentialHealth:
        """Attempt to acquire an ARM token; return the resulting health status.

        Does NOT raise — always returns a CredentialHealth value so callers
        can persist the result without try/except boilerplate.
        """
        try:
            token_str = await self._tokens.get_subscription_token(
                subscription_id=subscription_id,
                keyvault_secret_name=keyvault_secret_name,
                scope=_ARM_SCOPE,
            )
            if not token_str:
                _logger.warning(
                    "auth.credential.validation.empty_token",
                    subscription_id=str(subscription_id),
                )
                return CredentialHealth.INVALID
            return CredentialHealth.HEALTHY
        except CrossTenantAuthError as exc:
            _logger.warning(
                "auth.credential.validation.failed",
                subscription_id=str(subscription_id),
                reason=exc.reason,
            )
            return CredentialHealth.INVALID
        except CredentialUnavailableError as exc:
            _logger.warning(
                "auth.credential.validation.unavailable",
                subscription_id=str(subscription_id),
                reason=exc.reason,
            )
            return CredentialHealth.INVALID

    async def refresh_subscription_credential(self, subscription_id: uuid.UUID) -> None:
        """Evict cached credential; next use re-reads the secret from Key Vault."""
        await self._cross_tenant.invalidate_cache(subscription_id)
        _logger.info(
            "auth.credential.cache.invalidated",
            subscription_id=str(subscription_id),
        )

    # ── Platform tokens ───────────────────────────────────────────────────────

    async def get_arm_token(self) -> str:
        """Azure Resource Manager bearer token for management-plane calls."""
        return await self._tokens.get_arm_token()

    async def get_graph_token(self) -> str:
        """Microsoft Graph bearer token."""
        return await self._tokens.get_graph_token()

    async def get_keyvault_token(self) -> str:
        """Key Vault data-plane bearer token."""
        return await self._tokens.get_keyvault_token()
