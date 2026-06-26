"""Token provider — thin async wrapper over credential providers.

azure-identity manages its own in-process token cache and handles silent
refresh automatically. This class provides a stable interface for callers
that need a raw bearer token string rather than an AccessToken object.

Scopes follow the Azure pattern: "<resource-uri>/.default".
"""

from __future__ import annotations

import uuid

from waf_shared.auth.config import PlatformAuthConfig
from waf_shared.auth.credential_provider import (
    CredentialProvider,
    CrossTenantCredentialProvider,
)
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-shared", version="0.1.0")


class TokenProvider:
    """Acquires Azure access tokens for platform and cross-tenant operations."""

    def __init__(
        self,
        platform_provider: CredentialProvider,
        cross_tenant_provider: CrossTenantCredentialProvider,
        config: PlatformAuthConfig,
    ) -> None:
        self._platform = platform_provider
        self._cross_tenant = cross_tenant_provider
        self._config = config

    # ── Platform tokens ───────────────────────────────────────────────────────

    async def get_platform_token(self, scope: str) -> str:
        """Acquire a bearer token string for a platform-level Azure scope."""
        token = await self._platform.get_token(scope)
        return token.token

    async def get_arm_token(self) -> str:
        """Azure Resource Manager management-plane token."""
        return await self.get_platform_token(self._config.arm_scope)

    async def get_keyvault_token(self) -> str:
        """Azure Key Vault data-plane token."""
        return await self.get_platform_token(self._config.keyvault_scope)

    async def get_graph_token(self) -> str:
        """Microsoft Graph token."""
        return await self.get_platform_token(self._config.graph_scope)

    # ── Cross-tenant subscription tokens ─────────────────────────────────────

    async def get_subscription_token(
        self,
        subscription_id: uuid.UUID,
        keyvault_secret_name: str,
        scope: str | None = None,
    ) -> str:
        """Acquire an ARM token for a specific customer subscription.

        The service-principal credentials are read from Key Vault on first use
        and cached in-process. Pass scope to override the default ARM scope.
        """
        effective_scope = scope or self._config.arm_scope
        cred = await self._cross_tenant.get_credential_for_subscription(
            subscription_id=subscription_id,
            keyvault_secret_name=keyvault_secret_name,
        )
        token = await cred.get_token(effective_scope)
        _logger.debug(
            "auth.subscription.token.acquired",
            subscription_id=str(subscription_id),
            scope=effective_scope,
            expires_on=token.expires_on,
        )
        return token.token

    async def invalidate_subscription_credential(self, subscription_id: uuid.UUID) -> None:
        """Evict cached cross-tenant credential; next call re-reads Key Vault."""
        await self._cross_tenant.invalidate_cache(subscription_id)
