"""Integration tests for the Azure discovery layer.

All tests in this module require live Azure credentials and are skipped
unless ALL of the following environment variables are set:

  AZURE_INTEGRATION_TESTS=1   — opt-in gate
  AZURE_SUBSCRIPTION_ID       — UUID of the subscription to discover
  AZURE_KV_URI                — Key Vault URI holding the cross-tenant SP secret
  AZURE_KV_SECRET_NAME        — Secret name for the target subscription's SP JSON

Optional:
  AUTH_MODE   — credential mode for the platform identity; defaults to
                "default_chain" (DefaultAzureCredential) so Azure CLI works
                locally.  Set to "managed_identity" when running in Azure.

Each test closes all credential / provider objects in a try/finally block to
prevent ResourceWarning from unclosed aiohttp sessions.
"""

from __future__ import annotations

import os
import uuid

import pytest

from waf_shared.discovery.config import DiscoveryConfig
from waf_shared.discovery.models import AzureResource, AzureSubscription

_AZURE_INTEGRATION = pytest.mark.skipif(
    os.environ.get("AZURE_INTEGRATION_TESTS") != "1"
    or not os.environ.get("AZURE_SUBSCRIPTION_ID")
    or not os.environ.get("AZURE_KV_URI")
    or not os.environ.get("AZURE_KV_SECRET_NAME"),
    reason=(
        "Requires AZURE_INTEGRATION_TESTS=1, AZURE_SUBSCRIPTION_ID, "
        "AZURE_KV_URI, and AZURE_KV_SECRET_NAME"
    ),
)


def _sub_id() -> uuid.UUID:
    return uuid.UUID(os.environ["AZURE_SUBSCRIPTION_ID"])


def _kv_uri() -> str:
    return os.environ["AZURE_KV_URI"]


def _kv_secret() -> str:
    return os.environ["AZURE_KV_SECRET_NAME"]


def _make_platform_credential():
    """Return a platform credential provider suitable for the current environment.

    Reads AUTH_MODE from the environment (default: ``default_chain``).
    ``default_chain`` → DefaultAzureCredential, which resolves Azure CLI,
    environment variables, VS Code, and finally Managed Identity in that order.
    Set AUTH_MODE=managed_identity when running inside Azure-hosted compute.
    """
    from waf_shared.auth.config import AuthMode, PlatformAuthConfig
    from waf_shared.auth.credential_provider import create_platform_provider

    mode_str = os.environ.get("AUTH_MODE", "default_chain")
    try:
        mode = AuthMode(mode_str)
    except ValueError:
        mode = AuthMode.DEFAULT_CHAIN
    return create_platform_provider(PlatformAuthConfig(mode=mode))


# ── Subscription discovery ────────────────────────────────────────────────────


@pytest.mark.integration
class TestSubscriptionDiscoveryIntegration:
    @_AZURE_INTEGRATION
    @pytest.mark.asyncio
    async def test_list_subscriptions_returns_at_least_one(self) -> None:
        from waf_shared.discovery.subscription_discovery import (
            SubscriptionDiscoveryService,
        )

        credential = _make_platform_credential()
        try:
            svc = SubscriptionDiscoveryService()
            subs = await svc.list_subscriptions(credential)

            assert len(subs) >= 1
            for sub in subs:
                assert isinstance(sub, AzureSubscription)
                assert sub.subscription_id != uuid.UUID(int=0)
                assert sub.display_name
        finally:
            await credential.close()

    @_AZURE_INTEGRATION
    @pytest.mark.asyncio
    async def test_get_subscription_returns_target(self) -> None:
        from waf_shared.discovery.subscription_discovery import (
            SubscriptionDiscoveryService,
        )

        sub_id = _sub_id()
        credential = _make_platform_credential()
        try:
            svc = SubscriptionDiscoveryService()
            sub = await svc.get_subscription(credential, sub_id)

            assert sub.subscription_id == sub_id
            assert sub.state is not None
        finally:
            await credential.close()


# ── Resource group discovery ──────────────────────────────────────────────────


@pytest.mark.integration
class TestResourceGroupDiscoveryIntegration:
    @_AZURE_INTEGRATION
    @pytest.mark.asyncio
    async def test_list_resource_groups_returns_results(self) -> None:
        from waf_shared.auth.auth_service import AuthenticationService
        from waf_shared.auth.config import PlatformAuthConfig
        from waf_shared.auth.credential_provider import (
            CrossTenantCredentialProvider,
        )
        from waf_shared.auth.token_provider import TokenProvider
        from waf_shared.discovery.resource_group_discovery import (
            ResourceGroupDiscoveryService,
        )

        sub_id = _sub_id()
        platform = _make_platform_credential()
        cross_tenant = CrossTenantCredentialProvider(
            keyvault_uri=_kv_uri(), platform_provider=platform
        )
        try:
            token_provider = TokenProvider(
                platform_provider=platform,
                cross_tenant_provider=cross_tenant,
                config=PlatformAuthConfig(),
            )
            auth_svc = AuthenticationService(
                token_provider=token_provider, cross_tenant_provider=cross_tenant
            )
            credential = await auth_svc.get_subscription_credential(
                subscription_id=sub_id, keyvault_secret_name=_kv_secret()
            )

            svc = ResourceGroupDiscoveryService()
            rgs = await svc.list_resource_groups(credential, sub_id)

            assert len(rgs) >= 0  # subscription may have zero RGs; just confirm no error
            for rg in rgs:
                assert rg.subscription_id == sub_id
                assert rg.name
        finally:
            await cross_tenant.close()


# ── Resource inventory ────────────────────────────────────────────────────────


@pytest.mark.integration
class TestResourceInventoryIntegration:
    @_AZURE_INTEGRATION
    @pytest.mark.asyncio
    async def test_list_all_resources_returns_results(self) -> None:
        from waf_shared.auth.auth_service import AuthenticationService
        from waf_shared.auth.config import PlatformAuthConfig
        from waf_shared.auth.credential_provider import (
            CrossTenantCredentialProvider,
        )
        from waf_shared.auth.token_provider import TokenProvider
        from waf_shared.discovery.resource_inventory import ResourceInventoryService

        sub_id = _sub_id()
        platform = _make_platform_credential()
        cross_tenant = CrossTenantCredentialProvider(
            keyvault_uri=_kv_uri(), platform_provider=platform
        )
        try:
            token_provider = TokenProvider(
                platform_provider=platform,
                cross_tenant_provider=cross_tenant,
                config=PlatformAuthConfig(),
            )
            auth_svc = AuthenticationService(
                token_provider=token_provider, cross_tenant_provider=cross_tenant
            )
            credential = await auth_svc.get_subscription_credential(
                subscription_id=sub_id, keyvault_secret_name=_kv_secret()
            )

            config = DiscoveryConfig(page_size=50, max_pages=5)
            svc = ResourceInventoryService(config=config)
            resources = await svc.list_resources(credential, [sub_id])

            for resource in resources:
                assert isinstance(resource, AzureResource)
                assert resource.id
                assert resource.type == resource.type.lower()
        finally:
            await cross_tenant.close()

    @_AZURE_INTEGRATION
    @pytest.mark.asyncio
    async def test_list_resources_with_type_filter(self) -> None:
        from waf_shared.auth.auth_service import AuthenticationService
        from waf_shared.auth.config import PlatformAuthConfig
        from waf_shared.auth.credential_provider import (
            CrossTenantCredentialProvider,
        )
        from waf_shared.auth.token_provider import TokenProvider
        from waf_shared.discovery.resource_inventory import ResourceInventoryService

        sub_id = _sub_id()
        platform = _make_platform_credential()
        cross_tenant = CrossTenantCredentialProvider(
            keyvault_uri=_kv_uri(), platform_provider=platform
        )
        try:
            token_provider = TokenProvider(
                platform_provider=platform,
                cross_tenant_provider=cross_tenant,
                config=PlatformAuthConfig(),
            )
            auth_svc = AuthenticationService(
                token_provider=token_provider, cross_tenant_provider=cross_tenant
            )
            credential = await auth_svc.get_subscription_credential(
                subscription_id=sub_id, keyvault_secret_name=_kv_secret()
            )

            svc = ResourceInventoryService()
            resources = await svc.list_resources(
                credential,
                [sub_id],
                resource_types=["microsoft.network/applicationgateways"],
            )

            for resource in resources:
                assert resource.type == "microsoft.network/applicationgateways"
        finally:
            await cross_tenant.close()


# ── Advisor integration ───────────────────────────────────────────────────────


@pytest.mark.integration
class TestAdvisorIntegration:
    @_AZURE_INTEGRATION
    @pytest.mark.asyncio
    async def test_list_security_recommendations_does_not_raise(self) -> None:
        from waf_shared.auth.auth_service import AuthenticationService
        from waf_shared.auth.config import PlatformAuthConfig
        from waf_shared.auth.credential_provider import (
            CrossTenantCredentialProvider,
        )
        from waf_shared.auth.token_provider import TokenProvider
        from waf_shared.discovery.advisor_client import AzureAdvisorClient

        sub_id = _sub_id()
        platform = _make_platform_credential()
        cross_tenant = CrossTenantCredentialProvider(
            keyvault_uri=_kv_uri(), platform_provider=platform
        )
        try:
            token_provider = TokenProvider(
                platform_provider=platform,
                cross_tenant_provider=cross_tenant,
                config=PlatformAuthConfig(),
            )
            auth_svc = AuthenticationService(
                token_provider=token_provider, cross_tenant_provider=cross_tenant
            )
            credential = await auth_svc.get_subscription_credential(
                subscription_id=sub_id, keyvault_secret_name=_kv_secret()
            )

            advisor = AzureAdvisorClient()
            recs = await advisor.list_security_recommendations(credential, sub_id)

            for rec in recs:
                assert rec.subscription_id == sub_id
                assert rec.category
        finally:
            await cross_tenant.close()


# ── Full snapshot ─────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestDiscoveryServiceSnapshotIntegration:
    @_AZURE_INTEGRATION
    @pytest.mark.asyncio
    async def test_snapshot_subscription_returns_complete_result(self) -> None:
        from waf_api.services.discovery_service import DiscoveryService
        from waf_shared.auth.auth_service import AuthenticationService
        from waf_shared.auth.config import PlatformAuthConfig
        from waf_shared.auth.credential_provider import (
            CrossTenantCredentialProvider,
        )
        from waf_shared.auth.token_provider import TokenProvider

        sub_id = _sub_id()
        platform = _make_platform_credential()
        cross_tenant = CrossTenantCredentialProvider(
            keyvault_uri=_kv_uri(), platform_provider=platform
        )
        try:
            token_provider = TokenProvider(
                platform_provider=platform,
                cross_tenant_provider=cross_tenant,
                config=PlatformAuthConfig(),
            )
            auth_svc = AuthenticationService(
                token_provider=token_provider, cross_tenant_provider=cross_tenant
            )

            config = DiscoveryConfig(page_size=50, max_pages=3)
            svc = DiscoveryService(auth_service=auth_svc, config=config)

            snapshot = await svc.snapshot_subscription(
                subscription_id=sub_id,
                keyvault_secret_name=_kv_secret(),
                include_advisor=True,
            )

            assert snapshot.subscription.subscription_id == sub_id
            assert isinstance(snapshot.resource_groups, list)
            assert isinstance(snapshot.resources, list)
            assert isinstance(snapshot.advisor_recommendations, list)
        finally:
            await cross_tenant.close()
