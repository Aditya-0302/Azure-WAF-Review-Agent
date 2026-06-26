"""Regression tests: Azure SDK clients must be async (.aio) variants.

Root cause of the original bug: sync Azure management SDK clients were imported
(azure.mgmt.subscription.SubscriptionClient etc.) but passed AsyncTokenCredential
objects. The sync SDK called credential.get_token() synchronously, received a
coroutine object, then tried to access .token on it →
    AttributeError: 'coroutine' object has no attribute 'token'

Fix: import only the async (.aio) variants of all Azure management SDK clients.
These tests enforce that the correct variants remain imported.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from azure.mgmt.advisor.aio import AdvisorManagementClient as AsyncAdvisorClient
from azure.mgmt.resource.resources.aio import (
    ResourceManagementClient as AsyncResourceManagementClient,
)
from azure.mgmt.resourcegraph.aio import ResourceGraphClient as AsyncResourceGraphClient
from azure.mgmt.subscription.aio import SubscriptionClient as AsyncSubscriptionClient

import waf_shared.discovery.advisor_client as _adv_mod
import waf_shared.discovery.resource_graph_client as _rg_mod
import waf_shared.discovery.resource_group_discovery as _rgd_mod
import waf_shared.discovery.subscription_discovery as _sub_mod
from waf_shared.auth.credential_provider import CrossTenantCredentialProvider


@pytest.mark.unit
class TestAsyncSdkClientsImported:
    """The module-level SDK client names must be the async (.aio) variants."""

    def test_subscription_discovery_uses_async_client(self) -> None:
        assert _sub_mod.SubscriptionClient is AsyncSubscriptionClient, (
            "subscription_discovery must import azure.mgmt.subscription.aio.SubscriptionClient; "
            "the sync variant does not accept AsyncTokenCredential"
        )

    def test_resource_group_discovery_uses_async_client(self) -> None:
        assert _rgd_mod.ResourceManagementClient is AsyncResourceManagementClient, (
            "resource_group_discovery must import "
            "azure.mgmt.resource.resources.aio.ResourceManagementClient"
        )

    def test_advisor_client_uses_async_client(self) -> None:
        assert _adv_mod.AdvisorManagementClient is AsyncAdvisorClient, (
            "advisor_client must import azure.mgmt.advisor.aio.AdvisorManagementClient"
        )

    def test_resource_graph_client_uses_async_client(self) -> None:
        assert _rg_mod.ResourceGraphClient is AsyncResourceGraphClient, (
            "resource_graph_client must import azure.mgmt.resourcegraph.aio.ResourceGraphClient"
        )


@pytest.mark.unit
class TestSyncCredentialForExtraction:
    """Extraction agent must pass sync credentials to ResourceGraphClient.

    Root cause of the extraction bug: CrossTenantCredentialProvider returned
    azure.identity.aio.ClientSecretCredential (async). The sync SDK pipeline
    policy calls credential.get_token_info() without await; on an async
    credential this returns a coroutine, and accessing .token on the coroutine
    raises AttributeError: 'coroutine' object has no attribute 'token'.

    Fix: get_sync_credential_for_subscription returns azure.identity.ClientSecretCredential
    (sync). Its get_token() returns AccessToken directly, no await needed.
    """

    @pytest.mark.asyncio
    async def test_get_sync_credential_returns_non_async_get_token(self) -> None:
        """get_sync_credential_for_subscription must return a credential whose get_token is sync."""
        sp_json = json.dumps(
            {"tenant_id": "ext-t", "client_id": "ext-c", "client_secret": "ext-s"}
        )
        mock_secret = MagicMock()
        mock_secret.value = sp_json
        mock_kv = AsyncMock()
        mock_kv.get_secret = AsyncMock(return_value=mock_secret)

        platform = AsyncMock()
        platform.get_credential = AsyncMock(return_value=AsyncMock())

        provider = CrossTenantCredentialProvider(
            keyvault_uri="https://vault.azure.net",
            platform_provider=platform,
        )
        provider._kv_client = mock_kv

        cred = await provider.get_sync_credential_for_subscription(
            uuid.uuid4(), "my-secret"
        )

        assert not asyncio.iscoroutinefunction(cred.get_token), (
            "get_sync_credential_for_subscription must return azure.identity.ClientSecretCredential "
            "(sync). Calling get_token() on a sync credential returns AccessToken directly "
            "without needing await. An async credential's get_token() returns a coroutine — "
            "the sync SDK pipeline then tries cred.token on the coroutine → AttributeError."
        )

    def test_sync_credential_get_token_is_not_coroutine_function(self) -> None:
        """azure.identity.ClientSecretCredential.get_token must not be a coroutine function."""
        from azure.identity import ClientSecretCredential as SyncCSC

        assert not asyncio.iscoroutinefunction(SyncCSC.get_token), (
            "azure.identity.ClientSecretCredential (sync) must have a synchronous get_token; "
            "if this fails the installed azure-identity version changed its interface"
        )

    @pytest.mark.asyncio
    async def test_sync_credential_is_cached_after_first_fetch(self) -> None:
        """get_sync_credential_for_subscription caches credentials — KV is only called once."""
        sp_json = json.dumps(
            {"tenant_id": "ext-t", "client_id": "ext-c", "client_secret": "ext-s"}
        )
        mock_secret = MagicMock()
        mock_secret.value = sp_json
        mock_kv = AsyncMock()
        mock_kv.get_secret = AsyncMock(return_value=mock_secret)

        platform = AsyncMock()
        platform.get_credential = AsyncMock(return_value=AsyncMock())

        provider = CrossTenantCredentialProvider(
            keyvault_uri="https://vault.azure.net",
            platform_provider=platform,
        )
        provider._kv_client = mock_kv

        sub_id = uuid.uuid4()
        cred1 = await provider.get_sync_credential_for_subscription(sub_id, "s")
        cred2 = await provider.get_sync_credential_for_subscription(sub_id, "s")

        assert cred1 is cred2, "Second call must return the cached credential"
        assert mock_kv.get_secret.call_count == 1, "Key Vault must only be called once per subscription"

    @pytest.mark.asyncio
    async def test_invalidate_cache_evicts_sync_credential(self) -> None:
        """invalidate_cache must also evict the sync credential for the subscription."""
        sp_json = json.dumps(
            {"tenant_id": "ext-t", "client_id": "ext-c", "client_secret": "ext-s"}
        )
        mock_secret = MagicMock()
        mock_secret.value = sp_json
        mock_kv = AsyncMock()
        mock_kv.get_secret = AsyncMock(return_value=mock_secret)

        platform = AsyncMock()
        platform.get_credential = AsyncMock(return_value=AsyncMock())

        provider = CrossTenantCredentialProvider(
            keyvault_uri="https://vault.azure.net",
            platform_provider=platform,
        )
        provider._kv_client = mock_kv

        sub_id = uuid.uuid4()
        cred1 = await provider.get_sync_credential_for_subscription(sub_id, "s")
        await provider.invalidate_cache(sub_id)
        cred2 = await provider.get_sync_credential_for_subscription(sub_id, "s")

        assert cred1 is not cred2, "After invalidation a new credential must be fetched"
        assert mock_kv.get_secret.call_count == 2, "KV must be called again after invalidation"


@pytest.mark.unit
class TestCrossTenantCredentialIsAsync:
    """CrossTenantCredentialProvider must produce credentials with async get_token."""

    @pytest.mark.asyncio
    async def test_get_credential_for_subscription_returns_async_credential(
        self,
    ) -> None:
        """The returned cross-tenant credential must have an async get_token method.

        This guards against accidentally switching to azure.identity.ClientSecretCredential
        (sync) which would cause the same coroutine-has-no-attribute-token error in
        any async Azure SDK client that calls credential.get_token().
        """
        sp_json = json.dumps(
            {"tenant_id": "ext-t", "client_id": "ext-c", "client_secret": "ext-s"}
        )
        mock_secret = MagicMock()
        mock_secret.value = sp_json
        mock_kv = AsyncMock()
        mock_kv.get_secret = AsyncMock(return_value=mock_secret)

        platform = AsyncMock()
        platform.get_credential = AsyncMock(return_value=AsyncMock())

        provider = CrossTenantCredentialProvider(
            keyvault_uri="https://vault.azure.net",
            platform_provider=platform,
        )
        provider._kv_client = mock_kv

        cred = await provider.get_credential_for_subscription(
            uuid.uuid4(), "my-secret"
        )

        assert asyncio.iscoroutinefunction(cred.get_token), (
            "CrossTenantCredentialProvider must return a credential whose get_token "
            "is a coroutine function (async); a sync credential would cause "
            "AttributeError: 'coroutine' object has no attribute 'token' "
            "in async Azure SDK clients"
        )
