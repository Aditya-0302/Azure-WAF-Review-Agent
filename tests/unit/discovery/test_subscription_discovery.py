"""Unit tests for SubscriptionDiscoveryService."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from azure.core.exceptions import HttpResponseError

from waf_shared.discovery.subscription_discovery import (
    SubscriptionDiscoveryService,
    _map_subscription,
)
from waf_shared.discovery.models import AzureSubscription, SubscriptionState
from waf_shared.domain.errors.domain_errors import SubscriptionNotFoundError
from waf_shared.domain.errors.infrastructure_errors import ResourceDiscoveryError


def _make_sdk_subscription(
    sub_id: str | None = None,
    display_name: str = "Test Subscription",
    state: str = "Enabled",
    tenant_id: str = "tenant-abc",
    tags: dict | None = None,
) -> MagicMock:
    sub_id = sub_id or str(uuid.uuid4())
    m = MagicMock()
    m.id = f"/subscriptions/{sub_id}"
    m.subscription_id = sub_id
    m.display_name = display_name
    m.state = MagicMock()
    m.state.value = state
    m.tenant_id = tenant_id
    m.tags = tags or {}
    return m


def _make_subscription_client(
    list_items: list | None = None,
    get_result: object | None = None,
    get_error: Exception | None = None,
) -> AsyncMock:
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)

    async def _list_iter():
        for item in (list_items or []):
            yield item

    client.subscriptions = AsyncMock()
    client.subscriptions.list = MagicMock(return_value=_list_iter())

    if get_error:
        client.subscriptions.get = AsyncMock(side_effect=get_error)
    else:
        client.subscriptions.get = AsyncMock(return_value=get_result)

    return client


@pytest.mark.unit
class TestSubscriptionDiscoveryServiceList:
    @pytest.mark.asyncio
    async def test_list_returns_mapped_subscriptions(self) -> None:
        sub_id = str(uuid.uuid4())
        sdk_sub = _make_sdk_subscription(sub_id=sub_id, display_name="My Sub")
        mock_client = _make_subscription_client(list_items=[sdk_sub])
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.subscription_discovery.SubscriptionClient",
            return_value=mock_client,
        ):
            svc = SubscriptionDiscoveryService()
            result = await svc.list_subscriptions(credential)

        assert len(result) == 1
        assert result[0].display_name == "My Sub"
        assert result[0].subscription_id == uuid.UUID(sub_id)
        assert isinstance(result[0], AzureSubscription)

    @pytest.mark.asyncio
    async def test_list_returns_empty_when_no_subscriptions(self) -> None:
        mock_client = _make_subscription_client(list_items=[])
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.subscription_discovery.SubscriptionClient",
            return_value=mock_client,
        ):
            svc = SubscriptionDiscoveryService()
            result = await svc.list_subscriptions(credential)

        assert result == []

    @pytest.mark.asyncio
    async def test_list_raises_resource_discovery_error_on_http_failure(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        error = HttpResponseError(message="Forbidden")
        error.status_code = 403

        async def _bad_iter():
            raise error
            yield  # make it a generator

        mock_client.subscriptions = AsyncMock()
        mock_client.subscriptions.list = MagicMock(return_value=_bad_iter())

        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.subscription_discovery.SubscriptionClient",
            return_value=mock_client,
        ):
            svc = SubscriptionDiscoveryService()
            with pytest.raises(ResourceDiscoveryError) as exc_info:
                await svc.list_subscriptions(credential)

        assert exc_info.value.service == "SubscriptionClient"


@pytest.mark.unit
class TestSubscriptionDiscoveryServiceGet:
    @pytest.mark.asyncio
    async def test_get_returns_mapped_subscription(self) -> None:
        sub_id = uuid.uuid4()
        sdk_sub = _make_sdk_subscription(sub_id=str(sub_id), display_name="Found Sub")
        mock_client = _make_subscription_client(get_result=sdk_sub)
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.subscription_discovery.SubscriptionClient",
            return_value=mock_client,
        ):
            svc = SubscriptionDiscoveryService()
            result = await svc.get_subscription(credential, sub_id)

        assert result.subscription_id == sub_id
        assert result.display_name == "Found Sub"

    @pytest.mark.asyncio
    async def test_get_raises_not_found_on_404(self) -> None:
        sub_id = uuid.uuid4()
        error = HttpResponseError(message="Not Found")
        error.status_code = 404
        mock_client = _make_subscription_client(get_error=error)
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.subscription_discovery.SubscriptionClient",
            return_value=mock_client,
        ):
            svc = SubscriptionDiscoveryService()
            with pytest.raises(SubscriptionNotFoundError) as exc_info:
                await svc.get_subscription(credential, sub_id)

        assert exc_info.value.subscription_id == sub_id

    @pytest.mark.asyncio
    async def test_get_raises_resource_discovery_error_on_other_http_error(
        self,
    ) -> None:
        sub_id = uuid.uuid4()
        error = HttpResponseError(message="Service Unavailable")
        error.status_code = 503
        mock_client = _make_subscription_client(get_error=error)
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.subscription_discovery.SubscriptionClient",
            return_value=mock_client,
        ):
            svc = SubscriptionDiscoveryService()
            with pytest.raises(ResourceDiscoveryError):
                await svc.get_subscription(credential, sub_id)


@pytest.mark.unit
class TestMapSubscription:
    def test_maps_standard_state(self) -> None:
        sub_id = str(uuid.uuid4())
        sdk_sub = _make_sdk_subscription(sub_id=sub_id, state="Disabled")
        result = _map_subscription(sdk_sub)
        assert result.state == SubscriptionState.DISABLED

    def test_falls_back_to_enabled_on_unknown_state(self) -> None:
        sdk_sub = _make_sdk_subscription(state="UnknownFutureState")
        result = _map_subscription(sdk_sub)
        assert result.state == SubscriptionState.ENABLED

    def test_maps_tags(self) -> None:
        sdk_sub = _make_sdk_subscription(tags={"env": "prod", "team": "platform"})
        result = _map_subscription(sdk_sub)
        assert result.tags == {"env": "prod", "team": "platform"}
