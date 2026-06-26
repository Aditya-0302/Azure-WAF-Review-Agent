"""Unit tests for ResourceGroupDiscoveryService."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from azure.core.exceptions import HttpResponseError

from waf_shared.discovery.models import ResourceGroup
from waf_shared.discovery.resource_group_discovery import (
    ResourceGroupDiscoveryService,
    _map_resource_group,
)
from waf_shared.domain.errors.infrastructure_errors import ResourceDiscoveryError


def _make_sdk_rg(
    name: str = "my-rg",
    location: str = "eastus",
    tags: dict | None = None,
    provisioning_state: str = "Succeeded",
) -> MagicMock:
    rg = MagicMock()
    rg.id = f"/subscriptions/sub-1/resourceGroups/{name}"
    rg.name = name
    rg.location = location
    rg.tags = tags or {}
    rg.properties = MagicMock()
    rg.properties.provisioning_state = provisioning_state
    return rg


def _make_rg_client(
    list_items: list | None = None,
    get_result: object | None = None,
    get_error: Exception | None = None,
) -> AsyncMock:
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)

    async def _list_iter():
        for item in list_items or []:
            yield item

    client.resource_groups = AsyncMock()
    client.resource_groups.list = MagicMock(return_value=_list_iter())

    if get_error:
        client.resource_groups.get = AsyncMock(side_effect=get_error)
    else:
        client.resource_groups.get = AsyncMock(return_value=get_result)

    return client


@pytest.mark.unit
class TestResourceGroupDiscoveryServiceList:
    @pytest.mark.asyncio
    async def test_list_returns_mapped_resource_groups(self) -> None:
        sub_id = uuid.uuid4()
        rg1 = _make_sdk_rg(name="rg-alpha", location="westus2")
        rg2 = _make_sdk_rg(name="rg-beta", location="eastus")
        mock_client = _make_rg_client(list_items=[rg1, rg2])
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.resource_group_discovery.ResourceManagementClient",
            return_value=mock_client,
        ):
            svc = ResourceGroupDiscoveryService()
            result = await svc.list_resource_groups(credential, sub_id)

        assert len(result) == 2
        assert result[0].name == "rg-alpha"
        assert result[0].subscription_id == sub_id
        assert result[1].location == "eastus"

    @pytest.mark.asyncio
    async def test_list_returns_empty_when_no_resource_groups(self) -> None:
        sub_id = uuid.uuid4()
        mock_client = _make_rg_client(list_items=[])
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.resource_group_discovery.ResourceManagementClient",
            return_value=mock_client,
        ):
            svc = ResourceGroupDiscoveryService()
            result = await svc.list_resource_groups(credential, sub_id)

        assert result == []

    @pytest.mark.asyncio
    async def test_list_raises_resource_discovery_error_on_http_failure(self) -> None:
        sub_id = uuid.uuid4()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        error = HttpResponseError(message="Unauthorized")
        error.status_code = 401

        async def _bad_iter():
            raise error
            yield

        mock_client.resource_groups = AsyncMock()
        mock_client.resource_groups.list = MagicMock(return_value=_bad_iter())
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.resource_group_discovery.ResourceManagementClient",
            return_value=mock_client,
        ):
            svc = ResourceGroupDiscoveryService()
            with pytest.raises(ResourceDiscoveryError) as exc_info:
                await svc.list_resource_groups(credential, sub_id)

        assert exc_info.value.service == "ResourceManagementClient"


@pytest.mark.unit
class TestResourceGroupDiscoveryServiceGet:
    @pytest.mark.asyncio
    async def test_get_returns_resource_group(self) -> None:
        sub_id = uuid.uuid4()
        sdk_rg = _make_sdk_rg(name="found-rg", location="northeurope")
        mock_client = _make_rg_client(get_result=sdk_rg)
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.resource_group_discovery.ResourceManagementClient",
            return_value=mock_client,
        ):
            svc = ResourceGroupDiscoveryService()
            result = await svc.get_resource_group(credential, sub_id, "found-rg")

        assert result is not None
        assert result.name == "found-rg"
        assert result.location == "northeurope"

    @pytest.mark.asyncio
    async def test_get_returns_none_on_404(self) -> None:
        sub_id = uuid.uuid4()
        error = HttpResponseError(message="Not Found")
        error.status_code = 404
        mock_client = _make_rg_client(get_error=error)
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.resource_group_discovery.ResourceManagementClient",
            return_value=mock_client,
        ):
            svc = ResourceGroupDiscoveryService()
            result = await svc.get_resource_group(credential, sub_id, "missing-rg")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_raises_resource_discovery_error_on_non_404_error(self) -> None:
        sub_id = uuid.uuid4()
        error = HttpResponseError(message="Internal Server Error")
        error.status_code = 500
        mock_client = _make_rg_client(get_error=error)
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.resource_group_discovery.ResourceManagementClient",
            return_value=mock_client,
        ):
            svc = ResourceGroupDiscoveryService()
            with pytest.raises(ResourceDiscoveryError):
                await svc.get_resource_group(credential, sub_id, "bad-rg")


@pytest.mark.unit
class TestMapResourceGroup:
    def test_maps_provisioning_state_from_properties(self) -> None:
        sub_id = uuid.uuid4()
        sdk_rg = _make_sdk_rg(provisioning_state="Succeeded")
        result = _map_resource_group(sdk_rg, sub_id)
        assert result.provisioning_state == "Succeeded"

    def test_handles_missing_properties(self) -> None:
        sub_id = uuid.uuid4()
        sdk_rg = _make_sdk_rg()
        sdk_rg.properties = None
        result = _map_resource_group(sdk_rg, sub_id)
        assert result.provisioning_state is None

    def test_maps_tags(self) -> None:
        sub_id = uuid.uuid4()
        sdk_rg = _make_sdk_rg(tags={"cost-center": "123"})
        result = _map_resource_group(sdk_rg, sub_id)
        assert result.tags == {"cost-center": "123"}

    def test_result_is_resource_group_instance(self) -> None:
        sub_id = uuid.uuid4()
        sdk_rg = _make_sdk_rg()
        result = _map_resource_group(sdk_rg, sub_id)
        assert isinstance(result, ResourceGroup)
