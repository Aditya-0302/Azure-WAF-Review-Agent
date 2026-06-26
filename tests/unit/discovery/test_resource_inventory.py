"""Unit tests for ResourceInventoryService."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from waf_shared.discovery.models import AzureResource
from waf_shared.discovery.resource_inventory import (
    ResourceInventoryService,
    _map_resource,
    _validate_resource_types,
)


def _make_resource_row(
    resource_id: str | None = None,
    name: str = "app-gw-01",
    rtype: str = "microsoft.network/applicationgateways",
    location: str = "eastus",
    sub_id: str | None = None,
    rg: str = "my-rg",
    tags: dict | None = None,
    properties: dict | None = None,
) -> dict:
    return {
        "id": resource_id or f"/subscriptions/{uuid.uuid4()}/resourceGroups/{rg}/providers/{rtype}/{name}",
        "name": name,
        "type": rtype,
        "location": location,
        "subscriptionId": sub_id or str(uuid.uuid4()),
        "resourceGroup": rg,
        "tags": tags or {},
        "sku": None,
        "kind": None,
        "properties": properties or {"sku": {"tier": "WAF_v2"}},
    }


def _make_graph_client(rows: list[dict]) -> AsyncMock:
    client = AsyncMock()
    client.query_all = AsyncMock(return_value=rows)
    return client


@pytest.mark.unit
class TestResourceInventoryServiceListResources:
    @pytest.mark.asyncio
    async def test_returns_mapped_resources(self) -> None:
        sub_id = uuid.uuid4()
        rows = [_make_resource_row(sub_id=str(sub_id))]
        mock_graph = _make_graph_client(rows)
        credential = AsyncMock()

        svc = ResourceInventoryService(graph_client=mock_graph)
        result = await svc.list_resources(credential, [sub_id])

        assert len(result) == 1
        assert isinstance(result[0], AzureResource)
        assert result[0].type == "microsoft.network/applicationgateways"

    @pytest.mark.asyncio
    async def test_no_type_filter_uses_all_resources_kql(self) -> None:
        sub_id = uuid.uuid4()
        mock_graph = _make_graph_client([])
        credential = AsyncMock()

        svc = ResourceInventoryService(graph_client=mock_graph)
        await svc.list_resources(credential, [sub_id])

        kql_used: str = mock_graph.query_all.call_args[0][2]
        assert "in~" not in kql_used
        assert "Resources" in kql_used

    @pytest.mark.asyncio
    async def test_type_filter_builds_in_clause(self) -> None:
        sub_id = uuid.uuid4()
        mock_graph = _make_graph_client([])
        credential = AsyncMock()
        types = [
            "microsoft.network/applicationgateways",
            "microsoft.network/frontdoors",
        ]

        svc = ResourceInventoryService(graph_client=mock_graph)
        await svc.list_resources(credential, [sub_id], resource_types=types)

        kql_used: str = mock_graph.query_all.call_args[0][2]
        assert "type in~" in kql_used
        assert "'microsoft.network/applicationgateways'" in kql_used
        assert "'microsoft.network/frontdoors'" in kql_used

    @pytest.mark.asyncio
    async def test_passes_correct_subscription_ids_as_strings(self) -> None:
        sub_a = uuid.uuid4()
        sub_b = uuid.uuid4()
        mock_graph = _make_graph_client([])
        credential = AsyncMock()

        svc = ResourceInventoryService(graph_client=mock_graph)
        await svc.list_resources(credential, [sub_a, sub_b])

        call_sub_ids = mock_graph.query_all.call_args[0][1]
        assert str(sub_a) in call_sub_ids
        assert str(sub_b) in call_sub_ids

    @pytest.mark.asyncio
    async def test_invalid_resource_type_raises_value_error(self) -> None:
        sub_id = uuid.uuid4()
        mock_graph = _make_graph_client([])
        credential = AsyncMock()
        bad_types = ["microsoft.network/'; DROP TABLE resources; --"]

        svc = ResourceInventoryService(graph_client=mock_graph)
        with pytest.raises(ValueError, match="Invalid resource type"):
            await svc.list_resources(credential, [sub_id], resource_types=bad_types)


@pytest.mark.unit
class TestResourceInventoryServiceListInRG:
    @pytest.mark.asyncio
    async def test_list_in_rg_filters_by_rg_name(self) -> None:
        sub_id = uuid.uuid4()
        rows = [_make_resource_row(rg="target-rg")]
        mock_graph = _make_graph_client(rows)
        credential = AsyncMock()

        svc = ResourceInventoryService(graph_client=mock_graph)
        result = await svc.list_resources_in_resource_group(
            credential, sub_id, "target-rg"
        )

        kql_used: str = mock_graph.query_all.call_args[0][2]
        assert "target-rg" in kql_used
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_list_in_rg_raises_on_invalid_name(self) -> None:
        sub_id = uuid.uuid4()
        mock_graph = _make_graph_client([])
        credential = AsyncMock()

        svc = ResourceInventoryService(graph_client=mock_graph)
        with pytest.raises(ValueError, match="Invalid resource group name"):
            await svc.list_resources_in_resource_group(
                credential, sub_id, "'; DROP TABLE--"
            )


@pytest.mark.unit
class TestResourceInventoryServiceGetResource:
    @pytest.mark.asyncio
    async def test_get_resource_returns_model(self) -> None:
        sub_id = uuid.uuid4()
        resource_id = f"/subscriptions/{sub_id}/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw1"
        rows = [_make_resource_row(resource_id=resource_id, sub_id=str(sub_id))]
        mock_graph = _make_graph_client(rows)
        credential = AsyncMock()

        svc = ResourceInventoryService(graph_client=mock_graph)
        result = await svc.get_resource(credential, sub_id, resource_id)

        assert result is not None
        assert isinstance(result, AzureResource)

    @pytest.mark.asyncio
    async def test_get_resource_returns_none_when_not_found(self) -> None:
        sub_id = uuid.uuid4()
        mock_graph = _make_graph_client([])
        credential = AsyncMock()

        svc = ResourceInventoryService(graph_client=mock_graph)
        result = await svc.get_resource(
            credential, sub_id, "/subscriptions/x/resourceGroups/y/providers/z/w"
        )

        assert result is None


@pytest.mark.unit
class TestMapResource:
    def test_normalizes_type_to_lowercase(self) -> None:
        row = _make_resource_row(rtype="Microsoft.Network/ApplicationGateways")
        result = _map_resource(row)
        assert result.type == "microsoft.network/applicationgateways"

    def test_normalizes_resource_group_to_lowercase(self) -> None:
        row = _make_resource_row(rg="My-Resource-Group")
        result = _map_resource(row)
        assert result.resource_group == "my-resource-group"

    def test_handles_missing_subscription_id(self) -> None:
        row = _make_resource_row()
        row["subscriptionId"] = None
        result = _map_resource(row)
        assert result.subscription_id == uuid.UUID(int=0)

    def test_handles_none_sku(self) -> None:
        row = _make_resource_row()
        row["sku"] = None
        result = _map_resource(row)
        assert result.sku is None

    def test_handles_dict_sku(self) -> None:
        row = _make_resource_row()
        row["sku"] = {"name": "WAF_v2", "tier": "WAF_v2"}
        result = _map_resource(row)
        assert result.sku == {"name": "WAF_v2", "tier": "WAF_v2"}


@pytest.mark.unit
class TestValidateResourceTypes:
    def test_valid_types_pass(self) -> None:
        types = [
            "microsoft.network/applicationgateways",
            "Microsoft.ApiManagement/service",
            "microsoft.cdn/profiles",
        ]
        _validate_resource_types(types)  # no exception

    def test_type_with_semicolon_raises(self) -> None:
        with pytest.raises(ValueError):
            _validate_resource_types(["microsoft.network/app;injection"])

    def test_type_with_space_raises(self) -> None:
        with pytest.raises(ValueError):
            _validate_resource_types(["microsoft.network/app gateways"])
