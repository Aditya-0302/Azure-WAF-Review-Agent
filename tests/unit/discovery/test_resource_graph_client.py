"""Unit tests for AzureResourceGraphClient."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from waf_shared.discovery.config import DiscoveryConfig
from waf_shared.discovery.resource_graph_client import AzureResourceGraphClient
from waf_shared.domain.errors.infrastructure_errors import ResourceDiscoveryError


def _make_response(rows: list[dict], skip_token: str | None = None) -> MagicMock:
    r = MagicMock()
    r.data = rows
    r.skip_token = skip_token
    return r


def _make_client(responses: list[MagicMock]) -> AsyncMock:
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.resources = AsyncMock(side_effect=responses)
    return client


@pytest.mark.unit
class TestAzureResourceGraphClientQueryAll:
    @pytest.mark.asyncio
    async def test_returns_all_rows_from_single_page(self) -> None:
        rows = [{"id": "/subs/abc/res/1", "name": "res1"}]
        mock_client = _make_client([_make_response(rows)])
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.resource_graph_client.ResourceGraphClient",
            return_value=mock_client,
        ):
            client = AzureResourceGraphClient()
            result = await client.query_all(credential, ["sub-1"], "Resources")

        assert len(result) == 1
        assert result[0]["name"] == "res1"

    @pytest.mark.asyncio
    async def test_paginates_via_skip_token(self) -> None:
        page1_rows = [{"id": "r1"}]
        page2_rows = [{"id": "r2"}, {"id": "r3"}]
        responses = [
            _make_response(page1_rows, skip_token="tok-abc"),
            _make_response(page2_rows, skip_token=None),
        ]
        mock_client = _make_client(responses)
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.resource_graph_client.ResourceGraphClient",
            return_value=mock_client,
        ):
            client = AzureResourceGraphClient()
            result = await client.query_all(credential, ["sub-1"], "Resources")

        assert len(result) == 3
        assert mock_client.resources.call_count == 2

    @pytest.mark.asyncio
    async def test_stops_at_max_pages(self) -> None:
        config = DiscoveryConfig(max_pages=2)
        # Every response returns a skip_token — should stop after 2 pages
        responses = [_make_response([{"id": f"r{i}"}], skip_token="tok") for i in range(10)]
        mock_client = _make_client(responses)
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.resource_graph_client.ResourceGraphClient",
            return_value=mock_client,
        ):
            client = AzureResourceGraphClient(config=config)
            result = await client.query_all(credential, ["sub-1"], "Resources")

        assert len(result) == 2
        assert mock_client.resources.call_count == 2

    @pytest.mark.asyncio
    async def test_empty_page_returns_empty_list(self) -> None:
        mock_client = _make_client([_make_response([], skip_token=None)])
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.resource_graph_client.ResourceGraphClient",
            return_value=mock_client,
        ):
            client = AzureResourceGraphClient()
            result = await client.query_all(credential, ["sub-1"], "Resources")

        assert result == []

    @pytest.mark.asyncio
    async def test_raises_resource_discovery_error_on_sdk_failure(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.resources = AsyncMock(side_effect=RuntimeError("SDK failure"))
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.resource_graph_client.ResourceGraphClient",
            return_value=mock_client,
        ):
            client = AzureResourceGraphClient()
            with pytest.raises(ResourceDiscoveryError) as exc_info:
                await client.query_all(credential, ["sub-1"], "Resources")

        assert exc_info.value.service == "ResourceGraph"
        assert "SDK failure" in exc_info.value.reason

    @pytest.mark.asyncio
    async def test_passes_correct_subscription_ids_and_kql(self) -> None:
        mock_client = _make_client([_make_response([])])
        credential = AsyncMock()
        sub_ids = ["sub-aaa", "sub-bbb"]
        kql = "Resources | where type == 'x'"

        with patch(
            "waf_shared.discovery.resource_graph_client.ResourceGraphClient",
            return_value=mock_client,
        ):
            client = AzureResourceGraphClient()
            await client.query_all(credential, sub_ids, kql)

        call_args = mock_client.resources.call_args[0][0]
        assert call_args.subscriptions == sub_ids
        assert call_args.query == kql


@pytest.mark.unit
class TestAzureResourceGraphClientQueryPages:
    @pytest.mark.asyncio
    async def test_yields_one_page_per_api_call(self) -> None:
        pages = [
            _make_response([{"id": "r1"}], skip_token="t1"),
            _make_response([{"id": "r2"}], skip_token=None),
        ]
        mock_client = _make_client(pages)
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.resource_graph_client.ResourceGraphClient",
            return_value=mock_client,
        ):
            client = AzureResourceGraphClient()
            collected = []
            async for page in client.query_pages(credential, ["s1"], "Resources"):
                collected.append(page)

        assert len(collected) == 2
        assert collected[0] == [{"id": "r1"}]
        assert collected[1] == [{"id": "r2"}]
