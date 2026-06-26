"""Unit tests for AzureAdvisorClient."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from azure.core.exceptions import HttpResponseError

from waf_shared.discovery.advisor_client import AzureAdvisorClient, _map_recommendation
from waf_shared.discovery.models import AdvisorRecommendation
from waf_shared.domain.errors.infrastructure_errors import AdvisorAccessError


def _make_sdk_recommendation(
    rec_id: str | None = None,
    name: str | None = None,
    category: str = "Security",
    impact: str = "High",
    problem: str = "WAF not enabled",
    solution: str = "Enable WAF on Application Gateway",
    resource_id: str | None = None,
) -> MagicMock:
    rec = MagicMock()
    rec.id = rec_id or f"/subscriptions/sub/providers/Microsoft.Advisor/recommendations/{uuid.uuid4()}"
    rec.name = name or str(uuid.uuid4())
    rec.category = category
    rec.impact = impact

    rec.short_description = MagicMock()
    rec.short_description.problem = problem
    rec.short_description.solution = solution

    rec.resource_metadata = MagicMock()
    rec.resource_metadata.resource_id = (
        resource_id
        or "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw1"
    )
    rec.resource_metadata.source = "Microsoft.Network/applicationGateways"
    rec.extended_properties = {}
    rec.remediation = {}
    return rec


def _make_advisor_client(
    list_items: list | None = None,
    list_error: Exception | None = None,
) -> AsyncMock:
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)

    async def _list_iter(**kwargs):
        if list_error:
            raise list_error
        for item in (list_items or []):
            yield item

    client.recommendations = AsyncMock()
    client.recommendations.list = MagicMock(side_effect=lambda **kw: _list_iter(**kw))
    return client


@pytest.mark.unit
class TestAzureAdvisorClientListRecommendations:
    @pytest.mark.asyncio
    async def test_returns_mapped_recommendations(self) -> None:
        sub_id = uuid.uuid4()
        rec = _make_sdk_recommendation(category="Security", impact="High")
        mock_client = _make_advisor_client(list_items=[rec])
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.advisor_client.AdvisorManagementClient",
            return_value=mock_client,
        ):
            advisor = AzureAdvisorClient()
            result = await advisor.list_recommendations(credential, sub_id)

        assert len(result) == 1
        assert isinstance(result[0], AdvisorRecommendation)
        assert result[0].category == "Security"
        assert result[0].impact == "High"
        assert result[0].short_description == "WAF not enabled"

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_recommendations(self) -> None:
        sub_id = uuid.uuid4()
        mock_client = _make_advisor_client(list_items=[])
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.advisor_client.AdvisorManagementClient",
            return_value=mock_client,
        ):
            advisor = AzureAdvisorClient()
            result = await advisor.list_recommendations(credential, sub_id)

        assert result == []

    @pytest.mark.asyncio
    async def test_category_filter_passed_to_sdk(self) -> None:
        sub_id = uuid.uuid4()
        mock_client = _make_advisor_client(list_items=[])
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.advisor_client.AdvisorManagementClient",
            return_value=mock_client,
        ):
            advisor = AzureAdvisorClient()
            await advisor.list_recommendations(credential, sub_id, category="Security")

        call_kwargs = mock_client.recommendations.list.call_args[1]
        assert "Security" in call_kwargs.get("filter", "")

    @pytest.mark.asyncio
    async def test_no_category_passes_none_filter(self) -> None:
        sub_id = uuid.uuid4()
        mock_client = _make_advisor_client(list_items=[])
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.advisor_client.AdvisorManagementClient",
            return_value=mock_client,
        ):
            advisor = AzureAdvisorClient()
            await advisor.list_recommendations(credential, sub_id)

        call_kwargs = mock_client.recommendations.list.call_args[1]
        assert call_kwargs.get("filter") is None

    @pytest.mark.asyncio
    async def test_raises_advisor_access_error_on_http_error(self) -> None:
        sub_id = uuid.uuid4()
        error = HttpResponseError(message="Forbidden")
        error.status_code = 403
        mock_client = _make_advisor_client(list_error=error)
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.advisor_client.AdvisorManagementClient",
            return_value=mock_client,
        ):
            advisor = AzureAdvisorClient()
            with pytest.raises(AdvisorAccessError) as exc_info:
                await advisor.list_recommendations(credential, sub_id)

        assert exc_info.value.subscription_id == sub_id


@pytest.mark.unit
class TestAzureAdvisorClientConvenience:
    @pytest.mark.asyncio
    async def test_list_security_recommendations_uses_security_category(self) -> None:
        sub_id = uuid.uuid4()
        mock_client = _make_advisor_client(list_items=[])
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.advisor_client.AdvisorManagementClient",
            return_value=mock_client,
        ):
            advisor = AzureAdvisorClient()
            await advisor.list_security_recommendations(credential, sub_id)

        call_kwargs = mock_client.recommendations.list.call_args[1]
        assert "Security" in call_kwargs.get("filter", "")

    @pytest.mark.asyncio
    async def test_list_ha_recommendations_uses_high_availability_category(
        self,
    ) -> None:
        sub_id = uuid.uuid4()
        mock_client = _make_advisor_client(list_items=[])
        credential = AsyncMock()

        with patch(
            "waf_shared.discovery.advisor_client.AdvisorManagementClient",
            return_value=mock_client,
        ):
            advisor = AzureAdvisorClient()
            await advisor.list_high_availability_recommendations(credential, sub_id)

        call_kwargs = mock_client.recommendations.list.call_args[1]
        assert "HighAvailability" in call_kwargs.get("filter", "")


@pytest.mark.unit
class TestMapRecommendation:
    def test_maps_short_description(self) -> None:
        sub_id = uuid.uuid4()
        rec = _make_sdk_recommendation(
            problem="WAF not enabled", solution="Enable WAF"
        )
        result = _map_recommendation(rec, sub_id)
        assert result.short_description == "WAF not enabled"
        assert result.long_description == "Enable WAF"

    def test_maps_resource_metadata(self) -> None:
        sub_id = uuid.uuid4()
        resource_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/gw/gw1"
        rec = _make_sdk_recommendation(resource_id=resource_id)
        result = _map_recommendation(rec, sub_id)
        assert result.resource_id == resource_id
        assert "microsoft.network" in result.resource_type

    def test_handles_missing_short_description(self) -> None:
        sub_id = uuid.uuid4()
        rec = _make_sdk_recommendation()
        rec.short_description = None
        result = _map_recommendation(rec, sub_id)
        assert result.short_description == ""
        assert result.long_description is None

    def test_handles_missing_resource_metadata(self) -> None:
        sub_id = uuid.uuid4()
        rec = _make_sdk_recommendation()
        rec.resource_metadata = None
        result = _map_recommendation(rec, sub_id)
        assert result.resource_id == ""
        assert result.resource_type == ""

    def test_subscription_id_set_correctly(self) -> None:
        sub_id = uuid.uuid4()
        rec = _make_sdk_recommendation()
        result = _map_recommendation(rec, sub_id)
        assert result.subscription_id == sub_id
