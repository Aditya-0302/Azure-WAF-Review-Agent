"""Azure Advisor client — fetches recommendations for WAF-relevant resources."""

from __future__ import annotations

import time
import uuid

from azure.core.credentials_async import AsyncTokenCredential
from azure.core.exceptions import HttpResponseError
from azure.mgmt.advisor.aio import AdvisorManagementClient

from waf_shared.discovery.config import DiscoveryConfig
from waf_shared.discovery.metrics import DiscoveryMetrics
from waf_shared.discovery.models import AdvisorRecommendation
from waf_shared.discovery.retry import with_azure_retry
from waf_shared.domain.errors.infrastructure_errors import AdvisorAccessError
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-shared", version="0.1.0")


class AzureAdvisorClient:
    """Fetches Azure Advisor recommendations for a subscription."""

    def __init__(
        self,
        config: DiscoveryConfig | None = None,
        metrics: DiscoveryMetrics | None = None,
    ) -> None:
        self._config = config or DiscoveryConfig()
        self._metrics = metrics or DiscoveryMetrics()

    async def list_recommendations(
        self,
        credential: AsyncTokenCredential,
        subscription_id: uuid.UUID,
        *,
        category: str | None = None,
    ) -> list[AdvisorRecommendation]:
        """Return Advisor recommendations for the subscription.

        Pass category (e.g. 'Security', 'HighAvailability') to filter.
        Malformed individual recommendation objects are skipped with a warning
        rather than failing the entire call.
        """
        t0 = time.perf_counter()
        filter_str = f"Category eq '{category}'" if category else None
        _sub_id = str(subscription_id)

        async def _do_list() -> list[object]:
            client = AdvisorManagementClient(credential, _sub_id)
            return [rec async for rec in client.recommendations.list(filter=filter_str)]

        try:
            raw_recs = await with_azure_retry(
                _do_list,
                max_attempts=self._config.retry_max_attempts,
                initial_wait=self._config.retry_initial_wait_seconds,
                backoff_factor=self._config.retry_backoff_factor,
                max_wait=self._config.retry_max_wait_seconds,
                logger=_logger,
                operation="advisor.list_recommendations",
            )

            recs: list[AdvisorRecommendation] = []
            for rec in raw_recs:
                try:
                    recs.append(_map_recommendation(rec, subscription_id))
                except Exception:
                    _logger.warning(
                        "discovery.advisor.recommendation.map_failed",
                        recommendation_id=getattr(rec, "id", "unknown"),
                        subscription_id=_sub_id,
                    )

            self._metrics.advisor_recommendations_fetched.add(
                len(recs), {"subscription_id": _sub_id}
            )
            _logger.info(
                "discovery.advisor.recommendations.fetched",
                subscription_id=_sub_id,
                count=len(recs),
                category=category or "all",
            )
            return recs
        except HttpResponseError as exc:
            self._metrics.api_errors.add(
                1, {"service": "advisor", "operation": "list"}
            )
            raise AdvisorAccessError(
                subscription_id=subscription_id, reason=str(exc)
            ) from exc
        finally:
            self._metrics.api_call_duration.record(
                time.perf_counter() - t0,
                {"service": "advisor", "subscription_id": _sub_id},
            )

    async def list_security_recommendations(
        self,
        credential: AsyncTokenCredential,
        subscription_id: uuid.UUID,
    ) -> list[AdvisorRecommendation]:
        """Convenience: fetch only Security category recommendations."""
        return await self.list_recommendations(
            credential, subscription_id, category="Security"
        )

    async def list_high_availability_recommendations(
        self,
        credential: AsyncTokenCredential,
        subscription_id: uuid.UUID,
    ) -> list[AdvisorRecommendation]:
        """Convenience: fetch only HighAvailability category recommendations."""
        return await self.list_recommendations(
            credential, subscription_id, category="HighAvailability"
        )


def _map_recommendation(
    rec: object, subscription_id: uuid.UUID
) -> AdvisorRecommendation:
    short_desc = ""
    long_desc: str | None = None
    sd = getattr(rec, "short_description", None)
    if sd is not None:
        short_desc = getattr(sd, "problem", None) or ""
        long_desc = getattr(sd, "solution", None)

    resource_id = ""
    resource_type = ""
    rm = getattr(rec, "resource_metadata", None)
    if rm is not None:
        resource_id = getattr(rm, "resource_id", None) or ""
        resource_type = (getattr(rm, "source", None) or "").lower()

    return AdvisorRecommendation(
        id=getattr(rec, "id", None) or "",
        name=getattr(rec, "name", None) or "",
        category=str(getattr(rec, "category", None) or ""),
        impact=str(getattr(rec, "impact", None) or ""),
        short_description=short_desc,
        long_description=long_desc,
        resource_id=resource_id,
        resource_type=resource_type,
        subscription_id=subscription_id,
        extended_properties=dict(getattr(rec, "extended_properties", None) or {}),
        remediation=dict(getattr(rec, "remediation", None) or {}),
    )
