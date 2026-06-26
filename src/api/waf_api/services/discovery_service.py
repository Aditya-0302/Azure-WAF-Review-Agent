"""Discovery service — orchestrates per-subscription Azure resource discovery.

Consumers obtain the service via get_discovery_service() FastAPI dependency.
All Azure calls use per-subscription credentials fetched from Key Vault via
AuthenticationService; the platform credential is never passed to customer APIs.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field

from azure.core.credentials_async import AsyncTokenCredential

from waf_shared.auth.auth_service import AuthenticationService
from waf_shared.discovery.advisor_client import AzureAdvisorClient
from waf_shared.discovery.config import DiscoveryConfig
from waf_shared.discovery.metrics import DiscoveryMetrics
from waf_shared.discovery.models import (
    AdvisorRecommendation,
    AzureResource,
    AzureSubscription,
    ResourceGroup,
)
from waf_shared.discovery.resource_group_discovery import ResourceGroupDiscoveryService
from waf_shared.discovery.resource_inventory import ResourceInventoryService
from waf_shared.discovery.subscription_discovery import SubscriptionDiscoveryService
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-api", version="0.1.0")


@dataclass(frozen=True)
class SubscriptionSnapshot:
    """Complete discovery result for a single subscription."""

    subscription: AzureSubscription
    resource_groups: list[ResourceGroup]
    resources: list[AzureResource]
    advisor_recommendations: list[AdvisorRecommendation] = field(default_factory=list)


class DiscoveryService:
    """High-level Azure discovery orchestrator.

    Resolves cross-tenant credentials, then fans out concurrent discovery
    calls for subscriptions, resource groups, resources, and Advisor.
    """

    def __init__(
        self,
        auth_service: AuthenticationService,
        config: DiscoveryConfig | None = None,
        metrics: DiscoveryMetrics | None = None,
    ) -> None:
        self._auth = auth_service
        _config = config or DiscoveryConfig()
        _metrics = metrics or DiscoveryMetrics()

        self._sub_svc = SubscriptionDiscoveryService(config=_config, metrics=_metrics)
        self._rg_svc = ResourceGroupDiscoveryService(config=_config, metrics=_metrics)
        self._inventory_svc = ResourceInventoryService(config=_config, metrics=_metrics)
        self._advisor_svc = AzureAdvisorClient(config=_config, metrics=_metrics)

    async def snapshot_subscription(
        self,
        subscription_id: uuid.UUID,
        keyvault_secret_name: str,
        *,
        resource_types: list[str] | None = None,
        include_advisor: bool = True,
    ) -> SubscriptionSnapshot:
        """Run a full discovery pass for one subscription.

        Fetches the cross-tenant credential from Key Vault, then concurrently
        discovers subscription metadata, resource groups, resources, and
        (optionally) Advisor recommendations.
        """
        credential: AsyncTokenCredential = (
            await self._auth.get_subscription_credential(
                subscription_id=subscription_id,
                keyvault_secret_name=keyvault_secret_name,
            )
        )

        _logger.info(
            "discovery.snapshot.start",
            subscription_id=str(subscription_id),
            include_advisor=include_advisor,
        )

        base_tasks: list = [
            self._sub_svc.get_subscription(credential, subscription_id),
            self._rg_svc.list_resource_groups(credential, subscription_id),
            self._inventory_svc.list_resources(
                credential, [subscription_id], resource_types=resource_types
            ),
        ]

        if include_advisor:
            base_tasks.append(
                self._advisor_svc.list_recommendations(credential, subscription_id)
            )

        results = await asyncio.gather(*base_tasks, return_exceptions=False)

        sub: AzureSubscription = results[0]
        rgs: list[ResourceGroup] = results[1]
        resources: list[AzureResource] = results[2]
        advisor: list[AdvisorRecommendation] = results[3] if include_advisor else []

        _logger.info(
            "discovery.snapshot.complete",
            subscription_id=str(subscription_id),
            resource_groups=len(rgs),
            resources=len(resources),
            advisor_recommendations=len(advisor),
        )

        return SubscriptionSnapshot(
            subscription=sub,
            resource_groups=rgs,
            resources=resources,
            advisor_recommendations=advisor,
        )

    async def list_resources(
        self,
        subscription_id: uuid.UUID,
        keyvault_secret_name: str,
        resource_types: list[str] | None = None,
    ) -> list[AzureResource]:
        """List resources for a subscription without running a full snapshot."""
        credential = await self._auth.get_subscription_credential(
            subscription_id=subscription_id,
            keyvault_secret_name=keyvault_secret_name,
        )
        return await self._inventory_svc.list_resources(
            credential, [subscription_id], resource_types=resource_types
        )

    async def get_advisor_recommendations(
        self,
        subscription_id: uuid.UUID,
        keyvault_secret_name: str,
        *,
        category: str | None = None,
    ) -> list[AdvisorRecommendation]:
        """Fetch Advisor recommendations for a subscription."""
        credential = await self._auth.get_subscription_credential(
            subscription_id=subscription_id,
            keyvault_secret_name=keyvault_secret_name,
        )
        return await self._advisor_svc.list_recommendations(
            credential, subscription_id, category=category
        )

    async def list_resource_groups(
        self,
        subscription_id: uuid.UUID,
        keyvault_secret_name: str,
    ) -> list[ResourceGroup]:
        """List resource groups for a subscription."""
        credential = await self._auth.get_subscription_credential(
            subscription_id=subscription_id,
            keyvault_secret_name=keyvault_secret_name,
        )
        return await self._rg_svc.list_resource_groups(credential, subscription_id)
