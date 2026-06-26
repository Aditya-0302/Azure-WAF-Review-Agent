"""OTel metric instruments for the Azure discovery layer."""

from __future__ import annotations

from opentelemetry import metrics

_METER_NAME = "com.wafagent.discovery"


class DiscoveryMetrics:
    """Singleton container for discovery-layer metric instruments."""

    def __init__(self) -> None:
        meter = metrics.get_meter(_METER_NAME)

        self.subscriptions_discovered = meter.create_counter(
            name="waf.discovery.subscriptions.discovered",
            description="Total subscriptions listed via SubscriptionClient",
            unit="1",
        )
        self.resource_groups_discovered = meter.create_counter(
            name="waf.discovery.resource_groups.discovered",
            description="Total resource groups discovered across all subscriptions",
            unit="1",
        )
        self.resources_discovered = meter.create_counter(
            name="waf.discovery.resources.discovered",
            description="Total Azure resources returned by Resource Graph queries",
            unit="1",
        )
        self.advisor_recommendations_fetched = meter.create_counter(
            name="waf.discovery.advisor.recommendations",
            description="Total Advisor recommendations fetched",
            unit="1",
        )
        self.api_call_duration = meter.create_histogram(
            name="waf.discovery.api_call.duration",
            description="Wall-clock duration of Azure management API calls",
            unit="s",
        )
        self.api_errors = meter.create_counter(
            name="waf.discovery.api.errors",
            description="Total Azure API errors during discovery operations",
            unit="1",
        )
        self.retry_attempts = meter.create_counter(
            name="waf.discovery.retry.attempts",
            description="Total retry attempts across all discovery API calls",
            unit="1",
        )
