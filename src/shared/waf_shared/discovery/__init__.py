"""Azure resource discovery layer."""

from waf_shared.discovery.advisor_client import AzureAdvisorClient
from waf_shared.discovery.config import DiscoveryConfig
from waf_shared.discovery.metrics import DiscoveryMetrics
from waf_shared.discovery.models import (
    AdvisorCategory,
    AdvisorImpact,
    AdvisorRecommendation,
    AzureResource,
    AzureSubscription,
    ResourceGroup,
    ResourceType,
    SubscriptionState,
)
from waf_shared.discovery.resource_graph_client import AzureResourceGraphClient
from waf_shared.discovery.resource_group_discovery import ResourceGroupDiscoveryService
from waf_shared.discovery.resource_inventory import ResourceInventoryService
from waf_shared.discovery.retry import with_azure_retry
from waf_shared.discovery.subscription_discovery import SubscriptionDiscoveryService

__all__ = [
    # Config
    "DiscoveryConfig",
    # Metrics
    "DiscoveryMetrics",
    # Models
    "AdvisorCategory",
    "AdvisorImpact",
    "AdvisorRecommendation",
    "AzureResource",
    "AzureSubscription",
    "ResourceGroup",
    "ResourceType",
    "SubscriptionState",
    # Clients
    "AzureAdvisorClient",
    "AzureResourceGraphClient",
    # Services
    "ResourceGroupDiscoveryService",
    "ResourceInventoryService",
    "SubscriptionDiscoveryService",
    # Helpers
    "with_azure_retry",
]
