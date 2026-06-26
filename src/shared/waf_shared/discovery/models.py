"""Domain models for Azure resource discovery."""

from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict


class ResourceType(StrEnum):
    """Well-known Azure resource types relevant to WAF assessment."""

    APPLICATION_GATEWAY = "microsoft.network/applicationgateways"
    FRONT_DOOR_CLASSIC = "microsoft.network/frontdoors"
    FRONT_DOOR_CDN = "microsoft.cdn/profiles"
    API_MANAGEMENT = "microsoft.apimanagement/service"
    APP_GATEWAY_WAF_POLICY = "microsoft.network/applicationgatewaywebapplicationfirewallpolicies"
    FRONT_DOOR_WAF_POLICY = "microsoft.network/frontdoorwebapplicationfirewallpolicies"
    VIRTUAL_NETWORK = "microsoft.network/virtualnetworks"
    PUBLIC_IP = "microsoft.network/publicipaddresses"
    LOAD_BALANCER = "microsoft.network/loadbalancers"
    TRAFFIC_MANAGER = "microsoft.network/trafficmanagerprofiles"


class SubscriptionState(StrEnum):
    ENABLED = "Enabled"
    DISABLED = "Disabled"
    DELETED = "Deleted"
    PAST_DUE = "PastDue"
    WARNED = "Warned"


class AdvisorCategory(StrEnum):
    COST = "Cost"
    HIGH_AVAILABILITY = "HighAvailability"
    OPERATIONAL_EXCELLENCE = "OperationalExcellence"
    PERFORMANCE = "Performance"
    SECURITY = "Security"


class AdvisorImpact(StrEnum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class AzureSubscription(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str  # full ARM resource ID: /subscriptions/{guid}
    subscription_id: uuid.UUID
    display_name: str
    state: SubscriptionState
    tenant_id: str
    tags: dict[str, str] = {}


class ResourceGroup(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    location: str
    subscription_id: uuid.UUID
    tags: dict[str, str] = {}
    provisioning_state: str | None = None


class AzureResource(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    type: str  # lowercase normalized e.g. "microsoft.network/applicationgateways"
    location: str
    subscription_id: uuid.UUID
    resource_group: str  # lowercase normalized
    tags: dict[str, str] = {}
    sku: dict[str, Any] | None = None
    kind: str | None = None
    properties: dict[str, Any] = {}


class AdvisorRecommendation(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    category: str  # AdvisorCategory value or raw API string
    impact: str  # AdvisorImpact value or raw API string
    short_description: str
    long_description: str | None = None
    resource_id: str  # affected resource ARM ID
    resource_type: str
    subscription_id: uuid.UUID
    extended_properties: dict[str, Any] = {}
    remediation: dict[str, Any] = {}
