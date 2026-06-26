"""Resource inventory — builds ARM resource lists via Azure Resource Graph KQL.

All queries use the Resource Graph `Resources` table and project a fixed set
of columns so the mapper is stable regardless of resource type.

Security note: resource_types and resource_group_name are validated before
injection into KQL strings. Resource Graph is read-only, so KQL injection
cannot cause data modification, but we validate inputs to prevent unexpected
cross-tenant data leakage.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from azure.core.credentials_async import AsyncTokenCredential

from waf_shared.discovery.config import DiscoveryConfig
from waf_shared.discovery.metrics import DiscoveryMetrics
from waf_shared.discovery.models import AzureResource
from waf_shared.discovery.resource_graph_client import AzureResourceGraphClient
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-shared", version="0.1.0")

# Validates ARM resource type strings (e.g. "microsoft.network/applicationgateways")
_VALID_RESOURCE_TYPE = re.compile(r"^[a-zA-Z0-9./\-]+$")
# Validates ARM resource group names
_VALID_RG_NAME = re.compile(r"^[a-zA-Z0-9_\-.()\s]+$")

_PROJECT_COLS = (
    "id, name, type, location, subscriptionId, resourceGroup, tags, sku, kind, properties"
)

_ALL_RESOURCES_KQL = f"""
Resources
| project {_PROJECT_COLS}
| order by type asc, name asc
""".strip()

_TYPED_RESOURCES_KQL = f"""
Resources
| where type in~ ({{type_list}})
| project {_PROJECT_COLS}
| order by type asc, name asc
""".strip()

_RG_RESOURCES_KQL = f"""
Resources
| where subscriptionId =~ '{{subscription_id}}' and resourceGroup =~ '{{resource_group}}'
| project {_PROJECT_COLS}
| order by type asc, name asc
""".strip()

_SINGLE_RESOURCE_KQL = f"""
Resources
| where id =~ '{{resource_id}}'
| project {_PROJECT_COLS}
| limit 1
""".strip()


class ResourceInventoryService:
    """Builds resource inventories via Azure Resource Graph KQL queries."""

    def __init__(
        self,
        graph_client: AzureResourceGraphClient | None = None,
        config: DiscoveryConfig | None = None,
        metrics: DiscoveryMetrics | None = None,
    ) -> None:
        self._config = config or DiscoveryConfig()
        _metrics = metrics or DiscoveryMetrics()
        self._graph = graph_client or AzureResourceGraphClient(
            config=self._config, metrics=_metrics
        )

    async def list_resources(
        self,
        credential: AsyncTokenCredential,
        subscription_ids: list[uuid.UUID],
        *,
        resource_types: list[str] | None = None,
    ) -> list[AzureResource]:
        """Return all resources across the given subscriptions.

        Pass resource_types to restrict results to specific ARM types
        (case-insensitive, e.g. 'microsoft.network/applicationgateways').
        """
        sub_strs = [str(s) for s in subscription_ids]
        effective_types = resource_types or self._config.default_resource_types

        if effective_types:
            _validate_resource_types(effective_types)
            type_list = ", ".join(f"'{t}'" for t in effective_types)
            kql = _TYPED_RESOURCES_KQL.format(type_list=type_list)
        else:
            kql = _ALL_RESOURCES_KQL

        rows = await self._graph.query_all(credential, sub_strs, kql)
        resources = [_map_resource(row) for row in rows]
        _logger.info(
            "discovery.resources.listed",
            subscription_count=len(subscription_ids),
            resource_count=len(resources),
        )
        return resources

    async def list_resources_in_resource_group(
        self,
        credential: AsyncTokenCredential,
        subscription_id: uuid.UUID,
        resource_group_name: str,
    ) -> list[AzureResource]:
        """Return all resources within a specific resource group."""
        if not _VALID_RG_NAME.match(resource_group_name):
            raise ValueError(f"Invalid resource group name: {resource_group_name!r}")

        kql = _RG_RESOURCES_KQL.format(
            subscription_id=str(subscription_id),
            resource_group=resource_group_name.lower(),
        )
        rows = await self._graph.query_all(credential, [str(subscription_id)], kql)
        return [_map_resource(row) for row in rows]

    async def get_resource(
        self,
        credential: AsyncTokenCredential,
        subscription_id: uuid.UUID,
        resource_id: str,
    ) -> AzureResource | None:
        """Return a single resource by full ARM resource ID, or None if not found."""
        kql = _SINGLE_RESOURCE_KQL.format(resource_id=resource_id.replace("'", "\\'"))
        rows = await self._graph.query_all(credential, [str(subscription_id)], kql)
        return _map_resource(rows[0]) if rows else None


def _validate_resource_types(types: list[str]) -> None:
    for rt in types:
        if not _VALID_RESOURCE_TYPE.match(rt):
            raise ValueError(f"Invalid resource type: {rt!r}")


def _map_resource(row: dict[str, Any]) -> AzureResource:
    sub_raw = row.get("subscriptionId") or row.get("subscription_id") or ""
    try:
        sub_id = uuid.UUID(str(sub_raw))
    except (ValueError, TypeError):
        sub_id = uuid.UUID(int=0)

    sku_raw = row.get("sku")
    sku: dict[str, Any] | None = dict(sku_raw) if isinstance(sku_raw, dict) else None

    return AzureResource(
        id=row.get("id") or "",
        name=row.get("name") or "",
        type=(row.get("type") or "").lower(),
        location=row.get("location") or "",
        subscription_id=sub_id,
        resource_group=(row.get("resourceGroup") or "").lower(),
        tags=dict(row.get("tags") or {}),
        sku=sku,
        kind=row.get("kind"),
        properties=dict(row.get("properties") or {}),
    )
