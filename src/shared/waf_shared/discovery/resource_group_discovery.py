"""Resource group discovery — lists and retrieves resource groups in a subscription."""

from __future__ import annotations

import time
import uuid

from azure.core.credentials_async import AsyncTokenCredential
from azure.core.exceptions import HttpResponseError
from azure.mgmt.resource.resources.aio import ResourceManagementClient

from waf_shared.discovery.config import DiscoveryConfig
from waf_shared.discovery.metrics import DiscoveryMetrics
from waf_shared.discovery.models import ResourceGroup
from waf_shared.discovery.retry import with_azure_retry
from waf_shared.domain.errors.infrastructure_errors import ResourceDiscoveryError
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-shared", version="0.1.0")


class ResourceGroupDiscoveryService:
    """Lists and retrieves Azure resource groups within a subscription."""

    def __init__(
        self,
        config: DiscoveryConfig | None = None,
        metrics: DiscoveryMetrics | None = None,
    ) -> None:
        self._config = config or DiscoveryConfig()
        self._metrics = metrics or DiscoveryMetrics()

    async def list_resource_groups(
        self,
        credential: AsyncTokenCredential,
        subscription_id: uuid.UUID,
    ) -> list[ResourceGroup]:
        """Return all resource groups in the subscription."""
        t0 = time.perf_counter()
        _sub_id = str(subscription_id)

        try:
            client = ResourceManagementClient(credential, _sub_id)
            raw_groups: list[object] = []
            async for rg in client.resource_groups.list():
                raw_groups.append(rg)
            groups = [_map_resource_group(rg, subscription_id) for rg in raw_groups]
            self._metrics.resource_groups_discovered.add(len(groups), {"subscription_id": _sub_id})
            _logger.info(
                "discovery.resource_groups.listed",
                subscription_id=_sub_id,
                count=len(groups),
            )
            return groups
        except HttpResponseError as exc:
            self._metrics.api_errors.add(1, {"service": "resource_groups", "operation": "list"})
            raise ResourceDiscoveryError(
                service="ResourceManagementClient", reason=str(exc)
            ) from exc
        finally:
            self._metrics.api_call_duration.record(
                time.perf_counter() - t0, {"service": "resource_groups"}
            )

    async def get_resource_group(
        self,
        credential: AsyncTokenCredential,
        subscription_id: uuid.UUID,
        resource_group_name: str,
    ) -> ResourceGroup | None:
        """Return a resource group by name, or None if not found."""
        t0 = time.perf_counter()
        _sub_id = str(subscription_id)

        async def _do_get() -> object:
            client = ResourceManagementClient(credential, _sub_id)
            return await client.resource_groups.get(resource_group_name)

        try:
            rg = await with_azure_retry(
                _do_get,
                max_attempts=self._config.retry_max_attempts,
                initial_wait=self._config.retry_initial_wait_seconds,
                backoff_factor=self._config.retry_backoff_factor,
                max_wait=self._config.retry_max_wait_seconds,
                logger=_logger,
                operation="resource_groups.get",
            )
            return _map_resource_group(rg, subscription_id)
        except HttpResponseError as exc:
            if exc.status_code == 404:
                return None
            self._metrics.api_errors.add(1, {"service": "resource_groups", "operation": "get"})
            raise ResourceDiscoveryError(
                service="ResourceManagementClient", reason=str(exc)
            ) from exc
        finally:
            self._metrics.api_call_duration.record(
                time.perf_counter() - t0, {"service": "resource_groups"}
            )


def _map_resource_group(rg: object, subscription_id: uuid.UUID) -> ResourceGroup:
    provisioning_state: str | None = None
    props = getattr(rg, "properties", None)
    if props is not None:
        provisioning_state = getattr(props, "provisioning_state", None)

    return ResourceGroup(
        id=getattr(rg, "id", None) or "",
        name=getattr(rg, "name", None) or "",
        location=getattr(rg, "location", None) or "",
        subscription_id=subscription_id,
        tags=dict(getattr(rg, "tags", None) or {}),
        provisioning_state=provisioning_state,
    )
