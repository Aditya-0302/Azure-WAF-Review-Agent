"""Azure Resource Graph client with retry and cursor-based pagination.

Executes KQL queries against the Azure Resource Graph API, yielding pages of
flat dict records. Callers never see the SDK's QueryRequest / QueryResponse
objects — only plain Python dicts.

Usage:
    client = AzureResourceGraphClient(config)
    rows = await client.query_all(credential, [str(sub_id)], kql)

    # Or stream page-by-page:
    async for page in client.query_pages(credential, [str(sub_id)], kql):
        process(page)
"""

from __future__ import annotations

import re
import time
from collections.abc import AsyncIterator
from typing import Any

# ARM resource ID: /subscriptions/{uuid}/resourceGroups/{name}/providers/{ns}/{type}/{name}[/...]
_ARM_RESOURCE_ID_RE = re.compile(
    r"^/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"/resourceGroups/[^/'\"<>]+/providers/[A-Za-z0-9.]+/[A-Za-z0-9/._-]+$",
    re.IGNORECASE,
)

from azure.core.credentials_async import AsyncTokenCredential
from azure.mgmt.resourcegraph.aio import ResourceGraphClient
from azure.mgmt.resourcegraph.models import (
    QueryRequest,
    QueryRequestOptions,
    ResultFormat,
)

from waf_shared.discovery.config import DiscoveryConfig
from waf_shared.discovery.metrics import DiscoveryMetrics
from waf_shared.discovery.retry import with_azure_retry
from waf_shared.domain.errors.infrastructure_errors import ResourceDiscoveryError
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-shared", version="0.1.0")


class AzureResourceGraphClient:
    """Async wrapper around azure-mgmt-resourcegraph with retry and pagination."""

    def __init__(
        self,
        config: DiscoveryConfig | None = None,
        metrics: DiscoveryMetrics | None = None,
    ) -> None:
        self._config = config or DiscoveryConfig()
        self._metrics = metrics or DiscoveryMetrics()

    async def query_pages(
        self,
        credential: AsyncTokenCredential,
        subscription_ids: list[str],
        kql: str,
        *,
        page_size: int | None = None,
    ) -> AsyncIterator[list[dict[str, Any]]]:
        """Yield pages of KQL query results until all pages are consumed.

        Stops after config.max_pages pages regardless of remaining skip_token
        to prevent runaway queries against large tenants.
        """
        page_size = page_size or self._config.page_size
        skip_token: str | None = None
        pages_fetched = 0

        while pages_fetched < self._config.max_pages:
            # Bind current loop state into default arguments so each iteration's
            # closure is independent even when with_azure_retry retries.
            async def _do_query(
                _cred: AsyncTokenCredential = credential,
                _subs: list[str] = subscription_ids,
                _q: str = kql,
                _ps: int = page_size,
                _st: str | None = skip_token,
            ) -> Any:
                _logger.info(
                    "discovery.resource_graph.credential_type",
                    credential_type=type(_cred).__name__,
                )
                async with ResourceGraphClient(_cred) as client:
                    options = QueryRequestOptions(
                        result_format=ResultFormat.OBJECT_ARRAY,
                        top=_ps,
                        skip_token=_st,
                    )
                    request = QueryRequest(
                        subscriptions=_subs,
                        query=_q,
                        options=options,
                    )
                    return await client.resources(request)

            t0 = time.perf_counter()
            try:
                response = await with_azure_retry(
                    _do_query,
                    max_attempts=self._config.retry_max_attempts,
                    initial_wait=self._config.retry_initial_wait_seconds,
                    backoff_factor=self._config.retry_backoff_factor,
                    max_wait=self._config.retry_max_wait_seconds,
                    logger=_logger,
                    operation="resource_graph.query",
                )
            except ResourceDiscoveryError:
                raise
            except Exception as exc:
                self._metrics.api_errors.add(1, {"service": "resource_graph", "operation": "query"})
                raise ResourceDiscoveryError(service="ResourceGraph", reason=str(exc)) from exc
            finally:
                self._metrics.api_call_duration.record(
                    time.perf_counter() - t0, {"service": "resource_graph"}
                )

            rows: list[dict[str, Any]] = response.data or []
            if rows:
                self._metrics.resources_discovered.add(len(rows))
                yield rows

            skip_token = response.skip_token
            pages_fetched += 1

            if not skip_token:
                break

        if skip_token and pages_fetched >= self._config.max_pages:
            _logger.warning(
                "discovery.resource_graph.max_pages_reached",
                max_pages=self._config.max_pages,
                subscription_count=len(subscription_ids),
            )

    async def query_all(
        self,
        credential: AsyncTokenCredential,
        subscription_ids: list[str],
        kql: str,
        *,
        page_size: int | None = None,
    ) -> list[dict[str, Any]]:
        """Collect all pages and return a single flat list."""
        results: list[dict[str, Any]] = []
        async for page in self.query_pages(credential, subscription_ids, kql, page_size=page_size):
            results.extend(page)
        return results

    async def get_resource_properties(
        self,
        credential: AsyncTokenCredential,
        subscription_id: str,
        resource_ids: list[str],
    ) -> list[dict[str, Any]]:
        """Return full property sets for the given ARM resource IDs.

        Executes a single batched KQL query that fetches all requested
        resources in one round trip.  Resources not found in Azure (deleted
        between scoping and extraction) are simply absent from the result —
        the caller is responsible for detecting missing IDs.

        Args:
            credential: Credential for the customer subscription.
            subscription_id: UUID string of the target subscription.
            resource_ids: ARM resource IDs to fetch (e.g.
                "/subscriptions/…/providers/…/resource-name").

        Returns:
            List of raw Resource Graph row dicts, one per found resource.

        Raises:
            ResourceDiscoveryError: If the KQL query fails.
            AzureRateLimitError: If Resource Graph returns HTTP 429.
        """
        if not resource_ids:
            return []

        # Validate every ID is a well-formed ARM path before interpolating into KQL.
        # This prevents KQL injection if an upstream API ever returns a malformed ID.
        invalid = [rid for rid in resource_ids if not _ARM_RESOURCE_ID_RE.match(rid)]
        if invalid:
            raise ResourceDiscoveryError(
                service="ResourceGraph",
                reason=f"Refusing to query {len(invalid)} resource IDs that do not match "
                f"the ARM resource ID format: {invalid[:3]}",
            )

        # Single-quote each ID; ARM IDs should not contain quotes, but escape anyway.
        id_literals = ", ".join(
            f"'{rid.replace(chr(39), chr(39) + chr(39))}'" for rid in resource_ids
        )
        kql = (
            f"Resources\n"
            f"| where id in~ ({id_literals})\n"
            f"| project id, name, type, location, resourceGroup, subscriptionId,"
            f" tenantId, properties, tags, sku, kind, identity, zones, managedBy\n"
            f"| order by id asc"
        )
        return await self.query_all(credential, [subscription_id], kql)
