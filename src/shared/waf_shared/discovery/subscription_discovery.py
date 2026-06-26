"""Subscription discovery — lists and retrieves Azure subscription metadata."""

from __future__ import annotations

import time
import uuid

from azure.core.credentials_async import AsyncTokenCredential
from azure.core.exceptions import HttpResponseError
from azure.mgmt.subscription.aio import SubscriptionClient

from waf_shared.discovery.config import DiscoveryConfig
from waf_shared.discovery.metrics import DiscoveryMetrics
from waf_shared.discovery.models import AzureSubscription, SubscriptionState
from waf_shared.discovery.retry import with_azure_retry
from waf_shared.domain.errors.domain_errors import SubscriptionNotFoundError
from waf_shared.domain.errors.infrastructure_errors import ResourceDiscoveryError
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-shared", version="0.1.0")


class SubscriptionDiscoveryService:
    """Lists and retrieves Azure subscription metadata via ARM Subscriptions API."""

    def __init__(
        self,
        config: DiscoveryConfig | None = None,
        metrics: DiscoveryMetrics | None = None,
    ) -> None:
        self._config = config or DiscoveryConfig()
        self._metrics = metrics or DiscoveryMetrics()

    async def list_subscriptions(
        self,
        credential: AsyncTokenCredential,
    ) -> list[AzureSubscription]:
        """Return all subscriptions visible to the credential."""
        t0 = time.perf_counter()

        try:
            client = SubscriptionClient(credential)
            raw_subs: list[object] = []
            async for azure_sub in client.subscriptions.list():
                raw_subs.append(azure_sub)
            subs: list[AzureSubscription] = []
            for raw_sub in raw_subs:
                try:
                    subs.append(_map_subscription(raw_sub))
                except Exception:
                    _logger.warning(
                        "discovery.subscription.map_failed",
                        subscription_id=getattr(raw_sub, "subscription_id", "unknown"),
                    )
            self._metrics.subscriptions_discovered.add(len(subs))
            _logger.info(
                "discovery.subscriptions.listed",
                count=len(subs),
            )
            return subs
        except HttpResponseError as exc:
            self._metrics.api_errors.add(1, {"service": "subscriptions", "operation": "list"})
            raise ResourceDiscoveryError(service="SubscriptionClient", reason=str(exc)) from exc
        finally:
            self._metrics.api_call_duration.record(
                time.perf_counter() - t0, {"service": "subscriptions"}
            )

    async def get_subscription(
        self,
        credential: AsyncTokenCredential,
        subscription_id: uuid.UUID,
    ) -> AzureSubscription:
        """Fetch a single subscription by ID.

        Raises SubscriptionNotFoundError when the subscription does not exist or
        the credential cannot access it (HTTP 404).
        """
        t0 = time.perf_counter()
        _sub_id = str(subscription_id)

        async def _do_get() -> object:
            client = SubscriptionClient(credential)
            return await client.subscriptions.get(_sub_id)

        try:
            sub = await with_azure_retry(
                _do_get,
                max_attempts=self._config.retry_max_attempts,
                initial_wait=self._config.retry_initial_wait_seconds,
                backoff_factor=self._config.retry_backoff_factor,
                max_wait=self._config.retry_max_wait_seconds,
                logger=_logger,
                operation="subscriptions.get",
            )
            return _map_subscription(sub)
        except HttpResponseError as exc:
            if exc.status_code == 404:
                raise SubscriptionNotFoundError(subscription_id) from exc
            self._metrics.api_errors.add(1, {"service": "subscriptions", "operation": "get"})
            raise ResourceDiscoveryError(service="SubscriptionClient", reason=str(exc)) from exc
        finally:
            self._metrics.api_call_duration.record(
                time.perf_counter() - t0, {"service": "subscriptions"}
            )


def _map_subscription(sub: object) -> AzureSubscription:
    raw_state = getattr(sub, "state", None)
    if raw_state is not None and hasattr(raw_state, "value"):
        raw_state = raw_state.value
    try:
        state = SubscriptionState(str(raw_state))
    except ValueError:
        state = SubscriptionState.ENABLED

    sub_id_str = getattr(sub, "subscription_id", None) or ""
    arm_id = getattr(sub, "id", None) or f"/subscriptions/{sub_id_str}"

    return AzureSubscription(
        id=arm_id,
        subscription_id=uuid.UUID(sub_id_str),
        display_name=getattr(sub, "display_name", None) or "",
        state=state,
        tenant_id=getattr(sub, "tenant_id", None) or "",
        tags=dict(getattr(sub, "tags", None) or {}),
    )
