"""Preparation Agent message handler.

Processes one ``assessment.created`` CloudEvent from the Service Bus consumer
loop and orchestrates the full preparation workflow:

  1. Deserialise the CloudEventEnvelope[AssessmentCreatedEvent].
  2. Load the Assessment from the database; skip if not in PENDING/PREPARING.
  3. Validate the pillar filter against the five well-known WAF pillars.
  4. Check for a pending cancellation request before starting work.
  5. Discover Azure resources for every requested subscription in parallel
     (bounded concurrency via asyncio.Semaphore).
  6. Apply any tag filter client-side (ResourceInventoryService has no tag param).
  7. Create AssessmentBatch records in the database with globally unique indices.
  8. Re-check cancellation before publishing downstream events.
  9. Publish one ``extraction.requested`` event per batch.
 10. Update assessment status to EXTRACTING.

Error contract:
- Validation/auth/discovery failures (handled errors): update assessment to
  FAILED, log the reason, return normally so the consumer completes the message.
- Unexpected infrastructure errors (DB failures, etc.): propagate so the
  consumer can abandon the message and let Service Bus retry.
- Re-delivery safety: if the assessment is already PREPARING and batches exist,
  the handler either reuses them (all batches present) or clears partial batches
  and re-runs discovery (partial failure restart).
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from waf_shared.auth.credential_provider import CrossTenantCredentialProvider
from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.db.repositories.credential_repository import CredentialRepository
from waf_shared.discovery.models import AzureResource
from waf_shared.discovery.resource_inventory import ResourceInventoryService
from waf_shared.discovery.subscription_discovery import SubscriptionDiscoveryService
from waf_shared.domain.errors.domain_errors import (
    InvalidAssessmentScopeError,
    SubscriptionNotFoundError,
)
from waf_shared.domain.errors.infrastructure_errors import (
    AzureRateLimitError,
    CrossTenantAuthError,
    KeyVaultAccessError,
    ResourceDiscoveryError,
)
from waf_shared.domain.events.assessment_events import (
    AssessmentCreatedEvent,
    ExtractionRequestedEvent,
)
from waf_shared.domain.events.base import CloudEventEnvelope
from waf_shared.domain.models.assessment import (
    Assessment,
    AssessmentBatch,
    AssessmentStatus,
    BatchStatus,
)
from waf_shared.domain.models.credential import CredentialHealth
from waf_shared.messaging.queue_names import EXTRACTION_REQUESTED
from waf_shared.messaging.service_bus import ServiceBusPublisher
from waf_shared.telemetry.logging import StructuredLogger

# Errors that indicate a permanent problem with the assessment's scope or
# credentials.  These cause the assessment to be marked FAILED and the Service
# Bus message to be completed (not retried).
_HANDLED_ERRORS = (
    InvalidAssessmentScopeError,
    SubscriptionNotFoundError,
    CrossTenantAuthError,
    KeyVaultAccessError,
    AzureRateLimitError,
    ResourceDiscoveryError,
)

VALID_PILLARS: frozenset[str] = frozenset(
    {
        "Reliability",
        "Security",
        "Cost Optimization",
        "Operational Excellence",
        "Performance Efficiency",
    }
)

BATCH_SIZE: int = 50
_EVENT_SOURCE: str = "/agents/preparation"
_EXTRACTION_EVENT_TYPE: str = "com.wafagent.extraction.requested"


class PreparationHandler:
    """Stateless handler — all state lives in the database and Service Bus."""

    def __init__(
        self,
        *,
        assessment_repo: AssessmentRepository,
        credential_repo: CredentialRepository,
        cross_tenant_provider: CrossTenantCredentialProvider,
        subscription_discovery: SubscriptionDiscoveryService,
        resource_inventory: ResourceInventoryService,
        publisher: ServiceBusPublisher,
        logger: StructuredLogger,
        max_concurrent_subscriptions: int = 5,
    ) -> None:
        self._assessment_repo = assessment_repo
        self._credential_repo = credential_repo
        self._cross_tenant_provider = cross_tenant_provider
        self._subscription_discovery = subscription_discovery
        self._resource_inventory = resource_inventory
        self._publisher = publisher
        self._logger = logger
        self._semaphore = asyncio.Semaphore(max_concurrent_subscriptions)

    # ── Public entry point ─────────────────────────────────────────────────────

    async def process(self, raw_body: bytes) -> None:
        """Deserialise one assessment.created message and run the preparation workflow.

        Returns normally on success or handled failure.
        Propagates on unexpected infrastructure errors (consumer abandons the message).
        """
        envelope = CloudEventEnvelope.from_json_bytes(raw_body, AssessmentCreatedEvent)
        event = envelope.data
        log = self._logger.bind(
            assessment_id=str(event.assessment_id),
            tenant_id=str(event.tenant_id),
        )
        log.info("preparation.handler.received", subscription_count=len(event.subscription_ids))
        await self._handle(event, log)

    # ── Orchestration ──────────────────────────────────────────────────────────

    async def _handle(self, event: AssessmentCreatedEvent, log: StructuredLogger) -> None:
        assessment = await self._assessment_repo.get_by_id(event.tenant_id, event.assessment_id)
        if assessment is None:
            log.error("preparation.handler.assessment_not_found")
            return

        if assessment.status not in (AssessmentStatus.PENDING, AssessmentStatus.PREPARING):
            log.info(
                "preparation.handler.skipped",
                status=assessment.status.value,
                reason="already_processed",
            )
            return

        # Snapshot existing batches before transitioning (idempotency for re-delivery).
        existing_batches = await self._assessment_repo.list_batches(
            event.tenant_id, event.assessment_id
        )

        # Idempotent: if already PREPARING this is a no-op.
        assessment = await self._assessment_repo.update_status(
            event.tenant_id, event.assessment_id, AssessmentStatus.PREPARING
        )

        try:
            await self._run_preparation(assessment, existing_batches, log)
        except _HANDLED_ERRORS as exc:
            log.error(
                "preparation.handler.failed",
                exc_info=True,
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            await self._assessment_repo.update_status(
                event.tenant_id, event.assessment_id, AssessmentStatus.FAILED
            )

    async def _run_preparation(
        self,
        assessment: Assessment,
        existing_batches: list[AssessmentBatch],
        log: StructuredLogger,
    ) -> None:
        # Step 1 — validate pillar filter
        if assessment.pillar_filter:
            unknown = set(assessment.pillar_filter) - VALID_PILLARS
            if unknown:
                raise InvalidAssessmentScopeError(
                    f"Unknown WAF pillars: {sorted(unknown)!r}.  "
                    f"Valid pillars: {sorted(VALID_PILLARS)!r}"
                )

        # Step 2 — pre-flight cancellation gate
        if assessment.is_cancellation_pending:
            log.info("preparation.handler.cancelled_before_start")
            await self._assessment_repo.update_status(
                assessment.tenant_id, assessment.id, AssessmentStatus.CANCELLED
            )
            return

        # Step 3 — resolve batches (idempotent re-delivery handling)
        all_batches = await self._resolve_batches(assessment, existing_batches, log)

        if not all_batches:
            raise InvalidAssessmentScopeError(
                "No Azure resources found within scope across all requested subscriptions"
            )

        # Step 4 — persist total_batches (only update if value changed to avoid extra write)
        if assessment.total_batches != len(all_batches):
            await self._assessment_repo.set_total_batches(
                assessment.tenant_id, assessment.id, len(all_batches)
            )

        # Step 5 — final cancellation gate before publishing downstream events
        refreshed = await self._assessment_repo.get_by_id(assessment.tenant_id, assessment.id)
        if refreshed is not None and refreshed.is_cancellation_pending:
            log.info("preparation.handler.cancelled_before_publish")
            await self._assessment_repo.update_status(
                assessment.tenant_id, assessment.id, AssessmentStatus.CANCELLED
            )
            return

        # Step 6 — publish extraction.requested events
        for batch in all_batches:
            await self._publisher.publish(
                EXTRACTION_REQUESTED,
                CloudEventEnvelope.wrap(
                    event_type=_EXTRACTION_EVENT_TYPE,
                    source=_EVENT_SOURCE,
                    data=ExtractionRequestedEvent(
                        assessment_id=assessment.id,
                        tenant_id=assessment.tenant_id,
                        batch_id=batch.id,
                        subscription_id=batch.subscription_id,
                        batch_index=batch.batch_index,
                        resource_ids=batch.resource_ids,
                    ),
                ),
            )

        # Step 7 — transition to EXTRACTING
        await self._assessment_repo.update_status(
            assessment.tenant_id, assessment.id, AssessmentStatus.EXTRACTING
        )
        log.info(
            "preparation.handler.completed",
            total_batches=len(all_batches),
            subscription_count=len(assessment.subscription_ids),
        )

    # ── Idempotency / batch resolution ────────────────────────────────────────

    async def _resolve_batches(
        self,
        assessment: Assessment,
        existing_batches: list[AssessmentBatch],
        log: StructuredLogger,
    ) -> list[AssessmentBatch]:
        """Return the list of batches to use, handling re-delivery gracefully.

        - No existing batches → normal discovery path.
        - All batches already created (total_batches matches count) → reuse.
        - Partial batches (previous run failed mid-way) → delete and rediscover.
        """
        if not existing_batches:
            return await self._discover_and_create_batches(assessment, log)

        if assessment.total_batches is not None and assessment.total_batches == len(
            existing_batches
        ):
            log.warning(
                "preparation.handler.redelivery_reusing_batches",
                batch_count=len(existing_batches),
            )
            return existing_batches

        log.warning(
            "preparation.handler.redelivery_partial_cleanup",
            partial_count=len(existing_batches),
            expected=assessment.total_batches,
        )
        await self._assessment_repo.delete_all_batches(assessment.tenant_id, assessment.id)
        return await self._discover_and_create_batches(assessment, log)

    # ── Resource discovery ─────────────────────────────────────────────────────

    async def _discover_and_create_batches(
        self,
        assessment: Assessment,
        log: StructuredLogger,
    ) -> list[AssessmentBatch]:
        """Discover resources for all subscriptions in parallel, then create batches."""
        discover_tasks = [
            self._discover_resources_for_subscription(
                assessment, sub_id, assessment.tag_filter, log
            )
            for sub_id in assessment.subscription_ids
        ]

        # return_exceptions=True so we can attribute errors to the right subscription.
        results = await asyncio.gather(*discover_tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, BaseException):
                log.error(
                    "preparation.handler.subscription_failed",
                    subscription_id=str(assessment.subscription_ids[i]),
                    error_type=type(result).__name__,
                )
                raise result  # type: ignore[misc]

        # Assign globally unique batch_index values AFTER all resources are
        # collected so parallel coroutines cannot collide on the same index.
        all_batches: list[AssessmentBatch] = []
        for sub_id, resources in zip(assessment.subscription_ids, results, strict=False):
            resources_list: list[AzureResource] = resources  # type: ignore[assignment]
            for chunk in _chunks(resources_list, BATCH_SIZE):
                batch = await self._assessment_repo.create_batch(
                    AssessmentBatch(
                        id=uuid.uuid4(),
                        assessment_id=assessment.id,
                        tenant_id=assessment.tenant_id,
                        batch_index=len(all_batches),
                        subscription_id=sub_id,
                        status=BatchStatus.PENDING,
                        resource_ids=[r.id for r in chunk],
                        error_detail=None,
                        started_at=None,
                        completed_at=None,
                        created_at=datetime.now(UTC),
                    )
                )
                all_batches.append(batch)
                log.info(
                    "preparation.handler.batch_created",
                    batch_index=batch.batch_index,
                    subscription_id=str(sub_id),
                    resource_count=len(chunk),
                )

        return all_batches

    async def _discover_resources_for_subscription(
        self,
        assessment: Assessment,
        subscription_id: uuid.UUID,
        tag_filter: dict[str, str] | None,
        log: StructuredLogger,
    ) -> list[AzureResource]:
        async with self._semaphore:
            return await self._do_discover(assessment, subscription_id, tag_filter, log)

    async def _do_discover(
        self,
        assessment: Assessment,
        subscription_id: uuid.UUID,
        tag_filter: dict[str, str] | None,
        log: StructuredLogger,
    ) -> list[AzureResource]:
        # 1. Look up registered credential record for this subscription.
        credential_record = await self._credential_repo.get_by_subscription(
            assessment.tenant_id, subscription_id
        )
        if credential_record is None:
            raise InvalidAssessmentScopeError(
                f"No credential registered for subscription {subscription_id}.  "
                "Register a service principal via the credentials API first."
            )
        if credential_record.health in (CredentialHealth.EXPIRED, CredentialHealth.INVALID):
            raise InvalidAssessmentScopeError(
                f"Credential for subscription {subscription_id} has health "
                f"'{credential_record.health.value}'.  Rotate or re-register the credential."
            )

        # 2. Fetch cross-tenant credential from Key Vault.
        azure_credential = await self._cross_tenant_provider.get_credential_for_subscription(
            subscription_id, credential_record.keyvault_secret_name
        )

        # 3. Validate subscription access; raises SubscriptionNotFoundError on 404.
        await self._subscription_discovery.get_subscription(azure_credential, subscription_id)

        # 4. Enumerate resources via Azure Resource Graph.
        resources = await self._resource_inventory.list_resources(
            azure_credential, [subscription_id]
        )

        # 5. Apply tag filter client-side (ResourceInventoryService has no tag param).
        if tag_filter:
            resources = [
                r for r in resources if all(r.tags.get(k) == v for k, v in tag_filter.items())
            ]

        log.info(
            "preparation.handler.subscription_scoped",
            subscription_id=str(subscription_id),
            resource_count=len(resources),
            tag_filtered=tag_filter is not None,
        )
        return resources


# ── Helpers ───────────────────────────────────────────────────────────────────


def _chunks(lst: list[Any], n: int) -> Iterator[list[Any]]:
    for i in range(0, len(lst), n):
        yield lst[i : i + n]
