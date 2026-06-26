"""Extraction Agent message handler.

Processes one ``extraction.requested`` CloudEvent and orchestrates the full
extraction workflow for one batch:

  1.  Deserialise the CloudEventEnvelope[ExtractionRequestedEvent].
  2.  Load the Assessment from the database; skip if terminal or not found
      (safety guard against stale re-deliveries after assessment completion).
  3.  Mark the batch IN_PROGRESS.
  4.  Fetch the cross-tenant credential for the batch's subscription.
  5.  Query Azure Resource Graph for full property sets of all resource IDs in
      the batch (single batched KQL, not N individual calls).
  6.  Upsert each resource to ``assessment_resources``:
        - Found in Resource Graph → store with full ``raw_properties``.
        - Not found (deleted between scoping and extraction) → store with an
          error marker in ``raw_properties``; this is partial success, the
          batch as a whole still completes.
  7.  Re-read the Assessment to get the latest cancellation flag.
  8.  If cancellation is pending → log and return (no reasoning event).
  9.  Publish one ``reasoning.requested`` CloudEvent for this batch.

Batch lifecycle in this handler:
  - Marked IN_PROGRESS at the start of extraction.
  - Marked COMPLETED after all resources are upserted (line ~317).
  - The reasoning agent's complete_batch_and_check_fanin() then atomically
    increments the completed_batches fan-in counter.  The two COMPLETED writes
    are idempotent; the reasoning agent's atomic increment is the sole mechanism
    that detects the "last batch" condition and triggers reporting.

Error contract:
- Auth / rate-limit / discovery failures (handled errors): update batch status
  to FAILED, log, return normally.  The consumer completes the SB message so
  it is NOT retried (these failures are permanent for this batch).
- Unexpected infrastructure errors (DB failures, etc.): propagate so the
  consumer abandons the message and Service Bus retries automatically.
- Individual resource lookup failures (resource absent from RG response): stored
  with ``{"_extraction_failed": true, "_error": "…"}`` in raw_properties.  The
  batch still COMPLETES — the Reasoning Agent handles absent properties.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from waf_shared.auth.credential_provider import CrossTenantCredentialProvider
from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.db.repositories.credential_repository import CredentialRepository
from waf_shared.discovery.resource_graph_client import AzureResourceGraphClient
from waf_shared.domain.errors.infrastructure_errors import (
    AzureRateLimitError,
    CrossTenantAuthError,
    KeyVaultAccessError,
    ResourceDiscoveryError,
)
from waf_shared.domain.events.assessment_events import (
    ExtractionRequestedEvent,
    ReasoningRequestedEvent,
)
from waf_shared.domain.events.base import CloudEventEnvelope
from waf_shared.domain.models.assessment import (
    Assessment,
    AssessmentResource,
    AssessmentStatus,
    BatchStatus,
    TERMINAL_STATUSES,
)
from waf_shared.domain.models.credential import CredentialHealth
from waf_shared.messaging.queue_names import REASONING_REQUESTED
from waf_shared.messaging.service_bus import ServiceBusPublisher
from waf_shared.telemetry.logging import StructuredLogger

# Auth/rate-limit/discovery failures: mark batch FAILED, complete SB message.
# DB failures are NOT in this tuple — they propagate for SB retry.
_HANDLED_ERRORS = (
    CrossTenantAuthError,
    KeyVaultAccessError,
    AzureRateLimitError,
    ResourceDiscoveryError,
)

_EVENT_SOURCE: str = "/agents/extraction"
_REASONING_EVENT_TYPE: str = "com.wafagent.reasoning.requested"

# Sentinel written to raw_properties when a resource is absent from Resource Graph.
_EXTRACTION_FAILED_MARKER: dict[str, Any] = {
    "_extraction_failed": True,
}


class ExtractionHandler:
    """Stateless handler — all state lives in the database and Service Bus."""

    def __init__(
        self,
        *,
        assessment_repo: AssessmentRepository,
        credential_repo: CredentialRepository,
        cross_tenant_provider: CrossTenantCredentialProvider,
        resource_graph: AzureResourceGraphClient,
        publisher: ServiceBusPublisher,
        logger: StructuredLogger,
    ) -> None:
        self._assessment_repo = assessment_repo
        self._credential_repo = credential_repo
        self._cross_tenant_provider = cross_tenant_provider
        self._resource_graph = resource_graph
        self._publisher = publisher
        self._logger = logger

    # ── Public entry point ─────────────────────────────────────────────────────

    async def process(self, raw_body: bytes) -> None:
        """Deserialise one extraction.requested message and run the extraction workflow.

        Returns normally on success or handled failure.
        Propagates on unexpected infrastructure errors (consumer abandons the message).
        """
        envelope = CloudEventEnvelope.from_json_bytes(raw_body, ExtractionRequestedEvent)
        event = envelope.data
        log = self._logger.bind(
            assessment_id=str(event.assessment_id),
            tenant_id=str(event.tenant_id),
            batch_id=str(event.batch_id),
            batch_index=event.batch_index,
        )
        log.info(
            "extraction.handler.received",
            resource_count=len(event.resource_ids),
            subscription_id=str(event.subscription_id),
        )
        await self._handle(event, log)

    async def mark_batch_dead_lettered(self, raw_body: bytes) -> None:
        """Parse batch_id from a message body and mark the batch DEAD_LETTERED in the DB.

        Called by the consumer when the delivery count threshold is exceeded.
        Best-effort: the caller should handle any exception from this method.
        """
        envelope = CloudEventEnvelope.from_json_bytes(raw_body, ExtractionRequestedEvent)
        event = envelope.data
        await self._assessment_repo.update_batch_status(
            event.tenant_id,
            event.batch_id,
            BatchStatus.DEAD_LETTERED,
            error_detail="Batch dead-lettered after max delivery count exceeded",
        )

    # ── Orchestration ──────────────────────────────────────────────────────────

    async def _handle(self, event: ExtractionRequestedEvent, log: StructuredLogger) -> None:
        assessment = await self._assessment_repo.get_by_id(
            event.tenant_id, event.assessment_id
        )
        if assessment is None:
            log.error("extraction.handler.assessment_not_found")
            return

        if assessment.status in TERMINAL_STATUSES:
            log.info(
                "extraction.handler.skipped",
                status=assessment.status.value,
                reason="assessment_already_terminal",
            )
            return

        # Mark batch in-progress before any Azure calls.
        await self._assessment_repo.update_batch_status(
            event.tenant_id, event.batch_id, BatchStatus.IN_PROGRESS
        )

        try:
            await self._run_extraction(event, assessment, log)
        except _HANDLED_ERRORS as exc:
            log.error(
                "extraction.handler.batch_failed",
                exc_info=True,
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            await self._assessment_repo.update_batch_status(
                event.tenant_id,
                event.batch_id,
                BatchStatus.FAILED,
                error_detail=str(exc),
            )
        except Exception as exc:
            # Unexpected infrastructure error (DB, serialization, Service Bus).
            # Log with full details here because exc_info in the consumer's outer
            # handler is the only other place — and may be swallowed if the SB
            # abandon itself fails.
            log.error(
                "extraction.handler.stage_failed",
                exc_info=True,
                stage="unknown",
                exception_type=type(exc).__name__,
                exception_message=str(exc),
            )
            raise

    async def _run_extraction(
        self,
        event: ExtractionRequestedEvent,
        assessment: Assessment,
        log: StructuredLogger,
    ) -> None:
        # ── Stage: credential ─────────────────────────────────────────────────
        try:
            credential_record = await self._credential_repo.get_by_subscription(
                event.tenant_id, event.subscription_id
            )
            if credential_record is None:
                raise CrossTenantAuthError(
                    subscription_id=event.subscription_id,
                    reason="no credential registered for subscription; "
                           "re-register via the credentials API",
                )
            if credential_record.health in (CredentialHealth.EXPIRED, CredentialHealth.INVALID):
                raise CrossTenantAuthError(
                    subscription_id=event.subscription_id,
                    reason=f"credential health is '{credential_record.health.value}'; "
                           "rotate or re-register the credential",
                )
            azure_credential = await self._cross_tenant_provider.get_credential_for_subscription(
                event.subscription_id, credential_record.keyvault_secret_name
            )
        except _HANDLED_ERRORS:
            raise
        except Exception as exc:
            log.error(
                "extraction.handler.stage_failed",
                exc_info=True,
                stage="credential",
                exception_type=type(exc).__name__,
                exception_message=str(exc),
            )
            raise

        # ── Stage: resource_graph ─────────────────────────────────────────────
        try:
            raw_rows = await self._resource_graph.get_resource_properties(
                azure_credential,
                str(event.subscription_id),
                event.resource_ids,
            )
        except _HANDLED_ERRORS:
            raise
        except Exception as exc:
            log.error(
                "extraction.handler.stage_failed",
                exc_info=True,
                stage="resource_graph",
                exception_type=type(exc).__name__,
                exception_message=str(exc),
            )
            raise

        found_by_id: dict[str, dict[str, Any]] = {
            row["id"].lower(): row for row in raw_rows
        }
        log.info(
            "extraction.handler.rg_fetched",
            requested=len(event.resource_ids),
            returned=len(found_by_id),
        )

        # ── Stage: upsert_resources ───────────────────────────────────────────
        for resource_id in event.resource_ids:
            row = found_by_id.get(resource_id.lower())
            if row is not None:
                raw_props = _build_raw_properties(row)
                resource_type = (row.get("type") or "").lower()
                location = row.get("location") or ""
                resource_group = (row.get("resourceGroup") or "").lower()
            else:
                raw_props = {
                    **_EXTRACTION_FAILED_MARKER,
                    "_error": "resource not found in Azure Resource Graph",
                }
                resource_type, location, resource_group = _parse_arm_id(resource_id)
                log.warning(
                    "extraction.handler.resource_not_found",
                    resource_id=resource_id,
                )

            resource = AssessmentResource(
                id=uuid.uuid4(),
                assessment_id=event.assessment_id,
                batch_id=event.batch_id,
                tenant_id=event.tenant_id,
                resource_id=resource_id,
                resource_type=resource_type,
                location=location,
                subscription_id=event.subscription_id,
                resource_group=resource_group,
                raw_properties=raw_props,
                extracted_at=datetime.now(UTC),
            )
            try:
                await self._assessment_repo.upsert_resource(resource)
            except Exception as exc:
                log.error(
                    "extraction.handler.stage_failed",
                    exc_info=True,
                    stage="upsert_resource",
                    resource_id=resource_id,
                    resource_type=resource_type,
                    exception_type=type(exc).__name__,
                    exception_message=str(exc),
                )
                raise
            log.info(
                "resource.extracted",
                resource_id=resource_id,
                resource_type=resource_type,
                found=row is not None,
            )

        # ── Stage: complete_batch ─────────────────────────────────────────────
        await self._assessment_repo.update_batch_status(
            event.tenant_id, event.batch_id, BatchStatus.COMPLETED
        )
        log.info(
            "extraction.handler.batch_completed",
            resource_count=len(event.resource_ids),
        )

        # ── Stage: publish_reasoning ──────────────────────────────────────────
        refreshed = await self._assessment_repo.get_by_id(
            event.tenant_id, event.assessment_id
        )
        if refreshed is not None and refreshed.is_cancellation_pending:
            log.info("extraction.handler.cancelled_before_publish")
            return

        total_batches = (refreshed.total_batches if refreshed is not None else None) or 0
        try:
            await self._publisher.publish(
                REASONING_REQUESTED,
                CloudEventEnvelope.wrap(
                    event_type=_REASONING_EVENT_TYPE,
                    source=_EVENT_SOURCE,
                    data=ReasoningRequestedEvent(
                        assessment_id=event.assessment_id,
                        tenant_id=event.tenant_id,
                        batch_id=event.batch_id,
                        subscription_id=event.subscription_id,
                        batch_index=event.batch_index,
                        total_batches=total_batches,
                    ),
                ),
            )
        except Exception as exc:
            log.error(
                "extraction.handler.stage_failed",
                exc_info=True,
                stage="publish_reasoning",
                exception_type=type(exc).__name__,
                exception_message=str(exc),
            )
            raise
        log.info(
            "extraction.handler.reasoning_published",
            batch_index=event.batch_index,
            total_batches=total_batches,
        )


# ── Helpers ────────────────────────────────────────────────────────────────────


def _build_raw_properties(row: dict[str, Any]) -> dict[str, Any]:
    """Return the full Resource Graph row as the stored raw_properties dict."""
    return {
        "id": row.get("id", ""),
        "name": row.get("name", ""),
        "type": row.get("type", ""),
        "location": row.get("location", ""),
        "resourceGroup": row.get("resourceGroup", ""),
        "subscriptionId": row.get("subscriptionId", ""),
        "tenantId": row.get("tenantId", ""),
        "properties": row.get("properties") or {},
        "tags": row.get("tags") or {},
        "sku": row.get("sku"),
        "kind": row.get("kind"),
        "identity": row.get("identity"),
        "zones": row.get("zones"),
        "managedBy": row.get("managedBy"),
    }


def _parse_arm_id(resource_id: str) -> tuple[str, str, str]:
    """Extract (resource_type, location, resource_group) from an ARM resource ID.

    ARM IDs have the form:
      /subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}

    Location is not embedded in ARM IDs; we return an empty string for it.
    """
    parts = resource_id.lower().split("/")
    try:
        rg_idx = parts.index("resourcegroups")
        resource_group = parts[rg_idx + 1] if rg_idx + 1 < len(parts) else ""
    except ValueError:
        resource_group = ""

    try:
        prov_idx = parts.index("providers")
        namespace = parts[prov_idx + 1] if prov_idx + 1 < len(parts) else ""
        kind = parts[prov_idx + 2] if prov_idx + 2 < len(parts) else ""
        resource_type = f"{namespace}/{kind}" if namespace and kind else ""
    except ValueError:
        resource_type = ""

    return resource_type, "", resource_group
