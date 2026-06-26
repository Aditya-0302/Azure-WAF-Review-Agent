"""Extraction Agent entry point — Service Bus consumer loop.

Lifecycle:
  1. Read config from environment (ExtractionConfig).
  2. Build platform credential (Managed / Workload Identity).
  3. Connect to PostgreSQL pool and create all repository / service instances.
  4. Start an asyncio consumer loop that pulls one message at a time from the
     ``extraction.requested`` queue.
  5. On SIGTERM / SIGINT: set a stop flag, drain in-flight message, shut down.

Message settlement:
  - handler.process() returns normally → complete_message (ack).
  - handler.process() raises anything  → abandon_message (nack / requeue).
  - After max_delivery_count retries Service Bus dead-letters the message.

Lock renewal:
  Resource Graph queries across large batches can take > 60 s.  A background
  task renews the message lock every 30 s to prevent premature expiry.
"""

from __future__ import annotations

import asyncio
from typing import Any

from azure.servicebus.aio import ServiceBusClient
from azure.servicebus.exceptions import ServiceBusError

from waf_shared.auth.config import AuthMode, PlatformAuthConfig
from waf_shared.auth.credential_provider import (
    CrossTenantCredentialProvider,
    create_platform_provider,
)
from waf_shared.db.pool import DatabasePool
from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.db.repositories.credential_repository import CredentialRepository
from waf_shared.discovery.resource_graph_client import AzureResourceGraphClient
from waf_shared.messaging.queue_names import EXTRACTION_REQUESTED
from waf_shared.messaging.service_bus import ServiceBusPublisher
from waf_shared.runtime.signals import install_signal_handlers
from waf_shared.telemetry.logging import StructuredLogger, configure_structlog
from waf_extraction.config import ExtractionConfig
from waf_extraction.handler import ExtractionHandler

_LOCK_RENEWAL_INTERVAL = 30   # seconds; must be < Service Bus lock duration (default 60 s)
_RECEIVE_TIMEOUT = 5.0        # max seconds to wait for the next message before re-checking stop flag
_MAX_DELIVERY_COUNT = 3       # dead-letter after this many failed deliveries (0-indexed)


async def main() -> None:
    configure_structlog(json_output=True)
    logger = StructuredLogger(service="waf-extraction-agent", version="0.1.0")

    config = ExtractionConfig()

    logger.info("extraction.main.starting", namespace=config.servicebus_namespace)

    platform_config = PlatformAuthConfig(mode=AuthMode(config.auth_mode))
    platform_provider = create_platform_provider(platform_config)
    platform_credential = await platform_provider.get_credential()

    db = DatabasePool(
        dsn_primary=config.dsn_primary,
        dsn_readonly=config.dsn_readonly,
    )
    await db.connect()

    if config.servicebus_connection_string:
        publisher = ServiceBusPublisher(
            connection_string=config.servicebus_connection_string.get_secret_value(),
            logger=logger,
        )
    else:
        publisher = ServiceBusPublisher(
            fully_qualified_namespace=config.servicebus_namespace,
            credential=platform_credential,
            logger=logger,
        )

    cross_tenant_provider = CrossTenantCredentialProvider(
        keyvault_uri=config.keyvault_uri,
        platform_provider=platform_provider,
    )

    handler = ExtractionHandler(
        assessment_repo=AssessmentRepository(pool=db),
        credential_repo=CredentialRepository(pool=db),
        cross_tenant_provider=cross_tenant_provider,
        resource_graph=AzureResourceGraphClient(),
        publisher=publisher,
        logger=logger,
    )

    stop_event = asyncio.Event()
    install_signal_handlers(stop_event)

    try:
        await _run_consumer(handler, config, platform_credential, stop_event, logger)
    finally:
        logger.info("extraction.main.shutting_down")
        await publisher.close()
        await db.disconnect()
        await cross_tenant_provider.close()
        await platform_provider.close()
        logger.info("extraction.main.stopped")


async def _run_consumer(
    handler: ExtractionHandler,
    config: ExtractionConfig,
    credential: Any,
    stop_event: asyncio.Event,
    logger: StructuredLogger,
) -> None:
    if config.servicebus_connection_string:
        sb_client_ctx = ServiceBusClient.from_connection_string(
            config.servicebus_connection_string.get_secret_value()
        )
    else:
        sb_client_ctx = ServiceBusClient(
            fully_qualified_namespace=config.servicebus_namespace,
            credential=credential,
        )
    async with sb_client_ctx as sb_client:
        async with sb_client.get_queue_receiver(
            queue_name=EXTRACTION_REQUESTED,
            max_wait_time=_RECEIVE_TIMEOUT,
        ) as receiver:
            logger.info("extraction.main.consumer_started", queue=EXTRACTION_REQUESTED)

            while not stop_event.is_set():
                try:
                    messages = await receiver.receive_messages(
                        max_message_count=1,
                        max_wait_time=_RECEIVE_TIMEOUT,
                    )
                except ServiceBusError:
                    logger.error("extraction.main.receive_error", exc_info=True)
                    await asyncio.sleep(2.0)
                    continue

                for msg in messages:
                    await _process_one(handler, receiver, msg, logger)

    logger.info("extraction.main.consumer_stopped")


async def _process_one(
    handler: ExtractionHandler,
    receiver: Any,
    msg: Any,
    logger: StructuredLogger,
) -> None:
    # Materialise the body once — msg.body is a one-shot iterator.
    body = b"".join(msg.body)
    renewal_task = asyncio.create_task(
        _renew_lock_periodically(receiver, msg, logger)
    )
    try:
        await handler.process(body)
        await receiver.complete_message(msg)
        logger.info(
            "extraction.main.message_completed",
            delivery_count=msg.delivery_count,
        )
    except Exception:
        logger.error(
            "extraction.main.message_failed",
            exc_info=True,
            delivery_count=msg.delivery_count,
        )
        if msg.delivery_count >= _MAX_DELIVERY_COUNT:
            # Fail-fast: mark the batch dead-lettered in the DB so the
            # assessment can be audited / retried rather than looping forever.
            logger.error(
                "extraction.main.max_retries_exceeded",
                delivery_count=msg.delivery_count,
                threshold=_MAX_DELIVERY_COUNT,
            )
            try:
                await handler.mark_batch_dead_lettered(body)
            except Exception:
                logger.error("extraction.main.dead_letter_db_update_failed", exc_info=True)
            try:
                await receiver.dead_letter_message(
                    msg,
                    reason="MaxRetriesExceeded",
                    error_description=(
                        f"Batch failed on {msg.delivery_count + 1} consecutive deliveries; "
                        "see extraction.handler.stage_failed logs for root cause"
                    ),
                )
            except Exception:
                logger.error("extraction.main.dead_letter_failed", exc_info=True)
        else:
            try:
                await receiver.abandon_message(msg)
            except Exception:
                logger.error("extraction.main.abandon_failed", exc_info=True)
    finally:
        renewal_task.cancel()
        try:
            await renewal_task
        except asyncio.CancelledError:
            pass


async def _renew_lock_periodically(
    receiver: Any,
    msg: Any,
    logger: StructuredLogger,
) -> None:
    while True:
        await asyncio.sleep(_LOCK_RENEWAL_INTERVAL)
        try:
            await receiver.renew_message_lock(msg)
            logger.debug("extraction.main.lock_renewed")
        except Exception:
            logger.warning("extraction.main.lock_renewal_failed", exc_info=True)
            return  # lock lost; let the outer handler surface the failure


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
