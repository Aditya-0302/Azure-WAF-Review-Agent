"""Preparation Agent entry point — Service Bus consumer loop.

Lifecycle:
  1. Read config from environment (PreparationConfig).
  2. Build platform credential (Managed / Workload Identity).
  3. Connect to PostgreSQL pool and create all repository / service instances.
  4. Start an asyncio consumer loop that pulls one message at a time from the
     ``assessment.created`` queue.
  5. On SIGTERM / SIGINT: set a stop flag, drain in-flight message, shut down.

Message settlement:
  - handler.process() returns normally → complete_message (ack).
  - handler.process() raises anything  → abandon_message (nack / requeue).
  - After max_delivery_count retries Service Bus dead-letters the message.

Lock renewal:
  Resource discovery across many subscriptions can take > 60 s.  A background
  task renews the message lock every 30 s to prevent premature expiry.
"""

from __future__ import annotations

import asyncio
from typing import Any

from azure.servicebus.aio import ServiceBusClient
from azure.servicebus.exceptions import ServiceBusError
from waf_preparation.config import PreparationConfig
from waf_preparation.handler import PreparationHandler

from waf_shared.auth.config import AuthMode, PlatformAuthConfig
from waf_shared.auth.credential_provider import (
    CrossTenantCredentialProvider,
    create_platform_provider,
)
from waf_shared.db.pool import DatabasePool
from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.db.repositories.credential_repository import CredentialRepository
from waf_shared.discovery.resource_inventory import ResourceInventoryService
from waf_shared.discovery.subscription_discovery import SubscriptionDiscoveryService
from waf_shared.messaging.queue_names import ASSESSMENT_CREATED
from waf_shared.messaging.service_bus import ServiceBusPublisher
from waf_shared.runtime.signals import install_signal_handlers
from waf_shared.telemetry.logging import StructuredLogger, configure_structlog

_LOCK_RENEWAL_INTERVAL = 30  # seconds; must be < Service Bus lock duration (default 60 s)
_RECEIVE_TIMEOUT = 5.0  # max seconds to wait for the next message before re-checking stop flag


async def main() -> None:
    configure_structlog(json_output=True)
    logger = StructuredLogger(service="waf-preparation-agent", version="0.1.0")

    config = PreparationConfig()

    logger.info("preparation.main.starting", namespace=config.servicebus_namespace)

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

    handler = PreparationHandler(
        assessment_repo=AssessmentRepository(pool=db),
        credential_repo=CredentialRepository(pool=db),
        cross_tenant_provider=cross_tenant_provider,
        subscription_discovery=SubscriptionDiscoveryService(),
        resource_inventory=ResourceInventoryService(),
        publisher=publisher,
        logger=logger,
        max_concurrent_subscriptions=config.max_concurrent_subscriptions,
    )

    stop_event = asyncio.Event()
    install_signal_handlers(stop_event)

    try:
        await _run_consumer(handler, config, platform_credential, stop_event, logger)
    finally:
        logger.info("preparation.main.shutting_down")
        await publisher.close()
        await db.disconnect()
        await cross_tenant_provider.close()
        await platform_provider.close()
        logger.info("preparation.main.stopped")


async def _run_consumer(
    handler: PreparationHandler,
    config: PreparationConfig,
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
            queue_name=ASSESSMENT_CREATED,
            max_wait_time=_RECEIVE_TIMEOUT,
        ) as receiver:
            logger.info("preparation.main.consumer_started", queue=ASSESSMENT_CREATED)

            while not stop_event.is_set():
                try:
                    messages = await receiver.receive_messages(
                        max_message_count=1,
                        max_wait_time=_RECEIVE_TIMEOUT,
                    )
                except ServiceBusError:
                    logger.error("preparation.main.receive_error", exc_info=True)
                    # Brief back-off before retrying to avoid tight error loops.
                    await asyncio.sleep(2.0)
                    continue

                for msg in messages:
                    await _process_one(handler, receiver, msg, logger)

    logger.info("preparation.main.consumer_stopped")


async def _process_one(
    handler: PreparationHandler, receiver: Any, msg: Any, logger: StructuredLogger
) -> None:
    renewal_task = asyncio.create_task(_renew_lock_periodically(receiver, msg, logger))
    try:
        # azure-servicebus body is an Iterator[bytes]; join to a single bytes object.
        body = b"".join(msg.body)
        await handler.process(body)
        await receiver.complete_message(msg)
        logger.info(
            "preparation.main.message_completed",
            delivery_count=msg.delivery_count,
        )
    except Exception:
        logger.error(
            "preparation.main.message_failed",
            exc_info=True,
            delivery_count=msg.delivery_count,
        )
        try:
            await receiver.abandon_message(msg)
        except Exception:
            logger.error("preparation.main.abandon_failed", exc_info=True)
    finally:
        renewal_task.cancel()
        try:
            await renewal_task
        except asyncio.CancelledError:
            pass


async def _renew_lock_periodically(receiver: Any, msg: Any, logger: StructuredLogger) -> None:
    while True:
        await asyncio.sleep(_LOCK_RENEWAL_INTERVAL)
        try:
            await receiver.renew_message_lock(msg)
            logger.debug("preparation.main.lock_renewed")
        except Exception:
            logger.warning("preparation.main.lock_renewal_failed", exc_info=True)
            return  # lock lost; let the outer handler surface the failure


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
