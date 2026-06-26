"""Reporting Agent entry point — Service Bus consumer loop.

Lifecycle:
  1. Read ReportingConfig from environment.
  2. Build platform credential (Managed / Workload Identity).
  3. Connect to PostgreSQL pool; create all repositories.
  4. Build BlobServiceClient (Managed Identity).
  5. Build KeyVaultClient (Managed Identity).
  6. Start consumer loop for ``reporting.requested`` queue.
  7. On SIGTERM / SIGINT: set stop flag, drain in-flight message, shut down.

Message settlement:
  - handler.process() returns normally → complete_message (ack).
  - handler.process() raises anything  → abandon_message (nack / SB retry).

Lock renewal:
  Report generation (Excel + PDF) and Blob uploads may exceed 60 s.
  A background task renews the message lock every 30 s.

Authentication: Managed Identity for Service Bus, Blob Storage, and Key Vault.
No Spot instances — Reporting Agent pods run on a dedicated node pool.
"""

from __future__ import annotations

import asyncio
from typing import Any

from azure.servicebus.aio import ServiceBusClient
from azure.servicebus.exceptions import ServiceBusError
from azure.storage.blob.aio import BlobServiceClient
from waf_reporting.aggregator import FindingAggregator
from waf_reporting.config import ReportingConfig
from waf_reporting.excel_generator import ExcelGenerator
from waf_reporting.handler import ReportingHandler
from waf_reporting.pdf_generator import PdfGenerator
from waf_reporting.storage_uploader import StorageUploader
from waf_reporting.webhook_service import WebhookService

from waf_shared.auth.config import AuthMode, PlatformAuthConfig
from waf_shared.auth.credential_provider import create_platform_provider
from waf_shared.db.pool import DatabasePool
from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.db.repositories.finding_repository import FindingRepository
from waf_shared.db.repositories.human_review_repository import HumanReviewRepository
from waf_shared.db.repositories.report_repository import ReportRepository
from waf_shared.db.repositories.rule_repository import WafRuleRepository
from waf_shared.db.repositories.webhook_repository import WebhookRepository
from waf_shared.infra.keyvault import KeyVaultClient
from waf_shared.messaging.queue_names import REPORTING_REQUESTED
from waf_shared.runtime.signals import install_signal_handlers
from waf_shared.telemetry.logging import StructuredLogger, configure_structlog

_LOCK_RENEWAL_INTERVAL = 30  # seconds; must be < Service Bus lock duration (default 60 s)
_RECEIVE_TIMEOUT = 5.0  # max seconds to wait for next message before re-checking stop


async def main() -> None:
    configure_structlog(json_output=True)
    logger = StructuredLogger(service="waf-reporting-agent", version="0.1.0")

    config = ReportingConfig()
    logger.info("reporting.main.starting", namespace=config.servicebus_namespace)

    platform_config = PlatformAuthConfig(mode=AuthMode(config.auth_mode))
    platform_provider = create_platform_provider(platform_config)
    platform_credential = await platform_provider.get_credential()

    db = DatabasePool(
        dsn_primary=config.dsn_primary,
        dsn_readonly=config.dsn_readonly,
    )
    await db.connect()

    blob_service = BlobServiceClient(
        account_url=config.storage_account_url,
        credential=platform_credential,
    )

    kv_client = KeyVaultClient(
        vault_uri=config.keyvault_uri,
        credential=platform_credential,
    )

    assessment_repo = AssessmentRepository(pool=db)
    finding_repo = FindingRepository(pool=db)
    report_repo = ReportRepository(pool=db)
    webhook_repo = WebhookRepository(pool=db)
    human_review_repo = HumanReviewRepository(pool=db)
    rule_repo = WafRuleRepository(pool=db)

    aggregator = FindingAggregator(
        finding_repo=finding_repo,
        assessment_repo=assessment_repo,
        report_repo=report_repo,
        rule_repo=rule_repo,
    )
    excel_gen = ExcelGenerator()
    pdf_gen = PdfGenerator()
    uploader = StorageUploader(
        blob_service=blob_service,
        container_name=config.storage_reports_container,
        logger=logger,
    )
    webhook_service = WebhookService(
        webhook_repo=webhook_repo,
        logger=logger,
    )

    handler = ReportingHandler(
        assessment_repo=assessment_repo,
        finding_repo=finding_repo,
        report_repo=report_repo,
        webhook_repo=webhook_repo,
        human_review_repo=human_review_repo,
        aggregator=aggregator,
        excel_gen=excel_gen,
        pdf_gen=pdf_gen,
        uploader=uploader,
        webhook_service=webhook_service,
        kv_client=kv_client,
        logger=logger,
    )

    stop_event = asyncio.Event()
    install_signal_handlers(stop_event)

    try:
        await _run_consumer(handler, config, platform_credential, stop_event, logger)
    finally:
        logger.info("reporting.main.shutting_down")
        await blob_service.close()
        await kv_client.close()
        await db.disconnect()
        await platform_provider.close()
        logger.info("reporting.main.stopped")


async def _run_consumer(
    handler: ReportingHandler,
    config: ReportingConfig,
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
            queue_name=REPORTING_REQUESTED,
            max_wait_time=_RECEIVE_TIMEOUT,
        ) as receiver:
            logger.info("reporting.main.consumer_started", queue=REPORTING_REQUESTED)

            while not stop_event.is_set():
                try:
                    messages = await receiver.receive_messages(
                        max_message_count=1,
                        max_wait_time=_RECEIVE_TIMEOUT,
                    )
                except ServiceBusError:
                    logger.error("reporting.main.receive_error", exc_info=True)
                    await asyncio.sleep(2.0)
                    continue

                for msg in messages:
                    await _process_one(handler, receiver, msg, logger)

    logger.info("reporting.main.consumer_stopped")


async def _process_one(
    handler: ReportingHandler,
    receiver: Any,
    msg: Any,
    logger: StructuredLogger,
) -> None:
    renewal_task = asyncio.create_task(_renew_lock_periodically(receiver, msg, logger))
    try:
        body = b"".join(msg.body)
        await handler.process(body)
        await receiver.complete_message(msg)
        logger.info(
            "reporting.main.message_completed",
            delivery_count=msg.delivery_count,
        )
    except Exception:
        logger.error(
            "reporting.main.message_failed",
            exc_info=True,
            delivery_count=msg.delivery_count,
        )
        try:
            await receiver.abandon_message(msg)
        except Exception:
            logger.error("reporting.main.abandon_failed", exc_info=True)
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
            logger.debug("reporting.main.lock_renewed")
        except Exception:
            logger.warning("reporting.main.lock_renewal_failed", exc_info=True)
            return  # Lock lost; outer handler surfaces the failure.


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
