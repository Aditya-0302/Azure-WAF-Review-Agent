"""Reasoning Agent entry point — Service Bus consumer loop.

Lifecycle:
  1. Read config from environment (ReasoningConfig).
  2. Build platform credential (Managed / Workload Identity).
  3. Connect to PostgreSQL pool and create all repository / service instances.
  4. Build the configured LLM provider via create_llm_provider() (Gemini or Azure).
  5. Start an asyncio consumer loop that pulls one message at a time from the
     ``reasoning.requested`` queue.
  6. On SIGTERM / SIGINT: set a stop flag, drain in-flight message, shut down.

LLM provider selection:
  LLM_PROVIDER=gemini (default)  — uses Google Gemini; requires GEMINI_API_KEY.
  LLM_PROVIDER=azure             — uses Azure OpenAI; requires AZURE_OPENAI_* vars.

Message settlement:
  - handler.process() returns normally → complete_message (ack).
  - handler.process() raises anything  → abandon_message (nack / requeue).
  - After max_delivery_count retries Service Bus dead-letters the message.

Lock renewal:
  LLM calls + full-batch DB inserts can collectively exceed 60 seconds.
  A background task renews the message lock every 30 s.
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
from waf_shared.db.repositories.finding_repository import FindingRepository
from waf_shared.db.repositories.rule_repository import WafRuleRepository
from waf_shared.discovery.advisor_client import AzureAdvisorClient
from waf_shared.llm.factory import create_llm_provider
from waf_shared.messaging.queue_names import REASONING_REQUESTED
from waf_shared.messaging.service_bus import ServiceBusPublisher
from waf_shared.runtime.signals import install_signal_handlers
from waf_shared.telemetry.logging import StructuredLogger, configure_structlog
from waf_catalog.catalog import WafCatalog
from waf_catalog.startup import (
    CatalogStartupError,
    build_coverage_report,
    format_coverage_failure,
    validate_catalog_startup,
)
from waf_reasoning.config import ReasoningConfig
from waf_reasoning.deterministic_pipeline import DeterministicPipeline
from waf_reasoning.handler import ReasoningHandler
from waf_reasoning.llm_pipeline import LLMPipeline
from waf_reasoning.property_compressor import PropertyCompressor

_LOCK_RENEWAL_INTERVAL = 30    # seconds; must be < Service Bus lock duration (default 60 s)
_RECEIVE_TIMEOUT = 5.0         # max seconds to wait for next message before re-checking stop


async def main() -> None:
    configure_structlog(json_output=True)
    logger = StructuredLogger(service="waf-reasoning-agent", version="0.1.0")

    config = ReasoningConfig()

    logger.info(
        "reasoning.main.starting",
        namespace=config.servicebus_namespace,
        llm_provider=config.llm_provider,
    )

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

    # ── LLM provider ──────────────────────────────────────────────────────────
    # ReasoningConfig.validate_llm_provider() guarantees required vars are set.
    # The factory raises a clear ValueError at startup for invalid/missing config
    # rather than letting the error surface during message processing.
    llm_provider = create_llm_provider(
        provider=config.llm_provider,
        # Gemini
        gemini_api_key=(
            config.gemini_api_key.get_secret_value()
            if config.gemini_api_key
            else ""
        ),
        gemini_chat_model=config.gemini_chat_model,
        # Azure OpenAI
        azure_openai_endpoint=config.azure_openai_endpoint,
        azure_openai_api_version=config.azure_openai_api_version,
        azure_openai_deployment_chat=config.azure_openai_deployment_chat,
        azure_openai_credential=platform_credential,
    )
    logger.info("reasoning.main.llm_provider_ready", model=llm_provider.model_id())

    # ── WAF catalog startup validation ────────────────────────────────────────
    # Fail fast if the catalog files are missing, corrupt, or fail integrity
    # checks.  This prevents the agent from accepting messages that would
    # produce findings with permanently empty WAF traceability.
    catalog = WafCatalog.get_instance()
    try:
        validate_catalog_startup(catalog)
    except CatalogStartupError as exc:
        logger.error(
            "reasoning.main.catalog_startup_failed",
            error=str(exc),
        )
        raise

    logger.info(
        "reasoning.main.catalog_loaded",
        controls=len(catalog.get_all_controls()),
        mappings=len(catalog.get_mapped_rule_ids()),
    )

    # Rule coverage check: every active production rule in the DB must have a mapping.
    # Rule IDs with a "TEST-" prefix are integration-test fixtures inserted by the
    # test suite (see tests/integration/db/test_repositories.py).  They carry no WAF
    # control semantics and must never block agent startup.
    _rule_repo_startup = WafRuleRepository(pool=db)
    active_rules = await _rule_repo_startup.list_active()
    production_rule_ids = [r.rule_id for r in active_rules if not r.rule_id.startswith("TEST-")]
    test_fixture_ids = [r.rule_id for r in active_rules if r.rule_id.startswith("TEST-")]
    if test_fixture_ids:
        logger.warning(
            "reasoning.main.test_fixture_rules_skipped",
            count=len(test_fixture_ids),
            rule_ids=sorted(test_fixture_ids),
        )
    coverage = build_coverage_report(catalog, production_rule_ids)

    if not coverage.is_complete:
        msg = format_coverage_failure(coverage)
        logger.error(
            "reasoning.main.catalog_coverage_failed",
            missing_count=coverage.missing_count,
            total_rules=coverage.total_rules,
            missing_rule_ids=coverage.missing_rule_ids,
        )
        raise CatalogStartupError(msg)

    logger.info(
        "reasoning.main.catalog_coverage_ok",
        rules_covered=coverage.mapped_count,
        coverage_pct=coverage.coverage_percentage,
    )

    compressor = PropertyCompressor()
    det_pipeline = DeterministicPipeline(logger=logger)
    llm_pipeline = LLMPipeline(
        llm=llm_provider,
        compressor=compressor,
        logger=logger,
    )

    cross_tenant_provider = CrossTenantCredentialProvider(
        keyvault_uri=config.keyvault_uri,
        platform_provider=platform_provider,
    )

    handler = ReasoningHandler(
        assessment_repo=AssessmentRepository(pool=db),
        finding_repo=FindingRepository(pool=db),
        rule_repo=WafRuleRepository(pool=db),
        credential_repo=CredentialRepository(pool=db),
        cross_tenant_provider=cross_tenant_provider,
        advisor_client=AzureAdvisorClient(),
        deterministic_pipeline=det_pipeline,
        llm_pipeline=llm_pipeline,
        publisher=publisher,
        logger=logger,
    )

    stop_event = asyncio.Event()
    install_signal_handlers(stop_event)

    try:
        await _run_consumer(handler, config, platform_credential, stop_event, logger)
    finally:
        logger.info("reasoning.main.shutting_down")
        await publisher.close()
        await db.disconnect()
        await cross_tenant_provider.close()
        await platform_provider.close()
        logger.info("reasoning.main.stopped")


async def _run_consumer(
    handler: ReasoningHandler,
    config: ReasoningConfig,
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
            queue_name=REASONING_REQUESTED,
            max_wait_time=_RECEIVE_TIMEOUT,
        ) as receiver:
            logger.info("reasoning.main.consumer_started", queue=REASONING_REQUESTED)

            while not stop_event.is_set():
                try:
                    messages = await receiver.receive_messages(
                        max_message_count=1,
                        max_wait_time=_RECEIVE_TIMEOUT,
                    )
                except ServiceBusError:
                    logger.error("reasoning.main.receive_error", exc_info=True)
                    await asyncio.sleep(2.0)
                    continue

                for msg in messages:
                    await _process_one(handler, receiver, msg, logger)

    logger.info("reasoning.main.consumer_stopped")


async def _process_one(
    handler: ReasoningHandler,
    receiver: Any,
    msg: Any,
    logger: StructuredLogger,
) -> None:
    renewal_task = asyncio.create_task(
        _renew_lock_periodically(receiver, msg, logger)
    )
    try:
        body = b"".join(msg.body)
        await handler.process(body)
        await receiver.complete_message(msg)
        logger.info(
            "reasoning.main.message_completed",
            delivery_count=msg.delivery_count,
        )
    except Exception:
        logger.error(
            "reasoning.main.message_failed",
            exc_info=True,
            delivery_count=msg.delivery_count,
        )
        try:
            await receiver.abandon_message(msg)
        except Exception:
            logger.error("reasoning.main.abandon_failed", exc_info=True)
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
            logger.debug("reasoning.main.lock_renewed")
        except Exception:
            logger.warning("reasoning.main.lock_renewal_failed", exc_info=True)
            return  # Lock lost; outer handler surfaces the failure.


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
