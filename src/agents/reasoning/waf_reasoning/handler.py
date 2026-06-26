"""Reasoning Agent message handler.

Processes one ``reasoning.requested`` CloudEvent and orchestrates the full
reasoning pipeline for one batch:

  1.  Deserialise the CloudEventEnvelope[ReasoningRequestedEvent].
  2.  Load the Assessment; skip if terminal or not found (stale re-delivery guard).
  3.  Check cancellation flag — if pending, skip all evaluation and do not publish.
  4.  Load all AssessmentResources for this batch from the database.
  5.  For each resource:
        a. Load applicable WAF rules (filtered by resource_type and assessment
           pillar_filter, active rules only).
        b. Run DeterministicPipeline — evaluate condition_dsl; zero LLM calls.
        c. Run LLMPipeline — call Azure OpenAI for llm/hybrid rules.
        d. Run Advisor lookup — check cached Advisor recommendations for
           advisor_mapped rules (fetched lazily, once per batch subscription).
  6.  Batch-INSERT all collected findings via FindingRepository.create_batch().
  7.  Atomic fan-in: mark this batch COMPLETED in assessment_batches (idempotent);
      atomically increment assessment.completed_batches; return True if last batch.
  8.  If last batch:
        a. Update assessment status → REPORTING.
        b. Publish one ``reporting.requested`` event.

Error contract:
- LLMQuotaExhaustedError: permanent — mark batch FAILED, complete SB message.
- Individual resource LLM failures: produce REVIEW finding, continue the batch.
- DSLValidationError per rule: produce REVIEW finding, continue.
- Advisor failures: log warning, skip advisor findings, continue.
- DB errors: propagate → consumer abandons → SB retry.

Fan-in uses ``complete_batch_and_check_fanin()`` (atomic UPDATE + SELECT FOR UPDATE)
so exactly one Reasoning Agent pod publishes ``reporting.requested`` even when
multiple pods complete the final batch simultaneously.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from waf_catalog.catalog import WafCatalog
from waf_reasoning.deterministic_pipeline import DeterministicPipeline
from waf_reasoning.llm_pipeline import LLMPipeline

from waf_shared.auth.credential_provider import CrossTenantCredentialProvider
from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.db.repositories.credential_repository import CredentialRepository
from waf_shared.db.repositories.finding_repository import FindingRepository
from waf_shared.db.repositories.rule_repository import WafRuleRepository
from waf_shared.discovery.advisor_client import AzureAdvisorClient
from waf_shared.domain.errors.domain_errors import WafEnrichmentError
from waf_shared.domain.errors.infrastructure_errors import (
    AdvisorAccessError,
    AzureRateLimitError,
    LLMQuotaExhaustedError,
)
from waf_shared.domain.events.assessment_events import (
    ReasoningRequestedEvent,
    ReportingRequestedEvent,
)
from waf_shared.domain.events.base import CloudEventEnvelope
from waf_shared.domain.models.assessment import (
    TERMINAL_STATUSES,
    AssessmentResource,
    AssessmentStatus,
    BatchStatus,
)
from waf_shared.domain.models.finding import Finding, FindingStatus, Severity
from waf_shared.domain.models.rule import EvaluationType, WafRule
from waf_shared.messaging.queue_names import REPORTING_REQUESTED
from waf_shared.messaging.service_bus import ServiceBusPublisher
from waf_shared.telemetry.logging import StructuredLogger

# Permanent errors: mark batch FAILED and complete the SB message (no retry).
_HANDLED_ERRORS = (
    LLMQuotaExhaustedError,
    WafEnrichmentError,
)

_EVENT_SOURCE: str = "/agents/reasoning"
_REPORTING_EVENT_TYPE: str = "com.wafagent.reporting.requested"

# Advisor category → WAF pillar mapping (lowercase).
_ADVISOR_PILLAR_MAP: dict[str, str] = {
    "highavailability": "reliability",
    "security": "security",
    "cost": "cost_optimization",
    "performance": "performance_efficiency",
    "operationalexcellence": "operational_excellence",
}


class ReasoningHandler:
    """Stateless handler — all state lives in the database and Service Bus."""

    def __init__(
        self,
        *,
        assessment_repo: AssessmentRepository,
        finding_repo: FindingRepository,
        rule_repo: WafRuleRepository,
        advisor_client: AzureAdvisorClient,
        deterministic_pipeline: DeterministicPipeline,
        llm_pipeline: LLMPipeline | None,
        publisher: ServiceBusPublisher,
        logger: StructuredLogger,
        credential_repo: CredentialRepository | None = None,
        cross_tenant_provider: CrossTenantCredentialProvider | None = None,
    ) -> None:
        self._assessment_repo = assessment_repo
        self._finding_repo = finding_repo
        self._rule_repo = rule_repo
        self._credential_repo = credential_repo
        self._cross_tenant_provider = cross_tenant_provider
        self._advisor_client = advisor_client
        self._deterministic_pipeline = deterministic_pipeline
        self._llm_pipeline = llm_pipeline
        self._publisher = publisher
        self._logger = logger

    # ── Public entry point ─────────────────────────────────────────────────────

    async def process(self, raw_body: bytes) -> None:
        """Deserialise one reasoning.requested message and run the reasoning workflow.

        Returns normally on success or handled failure.
        Propagates on unexpected infrastructure errors (consumer abandons the message).
        """
        envelope = CloudEventEnvelope.from_json_bytes(raw_body, ReasoningRequestedEvent)
        event = envelope.data
        log = self._logger.bind(
            assessment_id=str(event.assessment_id),
            tenant_id=str(event.tenant_id),
            batch_id=str(event.batch_id),
            batch_index=event.batch_index,
            total_batches=event.total_batches,
        )
        log.info("reasoning.handler.received")
        await self._handle(event, log)

    # ── Orchestration ──────────────────────────────────────────────────────────

    async def _handle(self, event: ReasoningRequestedEvent, log: StructuredLogger) -> None:
        assessment = await self._assessment_repo.get_by_id(event.tenant_id, event.assessment_id)
        if assessment is None:
            log.error("reasoning.handler.assessment_not_found")
            return

        if assessment.status in TERMINAL_STATUSES:
            log.info(
                "reasoning.handler.skipped",
                status=assessment.status.value,
                reason="assessment_already_terminal",
            )
            return

        if assessment.is_cancellation_pending:
            log.info("reasoning.handler.cancelled_before_start")
            return

        try:
            await self._run_reasoning(event, assessment.pillar_filter, log)
        except _HANDLED_ERRORS as exc:
            log.error(
                "reasoning.handler.batch_failed",
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

    async def _run_reasoning(
        self,
        event: ReasoningRequestedEvent,
        pillar_filter: list[str] | None,
        log: StructuredLogger,
    ) -> None:
        # Step 1 — load resources for this batch.
        resources = await self._assessment_repo.list_resources_by_batch(
            event.tenant_id, event.batch_id
        )
        log.info("reasoning.handler.resources_loaded", count=len(resources))

        if not resources:
            log.warning("reasoning.handler.empty_batch")
        else:
            # Step 2 — evaluate each resource.
            all_findings = await self._evaluate_all_resources(
                resources=resources,
                event=event,
                pillar_filter=pillar_filter,
                log=log,
            )

            # Step 3 — enrich each finding with WAF control codes, titles, and URLs.
            if all_findings:
                catalog = WafCatalog.get_instance()
                enriched: list[Finding] = []
                for f in all_findings:
                    e = catalog.enrich_finding(f.rule_id)
                    enriched.append(
                        f.model_copy(
                            update={
                                "waf_codes": e.waf_codes,
                                "waf_titles": e.waf_titles,
                                "microsoft_urls": e.microsoft_urls,
                            }
                        )
                    )
                all_findings = enriched

                # Step 3a — persistence guard: every finding for a mapped rule
                # MUST have waf_codes after enrichment.  If enrichment returned
                # empty for a rule that IS in the mapping, the catalog is broken
                # (stale singleton, wrong import path, corrupt file).  Fail the
                # batch rather than inserting findings with silent empty metadata.
                mapped_rule_ids = catalog.get_mapped_rule_ids()
                enrichment_failures = [
                    f.rule_id
                    for f in all_findings
                    if f.rule_id in mapped_rule_ids and not f.waf_codes
                ]
                if enrichment_failures:
                    raise WafEnrichmentError(enrichment_failures)

            # Step 3b — batch INSERT findings (one SQL call for the whole batch).
            if all_findings:
                for _f in all_findings:
                    log.info(
                        "reasoning.handler.pre_persist_finding",
                        rule_id=_f.rule_id,
                        waf_codes=_f.waf_codes,
                        waf_titles=_f.waf_titles,
                        microsoft_urls=_f.microsoft_urls,
                    )
                await self._finding_repo.create_batch(event.tenant_id, all_findings)
                log.info(
                    "reasoning.handler.findings_inserted",
                    count=len(all_findings),
                )

        # Step 4 — atomic fan-in: mark batch complete, check if last.
        is_last = await self._assessment_repo.complete_batch_and_check_fanin(
            event.tenant_id,
            event.assessment_id,
            event.batch_id,
        )
        log.info("reasoning.handler.batch_complete", is_last_batch=is_last)

        if not is_last:
            return

        # Step 5 — last batch: re-read assessment for cancellation gate.
        refreshed = await self._assessment_repo.get_by_id(event.tenant_id, event.assessment_id)
        if refreshed is not None and refreshed.is_cancellation_pending:
            log.info("reasoning.handler.cancelled_before_reporting")
            return

        # Step 6 — count findings and transition to REPORTING.
        total_findings = await self._count_all_findings(event)

        await self._assessment_repo.update_status(
            event.tenant_id,
            event.assessment_id,
            AssessmentStatus.REPORTING,
        )

        # Step 7 — publish reporting.requested.
        await self._publisher.publish(
            REPORTING_REQUESTED,
            CloudEventEnvelope.wrap(
                event_type=_REPORTING_EVENT_TYPE,
                source=_EVENT_SOURCE,
                data=ReportingRequestedEvent(
                    assessment_id=event.assessment_id,
                    tenant_id=event.tenant_id,
                    batch_id=event.batch_id,
                    total_findings=total_findings,
                ),
            ),
        )
        log.info(
            "reasoning.handler.reporting_published",
            total_findings=total_findings,
        )

    # ── Per-resource evaluation ────────────────────────────────────────────────

    async def _evaluate_all_resources(
        self,
        *,
        resources: list[AssessmentResource],
        event: ReasoningRequestedEvent,
        pillar_filter: list[str] | None,
        log: StructuredLogger,
    ) -> list[Finding]:
        all_findings: list[Finding] = []

        # Lazily fetch Advisor recommendations for this batch's subscription.
        advisor_recs: list[Any] | None = None

        for resource in resources:
            resource_log = log.bind(resource_id=resource.resource_id)

            # Skip extraction-failed resources — no meaningful properties.
            if resource.raw_properties.get("_extraction_failed"):
                resource_log.warning("reasoning.handler.resource_skip_extraction_failed")
                continue

            rules = await self._load_applicable_rules(resource, pillar_filter)
            if not rules:
                resource_log.debug("reasoning.handler.no_applicable_rules")
                continue

            # Deterministic pipeline (always).
            det_findings = self._deterministic_pipeline.evaluate(
                resource=resource,
                rules=rules,
                assessment_id=event.assessment_id,
                batch_id=event.batch_id,
                tenant_id=event.tenant_id,
            )
            all_findings.extend(det_findings)

            # LLM pipeline (when provider is wired up).
            if self._llm_pipeline is not None:
                llm_rules = [
                    r
                    for r in rules
                    if r.evaluation_type in (EvaluationType.LLM, EvaluationType.HYBRID)
                ]
                if llm_rules:
                    llm_findings = await self._run_llm_safe(
                        resource=resource,
                        rules=llm_rules,
                        event=event,
                        log=resource_log,
                    )
                    all_findings.extend(llm_findings)

            # Advisor-mapped rules.
            advisor_rules = [
                r
                for r in rules
                if r.evaluation_type.value == "advisor_mapped"
                # hybrid rules with advisor source handled above via LLM pipeline
            ]
            if advisor_rules:
                if advisor_recs is None:
                    advisor_recs = await self._fetch_advisor_recs(event, log)
                advisor_findings = self._evaluate_advisor(
                    resource=resource,
                    rules=advisor_rules,
                    advisor_recs=advisor_recs or [],
                    event=event,
                )
                all_findings.extend(advisor_findings)

            resource_log.info(
                "reasoning.handler.resource_evaluated",
                findings_count=len(det_findings),
            )

        return all_findings

    async def _run_llm_safe(
        self,
        *,
        resource: AssessmentResource,
        rules: list[WafRule],
        event: ReasoningRequestedEvent,
        log: StructuredLogger,
    ) -> list[Finding]:
        """Run LLM pipeline; surface LLMRateLimitError but absorb other failures."""
        assert self._llm_pipeline is not None  # noqa: S101
        try:
            return await self._llm_pipeline.evaluate(
                resource=resource,
                rules=rules,
                assessment_id=event.assessment_id,
                batch_id=event.batch_id,
                tenant_id=event.tenant_id,
            )
        except LLMQuotaExhaustedError:
            raise  # Propagate — batch should be marked FAILED.
        except Exception as exc:
            log.error(
                "reasoning.handler.llm_pipeline_error",
                exc_info=True,
                resource_id=resource.resource_id,
                error=str(exc),
            )
            return []

    # ── Advisor integration ────────────────────────────────────────────────────

    async def _fetch_advisor_recs(
        self,
        event: ReasoningRequestedEvent,
        log: StructuredLogger,
    ) -> list[Any]:
        """Fetch Advisor recommendations for the batch subscription, or return []."""
        if self._credential_repo is None or self._cross_tenant_provider is None:
            return []
        try:
            cred_record = await self._credential_repo.get_by_subscription(
                event.tenant_id, event.subscription_id
            )
            if cred_record is None:
                log.warning(
                    "reasoning.handler.advisor_no_credential",
                    subscription_id=str(event.subscription_id),
                )
                return []

            credential = await self._cross_tenant_provider.get_credential_for_subscription(
                event.subscription_id, cred_record.keyvault_secret_name
            )
            return await self._advisor_client.list_recommendations(
                credential=credential,
                subscription_id=event.subscription_id,
            )
        except (AdvisorAccessError, AzureRateLimitError) as exc:
            log.warning(
                "reasoning.handler.advisor_fetch_failed",
                error=str(exc),
            )
            return []
        except Exception as exc:
            log.warning(
                "reasoning.handler.advisor_fetch_unexpected",
                exc_info=True,
                error=str(exc),
            )
            return []

    def _evaluate_advisor(
        self,
        *,
        resource: AssessmentResource,
        rules: list[WafRule],
        advisor_recs: list[Any],
        event: ReasoningRequestedEvent,
    ) -> list[Finding]:
        findings: list[Finding] = []
        resource_recs = [
            rec for rec in advisor_recs if rec.resource_id.lower() == resource.resource_id.lower()
        ]

        for rule in rules:
            matching = [rec for rec in resource_recs if _advisor_matches_rule(rec, rule)]
            if not matching:
                continue  # No advisor finding → no FAIL finding.

            for rec in matching:
                findings.append(
                    Finding(
                        id=uuid.uuid4(),
                        assessment_id=event.assessment_id,
                        batch_id=event.batch_id,
                        tenant_id=event.tenant_id,
                        rule_id=rule.rule_id,
                        resource_id=resource.resource_id,
                        resource_type=resource.resource_type,
                        status=FindingStatus.OPEN,
                        severity=Severity(rule.severity),
                        pillar=rule.pillar.value,
                        confidence_score=0.9,
                        title=rule.title,
                        recommendation=rec.long_description or rule.recommendation,
                        evidence={
                            "result": "FAIL",
                            "evaluation_type": "advisor_mapped",
                            "advisor_id": rec.id,
                            "advisor_category": rec.category,
                            "advisor_impact": rec.impact,
                            "advisor_description": rec.short_description,
                        },
                        evaluation_type="advisor_mapped",
                        created_at=datetime.now(UTC),
                    )
                )

        return findings

    # ── Helpers ────────────────────────────────────────────────────────────────

    async def _load_applicable_rules(
        self,
        resource: AssessmentResource,
        pillar_filter: list[str] | None,
    ) -> list[WafRule]:
        resource_types = [resource.resource_type, "*"]
        all_rules = await self._rule_repo.list_active(resource_types=resource_types)

        if not pillar_filter:
            return all_rules

        # Pillar filter values are human-readable ("Reliability", "Security" …).
        # The DB stores lowercase underscored values ("reliability", "cost_optimization").
        normalised = {p.lower().replace(" ", "_") for p in pillar_filter}
        return [r for r in all_rules if r.pillar.value in normalised]

    async def _count_all_findings(self, event: ReasoningRequestedEvent) -> int:
        rows = await self._finding_repo.count_by_pillar(event.tenant_id, event.assessment_id)
        return sum(rows.values())


# ── Helpers ────────────────────────────────────────────────────────────────────


def _advisor_matches_rule(rec: Any, rule: WafRule) -> bool:
    """Return True if an Advisor recommendation maps to a WAF rule."""
    rec_category = (getattr(rec, "category", "") or "").lower().replace(" ", "")
    rule_pillar = rule.pillar.value  # e.g. "reliability"
    mapped_pillar = _ADVISOR_PILLAR_MAP.get(rec_category)
    return mapped_pillar == rule_pillar
