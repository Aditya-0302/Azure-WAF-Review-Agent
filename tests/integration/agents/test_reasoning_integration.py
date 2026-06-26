"""Integration tests for the Reasoning Agent.

Scope:
  - ReasoningHandler wired to real (in-memory / fake) collaborators.
  - No real PostgreSQL or Azure OpenAI — DB repositories and the LLM provider
    are replaced with fakes that behave like the real implementations.
  - Service Bus publisher is mocked (AsyncMock).
  - Focus: end-to-end message flow, fan-in, cancellation gate, finding
    counts, and reporting event content.

All tests are asynchronous (asyncio_mode = "auto" in pyproject.toml).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from waf_shared.domain.events.assessment_events import (
    ReasoningRequestedEvent,
    ReportingRequestedEvent,
)
from waf_shared.domain.events.base import CloudEventEnvelope
from waf_shared.domain.models.assessment import (
    Assessment,
    AssessmentResource,
    AssessmentStatus,
    BatchStatus,
)
from waf_shared.domain.models.finding import Finding, FindingStatus, Severity
from waf_shared.domain.models.rule import EvaluationType, Pillar, WafRule


# ── Fake infrastructure helpers ────────────────────────────────────────────────

def _ts() -> datetime:
    return datetime.now(UTC)


def _make_assessment(
    *,
    status: AssessmentStatus = AssessmentStatus.REASONING,
    pillar_filter: list[str] | None = None,
    total_batches: int = 1,
    completed_batches: int = 0,
    cancellation_requested_at: datetime | None = None,
) -> Assessment:
    return Assessment(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        idempotency_key=str(uuid.uuid4()),
        status=status,
        subscription_ids=[uuid.uuid4()],
        pillar_filter=pillar_filter,
        tag_filter=None,
        requested_by_oid=str(uuid.uuid4()),
        total_batches=total_batches,
        completed_batches=completed_batches,
        cancellation_requested_at=cancellation_requested_at,
        created_at=_ts(),
        updated_at=_ts(),
    )


def _make_resource(
    assessment: Assessment,
    *,
    raw_properties: dict[str, Any] | None = None,
) -> AssessmentResource:
    return AssessmentResource(
        id=uuid.uuid4(),
        assessment_id=assessment.id,
        batch_id=uuid.uuid4(),
        tenant_id=assessment.tenant_id,
        resource_id=f"/subscriptions/{assessment.subscription_ids[0]}/rg/vm/{uuid.uuid4()}",
        resource_type="microsoft.compute/virtualmachines",
        location="eastus",
        subscription_id=assessment.subscription_ids[0],
        resource_group="rg",
        raw_properties=raw_properties or {"name": "vm1", "zones": []},
        extracted_at=_ts(),
    )


def _make_rule(
    *,
    evaluation_type: EvaluationType = EvaluationType.DETERMINISTIC,
    condition_dsl: dict[str, Any] | None = None,
) -> WafRule:
    return WafRule(
        id=uuid.uuid4(),
        rule_id="REL-VM-001",
        pillar=Pillar.RELIABILITY,
        resource_types=["microsoft.compute/virtualmachines"],
        evaluation_type=evaluation_type,
        condition_dsl=condition_dsl or {"op": "length_gte", "path": "zones", "value": 1},
        prompt_template_ref=None,
        severity="high",
        title="Availability Zones",
        description="VMs should be zone-redundant.",
        recommendation="Deploy across availability zones.",
        is_active=True,
        version=1,
        created_at=_ts(),
        updated_at=_ts(),
    )


def _make_finding(assessment: Assessment) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        assessment_id=assessment.id,
        batch_id=uuid.uuid4(),
        tenant_id=assessment.tenant_id,
        rule_id="REL-VM-001",
        resource_id="r1",
        resource_type="microsoft.compute/virtualmachines",
        status=FindingStatus.OPEN,
        severity=Severity.HIGH,
        pillar=Pillar.RELIABILITY.value,
        confidence_score=1.0,
        title="Availability Zones",
        recommendation="Deploy across zones.",
        evidence={"result": "FAIL"},
        evaluation_type="deterministic",
        created_at=_ts(),
    )


def _build_raw_event(
    assessment: Assessment,
    *,
    batch_id: uuid.UUID | None = None,
    batch_index: int = 0,
    total_batches: int = 1,
) -> bytes:
    batch_id = batch_id or uuid.uuid4()
    event = ReasoningRequestedEvent(
        assessment_id=assessment.id,
        tenant_id=assessment.tenant_id,
        batch_id=batch_id,
        batch_index=batch_index,
        total_batches=total_batches,
        pillar_filter=assessment.pillar_filter,
        subscription_id=assessment.subscription_ids[0],
    )
    env = CloudEventEnvelope.wrap(
        event_type="com.wafagent.reasoning.requested",
        source="/agents/orchestrator",
        data=event,
    )
    return env.to_json_bytes()


def _build_handler(
    *,
    assessment: Assessment,
    resources: list[AssessmentResource] | None = None,
    rules: list[WafRule] | None = None,
    existing_findings: list[Finding] | None = None,
    fanin_result: bool = True,
    det_findings: list[Finding] | None = None,
    llm_findings: list[Finding] | None = None,
    include_llm_pipeline: bool = False,
) -> tuple[Any, AsyncMock]:
    """Build a handler with all dependencies as mocks."""
    from waf_reasoning.deterministic_pipeline import DeterministicPipeline
    from waf_reasoning.handler import ReasoningHandler
    from waf_reasoning.llm_pipeline import LLMPipeline

    assessment_repo = MagicMock()
    assessment_repo.get_by_id = AsyncMock(return_value=assessment)
    assessment_repo.list_resources_by_batch = AsyncMock(return_value=resources or [])
    assessment_repo.update_batch_status = AsyncMock()
    assessment_repo.update_status = AsyncMock()
    assessment_repo.complete_batch_and_check_fanin = AsyncMock(return_value=fanin_result)

    finding_repo = MagicMock()
    finding_repo.create_batch = AsyncMock()
    finding_repo.count_by_pillar = AsyncMock(
        return_value={"reliability": len(existing_findings or [])}
    )

    rule_repo = MagicMock()
    rule_repo.list_active = AsyncMock(return_value=rules or [])

    advisor_client = MagicMock()
    advisor_client.list_recommendations = AsyncMock(return_value=[])

    det_pipeline = MagicMock(spec=DeterministicPipeline)
    det_pipeline.evaluate = MagicMock(return_value=det_findings or [])

    llm_pipeline_instance: Any = None
    if include_llm_pipeline:
        llm_pipeline_instance = MagicMock(spec=LLMPipeline)
        llm_pipeline_instance.evaluate = AsyncMock(return_value=llm_findings or [])

    publisher = MagicMock()
    publisher.publish = AsyncMock()

    logger = MagicMock()
    logger.bind = MagicMock(return_value=logger)
    logger.info = MagicMock()
    logger.warning = MagicMock()
    logger.error = MagicMock()
    logger.debug = MagicMock()

    handler = ReasoningHandler(
        assessment_repo=assessment_repo,
        finding_repo=finding_repo,
        rule_repo=rule_repo,
        advisor_client=advisor_client,
        deterministic_pipeline=det_pipeline,
        llm_pipeline=llm_pipeline_instance,
        publisher=publisher,
        logger=logger,
    )

    return handler, publisher


# ── Test: Full happy path (single batch, single finding) ──────────────────────

class TestReasoningIntegrationHappyPath:
    @pytest.mark.asyncio
    async def test_single_resource_finding_triggers_reporting(self):
        assessment = _make_assessment()
        resource = _make_resource(assessment)
        rule = _make_rule()
        finding = _make_finding(assessment)

        handler, publisher = _build_handler(
            assessment=assessment,
            resources=[resource],
            rules=[rule],
            det_findings=[finding],
            existing_findings=[finding],
            fanin_result=True,
        )

        raw = _build_raw_event(assessment)
        await handler.process(raw)

        publisher.publish.assert_awaited_once()
        call_args = publisher.publish.call_args
        topic = call_args[0][0]
        assert "reporting" in topic

        envelope_arg = call_args[0][1]
        payload = json.loads(envelope_arg.to_json_bytes())
        assert payload["data"]["assessment_id"] == str(assessment.id)
        assert payload["data"]["total_findings"] == 1

    @pytest.mark.asyncio
    async def test_non_last_batch_does_not_publish_reporting(self):
        assessment = _make_assessment(total_batches=3)
        resource = _make_resource(assessment)
        rule = _make_rule()
        finding = _make_finding(assessment)

        handler, publisher = _build_handler(
            assessment=assessment,
            resources=[resource],
            rules=[rule],
            det_findings=[finding],
            fanin_result=False,  # not the last batch
        )

        raw = _build_raw_event(assessment, total_batches=3)
        await handler.process(raw)

        publisher.publish.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_batch_still_participates_in_fanin(self):
        assessment = _make_assessment()

        handler, publisher = _build_handler(
            assessment=assessment,
            resources=[],  # no resources
            fanin_result=True,
        )

        raw = _build_raw_event(assessment)
        await handler.process(raw)

        # Fan-in was called even for empty batch.
        handler._assessment_repo.complete_batch_and_check_fanin.assert_awaited_once()
        # And reporting was published since this was the last batch.
        publisher.publish.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_zero_findings_reporting_event_has_zero_total(self):
        assessment = _make_assessment()
        resource = _make_resource(assessment, raw_properties={"name": "vm1", "zones": ["1", "2"]})
        rule = _make_rule(condition_dsl={"op": "length_gte", "path": "zones", "value": 1})

        handler, publisher = _build_handler(
            assessment=assessment,
            resources=[resource],
            rules=[rule],
            det_findings=[],  # all pass
            existing_findings=[],
            fanin_result=True,
        )
        handler._finding_repo.count_by_pillar = AsyncMock(return_value={})

        raw = _build_raw_event(assessment)
        await handler.process(raw)

        call_args = publisher.publish.call_args
        envelope_arg = call_args[0][1]
        payload = json.loads(envelope_arg.to_json_bytes())
        assert payload["data"]["total_findings"] == 0


# ── Test: Terminal and cancelled assessments ───────────────────────────────────

class TestReasoningIntegrationSkipGuards:
    @pytest.mark.asyncio
    async def test_completed_assessment_is_skipped(self):
        assessment = _make_assessment(status=AssessmentStatus.COMPLETED)

        handler, publisher = _build_handler(assessment=assessment)
        raw = _build_raw_event(assessment)
        await handler.process(raw)

        publisher.publish.assert_not_awaited()
        handler._assessment_repo.complete_batch_and_check_fanin.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_failed_assessment_is_skipped(self):
        assessment = _make_assessment(status=AssessmentStatus.FAILED)

        handler, publisher = _build_handler(assessment=assessment)
        raw = _build_raw_event(assessment)
        await handler.process(raw)

        publisher.publish.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_cancelled_before_start_skips_all(self):
        assessment = _make_assessment(cancellation_requested_at=_ts())

        handler, publisher = _build_handler(assessment=assessment)
        raw = _build_raw_event(assessment)
        await handler.process(raw)

        publisher.publish.assert_not_awaited()
        handler._assessment_repo.complete_batch_and_check_fanin.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_cancelled_after_fanin_skips_reporting(self):
        """Cancellation detected between fan-in and publishing should block reporting."""
        assessment_pre = _make_assessment()
        assessment_post = _make_assessment(
            status=AssessmentStatus.REASONING,
            cancellation_requested_at=_ts(),
        )
        assessment_post.id = assessment_pre.id
        assessment_post.tenant_id = assessment_pre.tenant_id

        resource = _make_resource(assessment_pre)

        handler, publisher = _build_handler(
            assessment=assessment_pre,
            resources=[resource],
            rules=[],
            fanin_result=True,
        )
        # After fan-in triggers, get_by_id returns the cancelled version.
        handler._assessment_repo.get_by_id = AsyncMock(
            side_effect=[assessment_pre, assessment_post]
        )

        raw = _build_raw_event(assessment_pre)
        await handler.process(raw)

        publisher.publish.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_none_assessment_is_skipped(self):
        assessment = _make_assessment()

        handler, publisher = _build_handler(assessment=assessment)
        handler._assessment_repo.get_by_id = AsyncMock(return_value=None)

        raw = _build_raw_event(assessment)
        await handler.process(raw)

        publisher.publish.assert_not_awaited()


# ── Test: Extraction-failed resources ─────────────────────────────────────────

class TestReasoningIntegrationExtractionFailed:
    @pytest.mark.asyncio
    async def test_extraction_failed_resource_is_skipped(self):
        assessment = _make_assessment()
        bad_resource = _make_resource(
            assessment,
            raw_properties={"_extraction_failed": True, "error": "Timeout"},
        )
        rule = _make_rule()

        handler, publisher = _build_handler(
            assessment=assessment,
            resources=[bad_resource],
            rules=[rule],
            fanin_result=True,
        )

        raw = _build_raw_event(assessment)
        await handler.process(raw)

        # Det pipeline must not have been called for extraction-failed resource.
        handler._deterministic_pipeline.evaluate.assert_not_called()
        # But fan-in and reporting still happen.
        handler._assessment_repo.complete_batch_and_check_fanin.assert_awaited_once()
        publisher.publish.assert_awaited_once()


# ── Test: LLM pipeline integration ────────────────────────────────────────────

class TestReasoningIntegrationLLMPipeline:
    @pytest.mark.asyncio
    async def test_llm_findings_merged_with_deterministic(self):
        from waf_shared.domain.errors.infrastructure_errors import LLMQuotaExhaustedError

        assessment = _make_assessment()
        resource = _make_resource(assessment)
        det_rule = _make_rule(evaluation_type=EvaluationType.DETERMINISTIC)
        llm_rule = _make_rule(
            evaluation_type=EvaluationType.LLM,
            condition_dsl=None,
        )

        det_finding = _make_finding(assessment)
        llm_finding = _make_finding(assessment)

        handler, publisher = _build_handler(
            assessment=assessment,
            resources=[resource],
            rules=[det_rule, llm_rule],
            det_findings=[det_finding],
            llm_findings=[llm_finding],
            existing_findings=[det_finding, llm_finding],
            include_llm_pipeline=True,
            fanin_result=True,
        )
        handler._finding_repo.count_by_pillar = AsyncMock(return_value={"reliability": 2})

        raw = _build_raw_event(assessment)
        await handler.process(raw)

        create_batch_call = handler._finding_repo.create_batch.call_args
        findings_arg = create_batch_call[0][1]
        assert len(findings_arg) == 2

    @pytest.mark.asyncio
    async def test_llm_quota_exhausted_marks_batch_failed(self):
        from waf_shared.domain.errors.infrastructure_errors import LLMQuotaExhaustedError

        assessment = _make_assessment()
        resource = _make_resource(assessment)
        llm_rule = _make_rule(evaluation_type=EvaluationType.LLM, condition_dsl=None)

        handler, publisher = _build_handler(
            assessment=assessment,
            resources=[resource],
            rules=[llm_rule],
            include_llm_pipeline=True,
        )
        handler._llm_pipeline.evaluate = AsyncMock(
            side_effect=LLMQuotaExhaustedError(deployment="gpt-4o")
        )

        raw = _build_raw_event(assessment)
        await handler.process(raw)

        # Batch should be marked FAILED (not just abandoned).
        handler._assessment_repo.update_batch_status.assert_awaited_once()
        call_kwargs = handler._assessment_repo.update_batch_status.call_args
        status_arg = call_kwargs[0][2] if call_kwargs[0] else call_kwargs[1].get("status")
        assert status_arg == BatchStatus.FAILED

        # Should NOT publish reporting.
        publisher.publish.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_llm_generic_error_absorbed_batch_completes(self):
        assessment = _make_assessment()
        resource = _make_resource(assessment)
        llm_rule = _make_rule(evaluation_type=EvaluationType.LLM, condition_dsl=None)

        handler, publisher = _build_handler(
            assessment=assessment,
            resources=[resource],
            rules=[llm_rule],
            include_llm_pipeline=True,
            fanin_result=True,
        )
        handler._llm_pipeline.evaluate = AsyncMock(
            side_effect=RuntimeError("transient error")
        )
        handler._finding_repo.count_by_pillar = AsyncMock(return_value={})

        raw = _build_raw_event(assessment)
        await handler.process(raw)

        # Batch still completes and reporting is published.
        handler._assessment_repo.complete_batch_and_check_fanin.assert_awaited_once()
        publisher.publish.assert_awaited_once()


# ── Test: Pillar filter restricts rules ───────────────────────────────────────

class TestReasoningIntegrationPillarFilter:
    @pytest.mark.asyncio
    async def test_pillar_filter_restricts_to_matching_pillar(self):
        assessment = _make_assessment(pillar_filter=["Reliability"])
        resource = _make_resource(assessment)

        rel_rule = _make_rule()  # pillar=RELIABILITY
        sec_rule = WafRule(
            id=uuid.uuid4(),
            rule_id="SEC-VM-001",
            pillar=Pillar.SECURITY,
            resource_types=["microsoft.compute/virtualmachines"],
            evaluation_type=EvaluationType.DETERMINISTIC,
            condition_dsl={"op": "always_fail"},
            prompt_template_ref=None,
            severity="critical",
            title="Security Rule",
            description="desc",
            recommendation="rec",
            is_active=True,
            version=1,
            created_at=_ts(),
            updated_at=_ts(),
        )

        handler, publisher = _build_handler(
            assessment=assessment,
            resources=[resource],
            rules=[rel_rule, sec_rule],
            fanin_result=True,
        )
        handler._finding_repo.count_by_pillar = AsyncMock(return_value={})

        raw = _build_raw_event(assessment)
        await handler.process(raw)

        call_args = handler._rule_repo.list_active.call_args
        # list_active is called; pillar filtering happens in handler
        handler._rule_repo.list_active.assert_awaited()

        # The deterministic pipeline should only see the reliability rule.
        det_call = handler._deterministic_pipeline.evaluate.call_args
        rules_arg = det_call[1]["rules"] if det_call[1] else det_call[0][1]
        rule_ids = {r.rule_id for r in rules_arg}
        assert "REL-VM-001" in rule_ids
        assert "SEC-VM-001" not in rule_ids


# ── Test: Reporting event correctness ─────────────────────────────────────────

class TestReasoningIntegrationReportingEvent:
    @pytest.mark.asyncio
    async def test_reporting_event_contains_correct_assessment_id(self):
        assessment = _make_assessment()

        handler, publisher = _build_handler(
            assessment=assessment,
            resources=[],
            fanin_result=True,
        )
        handler._finding_repo.count_by_pillar = AsyncMock(return_value={"reliability": 5})

        raw = _build_raw_event(assessment)
        await handler.process(raw)

        publisher.publish.assert_awaited_once()
        env_arg = publisher.publish.call_args[0][1]
        payload = json.loads(env_arg.to_json_bytes())

        assert payload["data"]["assessment_id"] == str(assessment.id)
        assert payload["data"]["tenant_id"] == str(assessment.tenant_id)
        assert payload["data"]["total_findings"] == 5

    @pytest.mark.asyncio
    async def test_reporting_event_type_and_source(self):
        assessment = _make_assessment()

        handler, publisher = _build_handler(
            assessment=assessment,
            resources=[],
            fanin_result=True,
        )
        handler._finding_repo.count_by_pillar = AsyncMock(return_value={})

        raw = _build_raw_event(assessment)
        await handler.process(raw)

        env_arg = publisher.publish.call_args[0][1]
        payload = json.loads(env_arg.to_json_bytes())

        assert payload["type"] == "com.wafagent.reporting.requested"
        assert payload["source"] == "/agents/reasoning"
