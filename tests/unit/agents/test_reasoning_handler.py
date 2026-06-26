"""Unit tests for ReasoningHandler.

All external I/O (DB, Service Bus, LLM, Advisor) is replaced with AsyncMock
so these tests run without any infrastructure.

asyncio_mode = "auto" eliminates the @pytest.mark.asyncio decorator.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from waf_shared.domain.errors.infrastructure_errors import LLMQuotaExhaustedError
from waf_shared.domain.events.assessment_events import ReasoningRequestedEvent
from waf_shared.domain.events.base import CloudEventEnvelope
from waf_shared.domain.models.assessment import (
    Assessment,
    AssessmentResource,
    AssessmentStatus,
    BatchStatus,
)
from waf_shared.domain.models.finding import Finding, FindingStatus, Severity
from waf_shared.domain.models.rule import EvaluationType, Pillar, WafRule

pytest_plugins = ["anyio"]


# ── pyproject.toml equivalent (asyncio_mode via ini_options) ──────────────────
# In conftest.py or pyproject.toml: asyncio_mode = "auto"
# Here we use pytest.ini_options in pyproject — marking individually for safety.


# ── Fixtures / helpers ─────────────────────────────────────────────────────────


def _make_assessment(
    *,
    status: AssessmentStatus = AssessmentStatus.REASONING,
    cancelled: bool = False,
    total_batches: int = 1,
    completed_batches: int = 0,
    pillar_filter: list[str] | None = None,
) -> Assessment:
    return Assessment(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        idempotency_key="test-key",
        status=status,
        subscription_ids=[uuid.uuid4()],
        pillar_filter=pillar_filter,
        tag_filter=None,
        requested_by_oid=uuid.uuid4(),
        total_batches=total_batches,
        completed_batches=completed_batches,
        cancellation_requested_at=datetime.now(UTC) if cancelled else None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def _make_resource(
    assessment_id: uuid.UUID,
    batch_id: uuid.UUID,
    tenant_id: uuid.UUID,
    *,
    resource_type: str = "microsoft.compute/virtualmachines",
    raw_properties: dict[str, Any] | None = None,
) -> AssessmentResource:
    return AssessmentResource(
        id=uuid.uuid4(),
        assessment_id=assessment_id,
        batch_id=batch_id,
        tenant_id=tenant_id,
        resource_id=f"/subscriptions/{uuid.uuid4()}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
        resource_type=resource_type,
        location="eastus",
        subscription_id=uuid.uuid4(),
        resource_group="rg",
        raw_properties=raw_properties or {"zones": ["1"], "properties": {}},
        extracted_at=datetime.now(UTC),
    )


def _make_rule(
    *,
    rule_id: str = "REL-VM-001",
    evaluation_type: EvaluationType = EvaluationType.DETERMINISTIC,
    pillar: Pillar = Pillar.RELIABILITY,
    resource_types: list[str] | None = None,
    condition_dsl: dict[str, Any] | None = None,
) -> WafRule:
    return WafRule(
        id=uuid.uuid4(),
        rule_id=rule_id,
        pillar=pillar,
        resource_types=resource_types or ["microsoft.compute/virtualmachines"],
        evaluation_type=evaluation_type,
        condition_dsl=condition_dsl or {"op": "length_gte", "path": "zones", "value": 1},
        prompt_template_ref=None,
        severity="high",
        title="Availability Zone Deployment",
        description="Ensure VMs are deployed across Availability Zones.",
        recommendation="Deploy VM to an Availability Zone.",
        is_active=True,
        version=1,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def _make_finding(assessment_id: uuid.UUID, batch_id: uuid.UUID, tenant_id: uuid.UUID) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        assessment_id=assessment_id,
        batch_id=batch_id,
        tenant_id=tenant_id,
        rule_id="REL-VM-001",
        resource_id="/subscriptions/x/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
        resource_type="microsoft.compute/virtualmachines",
        status=FindingStatus.OPEN,
        severity=Severity.HIGH,
        pillar="reliability",
        confidence_score=1.0,
        title="Availability Zone Deployment",
        recommendation="Deploy to AZ.",
        evidence={"result": "FAIL"},
        evaluation_type="deterministic",
        created_at=datetime.now(UTC),
    )


def _raw_event(
    assessment_id: uuid.UUID,
    tenant_id: uuid.UUID,
    batch_id: uuid.UUID,
    *,
    batch_index: int = 0,
    total_batches: int = 1,
    subscription_id: uuid.UUID | None = None,
) -> bytes:
    event = ReasoningRequestedEvent(
        assessment_id=assessment_id,
        tenant_id=tenant_id,
        batch_id=batch_id,
        subscription_id=subscription_id or uuid.uuid4(),
        batch_index=batch_index,
        total_batches=total_batches,
    )
    env = CloudEventEnvelope.wrap(
        event_type="com.wafagent.reasoning.requested",
        source="/agents/extraction",
        data=event,
    )
    return env.to_json_bytes()


class _Mocks:
    def __init__(self) -> None:
        self.assessment_repo = MagicMock()
        self.finding_repo = MagicMock()
        self.rule_repo = MagicMock()
        self.credential_repo = MagicMock()
        self.cross_tenant_provider = MagicMock()
        self.advisor_client = MagicMock()
        self.det_pipeline = MagicMock()
        self.llm_pipeline = MagicMock()
        self.publisher = MagicMock()
        self.logger = MagicMock()

        # Async methods
        self.assessment_repo.get_by_id = AsyncMock()
        self.assessment_repo.list_resources_by_batch = AsyncMock(return_value=[])
        self.assessment_repo.update_batch_status = AsyncMock()
        self.assessment_repo.update_status = AsyncMock()
        self.assessment_repo.complete_batch_and_check_fanin = AsyncMock(return_value=True)
        self.finding_repo.create_batch = AsyncMock()
        self.finding_repo.count_by_pillar = AsyncMock(return_value={})
        self.rule_repo.list_active = AsyncMock(return_value=[])
        self.credential_repo.get_by_subscription = AsyncMock(return_value=None)
        self.cross_tenant_provider.get_credential_for_subscription = AsyncMock()
        self.advisor_client.list_recommendations = AsyncMock(return_value=[])
        self.det_pipeline.evaluate = MagicMock(return_value=[])
        self.llm_pipeline.evaluate = AsyncMock(return_value=[])
        self.publisher.publish = AsyncMock()
        self.logger.bind = MagicMock(return_value=self.logger)
        self.logger.info = MagicMock()
        self.logger.warning = MagicMock()
        self.logger.error = MagicMock()
        self.logger.debug = MagicMock()


def _build_handler(mocks: _Mocks):
    from waf_reasoning.handler import ReasoningHandler

    return ReasoningHandler(
        assessment_repo=mocks.assessment_repo,
        finding_repo=mocks.finding_repo,
        rule_repo=mocks.rule_repo,
        credential_repo=mocks.credential_repo,
        cross_tenant_provider=mocks.cross_tenant_provider,
        advisor_client=mocks.advisor_client,
        deterministic_pipeline=mocks.det_pipeline,
        llm_pipeline=mocks.llm_pipeline,
        publisher=mocks.publisher,
        logger=mocks.logger,
    )


# ── Happy path ─────────────────────────────────────────────────────────────────


class TestReasoningHandlerHappyPath:
    @pytest.mark.asyncio
    async def test_single_resource_produces_finding_and_publishes_reporting(self):
        mocks = _Mocks()
        assessment = _make_assessment()
        batch_id = uuid.uuid4()
        resource = _make_resource(assessment.id, batch_id, assessment.tenant_id)
        finding = _make_finding(assessment.id, batch_id, assessment.tenant_id)

        mocks.assessment_repo.get_by_id.return_value = assessment
        mocks.assessment_repo.list_resources_by_batch.return_value = [resource]
        mocks.assessment_repo.complete_batch_and_check_fanin.return_value = True
        mocks.rule_repo.list_active.return_value = [_make_rule()]
        mocks.det_pipeline.evaluate.return_value = [finding]
        mocks.finding_repo.count_by_pillar.return_value = {"reliability": 1}

        handler = _build_handler(mocks)
        raw = _raw_event(assessment.id, assessment.tenant_id, batch_id, total_batches=1)
        await handler.process(raw)

        mocks.finding_repo.create_batch.assert_awaited_once()
        mocks.publisher.publish.assert_awaited_once()
        mocks.assessment_repo.update_status.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_non_last_batch_does_not_publish_reporting(self):
        mocks = _Mocks()
        assessment = _make_assessment(total_batches=3, completed_batches=1)
        batch_id = uuid.uuid4()

        mocks.assessment_repo.get_by_id.return_value = assessment
        mocks.assessment_repo.list_resources_by_batch.return_value = []
        mocks.assessment_repo.complete_batch_and_check_fanin.return_value = False

        handler = _build_handler(mocks)
        raw = _raw_event(assessment.id, assessment.tenant_id, batch_id, total_batches=3)
        await handler.process(raw)

        mocks.publisher.publish.assert_not_awaited()
        mocks.assessment_repo.update_status.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_batch_still_participates_in_fanin(self):
        mocks = _Mocks()
        assessment = _make_assessment()
        batch_id = uuid.uuid4()

        mocks.assessment_repo.get_by_id.return_value = assessment
        mocks.assessment_repo.list_resources_by_batch.return_value = []
        mocks.assessment_repo.complete_batch_and_check_fanin.return_value = True
        mocks.finding_repo.count_by_pillar.return_value = {}

        handler = _build_handler(mocks)
        raw = _raw_event(assessment.id, assessment.tenant_id, batch_id)
        await handler.process(raw)

        mocks.assessment_repo.complete_batch_and_check_fanin.assert_awaited_once()
        mocks.publisher.publish.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_reporting_event_has_correct_assessment_id(self):
        mocks = _Mocks()
        assessment = _make_assessment()
        batch_id = uuid.uuid4()

        mocks.assessment_repo.get_by_id.return_value = assessment
        mocks.assessment_repo.list_resources_by_batch.return_value = []
        mocks.assessment_repo.complete_batch_and_check_fanin.return_value = True
        mocks.finding_repo.count_by_pillar.return_value = {"reliability": 5}

        handler = _build_handler(mocks)
        raw = _raw_event(assessment.id, assessment.tenant_id, batch_id)
        await handler.process(raw)

        call_args = mocks.publisher.publish.call_args
        published_envelope = call_args[0][1]
        assert published_envelope.data.assessment_id == assessment.id
        assert published_envelope.data.total_findings == 5


# ── Skip conditions ────────────────────────────────────────────────────────────


class TestReasoningHandlerSkip:
    @pytest.mark.asyncio
    async def test_skips_completed_assessment(self):
        mocks = _Mocks()
        assessment = _make_assessment(status=AssessmentStatus.COMPLETED)
        batch_id = uuid.uuid4()

        mocks.assessment_repo.get_by_id.return_value = assessment
        handler = _build_handler(mocks)
        await handler.process(_raw_event(assessment.id, assessment.tenant_id, batch_id))

        mocks.assessment_repo.list_resources_by_batch.assert_not_awaited()
        mocks.publisher.publish.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_failed_assessment(self):
        mocks = _Mocks()
        assessment = _make_assessment(status=AssessmentStatus.FAILED)
        batch_id = uuid.uuid4()

        mocks.assessment_repo.get_by_id.return_value = assessment
        handler = _build_handler(mocks)
        await handler.process(_raw_event(assessment.id, assessment.tenant_id, batch_id))

        mocks.publisher.publish.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_cancelled_assessment(self):
        mocks = _Mocks()
        assessment = _make_assessment(status=AssessmentStatus.CANCELLED)
        batch_id = uuid.uuid4()

        mocks.assessment_repo.get_by_id.return_value = assessment
        handler = _build_handler(mocks)
        await handler.process(_raw_event(assessment.id, assessment.tenant_id, batch_id))

        mocks.publisher.publish.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_none_assessment(self):
        mocks = _Mocks()
        mocks.assessment_repo.get_by_id.return_value = None
        assessment_id = uuid.uuid4()
        tenant_id = uuid.uuid4()

        handler = _build_handler(mocks)
        await handler.process(_raw_event(assessment_id, tenant_id, uuid.uuid4()))

        mocks.publisher.publish.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_when_cancellation_pending_before_start(self):
        mocks = _Mocks()
        assessment = _make_assessment(cancelled=True)
        batch_id = uuid.uuid4()

        mocks.assessment_repo.get_by_id.return_value = assessment
        handler = _build_handler(mocks)
        await handler.process(_raw_event(assessment.id, assessment.tenant_id, batch_id))

        mocks.assessment_repo.list_resources_by_batch.assert_not_awaited()
        mocks.publisher.publish.assert_not_awaited()


# ── Cancellation gate ──────────────────────────────────────────────────────────


class TestReasoningHandlerCancellation:
    @pytest.mark.asyncio
    async def test_cancellation_after_findings_prevents_reporting_event(self):
        mocks = _Mocks()
        initial_assessment = _make_assessment()
        batch_id = uuid.uuid4()
        cancelled_assessment = _make_assessment(cancelled=True)

        mocks.assessment_repo.get_by_id.side_effect = [
            initial_assessment,  # first call: check terminal
            cancelled_assessment,  # second call: post fan-in cancellation gate
        ]
        mocks.assessment_repo.list_resources_by_batch.return_value = []
        mocks.assessment_repo.complete_batch_and_check_fanin.return_value = True

        handler = _build_handler(mocks)
        await handler.process(
            _raw_event(initial_assessment.id, initial_assessment.tenant_id, batch_id)
        )

        mocks.publisher.publish.assert_not_awaited()
        mocks.assessment_repo.update_status.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_no_cancellation_after_findings_publishes_reporting(self):
        mocks = _Mocks()
        assessment = _make_assessment()
        batch_id = uuid.uuid4()

        mocks.assessment_repo.get_by_id.return_value = assessment
        mocks.assessment_repo.list_resources_by_batch.return_value = []
        mocks.assessment_repo.complete_batch_and_check_fanin.return_value = True
        mocks.finding_repo.count_by_pillar.return_value = {}

        handler = _build_handler(mocks)
        await handler.process(_raw_event(assessment.id, assessment.tenant_id, batch_id))

        mocks.publisher.publish.assert_awaited_once()


# ── LLM pipeline integration ───────────────────────────────────────────────────


class TestReasoningHandlerLLMPipeline:
    @pytest.mark.asyncio
    async def test_llm_findings_included_in_batch_insert(self):
        mocks = _Mocks()
        assessment = _make_assessment()
        batch_id = uuid.uuid4()
        resource = _make_resource(assessment.id, batch_id, assessment.tenant_id)
        llm_rule = _make_rule(
            rule_id="CST-VM-001",
            evaluation_type=EvaluationType.LLM,
            condition_dsl=None,
        )
        # Need a prompt_template_ref for LLM rules
        llm_rule_with_ref = WafRule(
            **{**llm_rule.model_dump(), "condition_dsl": None, "prompt_template_ref": "cost-vm-001"}
        )
        llm_finding = _make_finding(assessment.id, batch_id, assessment.tenant_id)

        mocks.assessment_repo.get_by_id.return_value = assessment
        mocks.assessment_repo.list_resources_by_batch.return_value = [resource]
        mocks.assessment_repo.complete_batch_and_check_fanin.return_value = True
        mocks.rule_repo.list_active.return_value = [llm_rule_with_ref]
        mocks.det_pipeline.evaluate.return_value = []
        mocks.llm_pipeline.evaluate = AsyncMock(return_value=[llm_finding])
        mocks.finding_repo.count_by_pillar.return_value = {"reliability": 1}

        handler = _build_handler(mocks)
        await handler.process(_raw_event(assessment.id, assessment.tenant_id, batch_id))

        inserted_findings = mocks.finding_repo.create_batch.call_args[0][1]
        assert any(f.id == llm_finding.id for f in inserted_findings)

    @pytest.mark.asyncio
    async def test_llm_quota_exhausted_marks_batch_failed(self):
        mocks = _Mocks()
        assessment = _make_assessment()
        batch_id = uuid.uuid4()
        resource = _make_resource(assessment.id, batch_id, assessment.tenant_id)
        llm_rule = _make_rule(evaluation_type=EvaluationType.LLM)

        mocks.assessment_repo.get_by_id.return_value = assessment
        mocks.assessment_repo.list_resources_by_batch.return_value = [resource]
        mocks.rule_repo.list_active.return_value = [llm_rule]
        mocks.det_pipeline.evaluate.return_value = []
        mocks.llm_pipeline.evaluate = AsyncMock(
            side_effect=LLMQuotaExhaustedError(deployment="gpt-4o-2024-11-20")
        )

        handler = _build_handler(mocks)
        await handler.process(_raw_event(assessment.id, assessment.tenant_id, batch_id))

        mocks.assessment_repo.update_batch_status.assert_awaited_once()
        call_args = mocks.assessment_repo.update_batch_status.call_args
        assert call_args[0][2] == BatchStatus.FAILED

    @pytest.mark.asyncio
    async def test_no_llm_pipeline_skips_llm_rules(self):
        from waf_reasoning.handler import ReasoningHandler

        mocks = _Mocks()
        assessment = _make_assessment()
        batch_id = uuid.uuid4()
        resource = _make_resource(assessment.id, batch_id, assessment.tenant_id)
        llm_rule = _make_rule(evaluation_type=EvaluationType.LLM)

        mocks.assessment_repo.get_by_id.return_value = assessment
        mocks.assessment_repo.list_resources_by_batch.return_value = [resource]
        mocks.assessment_repo.complete_batch_and_check_fanin.return_value = False
        mocks.rule_repo.list_active.return_value = [llm_rule]
        mocks.det_pipeline.evaluate.return_value = []

        handler = ReasoningHandler(
            assessment_repo=mocks.assessment_repo,
            finding_repo=mocks.finding_repo,
            rule_repo=mocks.rule_repo,
            credential_repo=mocks.credential_repo,
            cross_tenant_provider=mocks.cross_tenant_provider,
            advisor_client=mocks.advisor_client,
            deterministic_pipeline=mocks.det_pipeline,
            llm_pipeline=None,  # Disabled
            publisher=mocks.publisher,
            logger=mocks.logger,
        )
        await handler.process(_raw_event(assessment.id, assessment.tenant_id, batch_id))

        mocks.finding_repo.create_batch.assert_not_awaited()


# ── Deterministic pipeline integration ────────────────────────────────────────


class TestReasoningHandlerDeterministicPipeline:
    @pytest.mark.asyncio
    async def test_deterministic_findings_inserted_correctly(self):
        mocks = _Mocks()
        assessment = _make_assessment()
        batch_id = uuid.uuid4()
        resource = _make_resource(assessment.id, batch_id, assessment.tenant_id)
        rule = _make_rule()
        finding = _make_finding(assessment.id, batch_id, assessment.tenant_id)

        mocks.assessment_repo.get_by_id.return_value = assessment
        mocks.assessment_repo.list_resources_by_batch.return_value = [resource]
        mocks.assessment_repo.complete_batch_and_check_fanin.return_value = False
        mocks.rule_repo.list_active.return_value = [rule]
        mocks.det_pipeline.evaluate.return_value = [finding]

        handler = _build_handler(mocks)
        await handler.process(_raw_event(assessment.id, assessment.tenant_id, batch_id))

        mocks.finding_repo.create_batch.assert_awaited_once()
        inserted = mocks.finding_repo.create_batch.call_args[0][1]
        assert any(f.id == finding.id for f in inserted)

    @pytest.mark.asyncio
    async def test_extraction_failed_resource_is_skipped(self):
        mocks = _Mocks()
        assessment = _make_assessment()
        batch_id = uuid.uuid4()
        resource = _make_resource(
            assessment.id,
            batch_id,
            assessment.tenant_id,
            raw_properties={"_extraction_failed": True, "_error": "not found"},
        )

        mocks.assessment_repo.get_by_id.return_value = assessment
        mocks.assessment_repo.list_resources_by_batch.return_value = [resource]
        mocks.assessment_repo.complete_batch_and_check_fanin.return_value = False
        mocks.rule_repo.list_active.return_value = [_make_rule()]

        handler = _build_handler(mocks)
        await handler.process(_raw_event(assessment.id, assessment.tenant_id, batch_id))

        mocks.det_pipeline.evaluate.assert_not_called()

    @pytest.mark.asyncio
    async def test_pillar_filter_restricts_rules_loaded(self):
        mocks = _Mocks()
        assessment = _make_assessment(pillar_filter=["Security"])
        batch_id = uuid.uuid4()
        resource = _make_resource(assessment.id, batch_id, assessment.tenant_id)

        mocks.assessment_repo.get_by_id.return_value = assessment
        mocks.assessment_repo.list_resources_by_batch.return_value = [resource]
        mocks.assessment_repo.complete_batch_and_check_fanin.return_value = False
        # Rule repo returns a Reliability rule → should be filtered out by pillar
        mocks.rule_repo.list_active.return_value = [_make_rule(pillar=Pillar.RELIABILITY)]
        mocks.det_pipeline.evaluate.return_value = []

        handler = _build_handler(mocks)
        await handler.process(_raw_event(assessment.id, assessment.tenant_id, batch_id))

        # handler short-circuits when all rules are filtered out — evaluate is never called
        mocks.det_pipeline.evaluate.assert_not_called()

    @pytest.mark.asyncio
    async def test_db_error_propagates_for_abandon(self):
        from waf_shared.domain.errors.infrastructure_errors import DatabaseError

        mocks = _Mocks()
        assessment = _make_assessment()
        batch_id = uuid.uuid4()

        mocks.assessment_repo.get_by_id.return_value = assessment
        mocks.assessment_repo.list_resources_by_batch.side_effect = DatabaseError("connection lost")

        handler = _build_handler(mocks)
        with pytest.raises(DatabaseError):
            await handler.process(_raw_event(assessment.id, assessment.tenant_id, batch_id))

        mocks.publisher.publish.assert_not_awaited()
