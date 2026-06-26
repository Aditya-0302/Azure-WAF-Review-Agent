"""Unit tests for the Reasoning Agent's internal pipelines.

Covers:
  - DSL evaluator (dsl_evaluator.py): all operators
  - PropertyCompressor (property_compressor.py): path projection, budget cap
  - DeterministicPipeline (deterministic_pipeline.py): PASS/FAIL/REVIEW findings
  - LLMPipeline (llm_pipeline.py): response parsing, retry, error handling

No infrastructure I/O.  LLMProvider is replaced by AsyncMock.
asyncio_mode = "auto" removes @pytest.mark.asyncio.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from waf_shared.domain.errors.domain_errors import DSLValidationError
from waf_shared.domain.errors.infrastructure_errors import (
    LLMQuotaExhaustedError,
    LLMRateLimitError,
)
from waf_shared.domain.models.assessment import AssessmentResource
from waf_shared.domain.models.finding import FindingStatus
from waf_shared.domain.models.rule import EvaluationType, Pillar, WafRule
from waf_shared.llm.provider import LLMResponse


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _make_rule(
    *,
    rule_id: str = "REL-VM-001",
    evaluation_type: EvaluationType = EvaluationType.DETERMINISTIC,
    condition_dsl: dict[str, Any] | None = None,
    prompt_template_ref: str | None = None,
) -> WafRule:
    return WafRule(
        id=uuid.uuid4(),
        rule_id=rule_id,
        pillar=Pillar.RELIABILITY,
        resource_types=["microsoft.compute/virtualmachines"],
        evaluation_type=evaluation_type,
        condition_dsl=condition_dsl or {"op": "length_gte", "path": "zones", "value": 1},
        prompt_template_ref=prompt_template_ref,
        severity="high",
        title="Test Rule",
        description="Test rule description.",
        recommendation="Fix it.",
        is_active=True,
        version=1,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def _make_resource(raw_properties: dict[str, Any]) -> AssessmentResource:
    return AssessmentResource(
        id=uuid.uuid4(),
        assessment_id=uuid.uuid4(),
        batch_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        resource_id="/subscriptions/x/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
        resource_type="microsoft.compute/virtualmachines",
        location="eastus",
        subscription_id=uuid.uuid4(),
        resource_group="rg",
        raw_properties=raw_properties,
        extracted_at=datetime.now(UTC),
    )


# ── DSL Evaluator tests ────────────────────────────────────────────────────────

class TestDSLEvaluator:
    def test_length_gte_pass(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        result = evaluate_condition(
            "REL-VM-001",
            {"op": "length_gte", "path": "zones", "value": 1},
            {"zones": ["1"]},
        )
        assert result is True

    def test_length_gte_fail(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        result = evaluate_condition(
            "REL-VM-001",
            {"op": "length_gte", "path": "zones", "value": 1},
            {"zones": []},
        )
        assert result is False

    def test_eq_operator(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        assert evaluate_condition("R", {"op": "eq", "path": "status", "value": "OK"}, {"status": "OK"}) is True
        assert evaluate_condition("R", {"op": "eq", "path": "status", "value": "OK"}, {"status": "FAIL"}) is False

    def test_ne_operator(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        assert evaluate_condition("R", {"op": "ne", "path": "x", "value": "bad"}, {"x": "good"}) is True
        assert evaluate_condition("R", {"op": "ne", "path": "x", "value": "bad"}, {"x": "bad"}) is False

    def test_in_operator(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        assert evaluate_condition("R", {"op": "in", "path": "tier", "values": ["Standard", "Premium"]}, {"tier": "Standard"}) is True
        assert evaluate_condition("R", {"op": "in", "path": "tier", "values": ["Standard", "Premium"]}, {"tier": "Basic"}) is False

    def test_not_in_operator(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        assert evaluate_condition("R", {"op": "not_in", "path": "t", "values": ["A", "B"]}, {"t": "C"}) is True
        assert evaluate_condition("R", {"op": "not_in", "path": "t", "values": ["A", "B"]}, {"t": "A"}) is False

    def test_exists_operator(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        assert evaluate_condition("R", {"op": "exists", "path": "prop"}, {"prop": "val"}) is True
        assert evaluate_condition("R", {"op": "exists", "path": "prop"}, {}) is False

    def test_is_null_operator(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        assert evaluate_condition("R", {"op": "is_null", "path": "x"}, {}) is True
        assert evaluate_condition("R", {"op": "is_null", "path": "x"}, {"x": None}) is True
        assert evaluate_condition("R", {"op": "is_null", "path": "x"}, {"x": "v"}) is False

    def test_and_operator_all_true(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        cond = {
            "op": "and",
            "conditions": [
                {"op": "exists", "path": "a"},
                {"op": "exists", "path": "b"},
            ],
        }
        assert evaluate_condition("R", cond, {"a": 1, "b": 2}) is True
        assert evaluate_condition("R", cond, {"a": 1}) is False

    def test_or_operator_any_true(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        cond = {
            "op": "or",
            "conditions": [
                {"op": "exists", "path": "a"},
                {"op": "exists", "path": "b"},
            ],
        }
        assert evaluate_condition("R", cond, {"a": 1}) is True
        assert evaluate_condition("R", cond, {}) is False

    def test_not_operator(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        cond = {"op": "not", "condition": {"op": "exists", "path": "managed_by"}}
        assert evaluate_condition("R", cond, {}) is True
        assert evaluate_condition("R", cond, {"managed_by": "vm1"}) is False

    def test_contains_case_insensitive(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        cond = {"op": "contains", "path": "name", "value": "prod"}
        assert evaluate_condition("R", cond, {"name": "vm-PROD-01"}) is True
        assert evaluate_condition("R", cond, {"name": "vm-dev-01"}) is False

    def test_bool_eq_operator(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        cond = {"op": "bool_eq", "path": "enabled", "value": True}
        assert evaluate_condition("R", cond, {"enabled": True}) is True
        assert evaluate_condition("R", cond, {"enabled": False}) is False
        assert evaluate_condition("R", cond, {"enabled": "true"}) is True

    def test_nested_path_resolution(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        cond = {"op": "eq", "path": "properties.diskState", "value": "Unattached"}
        assert evaluate_condition("R", cond, {"properties": {"diskState": "Unattached"}}) is True
        assert evaluate_condition("R", cond, {"properties": {"diskState": "Attached"}}) is False
        assert evaluate_condition("R", cond, {}) is False

    def test_missing_path_returns_none_not_error(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        # Missing path → None → eq comparison returns False (None != "value")
        assert evaluate_condition("R", {"op": "eq", "path": "a.b.c", "value": "x"}, {}) is False

    def test_unknown_operator_raises_dsl_error(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        with pytest.raises(DSLValidationError):
            evaluate_condition("R", {"op": "unsupported_op", "path": "x"}, {})

    def test_missing_op_field_raises_dsl_error(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        with pytest.raises(DSLValidationError):
            evaluate_condition("R", {"path": "x", "value": "y"}, {})

    def test_always_pass_operator(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        assert evaluate_condition("R", {"op": "always_pass"}, {}) is True

    def test_always_fail_operator(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        assert evaluate_condition("R", {"op": "always_fail"}, {}) is False

    def test_any_match_operator(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        cond = {
            "op": "any_match",
            "path": "rules",
            "condition": {"op": "eq", "path": "access", "value": "Allow"},
        }
        props = {"rules": [{"access": "Deny"}, {"access": "Allow"}]}
        assert evaluate_condition("R", cond, props) is True
        props_all_deny = {"rules": [{"access": "Deny"}, {"access": "Deny"}]}
        assert evaluate_condition("R", cond, props_all_deny) is False

    def test_gte_numeric_operator(self):
        from waf_reasoning.dsl_evaluator import evaluate_condition

        assert evaluate_condition("R", {"op": "gte", "path": "count", "value": 2}, {"count": 3}) is True
        assert evaluate_condition("R", {"op": "gte", "path": "count", "value": 2}, {"count": 1}) is False


# ── PropertyCompressor tests ───────────────────────────────────────────────────

class TestPropertyCompressor:
    def test_compress_for_dsl_extracts_referenced_paths(self):
        from waf_reasoning.property_compressor import PropertyCompressor

        c = PropertyCompressor()
        dsl = {"op": "eq", "path": "properties.diskState", "value": "Unattached"}
        props = {
            "id": "/sub/rg/disk1",
            "name": "disk1",
            "type": "Microsoft.Compute/disks",
            "location": "eastus",
            "resourceGroup": "rg",
            "subscriptionId": "sub1",
            "tenantId": "ten1",
            "properties": {"diskState": "Unattached", "other": "noise"},
            "tags": {"env": "prod"},
            "sku": {"name": "Premium_LRS"},
        }
        result = c.compress_for_dsl(props, dsl)
        assert "properties" in result
        assert result["name"] == "disk1"  # mandatory field

    def test_compress_for_dsl_includes_mandatory_fields(self):
        from waf_reasoning.property_compressor import PropertyCompressor

        c = PropertyCompressor()
        dsl = {"op": "length_gte", "path": "zones", "value": 1}
        props = {
            "id": "x",
            "name": "vm1",
            "type": "Microsoft.Compute/virtualMachines",
            "location": "eastus",
            "resourceGroup": "rg",
            "subscriptionId": "sub",
            "tenantId": "ten",
            "zones": ["1", "2"],
            "extra": "ignored",
        }
        result = c.compress_for_dsl(props, dsl)
        assert "name" in result
        assert "zones" in result
        assert "extra" not in result

    def test_compress_for_llm_returns_all_keys_under_budget(self):
        from waf_reasoning.property_compressor import PropertyCompressor

        c = PropertyCompressor()
        small_props = {"id": "x", "name": "vm1", "type": "t", "location": "l",
                       "resourceGroup": "rg", "subscriptionId": "s", "tenantId": "t2",
                       "properties": {"a": "b"}, "tags": {"env": "prod"}}
        result = c.compress_for_llm(small_props)
        assert "properties" in result
        assert "tags" in result

    def test_compress_for_llm_with_relevant_paths(self):
        from waf_reasoning.property_compressor import PropertyCompressor

        c = PropertyCompressor()
        props = {"id": "x", "name": "vm1", "type": "t", "location": "l",
                 "resourceGroup": "rg", "subscriptionId": "s", "tenantId": "t2",
                 "properties": {"thing": "val"},
                 "tags": {"env": "prod"},
                 "secret": "should-be-excluded"}
        result = c.compress_for_llm(props, relevant_paths=["properties", "tags"])
        assert "properties" in result
        assert "secret" not in result


# ── DeterministicPipeline tests ────────────────────────────────────────────────

class TestDeterministicPipeline:
    def _make_logger(self) -> MagicMock:
        log = MagicMock()
        log.bind = MagicMock(return_value=log)
        log.info = MagicMock()
        log.error = MagicMock()
        log.warning = MagicMock()
        return log

    def test_pass_produces_no_finding(self):
        from waf_reasoning.deterministic_pipeline import DeterministicPipeline

        pipeline = DeterministicPipeline(logger=self._make_logger())
        resource = _make_resource({"zones": ["1"]})
        rule = _make_rule(condition_dsl={"op": "length_gte", "path": "zones", "value": 1})
        findings = pipeline.evaluate(
            resource=resource,
            rules=[rule],
            assessment_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
        )
        assert findings == []

    def test_fail_produces_open_finding(self):
        from waf_reasoning.deterministic_pipeline import DeterministicPipeline

        pipeline = DeterministicPipeline(logger=self._make_logger())
        resource = _make_resource({"zones": []})
        rule = _make_rule(condition_dsl={"op": "length_gte", "path": "zones", "value": 1})
        findings = pipeline.evaluate(
            resource=resource,
            rules=[rule],
            assessment_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
        )
        assert len(findings) == 1
        assert findings[0].status == FindingStatus.OPEN
        assert findings[0].confidence_score == 1.0
        assert findings[0].evidence["result"] == "FAIL"

    def test_dsl_validation_error_produces_review_finding(self):
        from waf_reasoning.deterministic_pipeline import DeterministicPipeline

        pipeline = DeterministicPipeline(logger=self._make_logger())
        resource = _make_resource({})
        rule = _make_rule(condition_dsl={"op": "unknown_op", "path": "x"})
        findings = pipeline.evaluate(
            resource=resource,
            rules=[rule],
            assessment_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
        )
        assert len(findings) == 1
        assert findings[0].confidence_score < 1.0
        assert findings[0].evidence.get("result") == "REVIEW"

    def test_skips_llm_rules(self):
        from waf_reasoning.deterministic_pipeline import DeterministicPipeline

        pipeline = DeterministicPipeline(logger=self._make_logger())
        resource = _make_resource({})
        llm_rule = _make_rule(
            rule_id="CST-VM-001",
            evaluation_type=EvaluationType.LLM,
            condition_dsl=None,
            prompt_template_ref="tpl",
        )
        findings = pipeline.evaluate(
            resource=resource,
            rules=[llm_rule],
            assessment_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
        )
        assert findings == []

    def test_multiple_rules_multiple_findings(self):
        from waf_reasoning.deterministic_pipeline import DeterministicPipeline

        pipeline = DeterministicPipeline(logger=self._make_logger())
        resource = _make_resource({"zones": [], "enabled": False})
        rule1 = _make_rule(rule_id="REL-VM-001", condition_dsl={"op": "length_gte", "path": "zones", "value": 1})
        rule2 = _make_rule(rule_id="REL-VM-002", condition_dsl={"op": "bool_eq", "path": "enabled", "value": True})

        findings = pipeline.evaluate(
            resource=resource,
            rules=[rule1, rule2],
            assessment_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
        )
        assert len(findings) == 2


# ── LLMPipeline tests ──────────────────────────────────────────────────────────

class TestLLMPipeline:
    def _make_logger(self) -> MagicMock:
        log = MagicMock()
        log.bind = MagicMock(return_value=log)
        log.info = MagicMock()
        log.error = MagicMock()
        log.warning = MagicMock()
        return log

    def _make_llm_response(self, result: str, confidence: float = 0.9) -> LLMResponse:
        content = json.dumps({
            "result": result,
            "confidence": confidence,
            "evidence": "observed property X",
            "recommendation": "fix it" if result != "PASS" else "",
        })
        return LLMResponse(
            content=content,
            prompt_tokens=100,
            completion_tokens=50,
            model="gpt-4o-2024-11-20",
        )

    @pytest.mark.asyncio
    async def test_llm_pass_produces_no_finding(self):
        from waf_reasoning.llm_pipeline import LLMPipeline
        from waf_reasoning.property_compressor import PropertyCompressor

        mock_llm = MagicMock()
        mock_llm.chat_complete = AsyncMock(return_value=self._make_llm_response("PASS"))
        mock_llm.model_id = MagicMock(return_value="gpt-4o-2024-11-20")

        pipeline = LLMPipeline(
            llm=mock_llm,
            compressor=PropertyCompressor(),
            logger=self._make_logger(),
        )
        resource = _make_resource({"name": "vm1", "type": "t"})
        rule = _make_rule(
            rule_id="CST-VM-001",
            evaluation_type=EvaluationType.LLM,
            condition_dsl=None,
            prompt_template_ref="tpl",
        )

        findings = await pipeline.evaluate(
            resource=resource,
            rules=[rule],
            assessment_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
        )
        assert findings == []

    @pytest.mark.asyncio
    async def test_llm_fail_produces_open_finding(self):
        from waf_reasoning.llm_pipeline import LLMPipeline
        from waf_reasoning.property_compressor import PropertyCompressor

        mock_llm = MagicMock()
        mock_llm.chat_complete = AsyncMock(return_value=self._make_llm_response("FAIL"))
        mock_llm.model_id = MagicMock(return_value="gpt-4o-2024-11-20")

        pipeline = LLMPipeline(
            llm=mock_llm,
            compressor=PropertyCompressor(),
            logger=self._make_logger(),
        )
        resource = _make_resource({"name": "vm1", "type": "t"})
        rule = _make_rule(
            rule_id="CST-VM-001",
            evaluation_type=EvaluationType.LLM,
            condition_dsl=None,
            prompt_template_ref="tpl",
        )

        findings = await pipeline.evaluate(
            resource=resource,
            rules=[rule],
            assessment_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
        )
        assert len(findings) == 1
        assert findings[0].status == FindingStatus.OPEN
        assert findings[0].evidence["result"] == "FAIL"
        assert findings[0].confidence_score == pytest.approx(0.9)

    @pytest.mark.asyncio
    async def test_invalid_json_response_retries_and_produces_review(self):
        from waf_reasoning.llm_pipeline import LLMPipeline
        from waf_reasoning.property_compressor import PropertyCompressor

        # First call returns garbage; second call (retry) also returns garbage.
        bad_response = LLMResponse(
            content="not json at all",
            prompt_tokens=100,
            completion_tokens=10,
            model="gpt-4o-2024-11-20",
        )
        mock_llm = MagicMock()
        mock_llm.chat_complete = AsyncMock(return_value=bad_response)

        pipeline = LLMPipeline(
            llm=mock_llm,
            compressor=PropertyCompressor(),
            logger=self._make_logger(),
        )
        resource = _make_resource({"name": "vm1"})
        rule = _make_rule(
            rule_id="CST-VM-001",
            evaluation_type=EvaluationType.LLM,
            condition_dsl=None,
            prompt_template_ref="tpl",
        )

        findings = await pipeline.evaluate(
            resource=resource,
            rules=[rule],
            assessment_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
        )
        assert len(findings) == 1
        assert findings[0].evidence.get("result") == "REVIEW"
        assert findings[0].confidence_score < 1.0

    @pytest.mark.asyncio
    async def test_rate_limit_error_propagates(self):
        from waf_reasoning.llm_pipeline import LLMPipeline
        from waf_reasoning.property_compressor import PropertyCompressor

        mock_llm = MagicMock()
        mock_llm.chat_complete = AsyncMock(side_effect=LLMRateLimitError())

        pipeline = LLMPipeline(
            llm=mock_llm,
            compressor=PropertyCompressor(),
            logger=self._make_logger(),
        )
        resource = _make_resource({"name": "vm1"})
        rule = _make_rule(
            rule_id="CST-VM-001",
            evaluation_type=EvaluationType.LLM,
            condition_dsl=None,
            prompt_template_ref="tpl",
        )

        with pytest.raises(LLMRateLimitError):
            await pipeline.evaluate(
                resource=resource,
                rules=[rule],
                assessment_id=uuid.uuid4(),
                batch_id=uuid.uuid4(),
                tenant_id=uuid.uuid4(),
            )

    @pytest.mark.asyncio
    async def test_quota_exhausted_propagates(self):
        from waf_reasoning.llm_pipeline import LLMPipeline
        from waf_reasoning.property_compressor import PropertyCompressor

        mock_llm = MagicMock()
        mock_llm.chat_complete = AsyncMock(
            side_effect=LLMQuotaExhaustedError(deployment="gpt-4o-2024-11-20")
        )

        pipeline = LLMPipeline(
            llm=mock_llm,
            compressor=PropertyCompressor(),
            logger=self._make_logger(),
        )
        resource = _make_resource({"name": "vm1"})
        rule = _make_rule(
            rule_id="CST-VM-001",
            evaluation_type=EvaluationType.LLM,
            condition_dsl=None,
            prompt_template_ref="tpl",
        )

        with pytest.raises(LLMQuotaExhaustedError):
            await pipeline.evaluate(
                resource=resource,
                rules=[rule],
                assessment_id=uuid.uuid4(),
                batch_id=uuid.uuid4(),
                tenant_id=uuid.uuid4(),
            )

    @pytest.mark.asyncio
    async def test_skips_deterministic_rules(self):
        from waf_reasoning.llm_pipeline import LLMPipeline
        from waf_reasoning.property_compressor import PropertyCompressor

        mock_llm = MagicMock()
        mock_llm.chat_complete = AsyncMock()

        pipeline = LLMPipeline(
            llm=mock_llm,
            compressor=PropertyCompressor(),
            logger=self._make_logger(),
        )
        resource = _make_resource({})
        det_rule = _make_rule(evaluation_type=EvaluationType.DETERMINISTIC)

        findings = await pipeline.evaluate(
            resource=resource,
            rules=[det_rule],
            assessment_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
        )
        assert findings == []
        mock_llm.chat_complete.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_review_result_produces_finding(self):
        from waf_reasoning.llm_pipeline import LLMPipeline
        from waf_reasoning.property_compressor import PropertyCompressor

        mock_llm = MagicMock()
        mock_llm.chat_complete = AsyncMock(
            return_value=self._make_llm_response("REVIEW", confidence=0.4)
        )

        pipeline = LLMPipeline(
            llm=mock_llm,
            compressor=PropertyCompressor(),
            logger=self._make_logger(),
        )
        resource = _make_resource({"name": "vm1"})
        rule = _make_rule(
            rule_id="CST-VM-001",
            evaluation_type=EvaluationType.LLM,
            condition_dsl=None,
            prompt_template_ref="tpl",
        )

        findings = await pipeline.evaluate(
            resource=resource,
            rules=[rule],
            assessment_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
        )
        assert len(findings) == 1
        assert findings[0].evidence["result"] == "REVIEW"
        assert findings[0].confidence_score == pytest.approx(0.4)


# ── Cross-pillar DSL condition tests ───────────────────────────────────────────


class TestCrossPillarDSLConditions:
    """Verify that DSL conditions for non-security pillars evaluate correctly.

    These tests document the exact ARM property paths used in production rules
    so regressions (e.g. path typos, wrong operator for null zones) are caught
    before seeding to the database.
    """

    # ── Reliability ────────────────────────────────────────────────────────────

    def test_rel_vm_001_null_zones_fails(self):
        """Azure returns null for non-zone VMs; eq(zones,[]) used to miss this."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "or", "conditions": [
            {"op": "is_null", "path": "zones"},
            {"op": "length_eq", "path": "zones", "value": 0},
        ]}
        assert evaluate_condition("REL-VM-001", dsl, {"zones": None}) is True
        assert evaluate_condition("REL-VM-001", dsl, {"zones": []}) is True
        assert evaluate_condition("REL-VM-001", dsl, {"zones": ["1"]}) is False
        assert evaluate_condition("REL-VM-001", dsl, {}) is True

    def test_rel_vm_002_no_zone_no_avset_fails(self):
        """VM with no zone AND no availability set should trigger."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "and", "conditions": [
            {"op": "or", "conditions": [
                {"op": "is_null", "path": "zones"},
                {"op": "length_eq", "path": "zones", "value": 0},
            ]},
            {"op": "is_null", "path": "properties.availabilitySet"},
        ]}
        assert evaluate_condition("REL-VM-002", dsl, {"zones": None, "properties": {}}) is True
        assert evaluate_condition("REL-VM-002", dsl, {
            "zones": None,
            "properties": {"availabilitySet": {"id": "/sub/rg/avset1"}},
        }) is False
        assert evaluate_condition("REL-VM-002", dsl, {"zones": ["1"], "properties": {}}) is False

    def test_rel_vmss_001_no_zones_fails(self):
        """VMSS without zones is not zone-redundant."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "or", "conditions": [
            {"op": "is_null", "path": "zones"},
            {"op": "length_eq", "path": "zones", "value": 0},
        ]}
        assert evaluate_condition("REL-VMSS-001", dsl, {"zones": None}) is True
        assert evaluate_condition("REL-VMSS-001", dsl, {"zones": ["1", "2", "3"]}) is False

    def test_rel_stor_001_lrs_fails(self):
        """LRS storage does not protect against regional outage."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "in", "path": "sku.name", "value": ["Standard_LRS", "Premium_LRS"]}
        assert evaluate_condition("REL-STOR-001", dsl, {"sku": {"name": "Standard_LRS"}}) is True
        assert evaluate_condition("REL-STOR-001", dsl, {"sku": {"name": "Standard_GRS"}}) is False

    def test_rel_app_001_single_instance_fails(self):
        """App Service plan with one worker has no redundancy."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "lte", "path": "sku.capacity", "value": 1}
        assert evaluate_condition("REL-APP-001", dsl, {"sku": {"capacity": 1}}) is True
        assert evaluate_condition("REL-APP-001", dsl, {"sku": {"capacity": 2}}) is False

    def test_rel_lb_001_basic_sku_fails(self):
        """Basic SKU load balancer is not zone-redundant."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "eq", "path": "sku.name", "value": "Basic"}
        assert evaluate_condition("REL-LB-001", dsl, {"sku": {"name": "Basic"}}) is True
        assert evaluate_condition("REL-LB-001", dsl, {"sku": {"name": "Standard"}}) is False

    # ── Cost Optimization ──────────────────────────────────────────────────────

    def test_cst_vm_001_deallocated_fails(self):
        """Deallocated VM detected via properties.extended.instanceView.powerState.code."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "eq", "path": "properties.extended.instanceView.powerState.code",
               "value": "PowerState/deallocated"}
        props_deallocated = {
            "properties": {
                "extended": {
                    "instanceView": {
                        "powerState": {"code": "PowerState/deallocated"}
                    }
                }
            }
        }
        props_running = {
            "properties": {
                "extended": {
                    "instanceView": {
                        "powerState": {"code": "PowerState/running"}
                    }
                }
            }
        }
        assert evaluate_condition("CST-VM-001", dsl, props_deallocated) is True
        assert evaluate_condition("CST-VM-001", dsl, props_running) is False
        assert evaluate_condition("CST-VM-001", dsl, {}) is False

    def test_cst_disk_001_unattached_fails(self):
        """Disk with null managedBy is unattached (orphaned)."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "is_null", "path": "managedBy"}
        assert evaluate_condition("CST-DISK-001", dsl, {"managedBy": None}) is True
        assert evaluate_condition("CST-DISK-001", dsl, {}) is True
        assert evaluate_condition("CST-DISK-001", dsl, {
            "managedBy": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
        }) is False

    def test_cst_ip_001_unassociated_fails(self):
        """Public IP with no ipConfiguration is unassociated."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "is_null", "path": "properties.ipConfiguration"}
        assert evaluate_condition("CST-IP-001", dsl, {"properties": {}}) is True
        assert evaluate_condition("CST-IP-001", dsl, {
            "properties": {"ipConfiguration": {"id": "/sub/rg/ip/config1"}}
        }) is False

    def test_cst_stor_001_hot_tier_fails(self):
        """Storage account on Hot tier flagged for cost review."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "eq", "path": "properties.accessTier", "value": "Hot"}
        assert evaluate_condition("CST-STOR-001", dsl, {"properties": {"accessTier": "Hot"}}) is True
        assert evaluate_condition("CST-STOR-001", dsl, {"properties": {"accessTier": "Cool"}}) is False

    # ── Operational Excellence ─────────────────────────────────────────────────

    def test_ops_tag_001_missing_environment_tag_fails(self):
        """Resource without Environment tag triggers OE finding."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "or", "conditions": [
            {"op": "is_null", "path": "tags.Environment"},
            {"op": "is_null", "path": "tags.Owner"},
        ]}
        assert evaluate_condition("OPS-TAG-001", dsl, {"tags": {}}) is True
        assert evaluate_condition("OPS-TAG-001", dsl, {"tags": {"Environment": "prod"}}) is True
        assert evaluate_condition("OPS-TAG-001", dsl, {
            "tags": {"Environment": "prod", "Owner": "team@corp.com"}
        }) is False

    def test_ops_kv_001_short_retention_fails(self):
        """KV with short soft-delete retention triggers OE finding."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "or", "conditions": [
            {"op": "is_null", "path": "properties.softDeleteRetentionInDays"},
            {"op": "lt", "path": "properties.softDeleteRetentionInDays", "value": 14},
        ]}
        assert evaluate_condition("OPS-KV-001", dsl, {"properties": {"softDeleteRetentionInDays": 7}}) is True
        assert evaluate_condition("OPS-KV-001", dsl, {"properties": {}}) is True
        assert evaluate_condition("OPS-KV-001", dsl, {"properties": {"softDeleteRetentionInDays": 90}}) is False

    def test_ops_app_002_remote_debugging_fails(self):
        """Remote debugging enabled in production is an OE violation."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "bool_eq", "path": "properties.siteConfig.remoteDebuggingEnabled", "value": True}
        assert evaluate_condition("OPS-APP-002", dsl, {
            "properties": {"siteConfig": {"remoteDebuggingEnabled": True}}
        }) is True
        assert evaluate_condition("OPS-APP-002", dsl, {
            "properties": {"siteConfig": {"remoteDebuggingEnabled": False}}
        }) is False

    # ── Performance Efficiency ─────────────────────────────────────────────────

    def test_per_vm_003_no_ppg_fails(self):
        """VM without proximity placement group flagged for latency."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "is_null", "path": "properties.proximityPlacementGroup"}
        assert evaluate_condition("PER-VM-003", dsl, {"properties": {}}) is True
        assert evaluate_condition("PER-VM-003", dsl, {
            "properties": {"proximityPlacementGroup": {"id": "/sub/rg/ppg1"}}
        }) is False

    def test_per_app_002_no_http2_fails(self):
        """App Service without HTTP/2 has suboptimal performance."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "not", "condition": {"op": "bool_eq", "path": "properties.siteConfig.http20Enabled", "value": True}}
        assert evaluate_condition("PER-APP-002", dsl, {
            "properties": {"siteConfig": {"http20Enabled": False}}
        }) is True
        assert evaluate_condition("PER-APP-002", dsl, {
            "properties": {"siteConfig": {"http20Enabled": True}}
        }) is False

    def test_per_app_003_arr_affinity_fails(self):
        """ARR affinity prevents true horizontal scaling."""
        from waf_reasoning.dsl_evaluator import evaluate_condition

        dsl = {"op": "bool_eq", "path": "properties.clientAffinityEnabled", "value": True}
        assert evaluate_condition("PER-APP-003", dsl, {
            "properties": {"clientAffinityEnabled": True}
        }) is True
        assert evaluate_condition("PER-APP-003", dsl, {
            "properties": {"clientAffinityEnabled": False}
        }) is False

    # ── Multi-pillar finding simulation ────────────────────────────────────────

    def test_deterministic_pipeline_all_five_pillars(self):
        """DeterministicPipeline produces findings across all 5 WAF pillars
        when given one rule per pillar and resource properties that fail each check."""
        from waf_reasoning.deterministic_pipeline import DeterministicPipeline
        from unittest.mock import MagicMock

        log = MagicMock()
        log.bind = MagicMock(return_value=log)
        pipeline = DeterministicPipeline(logger=log)

        def _rule(rule_id: str, pillar_str: str, dsl: dict) -> WafRule:
            pillar = Pillar(pillar_str)
            return WafRule(
                id=uuid.uuid4(),
                rule_id=rule_id,
                pillar=pillar,
                resource_types=["microsoft.compute/virtualmachines"],
                evaluation_type=EvaluationType.DETERMINISTIC,
                condition_dsl=dsl,
                prompt_template_ref=None,
                severity="medium",
                title=f"Test {pillar_str}",
                description="desc",
                recommendation="fix",
                is_active=True,
                version=1,
                created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
                updated_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            )

        rules = [
            _rule("SEC-VM-001", "security", {"op": "is_null", "path": "properties.storageProfile.osDisk.encryptionSettings"}),
            _rule("REL-VM-001", "reliability", {"op": "or", "conditions": [{"op": "is_null", "path": "zones"}, {"op": "length_eq", "path": "zones", "value": 0}]}),
            _rule("CST-DISK-001", "cost_optimization", {"op": "is_null", "path": "managedBy"}),
            _rule("OPS-TAG-001", "operational_excellence", {"op": "is_null", "path": "tags.Environment"}),
            _rule("PER-VM-003", "performance_efficiency", {"op": "is_null", "path": "properties.proximityPlacementGroup"}),
        ]

        resource = _make_resource({
            "zones": None,
            "managedBy": None,
            "tags": {},
            "properties": {},
            "identity": None,
        })

        findings = pipeline.evaluate(
            resource=resource,
            rules=rules,
            assessment_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
        )

        assert len(findings) == 5
        pillars_found = {f.rule_id.split("-")[0] for f in findings}
        assert pillars_found == {"SEC", "REL", "CST", "OPS", "PER"}
