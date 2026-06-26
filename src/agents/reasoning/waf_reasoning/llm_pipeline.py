"""LLM-assisted evaluation pipeline — provider-agnostic WAF rule evaluation.

The pipeline uses the LLMProvider protocol; the concrete backend (Gemini, Azure
OpenAI, …) is injected at construction time.  No business logic here depends on
which provider is in use.

For each LLM-assisted WAF rule this pipeline:
  1. Compresses resource properties to the relevant fields (≤ 800 tokens).
  2. Constructs a structured JSON prompt (system + user) asking the LLM to
     assess the resource against the specific WAF rule.
  3. Calls LLMProvider.chat_complete() with JSON mode enabled.
  4. Parses the JSON response into a FindingResult.
  5. On JSON parse failure: retries once with a simplified fallback prompt.
  6. On LLMRateLimitError: raises (let tenacity in the handler retry the batch;
     individual rule errors produce REVIEW findings and do not fail the batch).
  7. On LLMQuotaExhaustedError: re-raises so the handler can fail the batch.

Findings are returned to the caller; never written to the DB here.

Token budget: ≤ 800 tokens per resource per rule.
The pipeline logs prompt_tokens and completion_tokens after each LLM call.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from waf_shared.domain.errors.infrastructure_errors import (
    LLMQuotaExhaustedError,
    LLMRateLimitError,
)
from waf_shared.domain.models.assessment import AssessmentResource
from waf_shared.domain.models.finding import Finding, FindingStatus, Severity
from waf_shared.domain.models.rule import EvaluationType, WafRule
from waf_shared.llm.provider import LLMProvider
from waf_shared.telemetry.logging import StructuredLogger
from waf_reasoning.property_compressor import PropertyCompressor

_RESULT_PASS = "PASS"
_RESULT_FAIL = "FAIL"
_RESULT_REVIEW = "REVIEW"
_CONFIDENCE_DEFAULT = 0.85
_CONFIDENCE_PARSE_ERROR = 0.3
_MAX_TOKENS = 4096

_SYSTEM_PROMPT = """\
You are a Microsoft Azure Well-Architected Framework (WAF) compliance expert.
Your task is to evaluate an Azure resource against a specific WAF rule and respond \
with a valid JSON object.

Required JSON schema:
{
  "result": "PASS" | "FAIL" | "REVIEW",
  "confidence": <float 0.0–1.0>,
  "evidence": "<specific properties that led to your conclusion, max 400 chars>",
  "recommendation": "<specific actionable fix if FAIL or REVIEW, max 400 chars>"
}

Rules:
- result: PASS if the resource complies, FAIL if non-compliant, REVIEW if you \
cannot determine with confidence from the provided properties.
- confidence: 1.0 for certain, lower for ambiguous or incomplete data.
- evidence: quote the specific property values observed, or note what is absent.
- recommendation: only required for FAIL or REVIEW; empty string for PASS.
- Respond ONLY with the JSON object — no prose, no markdown fences.
"""


class LLMPipeline:
    """Evaluates LLM-assisted WAF rules for one resource using the configured LLM provider."""

    def __init__(
        self,
        llm: LLMProvider,
        compressor: PropertyCompressor,
        logger: StructuredLogger,
    ) -> None:
        self._llm = llm
        self._compressor = compressor
        self._logger = logger

    async def evaluate(
        self,
        resource: AssessmentResource,
        rules: list[WafRule],
        *,
        assessment_id: uuid.UUID,
        batch_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> list[Finding]:
        """Evaluate all LLM-assisted rules and return findings for FAIL/REVIEW."""
        findings: list[Finding] = []

        for rule in rules:
            if rule.evaluation_type not in (EvaluationType.LLM, EvaluationType.HYBRID):
                continue

            finding = await self._evaluate_one(
                resource=resource,
                rule=rule,
                assessment_id=assessment_id,
                batch_id=batch_id,
                tenant_id=tenant_id,
            )
            if finding is not None:
                findings.append(finding)

        return findings

    async def _evaluate_one(
        self,
        *,
        resource: AssessmentResource,
        rule: WafRule,
        assessment_id: uuid.UUID,
        batch_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> Finding | None:
        compressed = self._compressor.compress_for_llm(resource.raw_properties)
        user_prompt = _build_user_prompt(resource, rule, compressed)

        try:
            response = await self._llm.chat_complete(
                _SYSTEM_PROMPT,
                user_prompt,
                max_tokens=_MAX_TOKENS,
                temperature=0.1,
            )
        except LLMQuotaExhaustedError:
            raise
        except LLMRateLimitError:
            raise
        except Exception as exc:
            self._logger.error(
                "reasoning.llm.call_failed",
                rule_id=rule.rule_id,
                resource_id=resource.resource_id,
                exc_info=True,
                error=str(exc),
            )
            return _make_finding(
                rule=rule,
                resource=resource,
                assessment_id=assessment_id,
                batch_id=batch_id,
                tenant_id=tenant_id,
                result=_RESULT_REVIEW,
                confidence=_CONFIDENCE_PARSE_ERROR,
                evidence={"result": _RESULT_REVIEW, "error": f"LLM call failed: {exc}"},
                recommendation=rule.recommendation,
            )

        self._logger.info(
            "reasoning.llm.call_completed",
            rule_id=rule.rule_id,
            resource_id=resource.resource_id,
            model=response.model,
            prompt_tokens=response.prompt_tokens,
            completion_tokens=response.completion_tokens,
        )

        parsed = _parse_response(response.content)
        if parsed is None:
            # Retry once with a simplified prompt.
            parsed = await self._retry_with_simple_prompt(resource, rule)

        if parsed is None:
            self._logger.error(
                "reasoning.llm.parse_failed",
                rule_id=rule.rule_id,
                resource_id=resource.resource_id,
                raw_content=response.content[:200],
            )
            return _make_finding(
                rule=rule,
                resource=resource,
                assessment_id=assessment_id,
                batch_id=batch_id,
                tenant_id=tenant_id,
                result=_RESULT_REVIEW,
                confidence=_CONFIDENCE_PARSE_ERROR,
                evidence={"result": _RESULT_REVIEW, "error": "LLM response could not be parsed"},
                recommendation=rule.recommendation,
            )

        result = parsed.get("result", _RESULT_REVIEW)
        confidence = float(parsed.get("confidence", _CONFIDENCE_DEFAULT))
        evidence_text = parsed.get("evidence", "")
        recommendation = parsed.get("recommendation", "") or rule.recommendation

        if result == _RESULT_PASS:
            return None  # No finding for compliant resources.

        return _make_finding(
            rule=rule,
            resource=resource,
            assessment_id=assessment_id,
            batch_id=batch_id,
            tenant_id=tenant_id,
            result=result,
            confidence=confidence,
            evidence={
                "result": result,
                "evaluation_type": "llm_assisted",
                "model": response.model,
                "evidence": evidence_text,
                "rule_id": rule.rule_id,
            },
            recommendation=recommendation,
        )

    async def _retry_with_simple_prompt(
        self,
        resource: AssessmentResource,
        rule: WafRule,
    ) -> dict[str, Any] | None:
        simple_prompt = (
            f"Evaluate Azure resource type '{resource.resource_type}' against WAF rule "
            f"'{rule.rule_id}: {rule.title}'. "
            f"Rule description: {rule.description}. "
            "Respond ONLY with JSON: "
            '{"result":"PASS"|"FAIL"|"REVIEW","confidence":0.8,'
            '"evidence":"<brief>","recommendation":"<fix>"}'
        )
        try:
            response = await self._llm.chat_complete(
                _SYSTEM_PROMPT,
                simple_prompt,
                max_tokens=512,
                temperature=0.0,
            )
            return _parse_response(response.content)
        except Exception:
            return None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _build_user_prompt(
    resource: AssessmentResource,
    rule: WafRule,
    compressed_props: dict[str, Any],
) -> str:
    props_json = json.dumps(compressed_props, indent=2, default=str)
    return (
        f"WAF Pillar: {rule.pillar.value.replace('_', ' ').title()}\n"
        f"Rule ID: {rule.rule_id}\n"
        f"Rule Name: {rule.title}\n"
        f"Rule Description: {rule.description}\n"
        f"Severity: {rule.severity}\n\n"
        f"Azure Resource:\n"
        f"  Type: {resource.resource_type}\n"
        f"  Location: {resource.location}\n"
        f"  Resource Group: {resource.resource_group}\n\n"
        f"Resource Properties (JSON):\n{props_json}\n\n"
        "Evaluate the resource against the WAF rule and respond with the required JSON."
    )


def _parse_response(content: str) -> dict[str, Any] | None:
    content = content.strip()
    if content.startswith("```"):
        lines = content.splitlines()
        content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    try:
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            return None
        if "result" not in parsed:
            return None
        if parsed["result"] not in (_RESULT_PASS, _RESULT_FAIL, _RESULT_REVIEW):
            return None
        return parsed
    except (json.JSONDecodeError, ValueError):
        return None


def _make_finding(
    *,
    rule: WafRule,
    resource: AssessmentResource,
    assessment_id: uuid.UUID,
    batch_id: uuid.UUID,
    tenant_id: uuid.UUID,
    result: str,
    confidence: float,
    evidence: dict[str, Any],
    recommendation: str,
) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        assessment_id=assessment_id,
        batch_id=batch_id,
        tenant_id=tenant_id,
        rule_id=rule.rule_id,
        resource_id=resource.resource_id,
        resource_type=resource.resource_type,
        status=FindingStatus.OPEN,
        severity=Severity(rule.severity),
        pillar=rule.pillar.value,
        confidence_score=min(1.0, max(0.0, confidence)),
        title=rule.title,
        recommendation=recommendation,
        evidence=evidence,
        evaluation_type=rule.evaluation_type.value,
        created_at=datetime.now(UTC),
    )
