"""Deterministic evaluation pipeline — zero LLM calls, zero cost.

For each deterministic WAF rule applicable to a resource this pipeline:
  1. Evaluates rule.condition_dsl against resource.raw_properties via the DSL
     evaluator.
  2. Produces a Finding (status=OPEN, evaluation result stored in evidence) only
     when the resource FAILS the rule.  PASS resources generate no Finding — the
     absence of a Finding is evidence of compliance.
  3. On DSLValidationError (malformed condition): logs the error and produces a
     REVIEW finding (confidence_score < 1.0) so an operator can investigate.
     The batch is NOT failed — one broken rule should not block all findings.

All findings are collected and returned to the caller; they are NOT written to
the database here (the handler batches all findings and does one INSERT).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from waf_reasoning.dsl_evaluator import evaluate_condition

from waf_shared.domain.errors.domain_errors import DSLValidationError
from waf_shared.domain.models.assessment import AssessmentResource
from waf_shared.domain.models.finding import Finding, FindingStatus, Severity
from waf_shared.domain.models.rule import EvaluationType, WafRule
from waf_shared.telemetry.logging import StructuredLogger

_DETERMINISTIC_RESULT_PASS = "PASS"
_DETERMINISTIC_RESULT_FAIL = "FAIL"
_DETERMINISTIC_RESULT_REVIEW = "REVIEW"
_CONFIDENCE_CERTAIN = 1.0
_CONFIDENCE_UNCERTAIN = 0.5

# Operators whose True result means "violation detected" (not "resource is compliant").
# All other operators use compliance-assertion semantics: True = passes the check.
_VIOLATION_OPS: frozenset[str] = frozenset({"is_null"})


def _condition_is_violation_detector(dsl: dict[str, Any]) -> bool:
    """Return True when the DSL node uses violation-detection semantics.

    ``is_null`` returns True when a non-compliant condition exists (property
    is absent or None).  Logical combinators (or/and) inherit the convention
    if any of their sub-nodes are violation detectors.
    """
    op = dsl.get("op", "")
    if op in _VIOLATION_OPS:
        return True
    if op in ("or", "and"):
        return any(_condition_is_violation_detector(c) for c in dsl.get("conditions", []))
    return False


class DeterministicPipeline:
    """Evaluates all deterministic rules for one resource without any I/O."""

    def __init__(self, logger: StructuredLogger) -> None:
        self._logger = logger

    def evaluate(
        self,
        resource: AssessmentResource,
        rules: list[WafRule],
        *,
        assessment_id: uuid.UUID,
        batch_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> list[Finding]:
        """Evaluate all deterministic rules and return findings for failures only.

        PASS results do not produce findings.
        """
        findings: list[Finding] = []

        for rule in rules:
            if rule.evaluation_type not in (EvaluationType.DETERMINISTIC, EvaluationType.HYBRID):
                continue
            if rule.condition_dsl is None:
                continue

            finding = self._evaluate_one(
                resource=resource,
                rule=rule,
                assessment_id=assessment_id,
                batch_id=batch_id,
                tenant_id=tenant_id,
            )
            if finding is not None:
                findings.append(finding)

        return findings

    def _evaluate_one(
        self,
        *,
        resource: AssessmentResource,
        rule: WafRule,
        assessment_id: uuid.UUID,
        batch_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> Finding | None:
        try:
            raw = evaluate_condition(
                rule.rule_id,
                rule.condition_dsl,  # type: ignore[arg-type]
                resource.raw_properties,
            )
        except DSLValidationError as exc:
            self._logger.error(
                "reasoning.deterministic.dsl_error",
                rule_id=rule.rule_id,
                resource_id=resource.resource_id,
                error=exc.detail,
            )
            return _make_finding(
                rule=rule,
                resource=resource,
                assessment_id=assessment_id,
                batch_id=batch_id,
                tenant_id=tenant_id,
                result=_DETERMINISTIC_RESULT_REVIEW,
                confidence=_CONFIDENCE_UNCERTAIN,
                evidence={
                    "result": _DETERMINISTIC_RESULT_REVIEW,
                    "evaluation_type": "deterministic",
                    "error": f"DSL evaluation error: {exc.detail}",
                },
            )

        # Resolve which convention the condition uses:
        #   Violation-detection (is_null, or/and containing is_null):
        #     True  = violation found  → finding
        #     False = no violation     → no finding
        #   Compliance-assertion (all other operators):
        #     True  = resource passes  → no finding
        #     False = resource fails   → finding
        violation_mode = _condition_is_violation_detector(rule.condition_dsl)  # type: ignore[arg-type]
        passed = not raw if violation_mode else raw

        self._logger.info(
            "reasoning.deterministic.evaluated",
            rule_id=rule.rule_id,
            resource_id=resource.resource_id,
            passed=passed,
        )

        if passed:
            return None  # No finding for compliant resources.

        return _make_finding(
            rule=rule,
            resource=resource,
            assessment_id=assessment_id,
            batch_id=batch_id,
            tenant_id=tenant_id,
            result=_DETERMINISTIC_RESULT_FAIL,
            confidence=_CONFIDENCE_CERTAIN,
            evidence={
                "result": _DETERMINISTIC_RESULT_FAIL,
                "evaluation_type": "deterministic",
                "rule_id": rule.rule_id,
                "resource_type": resource.resource_type,
            },
        )


# ── Helpers ────────────────────────────────────────────────────────────────────


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
        confidence_score=confidence,
        title=rule.title,
        recommendation=rule.recommendation,
        evidence=evidence,
        evaluation_type=rule.evaluation_type.value,
        created_at=datetime.now(UTC),
    )
