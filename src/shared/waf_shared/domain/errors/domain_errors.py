"""Domain-layer exceptions — represent invalid business state."""

from __future__ import annotations

import uuid


class WafAgentError(Exception):
    """Base exception for all WAF Agent errors."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or self.__class__.__name__.upper()


class DomainError(WafAgentError):
    """Raised when a business invariant is violated."""


class AssessmentNotFoundError(DomainError):
    def __init__(self, assessment_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
        super().__init__(
            f"Assessment {assessment_id} not found for tenant {tenant_id}",
        )
        self.assessment_id = assessment_id
        self.tenant_id = tenant_id


class QuotaExceededException(DomainError):
    def __init__(
        self,
        quota_name: str,
        limit: int,
        current: int,
        tenant_id: uuid.UUID,
    ) -> None:
        super().__init__(
            f"Quota '{quota_name}' exceeded for tenant {tenant_id}: limit={limit}, current={current}",
            code="QUOTA_EXCEEDED",
        )
        self.quota_name = quota_name
        self.limit = limit
        self.current = current
        self.tenant_id = tenant_id


class InvalidAssessmentScopeError(DomainError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid assessment scope: {reason}", code="INVALID_SCOPE")
        self.reason = reason


class TenantNotFoundError(DomainError):
    def __init__(self, tenant_id: uuid.UUID) -> None:
        super().__init__(f"Tenant {tenant_id} not found", code="TENANT_NOT_FOUND")
        self.tenant_id = tenant_id


class FindingNotFoundError(DomainError):
    def __init__(self, finding_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
        super().__init__(
            f"Finding {finding_id} not found for tenant {tenant_id}",
            code="FINDING_NOT_FOUND",
        )
        self.finding_id = finding_id
        self.tenant_id = tenant_id


class WafRuleNotFoundError(DomainError):
    def __init__(self, rule_id: str) -> None:
        super().__init__(f"WAF rule '{rule_id}' not found", code="RULE_NOT_FOUND")
        self.rule_id = rule_id


class DSLValidationError(DomainError):
    def __init__(self, rule_id: str, detail: str) -> None:
        super().__init__(
            f"DSL validation failed for rule '{rule_id}': {detail}",
            code="DSL_VALIDATION_ERROR",
        )
        self.rule_id = rule_id
        self.detail = detail


class CredentialNotFoundError(DomainError):
    def __init__(self, credential_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
        super().__init__(
            f"Subscription credential {credential_id} not found for tenant {tenant_id}",
            code="CREDENTIAL_NOT_FOUND",
        )
        self.credential_id = credential_id
        self.tenant_id = tenant_id


class PermissionDeniedError(DomainError):
    def __init__(
        self,
        principal_id: uuid.UUID,
        action: str,
        resource_id: object,
    ) -> None:
        super().__init__(
            f"Principal {principal_id} is not authorized to perform '{action}' on {resource_id}",
            code="PERMISSION_DENIED",
        )
        self.principal_id = principal_id
        self.action = action
        self.resource_id = resource_id


class SubscriptionNotFoundError(DomainError):
    def __init__(self, subscription_id: uuid.UUID) -> None:
        super().__init__(
            f"Subscription {subscription_id} not found or not accessible",
            code="SUBSCRIPTION_NOT_FOUND",
        )
        self.subscription_id = subscription_id


class HumanReviewNotFoundError(DomainError):
    def __init__(self, assessment_id: uuid.UUID, control_code: str) -> None:
        super().__init__(
            f"Human review for control '{control_code}' not found in assessment {assessment_id}",
            code="HUMAN_REVIEW_NOT_FOUND",
        )
        self.assessment_id = assessment_id
        self.control_code = control_code


class HumanReviewControlNotFoundError(DomainError):
    def __init__(self, control_code: str) -> None:
        super().__init__(
            f"Human review control '{control_code}' not found in the catalog",
            code="HUMAN_REVIEW_CONTROL_NOT_FOUND",
        )
        self.control_code = control_code


class WafEnrichmentError(DomainError):
    """Raised when WAF catalog enrichment returns empty waf_codes for a mapped rule.

    This is a permanent failure — the catalog is misconfigured or the mapping file
    was not loaded correctly. The assessment batch is marked FAILED rather than
    allowing findings with silent empty traceability to reach the database.
    """

    def __init__(self, rule_ids: list[str]) -> None:
        ids = sorted(set(rule_ids))
        super().__init__(
            f"WAF enrichment produced empty waf_codes for {len(ids)} mapped rule(s): "
            + ", ".join(ids),
            code="WAF_ENRICHMENT_FAILED",
        )
        self.rule_ids = ids
