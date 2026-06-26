"""Typed exception hierarchy for the WAF Agent."""

from waf_shared.domain.errors.application_errors import (
    ApplicationError,
    CancellationRequestedError,
    IdempotencyConflictError,
)
from waf_shared.domain.errors.domain_errors import (
    AssessmentNotFoundError,
    DSLValidationError,
    DomainError,
    InvalidAssessmentScopeError,
    QuotaExceededException,
    WafAgentError,
)
from waf_shared.domain.errors.infrastructure_errors import (
    AzureRateLimitError,
    ConnectionPoolExhaustedError,
    CredentialUnavailableError,
    DatabaseError,
    InfrastructureError,
    LLMQuotaExhaustedError,
    LLMRateLimitError,
    QueryTimeoutError,
    ServiceBusDeliveryError,
)

__all__ = [
    "WafAgentError",
    "DomainError",
    "ApplicationError",
    "InfrastructureError",
    "AssessmentNotFoundError",
    "QuotaExceededException",
    "InvalidAssessmentScopeError",
    "DSLValidationError",
    "IdempotencyConflictError",
    "CancellationRequestedError",
    "DatabaseError",
    "ConnectionPoolExhaustedError",
    "QueryTimeoutError",
    "CredentialUnavailableError",
    "AzureRateLimitError",
    "LLMRateLimitError",
    "LLMQuotaExhaustedError",
    "ServiceBusDeliveryError",
]
