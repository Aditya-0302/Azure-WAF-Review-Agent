"""Application-layer exceptions — orchestration and flow control failures."""

from __future__ import annotations

import uuid

from waf_shared.domain.errors.domain_errors import WafAgentError


class ApplicationError(WafAgentError):
    """Raised when an application use case cannot proceed due to state conflicts."""


class IdempotencyConflictError(ApplicationError):
    def __init__(self, idempotency_key: str, existing_id: uuid.UUID) -> None:
        super().__init__(
            f"Idempotency key '{idempotency_key}' already mapped to resource {existing_id}",
            code="IDEMPOTENCY_CONFLICT",
        )
        self.idempotency_key = idempotency_key
        self.existing_id = existing_id


class CancellationRequestedError(ApplicationError):
    def __init__(self, assessment_id: uuid.UUID) -> None:
        super().__init__(
            f"Assessment {assessment_id} has a pending cancellation request",
            code="CANCELLATION_REQUESTED",
        )
        self.assessment_id = assessment_id
