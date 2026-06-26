"""Repository interface for the Assessment aggregate."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from waf_shared.domain.models.assessment import (
    Assessment,
    AssessmentBatch,
    AssessmentStatus,
    BatchStatus,
)


class IAssessmentRepository(ABC):
    @abstractmethod
    async def get_by_id(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> Assessment | None: ...

    @abstractmethod
    async def get_by_idempotency_key(
        self,
        tenant_id: uuid.UUID,
        idempotency_key: str,
    ) -> Assessment | None: ...

    @abstractmethod
    async def create(self, assessment: Assessment) -> Assessment: ...

    @abstractmethod
    async def update_status(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        status: AssessmentStatus,
    ) -> Assessment: ...

    @abstractmethod
    async def set_total_batches(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        total_batches: int,
    ) -> None: ...

    @abstractmethod
    async def increment_completed_batches(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> int: ...

    @abstractmethod
    async def request_cancellation(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> Assessment: ...

    @abstractmethod
    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
        status_filter: AssessmentStatus | None = None,
    ) -> list[Assessment]: ...

    @abstractmethod
    async def count_active(self, tenant_id: uuid.UUID) -> int: ...

    @abstractmethod
    async def create_batch(self, batch: AssessmentBatch) -> AssessmentBatch: ...

    @abstractmethod
    async def update_batch_status(
        self,
        tenant_id: uuid.UUID,
        batch_id: uuid.UUID,
        status: BatchStatus,
        error_detail: str | None = None,
    ) -> AssessmentBatch: ...

    @abstractmethod
    async def list_batches(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> list[AssessmentBatch]: ...
