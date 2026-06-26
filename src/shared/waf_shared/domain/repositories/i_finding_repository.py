"""Repository interface for the Finding aggregate."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from waf_shared.domain.models.finding import Finding, FindingStatus, Severity


class IFindingRepository(ABC):
    @abstractmethod
    async def create_batch(
        self,
        tenant_id: uuid.UUID,
        findings: list[Finding],
    ) -> None: ...

    @abstractmethod
    async def get_by_id(
        self,
        tenant_id: uuid.UUID,
        finding_id: uuid.UUID,
    ) -> Finding | None: ...

    @abstractmethod
    async def list_by_assessment(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        severity: Severity | None = None,
        pillar: str | None = None,
        status: FindingStatus | None = None,
        limit: int = 100,
        cursor: uuid.UUID | None = None,
    ) -> list[Finding]: ...

    @abstractmethod
    async def update_status(
        self,
        tenant_id: uuid.UUID,
        finding_id: uuid.UUID,
        status: FindingStatus,
    ) -> Finding: ...

    @abstractmethod
    async def count_by_severity(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> dict[str, int]: ...

    @abstractmethod
    async def count_by_pillar(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> dict[str, int]: ...
