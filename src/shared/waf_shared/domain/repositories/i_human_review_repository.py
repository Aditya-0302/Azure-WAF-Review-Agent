"""Repository interface for the HumanReviewAssessment aggregate."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from waf_shared.domain.models.human_review import HumanReviewAssessment


class IHumanReviewRepository(ABC):
    @abstractmethod
    async def create(
        self,
        review: HumanReviewAssessment,
    ) -> HumanReviewAssessment: ...

    @abstractmethod
    async def get_by_id(
        self,
        tenant_id: uuid.UUID,
        review_id: uuid.UUID,
    ) -> HumanReviewAssessment | None: ...

    @abstractmethod
    async def get_by_control(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        control_code: str,
    ) -> HumanReviewAssessment | None: ...

    @abstractmethod
    async def list_by_assessment(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> list[HumanReviewAssessment]: ...

    @abstractmethod
    async def update(
        self,
        review: HumanReviewAssessment,
    ) -> HumanReviewAssessment: ...
