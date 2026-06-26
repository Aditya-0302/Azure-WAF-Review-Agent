"""Repository interface for WAF Rules (system-scoped, not per-tenant)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from waf_shared.domain.models.rule import Pillar, WafRule


class IWafRuleRepository(ABC):
    @abstractmethod
    async def get_by_rule_id(self, rule_id: str) -> WafRule | None: ...

    @abstractmethod
    async def list_active(
        self,
        pillar: Pillar | None = None,
        resource_types: list[str] | None = None,
    ) -> list[WafRule]: ...

    @abstractmethod
    async def upsert(self, rule: WafRule) -> WafRule: ...

    @abstractmethod
    async def deactivate(self, rule_id: str) -> None: ...

    @abstractmethod
    async def count_active(self) -> int: ...
