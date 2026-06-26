"""Unit tests for WafRuleRepository — covering JSONB normalisation."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest

from waf_shared.domain.models.rule import EvaluationType, Pillar, WafRule


def _make_rule_row(
    *,
    rule_id: str = "STOR-SECURE-001",
    condition_dsl: Any = None,  # dict, JSON string, or None
) -> dict:
    now = datetime.now(UTC)
    return {
        "id": uuid.uuid4(),
        "rule_id": rule_id,
        "pillar": "reliability",
        "resource_types": ["microsoft.network/applicationgateways"],
        "evaluation_type": "deterministic",
        "condition_dsl": condition_dsl,
        "prompt_template_ref": None,
        "severity": "high",
        "title": "Test rule",
        "description": "Test description",
        "recommendation": "Fix it",
        "is_active": True,
        "version": 1,
        "created_at": now,
        "updated_at": now,
    }


def _make_waf_rule(condition_dsl: dict[str, Any] | None = None) -> WafRule:
    now = datetime.now(UTC)
    return WafRule(
        id=uuid.uuid4(),
        rule_id="STOR-SECURE-001",
        pillar=Pillar.RELIABILITY,
        resource_types=["microsoft.network/applicationgateways"],
        evaluation_type=EvaluationType.DETERMINISTIC,
        condition_dsl=condition_dsl,
        prompt_template_ref=None,
        severity="high",
        title="Test rule",
        description="Test description",
        recommendation="Fix it",
        is_active=True,
        version=1,
        created_at=now,
        updated_at=now,
    )


@pytest.mark.unit
class TestWafRuleRepositoryListActive:
    @pytest.mark.asyncio
    async def test_list_active_with_null_condition_dsl(self) -> None:
        """Rules with no condition_dsl (NULL) must map to None without error."""
        from waf_shared.db.repositories.rule_repository import WafRuleRepository

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[_make_rule_row(condition_dsl=None)])

        repo = WafRuleRepository(conn=mock_conn, uow_tenant_id=uuid.uuid4())
        results = await repo.list_active()

        assert len(results) == 1
        assert results[0].condition_dsl is None

    @pytest.mark.asyncio
    async def test_list_active_condition_dsl_as_dict(self) -> None:
        """asyncpg with codec returns condition_dsl as Python dict."""
        from waf_shared.db.repositories.rule_repository import WafRuleRepository

        dsl = {"operator": "equals", "field": "enabledState", "value": "Enabled"}
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[_make_rule_row(condition_dsl=dsl)])

        repo = WafRuleRepository(conn=mock_conn, uow_tenant_id=uuid.uuid4())
        results = await repo.list_active()

        assert results[0].condition_dsl == dsl

    @pytest.mark.asyncio
    async def test_list_active_condition_dsl_as_json_string(self) -> None:
        """asyncpg without codec returns condition_dsl as JSON string — the production bug."""
        from waf_shared.db.repositories.rule_repository import WafRuleRepository

        dsl = {"operator": "equals", "field": "enabledState", "value": "Enabled"}
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[_make_rule_row(condition_dsl=json.dumps(dsl))])

        repo = WafRuleRepository(conn=mock_conn, uow_tenant_id=uuid.uuid4())
        results = await repo.list_active()

        assert results[0].condition_dsl == dsl

    @pytest.mark.asyncio
    async def test_get_by_rule_id_returns_rule(self) -> None:
        from waf_shared.db.repositories.rule_repository import WafRuleRepository

        dsl = {"check": "minTlsVersion", "expected": "TLS1_2"}
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[_make_rule_row(rule_id="STOR-TLS-001", condition_dsl=dsl)]
        )

        repo = WafRuleRepository(conn=mock_conn, uow_tenant_id=uuid.uuid4())
        result = await repo.get_by_rule_id("STOR-TLS-001")

        assert result is not None
        assert result.rule_id == "STOR-TLS-001"
        assert result.condition_dsl == dsl

    @pytest.mark.asyncio
    async def test_get_by_rule_id_returns_none_when_not_found(self) -> None:
        from waf_shared.db.repositories.rule_repository import WafRuleRepository

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = WafRuleRepository(conn=mock_conn, uow_tenant_id=uuid.uuid4())
        result = await repo.get_by_rule_id("NONEXISTENT")

        assert result is None


@pytest.mark.unit
class TestWafRuleRepositoryUpsert:
    @pytest.mark.asyncio
    async def test_upsert_condition_dsl_as_dict(self) -> None:
        from waf_shared.db.repositories.rule_repository import WafRuleRepository

        dsl = {"operator": "contains", "field": "wafMode", "value": "Prevention"}
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[_make_rule_row(condition_dsl=dsl)])

        repo = WafRuleRepository(conn=mock_conn, uow_tenant_id=uuid.uuid4())
        result = await repo.upsert(_make_waf_rule(condition_dsl=dsl))

        assert result.condition_dsl == dsl

    @pytest.mark.asyncio
    async def test_upsert_condition_dsl_as_json_string_in_returning(self) -> None:
        """RETURNING clause gives back JSON string even when dict was written."""
        from waf_shared.db.repositories.rule_repository import WafRuleRepository

        dsl = {"operator": "contains", "field": "wafMode", "value": "Prevention"}
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[_make_rule_row(condition_dsl=json.dumps(dsl))])

        repo = WafRuleRepository(conn=mock_conn, uow_tenant_id=uuid.uuid4())
        result = await repo.upsert(_make_waf_rule(condition_dsl=dsl))

        assert result.condition_dsl == dsl

    @pytest.mark.asyncio
    async def test_upsert_null_condition_dsl(self) -> None:
        from waf_shared.db.repositories.rule_repository import WafRuleRepository

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[_make_rule_row(condition_dsl=None)])

        repo = WafRuleRepository(conn=mock_conn, uow_tenant_id=uuid.uuid4())
        result = await repo.upsert(_make_waf_rule(condition_dsl=None))

        assert result.condition_dsl is None
