"""Unit tests for FindingRepository."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest

from waf_shared.domain.errors.domain_errors import FindingNotFoundError
from waf_shared.domain.models.finding import Finding, FindingStatus, Severity

_MISSING: Any = object()  # sentinel — distinguishes "not provided" from explicit None


def _make_finding_row(
    *,
    tenant_id: uuid.UUID | None = None,
    finding_id: uuid.UUID | None = None,
    assessment_id: uuid.UUID | None = None,
    severity: str = "high",
    status: str = "open",
    evidence: Any = _MISSING,  # dict, JSON string, None, or _MISSING → default dict
) -> dict:
    return {
        "id": finding_id or uuid.uuid4(),
        "assessment_id": assessment_id or uuid.uuid4(),
        "batch_id": uuid.uuid4(),
        "tenant_id": tenant_id or uuid.uuid4(),
        "rule_id": "REL-VM-001",
        "resource_id": "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
        "resource_type": "Microsoft.Compute/virtualMachines",
        "status": status,
        "severity": severity,
        "pillar": "reliability",
        "confidence_score": 0.95,
        "title": "VM not in availability set",
        "recommendation": "Place VM in availability set",
        "evidence": {"key": "value"} if evidence is _MISSING else evidence,
        "evaluation_type": "deterministic",
        "created_at": datetime.now(UTC),
        "waf_codes": [],
        "waf_titles": [],
        "microsoft_urls": [],
    }


@pytest.mark.unit
class TestFindingRepositoryGetById:
    @pytest.mark.asyncio
    async def test_returns_finding_when_found(self) -> None:
        from waf_shared.db.repositories.finding_repository import FindingRepository

        tenant_id = uuid.uuid4()
        finding_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[_make_finding_row(tenant_id=tenant_id, finding_id=finding_id)]
        )

        repo = FindingRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_id(tenant_id, finding_id)

        assert result is not None
        assert result.id == finding_id
        assert result.severity == Severity.HIGH
        assert result.status == FindingStatus.OPEN

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        from waf_shared.db.repositories.finding_repository import FindingRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = FindingRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_id(tenant_id, uuid.uuid4())

        assert result is None


@pytest.mark.unit
class TestFindingRepositoryUpdateStatus:
    @pytest.mark.asyncio
    async def test_update_status_returns_updated_finding(self) -> None:
        from waf_shared.db.repositories.finding_repository import FindingRepository

        tenant_id = uuid.uuid4()
        finding_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                _make_finding_row(
                    tenant_id=tenant_id,
                    finding_id=finding_id,
                    status="acknowledged",
                )
            ]
        )

        repo = FindingRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.update_status(tenant_id, finding_id, FindingStatus.ACKNOWLEDGED)

        assert result.status == FindingStatus.ACKNOWLEDGED

    @pytest.mark.asyncio
    async def test_update_status_raises_when_not_found(self) -> None:
        from waf_shared.db.repositories.finding_repository import FindingRepository

        tenant_id = uuid.uuid4()
        finding_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = FindingRepository(conn=mock_conn, uow_tenant_id=tenant_id)

        with pytest.raises(FindingNotFoundError) as exc_info:
            await repo.update_status(tenant_id, finding_id, FindingStatus.RESOLVED)

        assert exc_info.value.finding_id == finding_id


@pytest.mark.unit
class TestFindingRepositoryCreateBatch:
    @pytest.mark.asyncio
    async def test_create_batch_empty_list_is_no_op(self) -> None:
        from waf_shared.db.repositories.finding_repository import FindingRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.executemany = AsyncMock()

        repo = FindingRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        await repo.create_batch(tenant_id, [])

        mock_conn.executemany.assert_not_called()

    @pytest.mark.asyncio
    async def test_create_batch_calls_executemany_once(self) -> None:
        from waf_shared.db.repositories.finding_repository import FindingRepository

        tenant_id = uuid.uuid4()
        now = datetime.now(UTC)

        findings = [
            Finding(
                id=uuid.uuid4(),
                assessment_id=uuid.uuid4(),
                batch_id=uuid.uuid4(),
                tenant_id=tenant_id,
                rule_id="REL-VM-001",
                resource_id="/subs/xxx/rg/r1",
                resource_type="Microsoft.Compute/virtualMachines",
                status=FindingStatus.OPEN,
                severity=Severity.HIGH,
                pillar="reliability",
                confidence_score=0.9,
                title="Test finding",
                recommendation="Fix it",
                evidence={},
                evaluation_type="deterministic",
                created_at=now,
            )
        ]

        mock_conn = AsyncMock()
        mock_conn.executemany = AsyncMock()

        repo = FindingRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        await repo.create_batch(tenant_id, findings)

        mock_conn.executemany.assert_called_once()
        call_sql = mock_conn.executemany.call_args[0][0]
        assert "INSERT INTO assessment_findings" in call_sql

    @pytest.mark.asyncio
    async def test_create_batch_passes_all_findings(self) -> None:
        from waf_shared.db.repositories.finding_repository import FindingRepository

        tenant_id = uuid.uuid4()
        now = datetime.now(UTC)
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()

        findings = [
            Finding(
                id=uuid.uuid4(),
                assessment_id=assessment_id,
                batch_id=batch_id,
                tenant_id=tenant_id,
                rule_id=f"REL-VM-00{i}",
                resource_id=f"/subs/xxx/r{i}",
                resource_type="Microsoft.Compute/virtualMachines",
                status=FindingStatus.OPEN,
                severity=Severity.MEDIUM,
                pillar="reliability",
                confidence_score=0.8,
                title=f"Finding {i}",
                recommendation="Fix it",
                evidence={},
                evaluation_type="deterministic",
                created_at=now,
            )
            for i in range(3)
        ]

        mock_conn = AsyncMock()
        mock_conn.executemany = AsyncMock()

        repo = FindingRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        await repo.create_batch(tenant_id, findings)

        records = mock_conn.executemany.call_args[0][1]
        assert len(records) == 3


@pytest.mark.unit
class TestFindingRepositoryCountBySeverity:
    @pytest.mark.asyncio
    async def test_count_by_severity_returns_dict(self) -> None:
        from waf_shared.db.repositories.finding_repository import FindingRepository

        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                {"severity": "high", "n": 5},
                {"severity": "medium", "n": 3},
                {"severity": "low", "n": 1},
            ]
        )

        repo = FindingRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.count_by_severity(tenant_id, assessment_id)

        assert result == {"high": 5, "medium": 3, "low": 1}


# ── JSONB evidence column tests ───────────────────────────────────────────────


@pytest.mark.unit
class TestFindingRepositoryEvidenceJsonb:
    """evidence column must be correctly normalised from any asyncpg return type."""

    @pytest.mark.asyncio
    async def test_get_by_id_evidence_as_dict(self) -> None:
        """asyncpg with codec returns evidence as Python dict."""
        from waf_shared.db.repositories.finding_repository import FindingRepository

        tenant_id = uuid.uuid4()
        finding_id = uuid.uuid4()
        evidence = {"wafMode": "Detection", "recommendation": "Switch to Prevention"}

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                _make_finding_row(tenant_id=tenant_id, finding_id=finding_id, evidence=evidence)
            ]
        )

        repo = FindingRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_id(tenant_id, finding_id)

        assert result is not None
        assert result.evidence == evidence

    @pytest.mark.asyncio
    async def test_get_by_id_evidence_as_json_string(self) -> None:
        """asyncpg without codec returns evidence as JSON string — the production bug."""
        from waf_shared.db.repositories.finding_repository import FindingRepository

        tenant_id = uuid.uuid4()
        finding_id = uuid.uuid4()
        evidence: dict[str, Any] = {
            "wafMode": "Detection",
            "recommendation": "Switch to Prevention",
        }

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                _make_finding_row(
                    tenant_id=tenant_id,
                    finding_id=finding_id,
                    evidence=json.dumps(evidence),  # ← string, not dict
                )
            ]
        )

        repo = FindingRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_id(tenant_id, finding_id)

        assert result is not None
        assert result.evidence == evidence

    @pytest.mark.asyncio
    async def test_get_by_id_null_evidence_returns_empty_dict(self) -> None:
        """NULL evidence normalises to {} (non-optional field in domain model)."""
        from waf_shared.db.repositories.finding_repository import FindingRepository

        tenant_id = uuid.uuid4()
        finding_id = uuid.uuid4()

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                _make_finding_row(tenant_id=tenant_id, finding_id=finding_id, evidence=None)
            ]
        )

        repo = FindingRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_id(tenant_id, finding_id)

        assert result is not None
        assert result.evidence == {}
