"""Unit tests for AssessmentRepository."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest

from waf_shared.domain.errors.domain_errors import AssessmentNotFoundError
from waf_shared.domain.models.assessment import Assessment, AssessmentResource, AssessmentStatus


def _make_assessment_row(
    *,
    tenant_id: uuid.UUID | None = None,
    assessment_id: uuid.UUID | None = None,
    status: str = "pending",
) -> dict:
    now = datetime.now(UTC)
    t_id = tenant_id or uuid.uuid4()
    a_id = assessment_id or uuid.uuid4()
    return {
        "id": a_id,
        "tenant_id": t_id,
        "idempotency_key": "idem-001",
        "status": status,
        "subscription_ids": [uuid.uuid4()],
        "pillar_filter": None,
        "tag_filter": None,
        "requested_by_oid": uuid.uuid4(),
        "total_batches": None,
        "completed_batches": 0,
        "cancellation_requested_at": None,
        "created_at": now,
        "updated_at": now,
    }


@pytest.mark.unit
class TestAssessmentRepositoryGetById:
    @pytest.mark.asyncio
    async def test_returns_assessment_when_found(self) -> None:
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[_make_assessment_row(tenant_id=tenant_id, assessment_id=assessment_id)]
        )

        repo = AssessmentRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_id(tenant_id, assessment_id)

        assert result is not None
        assert result.id == assessment_id
        assert result.tenant_id == tenant_id
        assert result.status == AssessmentStatus.PENDING

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = AssessmentRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_id(tenant_id, uuid.uuid4())

        assert result is None

    @pytest.mark.asyncio
    async def test_query_filters_by_tenant_id(self) -> None:
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = AssessmentRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        await repo.get_by_id(tenant_id, assessment_id)

        call_sql = mock_conn.fetch.call_args[0][0]
        assert "tenant_id = $1" in call_sql


@pytest.mark.unit
class TestAssessmentRepositoryCreate:
    @pytest.mark.asyncio
    async def test_create_issues_insert_returning(self) -> None:
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        now = datetime.now(UTC)
        assessment_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[_make_assessment_row(tenant_id=tenant_id, assessment_id=assessment_id)]
        )

        repo = AssessmentRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        assessment = Assessment(
            id=assessment_id,
            tenant_id=tenant_id,
            idempotency_key="idem-001",
            status=AssessmentStatus.PENDING,
            subscription_ids=[uuid.uuid4()],
            pillar_filter=None,
            tag_filter=None,
            requested_by_oid=uuid.uuid4(),
            total_batches=None,
            completed_batches=0,
            cancellation_requested_at=None,
            created_at=now,
            updated_at=now,
        )

        result = await repo.create(assessment)

        assert result.id == assessment_id
        call_sql = mock_conn.fetch.call_args[0][0]
        assert "INSERT INTO assessments" in call_sql
        assert "RETURNING" in call_sql


@pytest.mark.unit
class TestAssessmentRepositoryUpdateStatus:
    @pytest.mark.asyncio
    async def test_update_status_returns_assessment(self) -> None:
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                _make_assessment_row(
                    tenant_id=tenant_id,
                    assessment_id=assessment_id,
                    status="completed",
                )
            ]
        )

        repo = AssessmentRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.update_status(tenant_id, assessment_id, AssessmentStatus.COMPLETED)

        assert result.status == AssessmentStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_update_status_raises_when_not_found(self) -> None:
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = AssessmentRepository(conn=mock_conn, uow_tenant_id=tenant_id)

        with pytest.raises(AssessmentNotFoundError) as exc_info:
            await repo.update_status(tenant_id, assessment_id, AssessmentStatus.FAILED)

        assert exc_info.value.assessment_id == assessment_id
        assert exc_info.value.tenant_id == tenant_id


@pytest.mark.unit
class TestAssessmentRepositoryCountActive:
    @pytest.mark.asyncio
    async def test_count_active_returns_integer(self) -> None:
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[{"n": 2}])

        repo = AssessmentRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.count_active(tenant_id)

        assert result == 2

    @pytest.mark.asyncio
    async def test_count_active_returns_zero_when_empty(self) -> None:
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = AssessmentRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.count_active(tenant_id)

        assert result == 0


@pytest.mark.unit
class TestAssessmentRepositoryIdempotencyKey:
    @pytest.mark.asyncio
    async def test_get_by_idempotency_key_returns_assessment(self) -> None:
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[_make_assessment_row(tenant_id=tenant_id, assessment_id=assessment_id)]
        )

        repo = AssessmentRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_idempotency_key(tenant_id, "idem-001")

        assert result is not None
        assert result.idempotency_key == "idem-001"


# ── Helpers for resource row tests ────────────────────────────────────────────


def _make_resource_row(
    *,
    tenant_id: uuid.UUID,
    assessment_id: uuid.UUID,
    batch_id: uuid.UUID,
    raw_properties: Any,  # dict or JSON string — tests both
) -> dict:
    now = datetime.now(UTC)
    return {
        "id": uuid.uuid4(),
        "assessment_id": assessment_id,
        "batch_id": batch_id,
        "tenant_id": tenant_id,
        "resource_id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw1",
        "resource_type": "microsoft.network/applicationgateways",
        "location": "eastus",
        "subscription_id": uuid.uuid4(),
        "resource_group": "rg",
        "raw_properties": raw_properties,
        "extracted_at": now,
    }


def _make_assessment_resource(
    tenant_id: uuid.UUID,
    assessment_id: uuid.UUID,
    batch_id: uuid.UUID,
    raw_props: dict[str, Any],
) -> AssessmentResource:
    now = datetime.now(UTC)
    return AssessmentResource(
        id=uuid.uuid4(),
        assessment_id=assessment_id,
        batch_id=batch_id,
        tenant_id=tenant_id,
        resource_id="/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw1",
        resource_type="microsoft.network/applicationgateways",
        location="eastus",
        subscription_id=uuid.uuid4(),
        resource_group="rg",
        raw_properties=raw_props,
        extracted_at=now,
    )


# ── normalize_jsonb unit tests ────────────────────────────────────────────────


@pytest.mark.unit
class TestNormalizeJsonb:
    """normalize_jsonb must handle every form asyncpg can return for a JSONB column."""

    def test_dict_input_returned_as_is(self) -> None:
        from waf_shared.db.jsonb import normalize_jsonb

        data: dict[str, Any] = {"key": "value", "nested": {"a": 1}}
        assert normalize_jsonb(data) == data

    def test_json_string_decoded_to_dict(self) -> None:
        """asyncpg without a registered codec returns raw JSON text — the production bug."""
        from waf_shared.db.jsonb import normalize_jsonb

        data: dict[str, Any] = {"id": "/sub/...", "properties": {"backendPools": []}}
        assert normalize_jsonb(json.dumps(data)) == data

    def test_none_returns_none(self) -> None:
        from waf_shared.db.jsonb import normalize_jsonb

        assert normalize_jsonb(None) is None

    def test_list_input_returned_as_is(self) -> None:
        from waf_shared.db.jsonb import normalize_jsonb

        data = [1, 2, 3]
        assert normalize_jsonb(data) == data

    def test_json_array_string_decoded_to_list(self) -> None:
        from waf_shared.db.jsonb import normalize_jsonb

        assert normalize_jsonb("[1, 2, 3]") == [1, 2, 3]

    def test_empty_dict_input(self) -> None:
        from waf_shared.db.jsonb import normalize_jsonb

        assert normalize_jsonb({}) == {}

    def test_empty_json_object_string(self) -> None:
        from waf_shared.db.jsonb import normalize_jsonb

        assert normalize_jsonb("{}") == {}

    def test_malformed_json_string_raises(self) -> None:
        from waf_shared.db.jsonb import normalize_jsonb

        with pytest.raises(json.JSONDecodeError):
            normalize_jsonb("{not: valid json")

    def test_unsupported_type_raises_type_error(self) -> None:
        from waf_shared.db.jsonb import normalize_jsonb

        with pytest.raises(TypeError, match="unsupported type"):
            normalize_jsonb(42)


# ── upsert_resource JSONB round-trip tests ────────────────────────────────────


@pytest.mark.unit
class TestUpsertResourceJsonb:
    """upsert_resource must accept JSONB returned as dict or JSON string."""

    @pytest.mark.asyncio
    async def test_upsert_resource_raw_props_as_dict(self) -> None:
        """asyncpg with native codec returns a Python dict — must still work."""
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        raw_props: dict[str, Any] = {"id": "/sub/x", "properties": {"wafEnabled": True}}

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                _make_resource_row(
                    tenant_id=tenant_id,
                    assessment_id=assessment_id,
                    batch_id=batch_id,
                    raw_properties=raw_props,
                )
            ]
        )

        repo = AssessmentRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.upsert_resource(
            _make_assessment_resource(tenant_id, assessment_id, batch_id, raw_props)
        )

        assert result.raw_properties == raw_props

    @pytest.mark.asyncio
    async def test_upsert_resource_raw_props_as_json_string(self) -> None:
        """asyncpg without codec returns a JSON string — this was the production bug."""
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        raw_props: dict[str, Any] = {"id": "/sub/x", "properties": {"wafEnabled": True}}

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                _make_resource_row(
                    tenant_id=tenant_id,
                    assessment_id=assessment_id,
                    batch_id=batch_id,
                    raw_properties=json.dumps(raw_props),  # ← string, not dict
                )
            ]
        )

        repo = AssessmentRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.upsert_resource(
            _make_assessment_resource(tenant_id, assessment_id, batch_id, raw_props)
        )

        assert result.raw_properties == raw_props

    @pytest.mark.asyncio
    async def test_upsert_resource_raw_props_none_returns_empty_dict(self) -> None:
        """NULL raw_properties normalises to an empty dict."""
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                _make_resource_row(
                    tenant_id=tenant_id,
                    assessment_id=assessment_id,
                    batch_id=batch_id,
                    raw_properties=None,
                )
            ]
        )

        repo = AssessmentRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.upsert_resource(
            _make_assessment_resource(tenant_id, assessment_id, batch_id, {})
        )

        assert result.raw_properties == {}


# ── complete_batch_and_check_fanin tests ──────────────────────────────────────


@pytest.mark.unit
class TestCompleteBatchAndCheckFanin:
    """Fan-in must correctly detect the last batch and guard against re-delivery."""

    def _make_conn(
        self,
        *,
        batch_update_result: str,
        completed_batches: int,
        total_batches: int | None,
    ) -> AsyncMock:
        conn = AsyncMock()
        # First execute = set_config (returns None); second = UPDATE assessment_batches
        conn.execute = AsyncMock(side_effect=[None, batch_update_result])
        conn.fetchrow = AsyncMock(
            return_value={
                "completed_batches": completed_batches,
                "total_batches": total_batches,
            }
        )
        return conn

    @pytest.mark.asyncio
    async def test_single_batch_returns_true(self) -> None:
        """total_batches=1, batch_index=0: the one and only batch must return True."""
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()

        conn = self._make_conn(
            batch_update_result="UPDATE 1",
            completed_batches=1,
            total_batches=1,
        )
        repo = AssessmentRepository(conn=conn, uow_tenant_id=tenant_id)
        result = await repo.complete_batch_and_check_fanin(tenant_id, assessment_id, batch_id)

        assert result is True

    @pytest.mark.asyncio
    async def test_first_of_two_batches_returns_false(self) -> None:
        """total_batches=2, batch_index=0: not the last batch, must return False."""
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()

        conn = self._make_conn(
            batch_update_result="UPDATE 1",
            completed_batches=1,
            total_batches=2,
        )
        repo = AssessmentRepository(conn=conn, uow_tenant_id=tenant_id)
        result = await repo.complete_batch_and_check_fanin(tenant_id, assessment_id, batch_id)

        assert result is False

    @pytest.mark.asyncio
    async def test_last_of_two_batches_returns_true(self) -> None:
        """total_batches=2, batch_index=1: the final batch must return True."""
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()

        conn = self._make_conn(
            batch_update_result="UPDATE 1",
            completed_batches=2,
            total_batches=2,
        )
        repo = AssessmentRepository(conn=conn, uow_tenant_id=tenant_id)
        result = await repo.complete_batch_and_check_fanin(tenant_id, assessment_id, batch_id)

        assert result is True

    @pytest.mark.asyncio
    async def test_redelivery_returns_false_without_incrementing(self) -> None:
        """If the batch was already COMPLETED (re-delivery), return False and skip increment."""
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository

        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()

        conn = AsyncMock()
        conn.execute = AsyncMock(side_effect=[None, "UPDATE 0"])
        conn.fetchrow = AsyncMock()  # must NOT be called

        repo = AssessmentRepository(conn=conn, uow_tenant_id=tenant_id)
        result = await repo.complete_batch_and_check_fanin(tenant_id, assessment_id, batch_id)

        assert result is False
        conn.fetchrow.assert_not_awaited()
