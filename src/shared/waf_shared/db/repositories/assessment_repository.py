"""Assessment repository — asyncpg implementation of IAssessmentRepository."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg

from waf_shared.db.jsonb import normalize_jsonb
from waf_shared.db.pool import DatabasePool
from waf_shared.db.repository import BaseRepository
from waf_shared.domain.errors.domain_errors import AssessmentNotFoundError
from waf_shared.domain.models.assessment import (
    Assessment,
    AssessmentBatch,
    AssessmentResource,
    AssessmentStatus,
    BatchStatus,
)
from waf_shared.domain.repositories.i_assessment_repository import IAssessmentRepository

_ASSESSMENT_COLS = """
    id, tenant_id, idempotency_key, status, subscription_ids,
    pillar_filter, tag_filter, requested_by_oid, total_batches,
    completed_batches, cancellation_requested_at, created_at, updated_at
"""

_BATCH_COLS = """
    id, assessment_id, tenant_id, batch_index, subscription_id,
    status, resource_ids, error_detail, started_at, completed_at, created_at
"""

_RESOURCE_COLS = """
    id, assessment_id, batch_id, tenant_id, resource_id, resource_type,
    location, subscription_id, resource_group, raw_properties, extracted_at
"""

_ACTIVE_STATUSES = (
    "pending", "preparing", "extracting", "reasoning", "reporting", "partial_failure"
)



class _AzureSDKEncoder(json.JSONEncoder):
    """JSON encoder that safely handles types the Azure SDK may return in resource properties.

    Handles datetime, uuid.UUID, bytes, and any other object the standard encoder
    cannot serialize — so a non-standard SDK type never crashes upsert_resource.
    """

    def default(self, o: Any) -> Any:  # type: ignore[override]
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, uuid.UUID):
            return str(o)
        if isinstance(o, bytes):
            return o.decode("utf-8", errors="replace")
        try:
            return super().default(o)
        except TypeError:
            return str(o)  # last resort — never crash the DB write


def _row_to_assessment(row: asyncpg.Record) -> Assessment:  # type: ignore[type-arg]
    return Assessment(
        id=row["id"],
        tenant_id=row["tenant_id"],
        idempotency_key=row["idempotency_key"],
        status=AssessmentStatus(row["status"]),
        subscription_ids=list(row["subscription_ids"]),
        pillar_filter=list(row["pillar_filter"]) if row["pillar_filter"] else None,
        tag_filter=normalize_jsonb(row["tag_filter"]) if row["tag_filter"] else None,
        requested_by_oid=row["requested_by_oid"],
        total_batches=row["total_batches"],
        completed_batches=row["completed_batches"],
        cancellation_requested_at=row["cancellation_requested_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_resource(row: asyncpg.Record) -> AssessmentResource:  # type: ignore[type-arg]
    return AssessmentResource(
        id=row["id"],
        assessment_id=row["assessment_id"],
        batch_id=row["batch_id"],
        tenant_id=row["tenant_id"],
        resource_id=row["resource_id"],
        resource_type=row["resource_type"],
        location=row["location"],
        subscription_id=row["subscription_id"],
        resource_group=row["resource_group"],
        raw_properties=normalize_jsonb(row["raw_properties"]) or {},
        extracted_at=row["extracted_at"],
    )


def _row_to_batch(row: asyncpg.Record) -> AssessmentBatch:  # type: ignore[type-arg]
    return AssessmentBatch(
        id=row["id"],
        assessment_id=row["assessment_id"],
        tenant_id=row["tenant_id"],
        batch_index=row["batch_index"],
        subscription_id=row["subscription_id"],
        status=BatchStatus(row["status"]),
        resource_ids=list(row["resource_ids"]),
        error_detail=row["error_detail"],
        started_at=row["started_at"],
        completed_at=row["completed_at"],
        created_at=row["created_at"],
    )


class AssessmentRepository(BaseRepository, IAssessmentRepository):
    def __init__(
        self,
        pool: DatabasePool | None = None,
        *,
        conn: asyncpg.Connection | None = None,  # type: ignore[type-arg]
        uow_tenant_id: uuid.UUID | None = None,
    ) -> None:
        super().__init__(pool=pool, conn=conn, uow_tenant_id=uow_tenant_id)

    async def get_by_id(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> Assessment | None:
        row = await self._read_one(
            f"SELECT {_ASSESSMENT_COLS} FROM assessments "
            "WHERE tenant_id = $1 AND id = $2",
            tenant_id,
            tenant_id,
            assessment_id,
        )
        return _row_to_assessment(row) if row else None

    async def get_by_idempotency_key(
        self,
        tenant_id: uuid.UUID,
        idempotency_key: str,
    ) -> Assessment | None:
        row = await self._read_one(
            f"SELECT {_ASSESSMENT_COLS} FROM assessments "
            "WHERE tenant_id = $1 AND idempotency_key = $2",
            tenant_id,
            tenant_id,
            idempotency_key,
        )
        return _row_to_assessment(row) if row else None

    async def create(self, assessment: Assessment) -> Assessment:
        row = await self._write_one(
            f"""
            INSERT INTO assessments (
                id, tenant_id, idempotency_key, status, subscription_ids,
                pillar_filter, tag_filter, requested_by_oid
            ) VALUES (
                $1, $2, $3, $4::assessment_status, $5::uuid[],
                $6::text[], $7::jsonb, $8
            )
            RETURNING {_ASSESSMENT_COLS}
            """,
            assessment.tenant_id,
            assessment.id,
            assessment.tenant_id,
            assessment.idempotency_key,
            assessment.status.value,
            assessment.subscription_ids,
            assessment.pillar_filter,
            json.dumps(assessment.tag_filter) if assessment.tag_filter is not None else None,
            assessment.requested_by_oid,
        )
        return _row_to_assessment(row) if row is not None else assessment  # type: ignore[arg-type]

    async def update_status(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        status: AssessmentStatus,
    ) -> Assessment:
        row = await self._write_one(
            f"""
            UPDATE assessments
            SET status = $3::assessment_status, updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING {_ASSESSMENT_COLS}
            """,
            tenant_id,
            tenant_id,
            assessment_id,
            status.value,
        )
        if row is None:
            raise AssessmentNotFoundError(assessment_id, tenant_id)
        return _row_to_assessment(row)

    async def set_total_batches(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        total_batches: int,
    ) -> None:
        await self._write(
            "UPDATE assessments SET total_batches = $3, updated_at = NOW() "
            "WHERE tenant_id = $1 AND id = $2",
            tenant_id,
            tenant_id,
            assessment_id,
            total_batches,
        )

    async def increment_completed_batches(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> int:
        row = await self._write_one(
            "UPDATE assessments "
            "SET completed_batches = completed_batches + 1, updated_at = NOW() "
            "WHERE tenant_id = $1 AND id = $2 "
            "RETURNING completed_batches",
            tenant_id,
            tenant_id,
            assessment_id,
        )
        if row is None:
            raise AssessmentNotFoundError(assessment_id, tenant_id)
        return int(row["completed_batches"])

    async def request_cancellation(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> Assessment:
        row = await self._write_one(
            f"""
            UPDATE assessments
            SET cancellation_requested_at = NOW(), updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
              AND cancellation_requested_at IS NULL
            RETURNING {_ASSESSMENT_COLS}
            """,
            tenant_id,
            tenant_id,
            assessment_id,
        )
        if row is None:
            raise AssessmentNotFoundError(assessment_id, tenant_id)
        return _row_to_assessment(row)

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
        status_filter: AssessmentStatus | None = None,
    ) -> list[Assessment]:
        if status_filter is None and cursor is None:
            rows = await self._read(
                f"SELECT {_ASSESSMENT_COLS} FROM assessments "
                "WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2",
                tenant_id,
                tenant_id,
                limit,
            )
        elif status_filter is not None and cursor is None:
            rows = await self._read(
                f"SELECT {_ASSESSMENT_COLS} FROM assessments "
                "WHERE tenant_id = $1 AND status = $2::assessment_status "
                "ORDER BY created_at DESC LIMIT $3",
                tenant_id,
                tenant_id,
                status_filter.value,
                limit,
            )
        elif status_filter is None and cursor is not None:
            rows = await self._read(
                f"SELECT {_ASSESSMENT_COLS} FROM assessments "
                "WHERE tenant_id = $1 AND id < $2 "
                "ORDER BY created_at DESC LIMIT $3",
                tenant_id,
                tenant_id,
                cursor,
                limit,
            )
        else:
            rows = await self._read(
                f"SELECT {_ASSESSMENT_COLS} FROM assessments "
                "WHERE tenant_id = $1 AND status = $2::assessment_status AND id < $3 "
                "ORDER BY created_at DESC LIMIT $4",
                tenant_id,
                tenant_id,
                status_filter.value,  # type: ignore[union-attr]
                cursor,
                limit,
            )
        return [_row_to_assessment(r) for r in rows]

    async def list(
        self,
        tenant_id: uuid.UUID,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
        status_filter: AssessmentStatus | None = None,
    ) -> list[Assessment]:
        """Alias for list_by_tenant — backward-compatible name used by integration tests."""
        return await self.list_by_tenant(
            tenant_id, limit=limit, cursor=cursor, status_filter=status_filter
        )

    async def count_active(self, tenant_id: uuid.UUID) -> int:
        row = await self._read_one(
            "SELECT COUNT(*) AS n FROM assessments "
            "WHERE tenant_id = $1 AND status = ANY($2::assessment_status[])",
            tenant_id,
            tenant_id,
            list(_ACTIVE_STATUSES),
        )
        return int(row["n"]) if row else 0

    async def create_batch(self, batch: AssessmentBatch) -> AssessmentBatch:
        row = await self._write_one(
            f"""
            INSERT INTO assessment_batches (
                id, assessment_id, tenant_id, batch_index,
                subscription_id, status, resource_ids
            ) VALUES ($1, $2, $3, $4, $5, $6::batch_status, $7::text[])
            RETURNING {_BATCH_COLS}
            """,
            batch.tenant_id,
            batch.id,
            batch.assessment_id,
            batch.tenant_id,
            batch.batch_index,
            batch.subscription_id,
            batch.status.value,
            batch.resource_ids,
        )
        return _row_to_batch(row)  # type: ignore[arg-type]

    async def update_batch_status(
        self,
        tenant_id: uuid.UUID,
        batch_id: uuid.UUID,
        status: BatchStatus,
        error_detail: str | None = None,
    ) -> AssessmentBatch:
        now = datetime.now(UTC)
        started_at = now if status == BatchStatus.IN_PROGRESS else None
        completed_at = now if status in (BatchStatus.COMPLETED, BatchStatus.FAILED, BatchStatus.DEAD_LETTERED) else None

        row = await self._write_one(
            f"""
            UPDATE assessment_batches
            SET status       = $3::batch_status,
                error_detail = $4,
                started_at   = COALESCE(started_at, $5),
                completed_at = COALESCE($6, completed_at)
            WHERE tenant_id = $1 AND id = $2
            RETURNING {_BATCH_COLS}
            """,
            tenant_id,
            tenant_id,
            batch_id,
            status.value,
            error_detail,
            started_at,
            completed_at,
        )
        if row is None:
            from waf_shared.domain.errors.infrastructure_errors import DatabaseError
            raise DatabaseError(f"Batch {batch_id} not found for tenant {tenant_id}")
        return _row_to_batch(row)

    async def list_batches(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> list[AssessmentBatch]:
        rows = await self._read(
            f"SELECT {_BATCH_COLS} FROM assessment_batches "
            "WHERE tenant_id = $1 AND assessment_id = $2 ORDER BY batch_index",
            tenant_id,
            tenant_id,
            assessment_id,
        )
        return [_row_to_batch(r) for r in rows]

    async def upsert_resource(self, resource: AssessmentResource) -> AssessmentResource:
        """Insert or update one assessment_resources row.

        On conflict (assessment_id, resource_id) the raw_properties and
        extracted_at are refreshed.  This makes the Extraction Agent idempotent
        on re-delivery: re-processing the same batch overwrites with the same
        data rather than violating the UNIQUE constraint.
        """
        row = await self._write_one(
            f"""
            INSERT INTO assessment_resources (
                id, assessment_id, batch_id, tenant_id, resource_id,
                resource_type, location, subscription_id, resource_group,
                raw_properties, extracted_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)
            ON CONFLICT (assessment_id, resource_id)
            DO UPDATE SET
                raw_properties = EXCLUDED.raw_properties,
                extracted_at   = EXCLUDED.extracted_at
            RETURNING {_RESOURCE_COLS}
            """,
            resource.tenant_id,
            resource.id,
            resource.assessment_id,
            resource.batch_id,
            resource.tenant_id,
            resource.resource_id,
            resource.resource_type,
            resource.location,
            resource.subscription_id,
            resource.resource_group,
            json.dumps(resource.raw_properties, cls=_AzureSDKEncoder),
            resource.extracted_at,
        )
        return _row_to_resource(row)  # type: ignore[arg-type]

    async def count_resources(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> int:
        """Count all assessment_resources rows for this assessment."""
        row = await self._read_one(
            "SELECT COUNT(*) AS n FROM assessment_resources "
            "WHERE tenant_id = $1 AND assessment_id = $2",
            tenant_id,
            tenant_id,
            assessment_id,
        )
        return int(row["n"]) if row else 0

    async def delete_all_batches(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> None:
        """Delete all batches for an assessment (used when restarting a failed preparation)."""
        await self._write(
            "DELETE FROM assessment_batches WHERE tenant_id = $1 AND assessment_id = $2",
            tenant_id,
            tenant_id,
            assessment_id,
        )

    async def aggregate_resource_inventory(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> list[tuple[str, int, int]]:
        """Return (resource_type, total_resources, resources_with_findings).

        Performs a LEFT JOIN between assessment_resources and assessment_findings
        so every resource type is shown even if it has no findings.
        """
        rows = await self._read(
            """
            SELECT
                ar.resource_type,
                COUNT(DISTINCT ar.resource_id)  AS total,
                COUNT(DISTINCT af.resource_id)  AS with_findings
            FROM assessment_resources ar
            LEFT JOIN assessment_findings af
                ON  af.resource_id   = ar.resource_id
                AND af.assessment_id = ar.assessment_id
                AND af.tenant_id     = ar.tenant_id
            WHERE ar.tenant_id     = $1
              AND ar.assessment_id = $2
            GROUP BY ar.resource_type
            ORDER BY total DESC
            """,
            tenant_id,
            tenant_id,
            assessment_id,
        )
        return [
            (r["resource_type"], int(r["total"]), int(r["with_findings"]))
            for r in rows
        ]

    async def list_resources_by_batch(
        self,
        tenant_id: uuid.UUID,
        batch_id: uuid.UUID,
    ) -> list[AssessmentResource]:
        """Return all assessment_resources belonging to a specific batch."""
        rows = await self._read(
            f"SELECT {_RESOURCE_COLS} FROM assessment_resources "
            "WHERE tenant_id = $1 AND batch_id = $2 ORDER BY resource_id",
            tenant_id,
            tenant_id,
            batch_id,
        )
        return [_row_to_resource(r) for r in rows]

    async def complete_batch_and_check_fanin(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        batch_id: uuid.UUID,
    ) -> bool:
        """Atomically mark a batch complete and check whether it was the last.

        Returns True if this call caused completed_batches == total_batches
        (i.e. this was the last batch and the caller should publish
        reporting.requested).  Returns False if the batch was already complete
        (re-delivery safety) or if other batches are still pending.

        The UPDATE + RETURNING is atomic in PostgreSQL, so concurrent pods
        calling this for different batch_ids will each get their own incremented
        count.  Exactly one pod sees the final count that equals total_batches.
        """
        async def _execute(conn: "asyncpg.Connection") -> bool:  # type: ignore[name-defined]
            await conn.execute(
                "SELECT set_config('app.current_tenant_id', $1, true)",
                str(tenant_id),
            )
            # Step 1 — mark batch completed (idempotent with respect to the
            # batch status).  Extraction sets status='completed' before it
            # publishes reasoning.requested, so the status may already be
            # 'completed' when reasoning arrives.  The old guard
            # `AND status != 'completed'` treated that as a re-delivery and
            # returned False; the new SQL has no status condition so it always
            # matches when the row exists.
            #
            # "UPDATE 0" now means the batch row itself is absent (stale / wrong
            # tenant), which is still a correct early-exit for that edge case.
            result = await conn.execute(
                "UPDATE assessment_batches "
                "SET status = 'completed', "
                "    completed_at = COALESCE(completed_at, NOW()) "
                "WHERE tenant_id = $1 AND id = $2",
                tenant_id,
                batch_id,
            )
            if result == "UPDATE 0":
                return False  # Stale message: batch not found for this tenant.

            # Step 2 — atomic fan-in: increment counter, guarded by
            # `completed_batches < total_batches` so we never exceed the total.
            row = await conn.fetchrow(
                "UPDATE assessments "
                "SET completed_batches = completed_batches + 1, updated_at = NOW() "
                "WHERE tenant_id = $1 AND id = $2 "
                "  AND completed_batches < total_batches "
                "RETURNING completed_batches, total_batches",
                tenant_id,
                assessment_id,
            )
            if row is None:
                return False  # Already at total (re-delivery) or assessment not found.

            completed = int(row["completed_batches"])
            total = int(row["total_batches"]) if row["total_batches"] is not None else 0
            return total > 0 and completed == total

        try:
            if self._conn is not None:
                # UoW mode: transaction already in progress.
                return await _execute(self._conn)

            async with self._pool.acquire_write() as conn:  # type: ignore[union-attr]
                async with conn.transaction():
                    return await _execute(conn)
        except asyncpg.PostgresError as exc:
            from waf_shared.domain.errors.infrastructure_errors import DatabaseError
            raise DatabaseError(f"Fan-in check failed: {exc}") from exc
