"""ReportRepository — asyncpg CRUD for assessment_reports."""

from __future__ import annotations

import json
import uuid
from datetime import datetime

import asyncpg

from waf_shared.db.pool import DatabasePool
from waf_shared.db.repository import BaseRepository
from waf_shared.domain.models.report import AssessmentReport, AssessmentSummary

_COLS = "id, assessment_id, tenant_id, xlsx_blob_path, pdf_blob_path, summary, generated_at"


def _row_to_report(row: asyncpg.Record) -> AssessmentReport:  # type: ignore[type-arg]
    summary_raw = row["summary"]
    if isinstance(summary_raw, str):
        summary_data = json.loads(summary_raw)
    else:
        summary_data = dict(summary_raw)
    return AssessmentReport(
        id=row["id"],
        assessment_id=row["assessment_id"],
        tenant_id=row["tenant_id"],
        xlsx_blob_path=row["xlsx_blob_path"],
        pdf_blob_path=row["pdf_blob_path"],
        summary=AssessmentSummary.model_validate(summary_data),
        generated_at=row["generated_at"],
    )


class ReportRepository(BaseRepository):
    def __init__(
        self,
        pool: DatabasePool | None = None,
        *,
        conn: asyncpg.Connection | None = None,  # type: ignore[type-arg]
        uow_tenant_id: uuid.UUID | None = None,
    ) -> None:
        super().__init__(pool=pool, conn=conn, uow_tenant_id=uow_tenant_id)

    async def create(self, report: AssessmentReport) -> AssessmentReport:
        row = await self._write_one(
            f"""
            INSERT INTO assessment_reports (
                id, assessment_id, tenant_id,
                xlsx_blob_path, pdf_blob_path, summary, generated_at
            ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
            RETURNING {_COLS}
            """,
            report.tenant_id,
            report.id,
            report.assessment_id,
            report.tenant_id,
            report.xlsx_blob_path,
            report.pdf_blob_path,
            report.summary.model_dump_json(),
            report.generated_at,
        )
        return _row_to_report(row)  # type: ignore[arg-type]

    async def get_by_assessment(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> AssessmentReport | None:
        row = await self._read_one(
            f"SELECT {_COLS} FROM assessment_reports "
            "WHERE tenant_id = $1 AND assessment_id = $2",
            tenant_id,
            tenant_id,
            assessment_id,
        )
        return _row_to_report(row) if row else None

    async def get_by_id(
        self,
        tenant_id: uuid.UUID,
        report_id: uuid.UUID,
    ) -> AssessmentReport | None:
        row = await self._read_one(
            f"SELECT {_COLS} FROM assessment_reports "
            "WHERE tenant_id = $1 AND id = $2",
            tenant_id,
            tenant_id,
            report_id,
        )
        return _row_to_report(row) if row else None

    async def list_recent_by_tenant(
        self,
        tenant_id: uuid.UUID,
        exclude_assessment_id: uuid.UUID,
        limit: int = 5,
    ) -> list[AssessmentReport]:
        """Return the most recent completed reports for this tenant.

        Excludes the current assessment so the trend is purely historical.
        Ordered newest-first so callers can reverse for chronological charts.
        """
        rows = await self._read(
            f"SELECT {_COLS} FROM assessment_reports "
            "WHERE tenant_id = $1 AND assessment_id != $2 "
            "ORDER BY generated_at DESC LIMIT $3",
            tenant_id,
            tenant_id,
            exclude_assessment_id,
            limit,
        )
        return [_row_to_report(r) for r in rows]
