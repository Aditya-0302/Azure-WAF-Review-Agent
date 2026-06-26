"""Finding repository — asyncpg implementation of IFindingRepository."""

from __future__ import annotations

import json
import uuid

import asyncpg

from waf_shared.db.jsonb import normalize_jsonb
from waf_shared.db.pool import DatabasePool
from waf_shared.db.repository import BaseRepository
from waf_shared.domain.errors.domain_errors import FindingNotFoundError
from waf_shared.domain.models.finding import Finding, FindingStatus, Severity
from waf_shared.domain.repositories.i_finding_repository import IFindingRepository

_FINDING_COLS = """
    id, assessment_id, batch_id, tenant_id, rule_id, resource_id,
    resource_type, status, severity, pillar, confidence_score,
    title, recommendation, evidence, evaluation_type, created_at,
    waf_codes, waf_titles, microsoft_urls
"""


def _row_to_finding(row: asyncpg.Record) -> Finding:  # type: ignore[type-arg]
    return Finding(
        id=row["id"],
        assessment_id=row["assessment_id"],
        batch_id=row["batch_id"],
        tenant_id=row["tenant_id"],
        rule_id=row["rule_id"],
        resource_id=row["resource_id"],
        resource_type=row["resource_type"],
        status=FindingStatus(row["status"]),
        severity=Severity(row["severity"]),
        pillar=row["pillar"],
        confidence_score=float(row["confidence_score"]),
        title=row["title"],
        recommendation=row["recommendation"],
        evidence=normalize_jsonb(row["evidence"]) or {},
        evaluation_type=row["evaluation_type"],
        created_at=row["created_at"],
        waf_codes=normalize_jsonb(row["waf_codes"]) or [],
        waf_titles=normalize_jsonb(row["waf_titles"]) or [],
        microsoft_urls=normalize_jsonb(row["microsoft_urls"]) or [],
    )


class FindingRepository(BaseRepository, IFindingRepository):
    def __init__(
        self,
        pool: DatabasePool | None = None,
        *,
        conn: asyncpg.Connection | None = None,  # type: ignore[type-arg]
        uow_tenant_id: uuid.UUID | None = None,
    ) -> None:
        super().__init__(pool=pool, conn=conn, uow_tenant_id=uow_tenant_id)

    async def create_batch(
        self,
        tenant_id: uuid.UUID,
        findings: list[Finding],
    ) -> None:
        if not findings:
            return

        records = [
            (
                f.id,
                f.assessment_id,
                f.batch_id,
                tenant_id,
                f.rule_id,
                f.resource_id,
                f.resource_type,
                f.status.value,
                f.severity.value,
                f.pillar,
                f.confidence_score,
                f.title,
                f.recommendation,
                json.dumps(f.evidence),
                f.evaluation_type,
                json.dumps(f.waf_codes),
                json.dumps(f.waf_titles),
                json.dumps(f.microsoft_urls),
            )
            for f in findings
        ]

        sql = """
            INSERT INTO assessment_findings (
                id, assessment_id, batch_id, tenant_id, rule_id, resource_id,
                resource_type, status, severity, pillar, confidence_score,
                title, recommendation, evidence, evaluation_type,
                waf_codes, waf_titles, microsoft_urls
            ) VALUES (
                $1, $2, $3, $4, $5, $6,
                $7, $8::finding_status, $9::severity, $10::pillar, $11,
                $12, $13, $14::jsonb, $15::evaluation_type,
                $16::jsonb, $17::jsonb, $18::jsonb
            )
            ON CONFLICT DO NOTHING
        """

        if self._conn is not None:
            await self._conn.executemany(sql, records)
        else:
            await self._executemany_system(sql, records)

    async def get_by_id(
        self,
        tenant_id: uuid.UUID,
        finding_id: uuid.UUID,
    ) -> Finding | None:
        row = await self._read_one(
            f"SELECT {_FINDING_COLS} FROM assessment_findings "
            "WHERE tenant_id = $1 AND id = $2",
            tenant_id,
            tenant_id,
            finding_id,
        )
        return _row_to_finding(row) if row else None

    async def list_by_assessment(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        severity: Severity | None = None,
        pillar: str | None = None,
        status: FindingStatus | None = None,
        limit: int = 100,
        cursor: uuid.UUID | None = None,
    ) -> list[Finding]:
        clauses = ["tenant_id = $1", "assessment_id = $2"]
        params: list[object] = [tenant_id, assessment_id]
        p = 3

        if severity is not None:
            clauses.append(f"severity = ${p}::severity")
            params.append(severity.value)
            p += 1

        if pillar is not None:
            clauses.append(f"pillar = ${p}::pillar")
            params.append(pillar)
            p += 1

        if status is not None:
            clauses.append(f"status = ${p}::finding_status")
            params.append(status.value)
            p += 1

        if cursor is not None:
            clauses.append(f"id > ${p}")
            params.append(cursor)
            p += 1

        params.append(limit)
        where = " AND ".join(clauses)
        sql = (
            f"SELECT {_FINDING_COLS} FROM assessment_findings "
            f"WHERE {where} ORDER BY id LIMIT ${p}"
        )
        rows = await self._read(sql, tenant_id, *params)
        return [_row_to_finding(r) for r in rows]

    async def update_status(
        self,
        tenant_id: uuid.UUID,
        finding_id: uuid.UUID,
        status: FindingStatus,
    ) -> Finding:
        row = await self._write_one(
            f"""
            UPDATE assessment_findings
            SET status = $3::finding_status
            WHERE tenant_id = $1 AND id = $2
            RETURNING {_FINDING_COLS}
            """,
            tenant_id,
            tenant_id,
            finding_id,
            status.value,
        )
        if row is None:
            raise FindingNotFoundError(finding_id, tenant_id)
        return _row_to_finding(row)

    async def count_by_severity(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> dict[str, int]:
        rows = await self._read(
            "SELECT severity, COUNT(*) AS n "
            "FROM assessment_findings "
            "WHERE tenant_id = $1 AND assessment_id = $2 "
            "GROUP BY severity",
            tenant_id,
            tenant_id,
            assessment_id,
        )
        return {r["severity"]: int(r["n"]) for r in rows}

    async def count_by_pillar(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> dict[str, int]:
        rows = await self._read(
            "SELECT pillar, COUNT(*) AS n "
            "FROM assessment_findings "
            "WHERE tenant_id = $1 AND assessment_id = $2 "
            "GROUP BY pillar",
            tenant_id,
            tenant_id,
            assessment_id,
        )
        return {r["pillar"]: int(r["n"]) for r in rows}

    async def aggregate_pillar_severity(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> dict[str, dict[str, int]]:
        """Return finding counts grouped by (pillar, severity).

        Returns {pillar: {severity: count}} for use in per-pillar compliance
        scoring and Excel/PDF report generation.
        """
        rows = await self._read(
            "SELECT pillar, severity, COUNT(*) AS n "
            "FROM assessment_findings "
            "WHERE tenant_id = $1 AND assessment_id = $2 "
            "GROUP BY pillar, severity",
            tenant_id,
            tenant_id,
            assessment_id,
        )
        result: dict[str, dict[str, int]] = {}
        for r in rows:
            pillar = r["pillar"]
            severity = r["severity"]
            if pillar not in result:
                result[pillar] = {}
            result[pillar][severity] = int(r["n"])
        return result

    async def count_distinct_resources(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> int:
        """Count distinct resource IDs that have at least one finding."""
        row = await self._read_one(
            "SELECT COUNT(DISTINCT resource_id) AS n "
            "FROM assessment_findings "
            "WHERE tenant_id = $1 AND assessment_id = $2",
            tenant_id,
            tenant_id,
            assessment_id,
        )
        return int(row["n"]) if row else 0

    async def aggregate_resource_type_severity(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> dict[str, dict[str, int]]:
        """Return {resource_type: {severity: count}} for all findings."""
        rows = await self._read(
            "SELECT resource_type, severity, COUNT(*) AS n "
            "FROM assessment_findings "
            "WHERE tenant_id = $1 AND assessment_id = $2 "
            "GROUP BY resource_type, severity",
            tenant_id,
            tenant_id,
            assessment_id,
        )
        result: dict[str, dict[str, int]] = {}
        for r in rows:
            rt = r["resource_type"]
            if rt not in result:
                result[rt] = {}
            result[rt][r["severity"]] = int(r["n"])
        return result

    async def list_top_risks(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        limit: int = 5,
    ) -> list[Finding]:
        """Return top-N findings ordered by severity (critical first)."""
        rows = await self._read(
            f"SELECT {_FINDING_COLS} FROM assessment_findings "
            "WHERE tenant_id = $1 AND assessment_id = $2 "
            "ORDER BY CASE severity "
            "  WHEN 'critical' THEN 1 "
            "  WHEN 'high'     THEN 2 "
            "  WHEN 'medium'   THEN 3 "
            "  WHEN 'low'      THEN 4 "
            "  ELSE 5 END, created_at ASC "
            "LIMIT $3",
            tenant_id,
            tenant_id,
            assessment_id,
            limit,
        )
        return [_row_to_finding(r) for r in rows]

    async def aggregate_pillar_resource_type_severity(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> dict[str, dict[str, dict[str, int]]]:
        """Return ``{pillar: {resource_type: {severity: count}}}`` for all findings.

        Used by the scoring engine to compute resource-criticality-weighted
        failure totals per pillar without a cartesian join.
        """
        rows = await self._read(
            "SELECT pillar, resource_type, severity, COUNT(*) AS n "
            "FROM assessment_findings "
            "WHERE tenant_id = $1 AND assessment_id = $2 "
            "GROUP BY pillar, resource_type, severity",
            tenant_id,
            tenant_id,
            assessment_id,
        )
        result: dict[str, dict[str, dict[str, int]]] = {}
        for r in rows:
            pillar = r["pillar"]
            rt = r["resource_type"]
            sev = r["severity"]
            result.setdefault(pillar, {}).setdefault(rt, {})[sev] = int(r["n"])
        return result

    async def aggregate_waf_control_coverage(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> dict[str, dict[str, int]]:
        """Return {pillar: {waf_code: has_critical_or_high}}.

        has_critical_or_high is 1 when the WAF control has at least one
        critical or high finding, 0 otherwise.  Used to compute
        controls_passed / controls_failed per pillar.
        """
        rows = await self._read(
            "SELECT pillar, "
            "       jsonb_array_elements_text(waf_codes) AS waf_code, "
            "       MAX(CASE WHEN severity IN ('critical', 'high') THEN 1 "
            "                ELSE 0 END) AS has_critical_or_high "
            "FROM assessment_findings "
            "WHERE tenant_id = $1 AND assessment_id = $2 "
            "  AND jsonb_array_length(waf_codes) > 0 "
            "GROUP BY pillar, waf_code",
            tenant_id,
            tenant_id,
            assessment_id,
        )
        result: dict[str, dict[str, int]] = {}
        for r in rows:
            pillar = r["pillar"]
            if pillar not in result:
                result[pillar] = {}
            result[pillar][r["waf_code"]] = int(r["has_critical_or_high"])
        return result
