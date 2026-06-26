"""WAF Rule repository — asyncpg implementation of IWafRuleRepository.

Rules are system-scoped (not per-tenant). All operations use _fetch_system
/ _write_system / _execute_system — no tenant context is set.
"""

from __future__ import annotations

import json
import uuid

import asyncpg

from waf_shared.db.jsonb import normalize_jsonb
from waf_shared.db.pool import DatabasePool
from waf_shared.db.repository import BaseRepository
from waf_shared.domain.errors.domain_errors import WafRuleNotFoundError
from waf_shared.domain.models.rule import EvaluationType, Pillar, WafRule
from waf_shared.domain.repositories.i_rule_repository import IWafRuleRepository

_RULE_COLS = """
    id, rule_id, pillar, resource_types, evaluation_type,
    condition_dsl, prompt_template_ref, severity,
    title, description, recommendation,
    is_active, version, created_at, updated_at
"""


def _row_to_rule(row: asyncpg.Record) -> WafRule:  # type: ignore[type-arg]
    return WafRule(
        id=row["id"],
        rule_id=row["rule_id"],
        pillar=Pillar(row["pillar"]),
        resource_types=list(row["resource_types"]),
        evaluation_type=EvaluationType(row["evaluation_type"]),
        condition_dsl=normalize_jsonb(row["condition_dsl"]) if row["condition_dsl"] else None,
        prompt_template_ref=row["prompt_template_ref"],
        severity=row["severity"],
        title=row["title"],
        description=row["description"],
        recommendation=row["recommendation"],
        is_active=row["is_active"],
        version=row["version"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class WafRuleRepository(BaseRepository, IWafRuleRepository):
    def __init__(
        self,
        pool: DatabasePool | None = None,
        *,
        conn: asyncpg.Connection | None = None,  # type: ignore[type-arg]
        uow_tenant_id: uuid.UUID | None = None,
    ) -> None:
        super().__init__(pool=pool, conn=conn, uow_tenant_id=uow_tenant_id)

    async def get_by_rule_id(self, rule_id: str) -> WafRule | None:
        row = await self._fetch_system_one(
            f"SELECT {_RULE_COLS} FROM waf_rules WHERE rule_id = $1",
            rule_id,
        )
        return _row_to_rule(row) if row else None

    async def list_active(
        self,
        pillar: Pillar | None = None,
        resource_types: list[str] | None = None,
    ) -> list[WafRule]:
        clauses = ["is_active = TRUE"]
        params: list[object] = []
        p = 1

        if pillar is not None:
            clauses.append(f"pillar = ${p}::pillar")
            params.append(pillar.value)
            p += 1

        if resource_types:
            clauses.append(f"resource_types && ${p}::text[]")
            params.append(resource_types)
            p += 1

        where = " AND ".join(clauses)
        rows = await self._fetch_system(
            f"SELECT {_RULE_COLS} FROM waf_rules WHERE {where} ORDER BY rule_id",
            *params,
        )
        return [_row_to_rule(r) for r in rows]

    async def upsert(self, rule: WafRule) -> WafRule:
        row = await self._write_system_one(
            f"""
            INSERT INTO waf_rules (
                id, rule_id, pillar, resource_types, evaluation_type,
                condition_dsl, prompt_template_ref, severity,
                title, description, recommendation, is_active, version
            ) VALUES (
                $1, $2, $3::pillar, $4::text[], $5::evaluation_type,
                $6::jsonb, $7, $8::severity,
                $9, $10, $11, $12, $13
            )
            ON CONFLICT (rule_id) DO UPDATE
                SET pillar              = EXCLUDED.pillar,
                    resource_types      = EXCLUDED.resource_types,
                    evaluation_type     = EXCLUDED.evaluation_type,
                    condition_dsl       = EXCLUDED.condition_dsl,
                    prompt_template_ref = EXCLUDED.prompt_template_ref,
                    severity            = EXCLUDED.severity,
                    title               = EXCLUDED.title,
                    description         = EXCLUDED.description,
                    recommendation      = EXCLUDED.recommendation,
                    is_active           = EXCLUDED.is_active,
                    version             = waf_rules.version + 1,
                    updated_at          = NOW()
            RETURNING {_RULE_COLS}
            """,
            rule.id,
            rule.rule_id,
            rule.pillar.value,
            rule.resource_types,
            rule.evaluation_type.value,
            json.dumps(rule.condition_dsl) if rule.condition_dsl is not None else None,
            rule.prompt_template_ref,
            rule.severity,
            rule.title,
            rule.description,
            rule.recommendation,
            rule.is_active,
            rule.version,
        )
        return _row_to_rule(row)  # type: ignore[arg-type]

    async def deactivate(self, rule_id: str) -> None:
        rows = await self._write_system(
            "UPDATE waf_rules SET is_active = FALSE, updated_at = NOW() "
            "WHERE rule_id = $1 RETURNING rule_id",
            rule_id,
        )
        if not rows:
            raise WafRuleNotFoundError(rule_id)

    async def count_active(self) -> int:
        row = await self._fetch_system_one(
            "SELECT COUNT(*) AS n FROM waf_rules WHERE is_active = TRUE"
        )
        return int(row["n"]) if row else 0
