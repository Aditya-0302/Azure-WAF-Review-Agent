"""System diagnostics endpoints.

/v1/system/waf-catalog-health — runtime health report for the WAF catalog.

Returns the loaded state of the catalog singleton plus a per-rule coverage
report built by querying all active rules from the database and comparing
them against the catalog mapping.  This is an operator/SRE endpoint; it
does NOT require a tenant JWT and is intended for internal cluster access.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

from waf_api.dependencies.db import get_db_pool
from waf_shared.db.pool import DatabasePool
from waf_shared.db.repositories.rule_repository import WafRuleRepository
from waf_shared.telemetry.logging import StructuredLogger

router = APIRouter(prefix="/v1/system", tags=["system"])

_logger = StructuredLogger(service="waf-api", version="0.1.0")


class WafCatalogHealthResponse(BaseModel):
    controls_loaded: int
    mappings_loaded: int
    coverage_percentage: float
    missing_rule_ids: list[str]
    validation_status: str  # "ok" | "degraded" | "failed"
    validation_errors: list[str]


@router.get(
    "/waf-catalog-health",
    response_model=WafCatalogHealthResponse,
    status_code=status.HTTP_200_OK,
    summary="WAF catalog health",
    description=(
        "Returns the loaded state of the WAF catalog singleton and coverage "
        "against all active rules in the database. validation_status is 'ok' "
        "when all rules are mapped and the catalog passes integrity checks."
    ),
)
async def waf_catalog_health(
    pool: Annotated[DatabasePool, Depends(get_db_pool)],
) -> WafCatalogHealthResponse:
    from waf_catalog.catalog import WafCatalog
    from waf_catalog.startup import build_coverage_report
    from waf_catalog.validator import CatalogValidationError, validate_catalog

    validation_errors: list[str] = []
    validation_status = "ok"

    # Load (or reuse) the singleton.  If the catalog files are missing or
    # corrupt the exception propagates as a 500 — that is intentional; the
    # service is broken and the operator needs to know immediately.
    catalog = WafCatalog.get_instance()

    # Run catalog integrity checks.
    try:
        validate_catalog(catalog)
    except CatalogValidationError as exc:
        validation_errors = [str(exc)]
        validation_status = "failed"
        _logger.error("system.waf_catalog_health.validation_failed", error=str(exc))
    except Exception as exc:  # noqa: BLE001
        validation_errors = [f"Unexpected validation error: {exc}"]
        validation_status = "failed"

    # Rule coverage check.
    rule_repo = WafRuleRepository(pool=pool)
    active_rules = await rule_repo.list_active()
    active_rule_ids = [r.rule_id for r in active_rules]
    coverage = build_coverage_report(catalog, active_rule_ids)

    if coverage.missing_rule_ids:
        validation_status = "degraded" if validation_status == "ok" else validation_status
        validation_errors.append(
            f"{coverage.missing_count} active rule(s) have no WAF catalog mapping: "
            + ", ".join(coverage.missing_rule_ids)
        )

    return WafCatalogHealthResponse(
        controls_loaded=len(catalog.get_all_controls()),
        mappings_loaded=len(catalog.get_mapped_rule_ids()),
        coverage_percentage=coverage.coverage_percentage,
        missing_rule_ids=coverage.missing_rule_ids,
        validation_status=validation_status,
        validation_errors=validation_errors,
    )
