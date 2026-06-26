"""Development-auth bootstrap — idempotently provisions the synthetic dev tenant.

Runs at API startup when API_AUTH_MODE=development. Never called from any
production code path.

Why raw SQL instead of TenantRepository?
  TenantRepository.create() has no ON CONFLICT clause and raises on a duplicate
  id. We need ON CONFLICT DO NOTHING so that repeated startups are idempotent
  without touching an existing row (e.g. one a developer seeded with custom quota
  limits).

Why set app.current_tenant_id before the tenant_quotas INSERT?
  tenant_quotas has ENABLE ROW LEVEL SECURITY with a USING policy that checks
  current_setting('app.current_tenant_id', ...). PostgreSQL applies the USING
  expression as a WITH CHECK on INSERT when no explicit WITH CHECK is defined.
  Setting the config satisfies that check for non-owner DB roles in production-
  equivalent setups where FORCE ROW LEVEL SECURITY is in effect.
"""

from __future__ import annotations

import uuid

from waf_shared.db.pool import DatabasePool
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-api", version="0.1.0")

_DEV_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
_DEV_TENANT_ID_STR = str(_DEV_TENANT_ID)


async def ensure_dev_tenant(pool: DatabasePool) -> None:
    """Idempotently create the synthetic development tenant and its quota row.

    Safe to call on every startup — ON CONFLICT DO NOTHING makes both inserts
    no-ops when the rows already exist.
    """
    async with pool.acquire_write() as conn:
        async with conn.transaction():
            # tenants has no RLS; no tenant context needed.
            await conn.execute(
                """
                INSERT INTO tenants (
                    id, slug, display_name, azure_tenant_id, plan_tier, is_active
                )
                VALUES (
                    $1::uuid,
                    'dev-0000-0001',
                    'Development Tenant',
                    $1::uuid,
                    'standard',
                    true
                )
                ON CONFLICT DO NOTHING
                """,
                _DEV_TENANT_ID_STR,
            )

            # Set RLS context so the tenant_quotas WITH CHECK passes on
            # non-owner DB roles.
            await conn.execute(
                "SELECT set_config('app.current_tenant_id', $1, true)",
                _DEV_TENANT_ID_STR,
            )

            # Permissive limits — local dev should never hit a quota ceiling.
            await conn.execute(
                """
                INSERT INTO tenant_quotas (
                    tenant_id,
                    max_concurrent_assessments,
                    max_monthly_assessments,
                    max_subscriptions_per_assessment,
                    max_resources_per_assessment
                )
                VALUES ($1::uuid, 100, 10000, 100, 100000)
                ON CONFLICT (tenant_id) DO NOTHING
                """,
                _DEV_TENANT_ID_STR,
            )

    _logger.info(
        "dev_auth.bootstrap.complete",
        tenant_id=_DEV_TENANT_ID_STR,
        slug="dev-0000-0001",
    )
