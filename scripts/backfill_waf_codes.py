#!/usr/bin/env python3
"""One-time repair: backfill waf_codes/waf_titles/microsoft_urls for findings
that were inserted before WAF enrichment was working.

The script is idempotent: rows with already-populated waf_codes are skipped.
``ON CONFLICT DO NOTHING`` is not used here — we UPDATE, not INSERT — so
re-running is safe.

Usage:
    # Dry-run (report without writing)
    python scripts/backfill_waf_codes.py --dry-run

    # Live run
    python scripts/backfill_waf_codes.py

Environment variables required:
    DATABASE_URL   — asyncpg DSN, e.g. postgresql://user:pass@host:5432/dbname
                     Falls back to individual DB_* vars if DATABASE_URL is unset.

Optional:
    DB_HOST        DB_PORT   DB_NAME   DB_USER   DB_PASSWORD
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

# Allow running from repo root without installing packages.
sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "shared"))

import asyncpg  # type: ignore[import-untyped]

from waf_catalog.catalog import WafCatalog


def _build_dsn() -> str:
    dsn = os.getenv("DATABASE_URL")
    if dsn:
        return dsn
    host = os.getenv("DB_HOST", "localhost")
    port = os.getenv("DB_PORT", "5432")
    name = os.getenv("DB_NAME", "waf_agent")
    user = os.getenv("DB_USER", "postgres")
    password = os.getenv("DB_PASSWORD", "")
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


async def backfill(*, dry_run: bool) -> None:
    dsn = _build_dsn()
    print(f"Connecting to database...")
    conn = await asyncpg.connect(dsn)

    try:
        catalog = WafCatalog.get_instance()
        print(
            f"Catalog loaded: {len(catalog.get_all_controls())} controls, "
            f"{len(catalog.get_mapped_rule_ids())} mapped rules."
        )

        # Fetch all findings with empty waf_codes.
        rows = await conn.fetch(
            """
            SELECT id, rule_id, tenant_id
            FROM assessment_findings
            WHERE jsonb_array_length(waf_codes) = 0
            ORDER BY created_at
            """
        )

        if not rows:
            print("No findings with empty waf_codes found. Nothing to backfill.")
            return

        print(f"\nFound {len(rows)} finding(s) with empty waf_codes.\n")

        updated = 0
        skipped = 0
        unmapped = 0

        for row in rows:
            rule_id = row["rule_id"]
            finding_id = row["id"]

            enrichment = catalog.enrich_finding(rule_id)

            if not enrichment.is_mapped:
                print(f"  SKIP  {finding_id}  rule_id={rule_id!r}  (no catalog mapping)")
                unmapped += 1
                continue

            waf_codes_json = json.dumps(enrichment.waf_codes)
            waf_titles_json = json.dumps(enrichment.waf_titles)
            microsoft_urls_json = json.dumps(enrichment.microsoft_urls)

            print(
                f"  {'DRY ' if dry_run else ''}UPDATE  {finding_id}  "
                f"rule_id={rule_id!r}  waf_codes={enrichment.waf_codes}"
            )

            if not dry_run:
                await conn.execute(
                    """
                    UPDATE assessment_findings
                    SET
                        waf_codes      = $1::jsonb,
                        waf_titles     = $2::jsonb,
                        microsoft_urls = $3::jsonb
                    WHERE id = $4
                    """,
                    waf_codes_json,
                    waf_titles_json,
                    microsoft_urls_json,
                    finding_id,
                )
                updated += 1
            else:
                skipped += 1

        print()
        if dry_run:
            print(f"DRY RUN complete. Would update {skipped} row(s), skip {unmapped} unmapped.")
        else:
            print(f"Backfill complete. Updated {updated} row(s), skipped {unmapped} unmapped.")

    finally:
        await conn.close()


def main() -> None:
    dry_run = "--dry-run" in sys.argv or "-n" in sys.argv
    if dry_run:
        print("=== WAF Codes Backfill (DRY RUN — no changes will be written) ===\n")
    else:
        print("=== WAF Codes Backfill ===\n")

    asyncio.run(backfill(dry_run=dry_run))


if __name__ == "__main__":
    main()
