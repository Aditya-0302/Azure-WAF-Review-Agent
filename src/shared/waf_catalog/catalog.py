"""WAF Catalog — loads the static WAF control inventory and rule-to-control mappings.

The catalog is loaded once at process startup from JSON files co-located with this
module. All public methods are synchronous and safe to call from async contexts.

Singleton access:
  catalog = WafCatalog.get_instance()
  enrichment = catalog.enrich_finding("SEC-KV-001")

The singleton is reset between tests by calling WafCatalog.reset() in test teardown.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict

_CATALOG_DIR: Final[Path] = Path(__file__).parent


class WafControl(BaseModel):
    """One official Microsoft Well-Architected Framework recommendation."""

    model_config = ConfigDict(frozen=True)

    code: str
    pillar: str
    title: str
    description: str
    microsoft_url: str
    keywords: list[str]
    applicable_resource_types: list[str]
    version: str
    status: str


class WafEnrichment(BaseModel):
    """WAF metadata payload that annotates a Finding produced by a reasoning rule."""

    model_config = ConfigDict(frozen=True)

    waf_codes: list[str]
    waf_titles: list[str]
    microsoft_urls: list[str]
    pillars: list[str]

    @property
    def is_mapped(self) -> bool:
        return bool(self.waf_codes)


class WafCatalog:
    """Process-wide singleton that provides WAF control lookup and finding enrichment.

    Loaded lazily on first call to get_instance(); subsequent calls return the cached
    instance without re-reading disk. Calls reset() between test cases to allow
    testing with custom catalog fixtures.
    """

    _instance: WafCatalog | None = None

    def __init__(
        self,
        controls_path: Path | None = None,
        mapping_path: Path | None = None,
    ) -> None:
        controls_raw: list[dict] = json.loads(
            (controls_path or _CATALOG_DIR / "waf_controls.json").read_text(encoding="utf-8")
        )
        mapping_raw: dict[str, list[str]] = json.loads(
            (mapping_path or _CATALOG_DIR / "waf_control_mapping.json").read_text(encoding="utf-8")
        )

        # Drop the _comment and schema_version meta-keys if present.
        clean_mapping = {
            k: v for k, v in mapping_raw.items() if not k.startswith("_") and k != "schema_version"
        }

        # Reject duplicate control codes before loading into the dict.
        seen_codes: set[str] = set()
        for c in controls_raw:
            code = c.get("code", "")
            if code in seen_codes:
                raise ValueError(
                    f"Duplicate control code '{code}' in waf_controls.json. "
                    "Each code must appear exactly once."
                )
            seen_codes.add(code)

        self._controls: dict[str, WafControl] = {
            c["code"]: WafControl.model_validate(c) for c in controls_raw
        }
        self._mapping: dict[str, list[str]] = clean_mapping

    # ── Singleton ──────────────────────────────────────────────────────────────

    @classmethod
    def get_instance(cls) -> WafCatalog:
        """Return the process-wide singleton, loading from disk on first call."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Discard the singleton. Use in test teardown to allow fixture overrides."""
        cls._instance = None

    # ── Control lookup ─────────────────────────────────────────────────────────

    def get_control(self, code: str) -> WafControl | None:
        return self._controls.get(code)

    def get_all_controls(self) -> list[WafControl]:
        return list(self._controls.values())

    def get_controls_for_pillar(self, pillar: str) -> list[WafControl]:
        return [c for c in self._controls.values() if c.pillar.lower() == pillar.lower()]

    def get_all_codes(self) -> set[str]:
        return set(self._controls.keys())

    def codes_per_pillar(self) -> dict[str, list[str]]:
        """Return {pillar: [code, ...]} for all controls."""
        result: dict[str, list[str]] = {}
        for code, ctrl in self._controls.items():
            result.setdefault(ctrl.pillar, []).append(code)
        return {p: sorted(codes) for p, codes in sorted(result.items())}

    # ── Rule mapping ───────────────────────────────────────────────────────────

    def get_codes_for_rule(self, rule_id: str) -> list[str]:
        return list(self._mapping.get(rule_id, []))

    def get_controls_for_rule(self, rule_id: str) -> list[WafControl]:
        codes = self._mapping.get(rule_id, [])
        return [self._controls[c] for c in codes if c in self._controls]

    def get_mapped_rule_ids(self) -> set[str]:
        return set(self._mapping.keys())

    def get_rules_for_code(self, code: str) -> list[str]:
        """Return all rule_ids that map to a given WAF control code."""
        return [rid for rid, codes in self._mapping.items() if code in codes]

    # ── Finding enrichment ─────────────────────────────────────────────────────

    def enrich_finding(self, rule_id: str) -> WafEnrichment:
        """Return WAF metadata for a rule_id; all lists empty if no mapping exists."""
        controls = self.get_controls_for_rule(rule_id)
        return WafEnrichment(
            waf_codes=[c.code for c in controls],
            waf_titles=[c.title for c in controls],
            microsoft_urls=[c.microsoft_url for c in controls],
            pillars=sorted({c.pillar for c in controls}),
        )

    # ── Inventory summary ──────────────────────────────────────────────────────

    def inventory_summary(self) -> dict[str, int]:
        """Return {pillar: count} plus a "total" key."""
        summary: dict[str, int] = {}
        for ctrl in self._controls.values():
            summary[ctrl.pillar] = summary.get(ctrl.pillar, 0) + 1
        summary["total"] = sum(summary.values())
        return summary
