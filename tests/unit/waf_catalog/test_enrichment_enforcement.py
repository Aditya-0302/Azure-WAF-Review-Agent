"""Tests proving WAF catalog enrichment is correct and enforcement is watertight.

Covers:
  - Real catalog enrichment for STORAGE-SECURE-TRANSFER, STORAGE-MIN-TLS-12, SEC-STOR-001
  - Missing mapping returns is_mapped=False
  - Invalid control code in mapping raises CatalogValidationError
  - Empty catalog raises CatalogValidationError on validate_catalog()
  - Duplicate control code raises ValueError at catalog load time
  - CatalogStartupError propagates from validate_catalog_startup()
  - WafEnrichmentError is raised when a mapped rule returns empty waf_codes
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from waf_catalog.catalog import _CATALOG_DIR, WafCatalog
from waf_catalog.startup import (
    CatalogStartupError,
    build_coverage_report,
    validate_catalog_startup,
)
from waf_catalog.validator import CatalogValidationError, validate_catalog

from waf_shared.domain.errors.domain_errors import WafEnrichmentError

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def reset_singleton():
    WafCatalog.reset()
    yield
    WafCatalog.reset()


@pytest.fixture
def real_catalog() -> WafCatalog:
    """Load the actual catalog files — proves live enrichment is correct."""
    return WafCatalog(
        controls_path=_CATALOG_DIR / "waf_controls.json",
        mapping_path=_CATALOG_DIR / "waf_control_mapping.json",
    )


_BASE_CONTROL = {
    "pillar": "Security",
    "title": "Test control",
    "description": ".",
    "microsoft_url": "https://learn.microsoft.com/test",
    "keywords": [],
    "applicable_resource_types": ["*"],
    "version": "2024",
    "status": "active",
}


def _make_catalog(tmp_path: Path, controls: list[dict], mapping: dict) -> WafCatalog:
    (tmp_path / "waf_controls.json").write_text(json.dumps(controls), encoding="utf-8")
    (tmp_path / "waf_control_mapping.json").write_text(json.dumps(mapping), encoding="utf-8")
    return WafCatalog(
        controls_path=tmp_path / "waf_controls.json",
        mapping_path=tmp_path / "waf_control_mapping.json",
    )


# ── Live catalog enrichment ───────────────────────────────────────────────────


class TestLiveCatalogEnrichment:
    """These tests use the real waf_control_mapping.json and waf_controls.json.
    They fail if a rule is removed from the mapping or a control is removed
    from the catalog.
    """

    def test_storage_secure_transfer_enriches_correctly(self, real_catalog: WafCatalog) -> None:
        e = real_catalog.enrich_finding("STORAGE-SECURE-TRANSFER")
        assert e.is_mapped is True
        assert "SE-03" in e.waf_codes
        assert len(e.waf_codes) >= 1
        assert len(e.waf_titles) == len(e.waf_codes)
        assert len(e.microsoft_urls) == len(e.waf_codes)
        assert all(url.startswith("https://") for url in e.microsoft_urls)

    def test_storage_min_tls_12_enriches_correctly(self, real_catalog: WafCatalog) -> None:
        e = real_catalog.enrich_finding("STORAGE-MIN-TLS-12")
        assert e.is_mapped is True
        codes = sorted(e.waf_codes)
        assert "SE-03" in codes
        assert "SE-04" in codes
        assert len(e.waf_titles) == len(codes)
        assert len(e.microsoft_urls) == len(codes)

    def test_sec_stor_001_enriches_correctly(self, real_catalog: WafCatalog) -> None:
        e = real_catalog.enrich_finding("SEC-STOR-001")
        assert e.is_mapped is True
        assert "SE-03" in e.waf_codes
        # Canonical title from waf_controls.json
        assert any("sensitive" in t.lower() or "data" in t.lower() for t in e.waf_titles)

    def test_all_catalog_rules_have_non_empty_enrichment(self, real_catalog: WafCatalog) -> None:
        """Every rule in the mapping must produce waf_codes with ≥1 entry."""
        for rule_id in real_catalog.get_mapped_rule_ids():
            e = real_catalog.enrich_finding(rule_id)
            assert (
                e.waf_codes
            ), f"Rule '{rule_id}' is mapped but enrichment returned empty waf_codes"
            assert e.waf_titles, f"Rule '{rule_id}' enrichment returned empty waf_titles"
            assert e.microsoft_urls, f"Rule '{rule_id}' enrichment returned empty microsoft_urls"


# ── Missing mapping ───────────────────────────────────────────────────────────


class TestMissingMapping:
    def test_missing_mapping_is_not_mapped(self, real_catalog: WafCatalog) -> None:
        e = real_catalog.enrich_finding("NONEXISTENT-RULE-99999")
        assert e.is_mapped is False
        assert e.waf_codes == []
        assert e.waf_titles == []
        assert e.microsoft_urls == []


# ── Catalog integrity violations ──────────────────────────────────────────────


class TestCatalogIntegrityViolations:
    def test_invalid_control_code_in_mapping_raises(self, tmp_path: Path) -> None:
        controls = [{**_BASE_CONTROL, "code": "SE-07"}]
        mapping = {"SEC-KV-001": ["SE-07", "XX-99"]}
        catalog = _make_catalog(tmp_path, controls, mapping)
        with pytest.raises(CatalogValidationError) as exc_info:
            validate_catalog(catalog)
        assert "XX-99" in str(exc_info.value)

    def test_duplicate_control_code_raises_at_load_time(self, tmp_path: Path) -> None:
        controls = [
            {**_BASE_CONTROL, "code": "SE-07"},
            {**_BASE_CONTROL, "code": "SE-07"},  # duplicate
        ]
        (tmp_path / "waf_controls.json").write_text(json.dumps(controls), encoding="utf-8")
        (tmp_path / "waf_control_mapping.json").write_text(json.dumps({}), encoding="utf-8")
        with pytest.raises(ValueError, match="Duplicate control code 'SE-07'"):
            WafCatalog(
                controls_path=tmp_path / "waf_controls.json",
                mapping_path=tmp_path / "waf_control_mapping.json",
            )

    def test_empty_url_raises_validation_error(self, tmp_path: Path) -> None:
        controls = [{**_BASE_CONTROL, "code": "SE-07", "microsoft_url": ""}]
        mapping = {"SEC-KV-001": ["SE-07"]}
        catalog = _make_catalog(tmp_path, controls, mapping)
        with pytest.raises(CatalogValidationError) as exc_info:
            validate_catalog(catalog)
        assert "SE-07" in str(exc_info.value)
        assert "microsoft_url" in str(exc_info.value)

    def test_empty_mapping_list_raises_validation_error(self, tmp_path: Path) -> None:
        controls = [{**_BASE_CONTROL, "code": "SE-07"}]
        mapping = {"SEC-KV-001": []}  # empty code list for a rule
        catalog = _make_catalog(tmp_path, controls, mapping)
        with pytest.raises(CatalogValidationError) as exc_info:
            validate_catalog(catalog)
        assert "SEC-KV-001" in str(exc_info.value)


# ── Empty catalog startup failure ─────────────────────────────────────────────


class TestEmptyCatalogStartupFailure:
    def test_zero_controls_raises_catalog_startup_error(self, tmp_path: Path) -> None:
        (tmp_path / "waf_controls.json").write_text("[]", encoding="utf-8")
        (tmp_path / "waf_control_mapping.json").write_text(
            '{"RULE-A": ["SE-01"]}', encoding="utf-8"
        )
        catalog = WafCatalog(
            controls_path=tmp_path / "waf_controls.json",
            mapping_path=tmp_path / "waf_control_mapping.json",
        )
        with pytest.raises(CatalogStartupError, match="0 controls"):
            validate_catalog_startup(catalog)

    def test_zero_mappings_raises_catalog_startup_error(self, tmp_path: Path) -> None:
        controls = [{**_BASE_CONTROL, "code": "SE-07"}]
        (tmp_path / "waf_controls.json").write_text(json.dumps(controls), encoding="utf-8")
        (tmp_path / "waf_control_mapping.json").write_text("{}", encoding="utf-8")
        catalog = WafCatalog(
            controls_path=tmp_path / "waf_controls.json",
            mapping_path=tmp_path / "waf_control_mapping.json",
        )
        with pytest.raises(CatalogStartupError, match="0 mappings"):
            validate_catalog_startup(catalog)

    def test_valid_catalog_passes_startup_validation(self, tmp_path: Path) -> None:
        controls = [{**_BASE_CONTROL, "code": "SE-07"}]
        mapping = {"SEC-KV-001": ["SE-07"]}
        catalog = _make_catalog(tmp_path, controls, mapping)
        validate_catalog_startup(catalog)  # must not raise


# ── WafEnrichmentError ────────────────────────────────────────────────────────


class TestWafEnrichmentError:
    def test_enrichment_error_lists_rule_ids(self) -> None:
        exc = WafEnrichmentError(["RULE-B", "RULE-A", "RULE-A"])
        assert "RULE-A" in str(exc)
        assert "RULE-B" in str(exc)
        # Deduplicated and sorted
        assert exc.rule_ids == ["RULE-A", "RULE-B"]
        assert exc.code == "WAF_ENRICHMENT_FAILED"

    def test_enrichment_error_is_domain_error(self) -> None:
        from waf_shared.domain.errors.domain_errors import DomainError

        exc = WafEnrichmentError(["RULE-X"])
        assert isinstance(exc, DomainError)


# ── Coverage report ───────────────────────────────────────────────────────────


class TestBuildCoverageReport:
    def test_complete_coverage(self, tmp_path: Path) -> None:
        controls = [{**_BASE_CONTROL, "code": "SE-07"}]
        mapping = {"SEC-KV-001": ["SE-07"]}
        catalog = _make_catalog(tmp_path, controls, mapping)
        report = build_coverage_report(catalog, ["SEC-KV-001"])
        assert report.is_complete is True
        assert report.missing_count == 0
        assert report.coverage_percentage == 100.0

    def test_missing_rule_appears_in_report(self, tmp_path: Path) -> None:
        controls = [{**_BASE_CONTROL, "code": "SE-07"}]
        mapping = {"SEC-KV-001": ["SE-07"]}
        catalog = _make_catalog(tmp_path, controls, mapping)
        report = build_coverage_report(catalog, ["SEC-KV-001", "NEW-RULE-001"])
        assert report.is_complete is False
        assert "NEW-RULE-001" in report.missing_rule_ids
        assert report.missing_count == 1
        assert report.coverage_percentage == 50.0

    def test_empty_rule_list_is_complete(self, tmp_path: Path) -> None:
        controls = [{**_BASE_CONTROL, "code": "SE-07"}]
        mapping = {"SEC-KV-001": ["SE-07"]}
        catalog = _make_catalog(tmp_path, controls, mapping)
        report = build_coverage_report(catalog, [])
        assert report.is_complete is True
        assert report.coverage_percentage == 100.0
