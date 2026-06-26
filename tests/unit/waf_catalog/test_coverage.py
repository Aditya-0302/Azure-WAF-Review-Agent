"""Unit tests for WAF coverage computation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from waf_catalog.catalog import WafCatalog
from waf_catalog.coverage import CoverageStatus, compute_coverage

_CONTROLS = [
    {
        "code": "SE-07", "pillar": "Security", "title": "Protect secrets",
        "description": ".", "microsoft_url": "https://example.com/SE-07",
        "keywords": [], "applicable_resource_types": ["*"], "version": "2024", "status": "active",
    },
    {
        "code": "RE-02", "pillar": "Reliability", "title": "Design for redundancy",
        "description": ".", "microsoft_url": "https://example.com/RE-02",
        "keywords": [], "applicable_resource_types": ["*"], "version": "2024", "status": "active",
    },
    {
        "code": "CO-06", "pillar": "Cost Optimization", "title": "Rightsize assets",
        "description": ".", "microsoft_url": "https://example.com/CO-06",
        "keywords": [], "applicable_resource_types": ["*"], "version": "2024", "status": "active",
    },
]

_MAPPING = {
    "SEC-KV-001": ["SE-07"],
    "REL-VM-001": ["RE-02"],
}


@pytest.fixture(autouse=True)
def reset_singleton():
    WafCatalog.reset()
    yield
    WafCatalog.reset()


@pytest.fixture
def catalog(tmp_path: Path) -> WafCatalog:
    (tmp_path / "waf_controls.json").write_text(json.dumps(_CONTROLS), encoding="utf-8")
    (tmp_path / "waf_control_mapping.json").write_text(json.dumps(_MAPPING), encoding="utf-8")
    return WafCatalog(
        controls_path=tmp_path / "waf_controls.json",
        mapping_path=tmp_path / "waf_control_mapping.json",
    )


class TestComputeCoverage:
    def test_fully_covered_control(self, catalog: WafCatalog) -> None:
        report = compute_coverage(catalog, {"SEC-KV-001": "deterministic"})
        se07 = next(c for c in report.controls if c.code == "SE-07")
        assert se07.status == CoverageStatus.COVERED
        assert "SEC-KV-001" in se07.rule_ids

    def test_partially_covered_with_llm_rule(self, catalog: WafCatalog) -> None:
        report = compute_coverage(catalog, {"SEC-KV-001": "llm"})
        se07 = next(c for c in report.controls if c.code == "SE-07")
        assert se07.status == CoverageStatus.PARTIALLY_COVERED

    def test_not_implemented_when_no_rule(self, catalog: WafCatalog) -> None:
        report = compute_coverage(catalog, {})
        co06 = next(c for c in report.controls if c.code == "CO-06")
        assert co06.status == CoverageStatus.NOT_IMPLEMENTED
        assert co06.rule_ids == []

    def test_overall_percentage_all_covered(self, catalog: WafCatalog) -> None:
        report = compute_coverage(
            catalog,
            {"SEC-KV-001": "deterministic", "REL-VM-001": "deterministic"},
        )
        # CO-06 is not covered, so 2 out of 3 = 66.7%
        assert report.covered_controls == 2
        assert report.not_implemented_controls == 1
        assert report.overall_percentage == pytest.approx(66.7, abs=0.1)

    def test_pillar_breakdown(self, catalog: WafCatalog) -> None:
        report = compute_coverage(catalog, {"SEC-KV-001": "deterministic"})
        security_pillar = report.pillars["Security"]
        assert security_pillar.covered == 1
        assert security_pillar.total == 1
        assert security_pillar.percentage == 100.0

    def test_empty_rules_zero_coverage(self, catalog: WafCatalog) -> None:
        report = compute_coverage(catalog, {})
        assert report.covered_controls == 0
        assert report.overall_percentage == 0.0

    def test_to_dict_structure(self, catalog: WafCatalog) -> None:
        report = compute_coverage(catalog, {"SEC-KV-001": "deterministic"})
        d = report.to_dict()
        assert "controls" in d
        assert "pillars" in d
        assert "overall_percentage" in d
        assert isinstance(d["controls"], list)

    def test_write_json(self, catalog: WafCatalog, tmp_path: Path) -> None:
        report = compute_coverage(catalog, {"SEC-KV-001": "deterministic"})
        out = tmp_path / "coverage.json"
        report.write_json(str(out))
        loaded = json.loads(out.read_text())
        assert loaded["total_controls"] == 3

    def test_hybrid_eval_type_counts_as_covered(self, catalog: WafCatalog) -> None:
        report = compute_coverage(catalog, {"SEC-KV-001": "hybrid"})
        se07 = next(c for c in report.controls if c.code == "SE-07")
        assert se07.status == CoverageStatus.COVERED
