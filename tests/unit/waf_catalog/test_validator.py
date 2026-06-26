"""Unit tests for WAF catalog CI validator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from waf_catalog.catalog import WafCatalog
from waf_catalog.validator import CatalogValidationError, validate_catalog

_VALID_CONTROLS = [
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
]

_VALID_MAPPING = {
    "SEC-KV-001": ["SE-07"],
    "REL-VM-001": ["RE-02"],
}


@pytest.fixture(autouse=True)
def reset_singleton():
    WafCatalog.reset()
    yield
    WafCatalog.reset()


@pytest.fixture
def valid_catalog(tmp_path: Path) -> WafCatalog:
    (tmp_path / "waf_controls.json").write_text(json.dumps(_VALID_CONTROLS), encoding="utf-8")
    (tmp_path / "waf_control_mapping.json").write_text(json.dumps(_VALID_MAPPING), encoding="utf-8")
    return WafCatalog(
        controls_path=tmp_path / "waf_controls.json",
        mapping_path=tmp_path / "waf_control_mapping.json",
    )


class TestValidateCatalog:
    def test_valid_catalog_passes(self, valid_catalog: WafCatalog) -> None:
        result = validate_catalog(valid_catalog)
        assert result.is_valid
        assert result.errors == []

    def test_mapping_to_unknown_code_raises(self, tmp_path: Path) -> None:
        bad_mapping = {"SEC-KV-001": ["SE-07", "XX-99"]}
        (tmp_path / "waf_controls.json").write_text(json.dumps(_VALID_CONTROLS), encoding="utf-8")
        (tmp_path / "waf_control_mapping.json").write_text(json.dumps(bad_mapping), encoding="utf-8")
        catalog = WafCatalog(
            controls_path=tmp_path / "waf_controls.json",
            mapping_path=tmp_path / "waf_control_mapping.json",
        )
        with pytest.raises(CatalogValidationError) as exc_info:
            validate_catalog(catalog)
        assert "XX-99" in str(exc_info.value)

    def test_invalid_code_format_raises(self, tmp_path: Path) -> None:
        bad_controls = [
            {
                "code": "BADFORMAT",
                "pillar": "Security",
                "title": "Bad",
                "description": ".",
                "microsoft_url": "https://example.com",
                "keywords": [],
                "applicable_resource_types": ["*"],
                "version": "2024",
                "status": "active",
            }
        ]
        (tmp_path / "waf_controls.json").write_text(json.dumps(bad_controls), encoding="utf-8")
        (tmp_path / "waf_control_mapping.json").write_text(json.dumps({}), encoding="utf-8")
        catalog = WafCatalog(
            controls_path=tmp_path / "waf_controls.json",
            mapping_path=tmp_path / "waf_control_mapping.json",
        )
        with pytest.raises(CatalogValidationError) as exc_info:
            validate_catalog(catalog)
        assert "BADFORMAT" in str(exc_info.value)

    def test_error_message_lists_all_errors(self, tmp_path: Path) -> None:
        bad_mapping = {
            "RULE-A": ["SE-07", "XX-00"],
            "RULE-B": ["YY-00"],
        }
        (tmp_path / "waf_controls.json").write_text(json.dumps(_VALID_CONTROLS), encoding="utf-8")
        (tmp_path / "waf_control_mapping.json").write_text(json.dumps(bad_mapping), encoding="utf-8")
        catalog = WafCatalog(
            controls_path=tmp_path / "waf_controls.json",
            mapping_path=tmp_path / "waf_control_mapping.json",
        )
        with pytest.raises(CatalogValidationError) as exc_info:
            validate_catalog(catalog)
        msg = str(exc_info.value)
        assert "XX-00" in msg
        assert "YY-00" in msg

    def test_valid_code_patterns_accepted(self, valid_catalog: WafCatalog) -> None:
        result = validate_catalog(valid_catalog)
        assert result.is_valid

    def test_empty_mapping_with_valid_controls_passes(self, tmp_path: Path) -> None:
        (tmp_path / "waf_controls.json").write_text(json.dumps(_VALID_CONTROLS), encoding="utf-8")
        (tmp_path / "waf_control_mapping.json").write_text(json.dumps({}), encoding="utf-8")
        catalog = WafCatalog(
            controls_path=tmp_path / "waf_controls.json",
            mapping_path=tmp_path / "waf_control_mapping.json",
        )
        result = validate_catalog(catalog)
        assert result.is_valid
