"""Unit tests for HumanReviewService — catalog loading and summary computation."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from waf_shared.domain.errors.domain_errors import HumanReviewControlNotFoundError
from waf_shared.domain.models.human_review import (
    ComplianceStatus,
    HumanReviewAssessment,
    HumanReviewControl,
    ReviewStatus,
)

pytestmark = pytest.mark.unit

_TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
_ASSESSMENT = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_NOW = datetime(2026, 6, 22, 12, 0, 0, tzinfo=UTC)

_KNOWN_CODES = {"SE-10", "OE-03", "OE-04", "CO-09"}


def _make_review(
    control_code: str, compliance_status: ComplianceStatus, score: int = 90
) -> HumanReviewAssessment:
    return HumanReviewAssessment(
        id=uuid.uuid4(),
        assessment_id=_ASSESSMENT,
        tenant_id=_TENANT,
        control_code=control_code,
        pillar="Security" if control_code == "SE-10" else "Operational Excellence",
        reviewer_oid="reviewer-oid-abc",
        status=ReviewStatus.COMPLETED,
        compliance_status=compliance_status,
        score=score,
        answers=[],
        evidence_refs=[],
        comments=None,
        reviewed_at=_NOW,
        created_at=_NOW,
        updated_at=_NOW,
    )


@pytest.fixture
def mock_pool():
    pool = MagicMock()
    return pool


@pytest.fixture
def service(mock_pool):
    from waf_api.services.human_review_service import HumanReviewService

    return HumanReviewService(pool=mock_pool)


# ── Catalog loading ────────────────────────────────────────────────────────────


class TestCatalogLoading:
    def test_list_controls_returns_four(self, service):
        controls = service.list_controls()
        assert len(controls) == 4

    def test_all_known_codes_present(self, service):
        codes = {c.code for c in service.list_controls()}
        assert codes == _KNOWN_CODES

    def test_each_control_has_questions(self, service):
        for ctrl in service.list_controls():
            assert len(ctrl.questions) >= 4, f"{ctrl.code} should have at least 4 questions"

    def test_each_control_has_microsoft_url(self, service):
        for ctrl in service.list_controls():
            assert ctrl.microsoft_url.startswith("https://learn.microsoft.com")

    def test_each_control_is_review_required(self, service):
        for ctrl in service.list_controls():
            assert ctrl.review_required is True

    def test_get_control_se10(self, service):
        ctrl = service.get_control("SE-10")
        assert isinstance(ctrl, HumanReviewControl)
        assert ctrl.code == "SE-10"
        assert ctrl.pillar == "Security"

    def test_get_control_oe03(self, service):
        ctrl = service.get_control("OE-03")
        assert ctrl.code == "OE-03"
        assert ctrl.pillar == "Operational Excellence"

    def test_get_control_oe04(self, service):
        ctrl = service.get_control("OE-04")
        assert ctrl.code == "OE-04"

    def test_get_control_co09(self, service):
        ctrl = service.get_control("CO-09")
        assert ctrl.code == "CO-09"
        assert ctrl.pillar == "Cost Optimization"

    def test_get_control_unknown_raises(self, service):
        with pytest.raises(HumanReviewControlNotFoundError) as exc_info:
            service.get_control("XX-99")
        assert "XX-99" in str(exc_info.value)
        assert exc_info.value.control_code == "XX-99"


# ── Question structure validation ─────────────────────────────────────────────


class TestQuestionStructure:
    def test_se10_has_pentest_frequency_question(self, service):
        ctrl = service.get_control("SE-10")
        q_types = {q.type for q in ctrl.questions}
        assert "boolean" in q_types
        assert "single_choice" in q_types
        assert "evidence" in q_types

    def test_oe04_has_cicd_platform_question(self, service):
        ctrl = service.get_control("OE-04")
        choice_qs = [q for q in ctrl.questions if q.type == "single_choice"]
        assert len(choice_qs) >= 1
        options = choice_qs[0].options
        assert any("Azure Pipelines" in o or "GitHub Actions" in o for o in options)

    def test_oe03_has_planning_tool_question(self, service):
        ctrl = service.get_control("OE-03")
        choice_qs = [q for q in ctrl.questions if q.type == "single_choice"]
        assert len(choice_qs) >= 1
        options = choice_qs[0].options
        assert any("Jira" in o or "Azure DevOps" in o for o in options)

    def test_evidence_questions_have_accepted_types(self, service):
        for code in _KNOWN_CODES:
            ctrl = service.get_control(code)
            evidence_qs = [q for q in ctrl.questions if q.type == "evidence"]
            assert len(evidence_qs) >= 1, f"{code} must have at least one evidence question"
            for q in evidence_qs:
                assert (
                    len(q.accepted_types) > 0
                ), f"{code} evidence question must list accepted_types"

    def test_required_questions_exist_in_each_control(self, service):
        for code in _KNOWN_CODES:
            ctrl = service.get_control(code)
            required_qs = [q for q in ctrl.questions if q.required]
            assert len(required_qs) >= 2, f"{code} should have at least 2 required questions"


# ── Summary computation ────────────────────────────────────────────────────────


class TestGetSummary:
    @pytest.mark.asyncio
    async def test_no_reviews_gives_93_percent(self, service, mock_pool):
        with patch.object(service._repo, "list_by_assessment", new=AsyncMock(return_value=[])):
            summary = await service.get_summary(_TENANT, _ASSESSMENT)

        assert summary.automated_coverage_percentage == 93.0
        assert summary.automated_controls_covered == 53
        assert summary.human_review_total == 4
        assert summary.human_review_completed == 0
        assert summary.human_review_compliant == 0
        assert summary.human_review_pending == 4
        assert summary.total_framework_coverage_percentage == 93.0

    @pytest.mark.asyncio
    async def test_all_four_compliant_gives_100_percent(self, service, mock_pool):
        reviews = [_make_review(code, ComplianceStatus.COMPLIANT) for code in _KNOWN_CODES]
        with patch.object(service._repo, "list_by_assessment", new=AsyncMock(return_value=reviews)):
            summary = await service.get_summary(_TENANT, _ASSESSMENT)

        assert summary.human_review_compliant == 4
        assert summary.human_review_completed == 4
        assert summary.human_review_pending == 0
        assert summary.total_framework_coverage_percentage == 100.0

    @pytest.mark.asyncio
    async def test_partially_compliant_counts_as_covered(self, service, mock_pool):
        reviews = [
            _make_review("SE-10", ComplianceStatus.PARTIALLY_COMPLIANT),
        ]
        with patch.object(service._repo, "list_by_assessment", new=AsyncMock(return_value=reviews)):
            summary = await service.get_summary(_TENANT, _ASSESSMENT)

        assert summary.human_review_compliant == 1
        expected_pct = round((53 + 1) / 57 * 100, 1)
        assert summary.total_framework_coverage_percentage == pytest.approx(expected_pct, abs=0.1)

    @pytest.mark.asyncio
    async def test_non_compliant_does_not_increase_coverage(self, service, mock_pool):
        reviews = [
            _make_review("SE-10", ComplianceStatus.NON_COMPLIANT),
        ]
        with patch.object(service._repo, "list_by_assessment", new=AsyncMock(return_value=reviews)):
            summary = await service.get_summary(_TENANT, _ASSESSMENT)

        assert summary.human_review_compliant == 0
        assert summary.total_framework_coverage_percentage == 93.0

    @pytest.mark.asyncio
    async def test_not_assessed_does_not_increase_coverage(self, service, mock_pool):
        review = HumanReviewAssessment(
            id=uuid.uuid4(),
            assessment_id=_ASSESSMENT,
            tenant_id=_TENANT,
            control_code="OE-03",
            pillar="Operational Excellence",
            reviewer_oid="oid",
            status=ReviewStatus.IN_PROGRESS,
            compliance_status=ComplianceStatus.NOT_ASSESSED,
            score=0,
            reviewed_at=None,
            created_at=_NOW,
            updated_at=_NOW,
        )
        with patch.object(
            service._repo, "list_by_assessment", new=AsyncMock(return_value=[review])
        ):
            summary = await service.get_summary(_TENANT, _ASSESSMENT)

        assert summary.human_review_compliant == 0
        assert summary.total_framework_coverage_percentage == 93.0

    @pytest.mark.asyncio
    async def test_summary_includes_reviews(self, service, mock_pool):
        reviews = [_make_review("SE-10", ComplianceStatus.COMPLIANT)]
        with patch.object(service._repo, "list_by_assessment", new=AsyncMock(return_value=reviews)):
            summary = await service.get_summary(_TENANT, _ASSESSMENT)

        assert len(summary.reviews) == 1
        assert summary.reviews[0].control_code == "SE-10"

    @pytest.mark.asyncio
    async def test_summary_assessment_and_tenant_ids(self, service, mock_pool):
        with patch.object(service._repo, "list_by_assessment", new=AsyncMock(return_value=[])):
            summary = await service.get_summary(_TENANT, _ASSESSMENT)

        assert summary.assessment_id == _ASSESSMENT
        assert summary.tenant_id == _TENANT
        assert summary.total_controls == 57


# ── Catalog JSON integrity ─────────────────────────────────────────────────────


class TestCatalogIntegrity:
    def test_no_duplicate_control_codes(self, service):
        controls = service.list_controls()
        codes = [c.code for c in controls]
        assert len(codes) == len(set(codes))

    def test_all_questions_have_unique_ids_per_control(self, service):
        for ctrl in service.list_controls():
            q_ids = [q.id for q in ctrl.questions]
            assert len(q_ids) == len(set(q_ids)), f"{ctrl.code} has duplicate question IDs"

    def test_all_question_ids_contain_control_prefix(self, service):
        expected_prefixes = {
            "SE-10": "se10",
            "OE-03": "oe03",
            "OE-04": "oe04",
            "CO-09": "co09",
        }
        for ctrl in service.list_controls():
            prefix = expected_prefixes[ctrl.code]
            for q in ctrl.questions:
                assert q.id.startswith(
                    prefix
                ), f"{ctrl.code} question id '{q.id}' should start with '{prefix}'"

    def test_reason_for_human_review_is_not_empty(self, service):
        for ctrl in service.list_controls():
            assert (
                len(ctrl.reason_for_human_review) > 20
            ), f"{ctrl.code} reason_for_human_review is too short"

    def test_expected_pillars(self, service):
        pillar_map = {c.code: c.pillar for c in service.list_controls()}
        assert pillar_map["SE-10"] == "Security"
        assert pillar_map["OE-03"] == "Operational Excellence"
        assert pillar_map["OE-04"] == "Operational Excellence"
        assert pillar_map["CO-09"] == "Cost Optimization"
