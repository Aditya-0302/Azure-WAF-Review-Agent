"""Unit tests for the human review domain models."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from waf_shared.domain.models.human_review import (
    ComplianceStatus,
    EvidenceReference,
    EvidenceType,
    HumanReviewAssessment,
    HumanReviewControl,
    HumanReviewQuestion,
    HumanReviewSummary,
    ReviewAnswer,
    ReviewStatus,
)

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 6, 22, 12, 0, 0, tzinfo=UTC)
_TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
_ASSESSMENT = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_REVIEW_ID = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")


# ── HumanReviewQuestion ───────────────────────────────────────────────────────


class TestHumanReviewQuestion:
    def test_boolean_question(self):
        q = HumanReviewQuestion(
            id="se10-q1",
            text="Do you conduct penetration testing?",
            type="boolean",
            required=True,
            evidence_required=False,
        )
        assert q.id == "se10-q1"
        assert q.type == "boolean"
        assert q.options == []
        assert q.required is True
        assert q.evidence_required is False

    def test_single_choice_question(self):
        q = HumanReviewQuestion(
            id="se10-q2",
            text="How frequently?",
            type="single_choice",
            options=["Annually", "Quarterly", "Never"],
            required=True,
            evidence_required=False,
        )
        assert q.options == ["Annually", "Quarterly", "Never"]

    def test_evidence_question(self):
        q = HumanReviewQuestion(
            id="se10-q5",
            text="Provide evidence.",
            type="evidence",
            required=False,
            evidence_required=True,
            accepted_types=["PDF", "link"],
        )
        assert q.accepted_types == ["PDF", "link"]
        assert q.evidence_required is True

    def test_frozen(self):
        q = HumanReviewQuestion(
            id="q1",
            text="Q",
            type="boolean",
            required=True,
            evidence_required=False,
        )
        with pytest.raises(Exception):
            q.id = "q2"  # type: ignore[misc]


# ── HumanReviewControl ────────────────────────────────────────────────────────


class TestHumanReviewControl:
    def _make(self) -> HumanReviewControl:
        return HumanReviewControl(
            code="SE-10",
            pillar="Security",
            title="Perform adversarial testing",
            microsoft_url="https://learn.microsoft.com/azure/well-architected/security/adversarial-testing",
            review_required=True,
            reason_for_human_review="No ARM API evidence.",
            questions=[
                HumanReviewQuestion(
                    id="se10-q1",
                    text="Do you pentest?",
                    type="boolean",
                    required=True,
                    evidence_required=False,
                )
            ],
        )

    def test_creates_control(self):
        ctrl = self._make()
        assert ctrl.code == "SE-10"
        assert ctrl.pillar == "Security"
        assert ctrl.review_required is True
        assert len(ctrl.questions) == 1

    def test_frozen(self):
        ctrl = self._make()
        with pytest.raises(Exception):
            ctrl.code = "OE-03"  # type: ignore[misc]


# ── ReviewAnswer ───────────────────────────────────────────────────────────────


class TestReviewAnswer:
    def test_boolean_answer(self):
        a = ReviewAnswer(question_id="se10-q1", answer=True)
        assert a.question_id == "se10-q1"
        assert a.answer is True
        assert a.notes is None

    def test_string_answer_with_notes(self):
        a = ReviewAnswer(question_id="se10-q2", answer="Annually", notes="Per SOC2 requirement")
        assert a.answer == "Annually"
        assert a.notes == "Per SOC2 requirement"

    def test_frozen(self):
        a = ReviewAnswer(question_id="q1", answer=True)
        with pytest.raises(Exception):
            a.answer = False  # type: ignore[misc]


# ── EvidenceReference ─────────────────────────────────────────────────────────


class TestEvidenceReference:
    def test_creates_pdf_evidence(self):
        e = EvidenceReference(
            evidence_type=EvidenceType.PDF,
            url_or_filename="PenTest_Report_2026.pdf",
            description="Annual penetration test report",
            uploaded_at=_NOW,
        )
        assert e.evidence_type == EvidenceType.PDF
        assert e.url_or_filename == "PenTest_Report_2026.pdf"

    def test_creates_link_evidence(self):
        e = EvidenceReference(
            evidence_type=EvidenceType.LINK,
            url_or_filename="https://boards.example.com/sprints/42",
            description="Sprint board screenshot",
            uploaded_at=_NOW,
        )
        assert e.evidence_type == EvidenceType.LINK


# ── HumanReviewAssessment ─────────────────────────────────────────────────────


class TestHumanReviewAssessment:
    def _make(self, **overrides) -> HumanReviewAssessment:
        base = dict(
            id=_REVIEW_ID,
            assessment_id=_ASSESSMENT,
            tenant_id=_TENANT,
            control_code="SE-10",
            pillar="Security",
            reviewer_oid="reviewer-oid-abc",
            status=ReviewStatus.COMPLETED,
            compliance_status=ComplianceStatus.COMPLIANT,
            score=88,
            answers=[],
            evidence_refs=[],
            comments="Reviewed and approved.",
            reviewed_at=_NOW,
            created_at=_NOW,
            updated_at=_NOW,
        )
        base.update(overrides)
        return HumanReviewAssessment(**base)

    def test_creates_completed_review(self):
        review = self._make()
        assert review.status == ReviewStatus.COMPLETED
        assert review.compliance_status == ComplianceStatus.COMPLIANT
        assert review.score == 88
        assert review.control_code == "SE-10"

    def test_score_zero_is_valid(self):
        review = self._make(score=0)
        assert review.score == 0

    def test_score_100_is_valid(self):
        review = self._make(score=100)
        assert review.score == 100

    def test_score_below_zero_raises(self):
        with pytest.raises(Exception):
            self._make(score=-1)

    def test_score_above_100_raises(self):
        with pytest.raises(Exception):
            self._make(score=101)

    def test_mutable_allows_status_update(self):
        review = self._make(status=ReviewStatus.IN_PROGRESS)
        review.status = ReviewStatus.COMPLETED
        assert review.status == ReviewStatus.COMPLETED

    def test_not_assessed_default(self):
        review = self._make(
            status=ReviewStatus.PENDING,
            compliance_status=ComplianceStatus.NOT_ASSESSED,
            score=0,
            reviewed_at=None,
        )
        assert review.compliance_status == ComplianceStatus.NOT_ASSESSED
        assert review.reviewed_at is None

    def test_with_answers_and_evidence(self):
        review = self._make(
            answers=[ReviewAnswer(question_id="se10-q1", answer=True)],
            evidence_refs=[
                EvidenceReference(
                    evidence_type=EvidenceType.PDF,
                    url_or_filename="report.pdf",
                    description="Pentest",
                    uploaded_at=_NOW,
                )
            ],
        )
        assert len(review.answers) == 1
        assert review.answers[0].question_id == "se10-q1"
        assert len(review.evidence_refs) == 1

    def test_all_four_controls_accepted(self):
        for code in ("SE-10", "OE-03", "OE-04", "CO-09"):
            review = self._make(control_code=code)
            assert review.control_code == code


# ── HumanReviewSummary ────────────────────────────────────────────────────────


class TestHumanReviewSummary:
    def test_zero_reviews_gives_93_percent_total(self):
        summary = HumanReviewSummary(
            assessment_id=_ASSESSMENT,
            tenant_id=_TENANT,
            automated_coverage_percentage=93.0,
            automated_controls_covered=53,
            automated_controls_total=57,
            human_review_total=4,
            human_review_completed=0,
            human_review_compliant=0,
            human_review_pending=4,
            total_framework_coverage_percentage=93.0,
            total_controls=57,
            reviews=[],
        )
        assert summary.total_framework_coverage_percentage == 93.0
        assert summary.human_review_pending == 4
        assert summary.human_review_compliant == 0

    def test_all_four_compliant_gives_100_percent(self):
        summary = HumanReviewSummary(
            assessment_id=_ASSESSMENT,
            tenant_id=_TENANT,
            automated_coverage_percentage=93.0,
            automated_controls_covered=53,
            automated_controls_total=57,
            human_review_total=4,
            human_review_completed=4,
            human_review_compliant=4,
            human_review_pending=0,
            total_framework_coverage_percentage=100.0,
            total_controls=57,
            reviews=[],
        )
        assert summary.total_framework_coverage_percentage == 100.0
        assert summary.human_review_pending == 0

    def test_partial_human_review(self):
        summary = HumanReviewSummary(
            assessment_id=_ASSESSMENT,
            tenant_id=_TENANT,
            automated_coverage_percentage=93.0,
            automated_controls_covered=53,
            automated_controls_total=57,
            human_review_total=4,
            human_review_completed=2,
            human_review_compliant=2,
            human_review_pending=2,
            total_framework_coverage_percentage=round((53 + 2) / 57 * 100, 1),
            total_controls=57,
            reviews=[],
        )
        assert summary.human_review_compliant == 2
        assert summary.total_framework_coverage_percentage == pytest.approx(96.5, abs=0.1)

    def test_frozen(self):
        summary = HumanReviewSummary(
            assessment_id=_ASSESSMENT,
            tenant_id=_TENANT,
            automated_coverage_percentage=93.0,
            automated_controls_covered=53,
            automated_controls_total=57,
            human_review_total=4,
            human_review_completed=0,
            human_review_compliant=0,
            human_review_pending=4,
            total_framework_coverage_percentage=93.0,
            total_controls=57,
        )
        with pytest.raises(Exception):
            summary.human_review_compliant = 4  # type: ignore[misc]


# ── ReviewStatus enum ─────────────────────────────────────────────────────────


class TestReviewStatus:
    def test_all_values_exist(self):
        assert ReviewStatus.PENDING == "pending"
        assert ReviewStatus.IN_PROGRESS == "in_progress"
        assert ReviewStatus.COMPLETED == "completed"
        assert ReviewStatus.NOT_ASSESSED == "not_assessed"

    def test_str_round_trip(self):
        for s in ReviewStatus:
            assert ReviewStatus(s.value) == s


# ── ComplianceStatus enum ─────────────────────────────────────────────────────


class TestComplianceStatus:
    def test_all_values_exist(self):
        assert ComplianceStatus.COMPLIANT == "compliant"
        assert ComplianceStatus.PARTIALLY_COMPLIANT == "partially_compliant"
        assert ComplianceStatus.NON_COMPLIANT == "non_compliant"
        assert ComplianceStatus.NOT_ASSESSED == "not_assessed"

    def test_str_round_trip(self):
        for s in ComplianceStatus:
            assert ComplianceStatus(s.value) == s
