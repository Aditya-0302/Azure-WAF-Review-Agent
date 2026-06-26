"""Unit tests for ReportingHandler.

Tests the orchestration logic of handler.process() using AsyncMock/MagicMock
for all I/O dependencies. Infrastructure calls (DB, Blob, KV, webhook) are
fully mocked so these tests run without any Azure or database services.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from waf_reporting.aggregator import AggregatedReport, FindingAggregator, PillarSummary
from waf_reporting.excel_generator import ExcelGenerator
from waf_reporting.handler import ReportingHandler
from waf_reporting.pdf_generator import PdfGenerator
from waf_reporting.storage_uploader import StorageUploader
from waf_reporting.webhook_service import WebhookDeliveryError, WebhookService

from waf_shared.db.repositories.human_review_repository import HumanReviewRepository
from waf_shared.domain.events.assessment_events import ReportingRequestedEvent
from waf_shared.domain.events.base import CloudEventEnvelope
from waf_shared.domain.models.assessment import Assessment, AssessmentStatus
from waf_shared.domain.models.finding import Finding, FindingStatus, Severity
from waf_shared.domain.models.report import AssessmentReport, AssessmentSummary
from waf_shared.domain.models.webhook import TenantWebhookEndpoint

# ── Fixtures and helpers ──────────────────────────────────────────────────────

_TENANT_ID = uuid.UUID("10000000-0000-0000-0000-000000000001")
_ASSESSMENT_ID = uuid.UUID("20000000-0000-0000-0000-000000000002")
_BATCH_ID = uuid.UUID("30000000-0000-0000-0000-000000000003")
_REPORT_ID = uuid.UUID("40000000-0000-0000-0000-000000000004")


def _make_assessment(status: AssessmentStatus = AssessmentStatus.REPORTING) -> Assessment:
    return Assessment(
        id=_ASSESSMENT_ID,
        tenant_id=_TENANT_ID,
        idempotency_key="idem-key",
        status=status,
        subscription_ids=["sub-1"],
        pillar_filter=None,
        tag_filter=None,
        requested_by_oid="oid-123",
        total_batches=1,
        completed_batches=1,
        cancellation_requested_at=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def _make_finding(severity: str = "medium") -> Finding:
    return Finding(
        id=uuid.uuid4(),
        assessment_id=_ASSESSMENT_ID,
        batch_id=_BATCH_ID,
        tenant_id=_TENANT_ID,
        rule_id="WAF-SEC-001",
        resource_id="/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/ag1",
        resource_type="Microsoft.Network/applicationGateways",
        status=FindingStatus.OPEN,
        severity=Severity(severity),
        pillar="security",
        confidence_score=0.9,
        title="Test finding",
        recommendation="Fix it",
        evidence={"result": "FAIL"},
        evaluation_type="deterministic",
        created_at=datetime.now(UTC),
    )


def _make_aggregated(total_findings: int = 3) -> AggregatedReport:
    return AggregatedReport(
        assessment_id=_ASSESSMENT_ID,
        tenant_id=_TENANT_ID,
        total_resources=10,
        resources_with_findings=3,
        total_findings=total_findings,
        findings_by_pillar={
            "security": PillarSummary(
                pillar="security",
                findings_by_severity={"medium": total_findings},
                total_findings=total_findings,
                compliance_score=0.5,
            )
        },
        findings_by_severity={"medium": total_findings},
        top_critical_findings=[],
        coverage_percentage=0.3,
        generated_at=datetime.now(UTC),
    )


def _make_report() -> AssessmentReport:
    return AssessmentReport(
        id=_REPORT_ID,
        assessment_id=_ASSESSMENT_ID,
        tenant_id=_TENANT_ID,
        xlsx_blob_path=f"reports/{_TENANT_ID}/{_ASSESSMENT_ID}/report.xlsx",
        pdf_blob_path=f"reports/{_TENANT_ID}/{_ASSESSMENT_ID}/report.pdf",
        summary=AssessmentSummary(
            assessment_id=_ASSESSMENT_ID,
            tenant_id=_TENANT_ID,
            total_resources=10,
            total_findings=3,
            findings_by_severity={"medium": 3},
            findings_by_pillar={"security": 3},
            coverage_percentage=0.3,
        ),
        generated_at=datetime.now(UTC),
    )


def _make_raw_event(
    assessment_id: uuid.UUID = _ASSESSMENT_ID,
    tenant_id: uuid.UUID = _TENANT_ID,
    total_findings: int = 3,
) -> bytes:
    event = ReportingRequestedEvent(
        assessment_id=assessment_id,
        tenant_id=tenant_id,
        batch_id=_BATCH_ID,
        total_findings=total_findings,
    )
    envelope = CloudEventEnvelope.wrap(
        event_type="com.wafagent.reporting.requested",
        source="/agents/reasoning",
        data=event,
    )
    return envelope.to_json_bytes()


def _build_handler(
    *,
    assessment: Assessment | None = None,
    aggregated: AggregatedReport | None = None,
    findings: list[Finding] | None = None,
    report: AssessmentReport | None = None,
    webhook_endpoint: TenantWebhookEndpoint | None = None,
    kv_secret: str | None = None,
    xlsx_bytes: bytes = b"xlsx_data",
    pdf_bytes: bytes = b"pdf_data",
    xlsx_path: str | None = None,
    pdf_path: str | None = None,
) -> tuple[ReportingHandler, dict[str, Any]]:
    if assessment is None:
        assessment = _make_assessment()
    if aggregated is None:
        aggregated = _make_aggregated()
    if findings is None:
        findings = [_make_finding()]
    if report is None:
        report = _make_report()
    if xlsx_path is None:
        xlsx_path = f"reports/{_TENANT_ID}/{_ASSESSMENT_ID}/report.xlsx"
    if pdf_path is None:
        pdf_path = f"reports/{_TENANT_ID}/{_ASSESSMENT_ID}/report.pdf"

    assessment_repo = MagicMock()
    assessment_repo.get_by_id = AsyncMock(return_value=assessment)
    assessment_repo.update_status = AsyncMock(return_value=assessment)

    finding_repo = MagicMock()
    finding_repo.list_by_assessment = AsyncMock(return_value=findings)

    report_repo = MagicMock()
    report_repo.create = AsyncMock(return_value=report)

    webhook_repo = MagicMock()
    webhook_repo.get_endpoint_by_tenant = AsyncMock(return_value=webhook_endpoint)

    human_review_repo = MagicMock(spec=HumanReviewRepository)
    human_review_repo.list_by_assessment = AsyncMock(return_value=[])

    agg_mock = MagicMock(spec=FindingAggregator)
    agg_mock.aggregate = AsyncMock(return_value=aggregated)

    excel_gen = MagicMock(spec=ExcelGenerator)
    excel_gen.generate = MagicMock(return_value=xlsx_bytes)

    pdf_gen = MagicMock(spec=PdfGenerator)
    pdf_gen.generate = MagicMock(return_value=pdf_bytes)

    uploader = MagicMock(spec=StorageUploader)
    uploader.upload_report = AsyncMock(side_effect=[xlsx_path, pdf_path])

    webhook_svc = MagicMock(spec=WebhookService)
    webhook_svc.deliver = AsyncMock(return_value=None)

    kv_client = MagicMock()
    kv_client.get_secret = AsyncMock(return_value=kv_secret or "secret-value")

    logger = MagicMock()
    logger.bind = MagicMock(return_value=logger)
    logger.info = MagicMock()
    logger.warning = MagicMock()
    logger.error = MagicMock()
    logger.debug = MagicMock()

    handler = ReportingHandler(
        assessment_repo=assessment_repo,
        finding_repo=finding_repo,
        report_repo=report_repo,
        webhook_repo=webhook_repo,
        human_review_repo=human_review_repo,
        aggregator=agg_mock,
        excel_gen=excel_gen,
        pdf_gen=pdf_gen,
        uploader=uploader,
        webhook_service=webhook_svc,
        kv_client=kv_client,
        logger=logger,
    )
    mocks = {
        "assessment_repo": assessment_repo,
        "finding_repo": finding_repo,
        "report_repo": report_repo,
        "webhook_repo": webhook_repo,
        "human_review_repo": human_review_repo,
        "aggregator": agg_mock,
        "excel_gen": excel_gen,
        "pdf_gen": pdf_gen,
        "uploader": uploader,
        "webhook_svc": webhook_svc,
        "kv_client": kv_client,
        "logger": logger,
    }
    return handler, mocks


# ── Happy path ────────────────────────────────────────────────────────────────


class TestReportingHandlerHappyPath:
    @pytest.mark.asyncio
    async def test_full_pipeline_no_webhook(self) -> None:
        """Successful report generation without a configured webhook."""
        handler, mocks = _build_handler(webhook_endpoint=None)
        await handler.process(_make_raw_event())

        call_args = mocks["aggregator"].aggregate.call_args
        assert call_args.args[0] == _TENANT_ID
        assert call_args.args[1] == _ASSESSMENT_ID
        mocks["finding_repo"].list_by_assessment.assert_called_once()
        mocks["excel_gen"].generate.assert_called_once()
        mocks["pdf_gen"].generate.assert_called_once()
        assert mocks["uploader"].upload_report.call_count == 2
        mocks["report_repo"].create.assert_called_once()
        mocks["assessment_repo"].update_status.assert_called_once_with(
            _TENANT_ID,
            _ASSESSMENT_ID,
            AssessmentStatus.COMPLETED,
        )
        mocks["webhook_svc"].deliver.assert_not_called()

    @pytest.mark.asyncio
    async def test_full_pipeline_with_webhook(self) -> None:
        """Successful report generation including webhook delivery."""
        endpoint = TenantWebhookEndpoint(
            id=uuid.uuid4(),
            tenant_id=_TENANT_ID,
            webhook_url="https://example.com/webhook",
            secret_kv_name="wh-secret-tenant-1",
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        handler, mocks = _build_handler(webhook_endpoint=endpoint, kv_secret="my-secret")
        await handler.process(_make_raw_event())

        mocks["kv_client"].get_secret.assert_called_once_with("wh-secret-tenant-1")
        mocks["webhook_svc"].deliver.assert_called_once()
        call_kwargs = mocks["webhook_svc"].deliver.call_args[1]
        assert call_kwargs["webhook_url"] == "https://example.com/webhook"
        assert call_kwargs["webhook_secret"] == b"my-secret"
        payload = call_kwargs["payload"]
        assert payload["status"] == "completed"
        assert payload["assessment_id"] == str(_ASSESSMENT_ID)
        assert "report_xlsx_path" in payload
        assert "report_pdf_path" in payload

    @pytest.mark.asyncio
    async def test_blob_paths_stored_not_sas(self) -> None:
        """AssessmentReport must store blob paths, never SAS URLs."""
        handler, mocks = _build_handler(webhook_endpoint=None)
        await handler.process(_make_raw_event())

        created_report: AssessmentReport = mocks["report_repo"].create.call_args[0][0]
        assert created_report.xlsx_blob_path.startswith("reports/")
        assert "?" not in created_report.xlsx_blob_path  # no SAS query string
        assert created_report.pdf_blob_path.startswith("reports/")
        assert "?" not in created_report.pdf_blob_path

    @pytest.mark.asyncio
    async def test_assessment_summary_fields(self) -> None:
        """AssessmentSummary created from AggregatedReport has correct values."""
        agg = _make_aggregated(total_findings=7)
        handler, mocks = _build_handler(aggregated=agg, webhook_endpoint=None)
        await handler.process(_make_raw_event(total_findings=7))

        created_report: AssessmentReport = mocks["report_repo"].create.call_args[0][0]
        s = created_report.summary
        assert s.total_findings == 7
        assert s.total_resources == 10
        assert s.coverage_percentage == 0.3
        assert "security" in s.findings_by_pillar


# ── Status guard ──────────────────────────────────────────────────────────────


class TestReportingHandlerStatusGuard:
    @pytest.mark.asyncio
    async def test_skips_if_assessment_not_found(self) -> None:
        handler, mocks = _build_handler()
        mocks["assessment_repo"].get_by_id = AsyncMock(return_value=None)
        await handler.process(_make_raw_event())

        mocks["aggregator"].aggregate.assert_not_called()
        mocks["report_repo"].create.assert_not_called()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "status",
        [
            AssessmentStatus.COMPLETED,
            AssessmentStatus.FAILED,
            AssessmentStatus.CANCELLED,
        ],
    )
    async def test_skips_if_terminal_status(self, status: AssessmentStatus) -> None:
        handler, mocks = _build_handler(assessment=_make_assessment(status))
        await handler.process(_make_raw_event())

        mocks["aggregator"].aggregate.assert_not_called()
        mocks["assessment_repo"].update_status.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_if_not_reporting_status(self) -> None:
        """Handler must skip if assessment is in REASONING (wrong status)."""
        handler, mocks = _build_handler(assessment=_make_assessment(AssessmentStatus.REASONING))
        await handler.process(_make_raw_event())

        mocks["aggregator"].aggregate.assert_not_called()


# ── Webhook failure isolation ─────────────────────────────────────────────────


class TestReportingHandlerWebhookIsolation:
    @pytest.mark.asyncio
    async def test_kv_failure_does_not_abort_assessment(self) -> None:
        """Key Vault fetch failure must NOT prevent COMPLETED status update."""
        endpoint = TenantWebhookEndpoint(
            id=uuid.uuid4(),
            tenant_id=_TENANT_ID,
            webhook_url="https://example.com/webhook",
            secret_kv_name="bad-secret",
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        handler, mocks = _build_handler(webhook_endpoint=endpoint)
        mocks["kv_client"].get_secret = AsyncMock(side_effect=Exception("KV down"))

        await handler.process(_make_raw_event())

        # Assessment must still be completed despite KV failure.
        mocks["assessment_repo"].update_status.assert_called_once_with(
            _TENANT_ID, _ASSESSMENT_ID, AssessmentStatus.COMPLETED
        )
        mocks["webhook_svc"].deliver.assert_not_called()

    @pytest.mark.asyncio
    async def test_webhook_delivery_error_does_not_abort_assessment(self) -> None:
        """WebhookDeliveryError must be swallowed; assessment stays COMPLETED."""
        endpoint = TenantWebhookEndpoint(
            id=uuid.uuid4(),
            tenant_id=_TENANT_ID,
            webhook_url="https://example.com/webhook",
            secret_kv_name="good-secret",
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        handler, mocks = _build_handler(webhook_endpoint=endpoint)
        mocks["webhook_svc"].deliver = AsyncMock(
            side_effect=WebhookDeliveryError("https://example.com/webhook", 4)
        )

        await handler.process(_make_raw_event())

        mocks["assessment_repo"].update_status.assert_called_once_with(
            _TENANT_ID, _ASSESSMENT_ID, AssessmentStatus.COMPLETED
        )

    @pytest.mark.asyncio
    async def test_no_webhook_when_endpoint_inactive(self) -> None:
        """No webhook is sent when endpoint.is_active=False is handled at DB level."""
        handler, mocks = _build_handler(webhook_endpoint=None)
        await handler.process(_make_raw_event())

        mocks["kv_client"].get_secret.assert_not_called()
        mocks["webhook_svc"].deliver.assert_not_called()


# ── Finding pagination ────────────────────────────────────────────────────────


class TestReportingHandlerPagination:
    @pytest.mark.asyncio
    async def test_paginated_findings_merged(self) -> None:
        """list_by_assessment is called repeatedly until the page is short."""
        page1 = [_make_finding() for _ in range(500)]
        page2 = [_make_finding() for _ in range(3)]

        handler, mocks = _build_handler(webhook_endpoint=None)
        mocks["finding_repo"].list_by_assessment = AsyncMock(side_effect=[page1, page2, []])

        await handler.process(_make_raw_event())

        # excel_gen.generate was called with all 503 findings.
        all_findings = mocks["excel_gen"].generate.call_args[0][1]
        assert len(all_findings) == 503

    @pytest.mark.asyncio
    async def test_empty_findings_still_generates_report(self) -> None:
        """An assessment with zero findings should still produce an empty report."""
        handler, mocks = _build_handler(
            aggregated=_make_aggregated(total_findings=0),
            findings=[],
            webhook_endpoint=None,
        )
        mocks["finding_repo"].list_by_assessment = AsyncMock(return_value=[])
        await handler.process(_make_raw_event(total_findings=0))

        mocks["report_repo"].create.assert_called_once()
        mocks["assessment_repo"].update_status.assert_called_once()


# ── Webhook payload structure ─────────────────────────────────────────────────


class TestWebhookPayloadStructure:
    @pytest.mark.asyncio
    async def test_payload_contains_required_fields(self) -> None:
        endpoint = TenantWebhookEndpoint(
            id=uuid.uuid4(),
            tenant_id=_TENANT_ID,
            webhook_url="https://hooks.example.com/waf",
            secret_kv_name="kv-secret-name",
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        handler, mocks = _build_handler(webhook_endpoint=endpoint)
        await handler.process(_make_raw_event())

        payload = mocks["webhook_svc"].deliver.call_args[1]["payload"]
        required_keys = {
            "assessment_id",
            "tenant_id",
            "status",
            "total_findings",
            "report_xlsx_path",
            "report_pdf_path",
            "generated_at",
        }
        assert required_keys.issubset(set(payload.keys()))
        assert payload["status"] == "completed"

    @pytest.mark.asyncio
    async def test_payload_does_not_contain_sas_tokens(self) -> None:
        endpoint = TenantWebhookEndpoint(
            id=uuid.uuid4(),
            tenant_id=_TENANT_ID,
            webhook_url="https://hooks.example.com/waf",
            secret_kv_name="kv-secret-name",
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        handler, mocks = _build_handler(webhook_endpoint=endpoint)
        await handler.process(_make_raw_event())

        payload = mocks["webhook_svc"].deliver.call_args[1]["payload"]
        # Blob paths must not look like SAS URLs.
        for key in ("report_xlsx_path", "report_pdf_path"):
            assert "?" not in payload[key], f"{key} contains SAS token query string"
            assert "sig=" not in payload[key]
