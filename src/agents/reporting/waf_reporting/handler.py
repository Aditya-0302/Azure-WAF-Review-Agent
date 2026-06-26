"""Reporting Agent message handler.

Orchestrates the full Transform-and-Report pipeline for one
``reporting.requested`` CloudEvent:

  1.  Deserialise CloudEventEnvelope[ReportingRequestedEvent].
  2.  Load the Assessment; skip if terminal or not REPORTING (stale re-delivery guard).
  3.  Aggregate findings (SQL GROUP BY → AggregatedReport).
  4.  Fetch all findings (paginated up to _MAX_FINDINGS per assessment).
  5.  Fetch human review results for this assessment (SE-10 / OE-03 / OE-04 / CO-09).
  6.  Generate Excel workbook (openpyxl — 14 sheets).
  7.  Generate PDF document (reportlab — 12 sections).
  8.  Upload both files to Azure Blob Storage (Managed Identity; path only, no SAS).
  9.  Build AssessmentSummary and write AssessmentReport record to DB.
  10. Update assessment status → COMPLETED.
  11. If tenant has an active webhook endpoint:
        a. Fetch HMAC secret from Key Vault.
        b. Deliver signed webhook (retry 30 s / 2 min / 10 min).
        c. WebhookDeliveryError is logged and swallowed — webhook failure must
           not roll back the completed assessment.

Blob paths are stored in assessment_reports; SAS tokens are generated on
demand by the API tier (≤ 15-minute TTL). This handler never produces SAS URLs.

Webhook payload is HMAC-SHA256 signed with a per-tenant secret from Key Vault.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from waf_reporting.aggregator import AggregatedReport, FindingAggregator
from waf_reporting.excel_generator import ExcelGenerator
from waf_reporting.pdf_generator import PdfGenerator
from waf_reporting.storage_uploader import StorageUploader
from waf_reporting.webhook_service import WebhookDeliveryError, WebhookService

from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.db.repositories.finding_repository import FindingRepository
from waf_shared.db.repositories.human_review_repository import HumanReviewRepository
from waf_shared.db.repositories.report_repository import ReportRepository
from waf_shared.db.repositories.webhook_repository import WebhookRepository
from waf_shared.domain.events.assessment_events import ReportingRequestedEvent
from waf_shared.domain.events.base import CloudEventEnvelope
from waf_shared.domain.models.assessment import TERMINAL_STATUSES, AssessmentStatus
from waf_shared.domain.models.finding import Finding
from waf_shared.domain.models.human_review import HumanReviewAssessment
from waf_shared.domain.models.report import AssessmentReport, AssessmentSummary
from waf_shared.infra.keyvault import KeyVaultClient
from waf_shared.telemetry.logging import StructuredLogger

# Findings are loaded paginated; this caps total findings per assessment in
# memory to protect against pathological assessments.
_MAX_FINDINGS = 10_000
_FINDINGS_PAGE_SIZE = 500

# Blob upload is best-effort. When it fails, reports are written here and the
# assessment is still marked COMPLETED. The local path is stored in the DB so
# the API tier can surface a "locally cached" download path instead of a SAS URL.
_LOCAL_REPORTS_DIR = Path("/tmp/reports")  # nosec B108 — containerised; /tmp is ephemeral pod storage, not a shared host path

_XLSX_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
_PDF_CONTENT_TYPE = "application/pdf"


class ReportingHandler:
    """Stateless handler — all state lives in PostgreSQL and Azure Blob Storage."""

    def __init__(
        self,
        *,
        assessment_repo: AssessmentRepository,
        finding_repo: FindingRepository,
        report_repo: ReportRepository,
        webhook_repo: WebhookRepository,
        human_review_repo: HumanReviewRepository,
        aggregator: FindingAggregator,
        excel_gen: ExcelGenerator,
        pdf_gen: PdfGenerator,
        uploader: StorageUploader,
        webhook_service: WebhookService,
        kv_client: KeyVaultClient,
        logger: StructuredLogger,
    ) -> None:
        self._assessment_repo = assessment_repo
        self._finding_repo = finding_repo
        self._report_repo = report_repo
        self._webhook_repo = webhook_repo
        self._human_review_repo = human_review_repo
        self._aggregator = aggregator
        self._excel_gen = excel_gen
        self._pdf_gen = pdf_gen
        self._uploader = uploader
        self._webhook_service = webhook_service
        self._kv_client = kv_client
        self._logger = logger

    # ── Public entry point ────────────────────────────────────────────────────

    async def process(self, raw_body: bytes) -> None:
        """Process one reporting.requested message.

        Returns normally on success or handled failure.
        Propagates DB / storage errors so the consumer abandons and SB retries.
        """
        envelope = CloudEventEnvelope.from_json_bytes(raw_body, ReportingRequestedEvent)
        event = envelope.data
        log = self._logger.bind(
            assessment_id=str(event.assessment_id),
            tenant_id=str(event.tenant_id),
            total_findings=event.total_findings,
        )
        log.info("reporting.handler.received")
        await self._handle(event, log)

    # ── Orchestration ─────────────────────────────────────────────────────────

    async def _handle(
        self,
        event: ReportingRequestedEvent,
        log: StructuredLogger,
    ) -> None:
        # Step 1 — guard: load assessment and check it is in REPORTING status.
        assessment = await self._assessment_repo.get_by_id(event.tenant_id, event.assessment_id)
        if assessment is None:
            log.error("reporting.handler.assessment_not_found")
            return

        if assessment.status in TERMINAL_STATUSES:
            log.info(
                "reporting.handler.skipped",
                status=assessment.status.value,
                reason="already_terminal",
            )
            return

        if assessment.status != AssessmentStatus.REPORTING:
            log.warning(
                "reporting.handler.unexpected_status",
                status=assessment.status.value,
            )
            return

        # Step 2 — aggregate findings from DB (SQL GROUP BY).
        log.info("reporting.handler.aggregating")
        aggregated = await self._aggregator.aggregate(
            event.tenant_id, event.assessment_id, assessment
        )
        log.info(
            "reporting.handler.aggregated",
            total_findings=aggregated.total_findings,
            total_resources=aggregated.total_resources,
            pillars=list(aggregated.findings_by_pillar.keys()),
            overall_compliance=aggregated.overall_compliance_score,
            risk_score=aggregated.overall_risk_score,
        )

        # Step 3 — fetch all findings (paginated, for report generation).
        findings = await self._fetch_all_findings(event, log)

        # Step 4 — fetch human review results (non-fatal if absent).
        human_reviews = await self._fetch_human_reviews(event, log)

        # Step 5 — generate Excel workbook.
        log.info("reporting.handler.generating_excel")
        xlsx_bytes = self._excel_gen.generate(aggregated, findings, human_reviews)
        log.info("reporting.handler.excel_generated", size_bytes=len(xlsx_bytes))

        # Step 6 — generate PDF.
        log.info("reporting.handler.generating_pdf")
        pdf_bytes = self._pdf_gen.generate(aggregated, findings, human_reviews)
        log.info("reporting.handler.pdf_generated", size_bytes=len(pdf_bytes))

        # Step 7 — upload both to Blob Storage (best-effort; falls back to /tmp).
        xlsx_path, pdf_path = await self._upload_or_fallback(event, xlsx_bytes, pdf_bytes, log)

        # Step 8 — build AssessmentSummary and persist AssessmentReport.
        summary = AssessmentSummary(
            assessment_id=event.assessment_id,
            tenant_id=event.tenant_id,
            total_resources=aggregated.total_resources,
            total_findings=aggregated.total_findings,
            findings_by_severity=aggregated.findings_by_severity,
            findings_by_pillar={
                p: s.total_findings for p, s in aggregated.findings_by_pillar.items()
            },
            coverage_percentage=aggregated.coverage_percentage,
        )
        report = AssessmentReport(
            id=uuid.uuid4(),
            assessment_id=event.assessment_id,
            tenant_id=event.tenant_id,
            xlsx_blob_path=xlsx_path,
            pdf_blob_path=pdf_path,
            summary=summary,
            generated_at=aggregated.generated_at,
        )
        await self._report_repo.create(report)
        log.info("reporting.handler.report_persisted", report_id=str(report.id))

        # Step 9 — transition assessment to COMPLETED.
        await self._assessment_repo.update_status(
            event.tenant_id,
            event.assessment_id,
            AssessmentStatus.COMPLETED,
        )
        log.info("reporting.handler.assessment_completed")

        # Step 10 — deliver webhook (non-fatal).
        await self._deliver_webhook(event, report, aggregated, log)

    async def _fetch_all_findings(
        self,
        event: ReportingRequestedEvent,
        log: StructuredLogger,
    ) -> list[Finding]:
        findings = []
        cursor: uuid.UUID | None = None
        while len(findings) < _MAX_FINDINGS:
            page = await self._finding_repo.list_by_assessment(
                tenant_id=event.tenant_id,
                assessment_id=event.assessment_id,
                limit=_FINDINGS_PAGE_SIZE,
                cursor=cursor,
            )
            if not page:
                break
            findings.extend(page)
            cursor = page[-1].id
            if len(page) < _FINDINGS_PAGE_SIZE:
                break

        log.info("reporting.handler.findings_loaded", count=len(findings))
        return findings

    async def _fetch_human_reviews(
        self,
        event: ReportingRequestedEvent,
        log: StructuredLogger,
    ) -> list[HumanReviewAssessment]:
        try:
            reviews = await self._human_review_repo.list_by_assessment(
                event.tenant_id, event.assessment_id
            )
            log.info("reporting.handler.human_reviews_loaded", count=len(reviews))
            return reviews
        except Exception:
            log.warning(
                "reporting.handler.human_reviews_fetch_failed",
                exc_info=True,
                fallback="empty_list",
            )
            return []

    async def _upload_or_fallback(
        self,
        event: ReportingRequestedEvent,
        xlsx_bytes: bytes,
        pdf_bytes: bytes,
        log: StructuredLogger,
    ) -> tuple[str, str]:
        """Try Blob Storage upload; on any failure save to /tmp and continue."""
        try:
            xlsx_path = await self._uploader.upload_report(
                tenant_id=event.tenant_id,
                assessment_id=event.assessment_id,
                data=xlsx_bytes,
                extension="xlsx",
                content_type=_XLSX_CONTENT_TYPE,
            )
            pdf_path = await self._uploader.upload_report(
                tenant_id=event.tenant_id,
                assessment_id=event.assessment_id,
                data=pdf_bytes,
                extension="pdf",
                content_type=_PDF_CONTENT_TYPE,
            )
            log.info("reporting.handler.uploaded", xlsx_path=xlsx_path, pdf_path=pdf_path)
            return xlsx_path, pdf_path
        except Exception:
            log.warning(
                "reporting.handler.blob_upload_failed",
                exc_info=True,
                assessment_id=str(event.assessment_id),
                fallback="local_filesystem",
            )
            return self._save_locally(event.assessment_id, xlsx_bytes, pdf_bytes, log)

    def _save_locally(
        self,
        assessment_id: uuid.UUID,
        xlsx_bytes: bytes,
        pdf_bytes: bytes,
        log: StructuredLogger,
    ) -> tuple[str, str]:
        """Write reports to /tmp/reports/{assessment_id}/ and return the paths.

        WARNING: This is a DEGRADED path.  Local paths are ephemeral in
        containerised environments.  If the pod restarts, the files are gone
        while the DB record still contains the local path, making the report
        undownloadable.  The blob upload failure MUST be investigated and
        resolved; this fallback only prevents the assessment from being stuck
        in REPORTING indefinitely during a transient storage outage.
        """
        report_dir = _LOCAL_REPORTS_DIR / str(assessment_id)
        report_dir.mkdir(parents=True, exist_ok=True)
        xlsx_local = report_dir / "report.xlsx"
        pdf_local = report_dir / "report.pdf"
        xlsx_local.write_bytes(xlsx_bytes)
        pdf_local.write_bytes(pdf_bytes)
        log.warning(
            "reporting.handler.reports_saved_locally",
            xlsx_path=str(xlsx_local),
            pdf_path=str(pdf_local),
            degraded=True,
            action_required="Blob upload failed — local paths do not survive pod restart; "
            "investigate storage connectivity and re-trigger reporting if needed.",
        )
        return str(xlsx_local), str(pdf_local)

    async def _deliver_webhook(
        self,
        event: ReportingRequestedEvent,
        report: AssessmentReport,
        aggregated: AggregatedReport,
        log: StructuredLogger,
    ) -> None:
        endpoint = await self._webhook_repo.get_endpoint_by_tenant(event.tenant_id)
        if endpoint is None:
            log.debug("reporting.handler.no_webhook_configured")
            return

        try:
            secret_str = await self._kv_client.get_secret(endpoint.secret_kv_name)
            webhook_secret = secret_str.encode("utf-8")
        except Exception:
            log.error(
                "reporting.handler.webhook_secret_fetch_failed",
                exc_info=True,
                secret_kv_name=endpoint.secret_kv_name,
            )
            return

        payload = {
            "assessment_id": str(event.assessment_id),
            "tenant_id": str(event.tenant_id),
            "status": "completed",
            "total_findings": aggregated.total_findings,
            "compliance_score": aggregated.overall_compliance_score,
            "risk_score": aggregated.overall_risk_score,
            "report_xlsx_path": report.xlsx_blob_path,
            "report_pdf_path": report.pdf_blob_path,
            "generated_at": aggregated.generated_at.isoformat(),
        }

        try:
            await self._webhook_service.deliver(
                tenant_id=event.tenant_id,
                assessment_id=event.assessment_id,
                webhook_url=endpoint.webhook_url,
                webhook_secret=webhook_secret,
                payload=payload,
            )
        except WebhookDeliveryError as exc:
            log.error(
                "reporting.handler.webhook_delivery_failed",
                webhook_url=endpoint.webhook_url,
                attempts=exc.attempts,
            )
