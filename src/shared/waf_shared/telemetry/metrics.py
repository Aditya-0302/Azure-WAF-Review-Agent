"""Business metric instruments — 7 counters/histograms for WAF Agent operations."""

from __future__ import annotations

from opentelemetry import metrics

_METER_NAME = "com.wafagent"


class WafMetrics:
    """Singleton container for all business metric instruments."""

    def __init__(self) -> None:
        meter = metrics.get_meter(_METER_NAME)

        self.assessments_created = meter.create_counter(
            name="waf.assessments.created",
            description="Total assessments created",
            unit="1",
        )
        self.assessments_completed = meter.create_counter(
            name="waf.assessments.completed",
            description="Total assessments completed (terminal status)",
            unit="1",
        )
        self.findings_generated = meter.create_counter(
            name="waf.findings.generated",
            description="Total findings generated across all assessments",
            unit="1",
        )
        self.llm_tokens_used = meter.create_counter(
            name="waf.llm.tokens.used",
            description="Total tokens consumed by LLM calls",
            unit="1",
        )
        self.assessment_duration = meter.create_histogram(
            name="waf.assessment.duration",
            description="End-to-end assessment duration",
            unit="s",
        )
        self.batch_processing_duration = meter.create_histogram(
            name="waf.batch.processing.duration",
            description="Per-batch reasoning duration",
            unit="s",
        )
        self.quota_rejections = meter.create_counter(
            name="waf.quota.rejections",
            description="Total requests rejected due to quota limits",
            unit="1",
        )
