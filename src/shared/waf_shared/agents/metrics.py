"""OTel metric instruments for the agent framework."""

from __future__ import annotations

from opentelemetry import metrics

_METER_NAME = "com.wafagent.agents"


class AgentMetrics:
    """Singleton container for all agent framework metric instruments."""

    def __init__(self) -> None:
        meter = metrics.get_meter(_METER_NAME)

        self.agent_executions = meter.create_counter(
            name="waf.agent.executions",
            description="Total agent execution attempts (includes retries)",
            unit="1",
        )
        self.agent_errors = meter.create_counter(
            name="waf.agent.errors",
            description="Total agent execution errors (terminal failures only)",
            unit="1",
        )
        self.agent_retries = meter.create_counter(
            name="waf.agent.retries",
            description="Total retry attempts across all agents",
            unit="1",
        )
        self.agent_duration = meter.create_histogram(
            name="waf.agent.duration",
            description="Agent execution duration per attempt",
            unit="s",
        )
        self.pipeline_executions = meter.create_counter(
            name="waf.pipeline.executions",
            description="Total pipeline runs started",
            unit="1",
        )
        self.pipeline_errors = meter.create_counter(
            name="waf.pipeline.errors",
            description="Total pipeline runs that ended in FAILED state",
            unit="1",
        )
        self.pipeline_duration = meter.create_histogram(
            name="waf.pipeline.duration",
            description="End-to-end pipeline execution duration",
            unit="s",
        )
        self.workflow_executions = meter.create_counter(
            name="waf.workflow.executions",
            description="Total workflows started",
            unit="1",
        )
        self.workflow_completions = meter.create_counter(
            name="waf.workflow.completions",
            description="Total workflows that reached a terminal state",
            unit="1",
        )
        self.workflow_duration = meter.create_histogram(
            name="waf.workflow.duration",
            description="End-to-end workflow duration",
            unit="s",
        )
