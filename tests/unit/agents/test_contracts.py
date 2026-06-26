"""Unit tests for AgentContext, AgentInput, AgentOutput, AgentSuccess, AgentFailure."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from waf_shared.agents.contracts import (
    AgentContext,
    AgentFailure,
    AgentInput,
    AgentOutput,
    AgentSuccess,
)


@pytest.mark.unit
class TestAgentContext:
    def test_is_frozen(self) -> None:
        ctx = AgentContext(
            workflow_id=uuid.uuid4(),
            stage_name="test",
            tenant_id=uuid.uuid4(),
        )
        with pytest.raises((AttributeError, TypeError)):
            ctx.attempt = 5  # type: ignore[misc]

    def test_with_attempt_returns_new_instance(self) -> None:
        ctx = AgentContext(
            workflow_id=uuid.uuid4(),
            stage_name="prep",
            tenant_id=uuid.uuid4(),
            attempt=1,
        )
        updated = ctx.with_attempt(3)
        assert updated.attempt == 3
        assert ctx.attempt == 1
        assert updated is not ctx
        assert updated.workflow_id == ctx.workflow_id
        assert updated.stage_name == ctx.stage_name
        assert updated.tenant_id == ctx.tenant_id

    def test_is_expired_returns_false_when_no_deadline(self) -> None:
        ctx = AgentContext(
            workflow_id=uuid.uuid4(),
            stage_name="s",
            tenant_id=uuid.uuid4(),
        )
        assert ctx.is_expired is False

    def test_is_expired_returns_false_when_deadline_in_future(self) -> None:
        ctx = AgentContext(
            workflow_id=uuid.uuid4(),
            stage_name="s",
            tenant_id=uuid.uuid4(),
            deadline=datetime.now(UTC) + timedelta(minutes=5),
        )
        assert ctx.is_expired is False

    def test_is_expired_returns_true_when_deadline_passed(self) -> None:
        ctx = AgentContext(
            workflow_id=uuid.uuid4(),
            stage_name="s",
            tenant_id=uuid.uuid4(),
            deadline=datetime.now(UTC) - timedelta(seconds=1),
        )
        assert ctx.is_expired is True

    def test_correlation_id_defaults_to_unique_uuid(self) -> None:
        ctx1 = AgentContext(workflow_id=uuid.uuid4(), stage_name="s", tenant_id=uuid.uuid4())
        ctx2 = AgentContext(workflow_id=uuid.uuid4(), stage_name="s", tenant_id=uuid.uuid4())
        assert ctx1.correlation_id != ctx2.correlation_id

    def test_metadata_defaults_to_empty_dict(self) -> None:
        ctx = AgentContext(workflow_id=uuid.uuid4(), stage_name="s", tenant_id=uuid.uuid4())
        assert ctx.metadata == {}


@pytest.mark.unit
class TestAgentInput:
    def test_carries_payload_and_context(self) -> None:
        ctx = AgentContext(workflow_id=uuid.uuid4(), stage_name="s", tenant_id=uuid.uuid4())
        inp = AgentInput(payload={"data": 42}, context=ctx)
        assert inp.payload == {"data": 42}
        assert inp.context is ctx


@pytest.mark.unit
class TestAgentOutput:
    def test_fields_are_stored(self) -> None:
        out = AgentOutput(
            payload="result",
            agent_name="echo",
            agent_version="1.0.0",
            duration_ms=12.5,
            attempt=2,
        )
        assert out.payload == "result"
        assert out.agent_name == "echo"
        assert out.duration_ms == 12.5
        assert out.attempt == 2

    def test_metadata_defaults_to_empty(self) -> None:
        out = AgentOutput(
            payload=None,
            agent_name="x",
            agent_version="1",
            duration_ms=0.0,
            attempt=1,
        )
        assert out.metadata == {}


@pytest.mark.unit
class TestAgentSuccessAndFailure:
    def test_agent_success_wraps_output(self) -> None:
        out = AgentOutput(
            payload=99,
            agent_name="counter",
            agent_version="1.0",
            duration_ms=5.0,
            attempt=1,
        )
        success = AgentSuccess(output=out)
        assert success.output is out
        assert success.output.payload == 99

    def test_agent_failure_captures_error(self) -> None:
        exc = ValueError("transient")
        failure = AgentFailure(
            error=exc,
            agent_name="flaky",
            stage_name="step1",
            attempt=3,
            is_retryable=True,
        )
        assert failure.error is exc
        assert failure.is_retryable is True
        assert failure.attempt == 3
