"""Unit tests for AgentState, StageState, WorkflowState, WorkflowCheckpoint."""

from __future__ import annotations

import uuid

import pytest

from waf_shared.agents.state import (
    AgentState,
    StageState,
    WorkflowCheckpoint,
    WorkflowState,
)


@pytest.mark.unit
class TestAgentState:
    def test_terminal_states(self) -> None:
        assert AgentState.COMPLETED.is_terminal is True
        assert AgentState.FAILED.is_terminal is True
        assert AgentState.CANCELLED.is_terminal is True

    def test_non_terminal_states(self) -> None:
        assert AgentState.IDLE.is_terminal is False
        assert AgentState.RUNNING.is_terminal is False
        assert AgentState.PAUSED.is_terminal is False


@pytest.mark.unit
class TestStageState:
    def test_pending_factory(self) -> None:
        s = StageState.pending("ingest")
        assert s.stage_name == "ingest"
        assert s.state == AgentState.IDLE
        assert s.attempt == 0
        assert s.started_at is None

    def test_running_factory(self) -> None:
        s = StageState.running("ingest", attempt=2)
        assert s.state == AgentState.RUNNING
        assert s.attempt == 2
        assert s.started_at is not None

    def test_complete_transition(self) -> None:
        s = StageState.running("ingest", attempt=1).complete(duration_ms=123.4)
        assert s.state == AgentState.COMPLETED
        assert s.duration_ms == 123.4
        assert s.completed_at is not None
        assert s.error_code is None

    def test_fail_transition(self) -> None:
        s = StageState.running("ingest", attempt=1).fail(
            error_code="AGENT_TIMEOUT", error_message="timed out"
        )
        assert s.state == AgentState.FAILED
        assert s.error_code == "AGENT_TIMEOUT"
        assert s.error_message == "timed out"

    def test_immutability(self) -> None:
        s = StageState.pending("x")
        with pytest.raises((AttributeError, TypeError)):
            s.state = AgentState.COMPLETED  # type: ignore[misc]


@pytest.mark.unit
class TestWorkflowState:
    def _make(self) -> WorkflowState:
        return WorkflowState(
            workflow_id=uuid.uuid4(),
            pipeline_name="waf-pipeline",
            state=AgentState.IDLE,
        )

    def test_is_terminal_false_for_idle(self) -> None:
        assert self._make().is_terminal is False

    def test_is_terminal_true_for_completed(self) -> None:
        w = self._make().with_state(AgentState.COMPLETED)
        assert w.is_terminal is True

    def test_with_state_returns_new_instance(self) -> None:
        original = self._make()
        updated = original.with_state(AgentState.RUNNING)
        assert updated.state == AgentState.RUNNING
        assert original.state == AgentState.IDLE
        assert updated is not original

    def test_with_stage_adds_entry(self) -> None:
        w = self._make()
        stage = StageState.pending("step-1")
        updated = w.with_stage(stage)
        assert "step-1" in updated.stages
        assert "step-1" not in w.stages

    def test_with_stage_replaces_existing(self) -> None:
        w = self._make().with_stage(StageState.pending("s"))
        completed = StageState.running("s", attempt=1).complete(42.0)
        updated = w.with_stage(completed)
        assert updated.stages["s"].state == AgentState.COMPLETED

    def test_with_metadata_adds_key(self) -> None:
        w = self._make().with_metadata("batch_count", 5)
        assert w.metadata["batch_count"] == 5

    def test_updated_at_advances_on_mutation(self) -> None:
        original = self._make()
        updated = original.with_state(AgentState.RUNNING)
        assert updated.updated_at >= original.updated_at


@pytest.mark.unit
class TestWorkflowCheckpoint:
    def test_round_trip_json(self) -> None:
        wid = uuid.uuid4()
        cp = WorkflowCheckpoint(
            workflow_id=wid,
            pipeline_name="p",
            completed_stages=["a", "b"],
            current_stage="c",
            intermediate_results={"count": 3},
        )
        restored = WorkflowCheckpoint.from_json(cp.to_json())
        assert restored.workflow_id == wid
        assert restored.completed_stages == ["a", "b"]
        assert restored.current_stage == "c"
        assert restored.intermediate_results == {"count": 3}

    def test_defaults_to_empty_lists(self) -> None:
        cp = WorkflowCheckpoint(workflow_id=uuid.uuid4(), pipeline_name="p")
        assert cp.completed_stages == []
        assert cp.current_stage is None
        assert cp.intermediate_results == {}
