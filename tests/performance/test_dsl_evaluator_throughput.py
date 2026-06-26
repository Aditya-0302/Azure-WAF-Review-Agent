"""Performance tests for the DSL evaluator — throughput and latency.

These verify that deterministic rule evaluation stays well within the
latency budget so it never becomes a bottleneck in the reasoning agent.

Budget assumption (from architecture):
  - 500 resources × 60 rules = 30,000 evaluate_condition calls per batch
  - Must complete in < 1 second (=> ~30,000 evaluations/sec minimum)

Marked @pytest.mark.slow so they are excluded from the default fast suite.
"""

from __future__ import annotations

import time

import pytest
from waf_reasoning.dsl_evaluator import evaluate_condition

pytestmark = pytest.mark.slow


# ---------------------------------------------------------------------------
# Fixtures — representative WAF rule conditions
# ---------------------------------------------------------------------------

_SIMPLE_EQ = {"op": "eq", "path": "properties.sku.name", "value": "Standard"}

_COMPLEX_AND = {
    "op": "and",
    "conditions": [
        {"op": "exists", "path": "zones"},
        {"op": "length_gte", "path": "zones", "value": 2},
        {
            "op": "not",
            "condition": {"op": "eq", "path": "properties.enableRBAC", "value": False},
        },
    ],
}

_NESTED_ANY_MATCH = {
    "op": "any_match",
    "path": "properties.securityRules",
    "condition": {
        "op": "and",
        "conditions": [
            {"op": "eq", "path": "properties.destinationPortRange", "value": "22"},
            {"op": "eq", "path": "properties.sourceAddressPrefix", "value": "*"},
        ],
    },
}

_RULE_ID = "PERF-TEST-001"


def _sample_vm_properties() -> dict:
    return {
        "id": "/subscriptions/abc/rg/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
        "name": "vm1",
        "type": "Microsoft.Compute/virtualMachines",
        "location": "eastus",
        "zones": ["1", "2", "3"],
        "properties": {
            "sku": {"name": "Standard"},
            "enableRBAC": True,
            "securityRules": [
                {
                    "properties": {
                        "destinationPortRange": "80",
                        "sourceAddressPrefix": "10.0.0.0/8",
                        "access": "Allow",
                        "direction": "Inbound",
                    }
                }
            ],
        },
    }


# ---------------------------------------------------------------------------
# Throughput tests
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestDSLEvaluatorThroughput:
    def test_simple_eq_throughput(self) -> None:
        """Simple equality check must execute at > 100,000 evaluations/sec."""
        props = _sample_vm_properties()
        n = 100_000

        start = time.perf_counter()
        for _ in range(n):
            evaluate_condition(_RULE_ID, _SIMPLE_EQ, props)
        elapsed = time.perf_counter() - start

        rate = n / elapsed
        print(f"\neq throughput: {rate:,.0f} evals/sec ({elapsed:.3f}s for {n:,} evals)")
        assert rate >= 100_000, f"eq operator too slow: {rate:,.0f} evals/sec"

    def test_complex_and_throughput(self) -> None:
        """Complex AND with 3 sub-conditions must execute at > 30,000 evals/sec."""
        props = _sample_vm_properties()
        n = 30_000

        start = time.perf_counter()
        for _ in range(n):
            evaluate_condition(_RULE_ID, _COMPLEX_AND, props)
        elapsed = time.perf_counter() - start

        rate = n / elapsed
        print(f"\ncomplex AND throughput: {rate:,.0f} evals/sec ({elapsed:.3f}s)")
        assert rate >= 30_000, f"complex AND too slow: {rate:,.0f} evals/sec"

    def test_nested_any_match_throughput(self) -> None:
        """any_match over a list must execute at > 20,000 evals/sec."""
        props = _sample_vm_properties()
        n = 20_000

        start = time.perf_counter()
        for _ in range(n):
            evaluate_condition(_RULE_ID, _NESTED_ANY_MATCH, props)
        elapsed = time.perf_counter() - start

        rate = n / elapsed
        print(f"\nany_match throughput: {rate:,.0f} evals/sec ({elapsed:.3f}s)")
        assert rate >= 20_000, f"any_match too slow: {rate:,.0f} evals/sec"

    def test_full_batch_simulation(self) -> None:
        """Simulate 500 resources × 60 rules must complete in < 1 second."""
        props = _sample_vm_properties()
        conditions = [_SIMPLE_EQ, _COMPLEX_AND, _NESTED_ANY_MATCH]
        n_resources = 500
        n_rules = 60
        evaluations = n_resources * n_rules

        start = time.perf_counter()
        for _ in range(evaluations):
            cond = conditions[_ % len(conditions)]
            evaluate_condition(_RULE_ID, cond, props)
        elapsed = time.perf_counter() - start

        print(f"\nFull batch ({evaluations:,} evals): {elapsed:.3f}s")
        assert elapsed < 1.0, (
            f"Batch evaluation of {evaluations:,} conditions took {elapsed:.3f}s — "
            "must complete in < 1 second"
        )


# ---------------------------------------------------------------------------
# Latency tests — single-call P99
# ---------------------------------------------------------------------------


@pytest.mark.slow
class TestDSLEvaluatorLatency:
    def _measure_latencies(self, condition: dict, n: int = 1000) -> list[float]:
        props = _sample_vm_properties()
        latencies = []
        for _ in range(n):
            t0 = time.perf_counter()
            evaluate_condition(_RULE_ID, condition, props)
            latencies.append((time.perf_counter() - t0) * 1_000)  # ms
        return sorted(latencies)

    def test_simple_eq_p99_under_1ms(self) -> None:
        latencies = self._measure_latencies(_SIMPLE_EQ)
        p99_idx = int(0.99 * len(latencies))
        p99 = latencies[p99_idx]
        print(f"\neq p99: {p99:.3f}ms")
        assert p99 < 1.0, f"eq p99 latency {p99:.3f}ms exceeds 1ms"

    def test_complex_and_p99_under_5ms(self) -> None:
        latencies = self._measure_latencies(_COMPLEX_AND)
        p99_idx = int(0.99 * len(latencies))
        p99 = latencies[p99_idx]
        print(f"\ncomplex AND p99: {p99:.3f}ms")
        assert p99 < 5.0, f"complex AND p99 latency {p99:.3f}ms exceeds 5ms"

    def test_any_match_p99_under_10ms(self) -> None:
        latencies = self._measure_latencies(_NESTED_ANY_MATCH)
        p99_idx = int(0.99 * len(latencies))
        p99 = latencies[p99_idx]
        print(f"\nany_match p99: {p99:.3f}ms")
        assert p99 < 10.0, f"any_match p99 latency {p99:.3f}ms exceeds 10ms"
