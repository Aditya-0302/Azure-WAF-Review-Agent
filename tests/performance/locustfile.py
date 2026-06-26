"""Locust performance test suite for the WAF Review Agent API.

Usage:
  # Install: pip install locust
  # Headless run (CI):
  locust -f tests/performance/locustfile.py \
         --host http://localhost:8080 \
         --users 50 --spawn-rate 5 \
         --run-time 2m --headless \
         --csv tests/performance/results/run

Environment variables:
  PERF_BEARER_TOKEN   — A valid JWT for authentication
  PERF_SUBSCRIPTION_ID — UUID of the subscription used in test payloads

Scenarios:
  WafApiUser        — Representative production traffic mix
  AssessmentCreator — Create-only workload (measures creation throughput)
  FindingsFetcher   — Read-only workload (measures read scalability)
"""

from __future__ import annotations

import os
import random
import uuid
from typing import Any

from locust import HttpUser, between, events, task
from locust.contrib.fasthttp import FastHttpUser


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BEARER_TOKEN = os.getenv("PERF_BEARER_TOKEN", "test-bearer-token")
SUBSCRIPTION_ID = os.getenv("PERF_SUBSCRIPTION_ID", str(uuid.uuid4()))

_AUTH_HEADERS = {"Authorization": f"Bearer {BEARER_TOKEN}"}

_PILLARS = ["Security", "Reliability", "Cost Optimization", "Operational Excellence", "Performance"]

# Pre-created assessment IDs that the read tasks can use
_known_assessment_ids: list[str] = []


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _random_pillar_filter() -> list[str]:
    n = random.randint(1, 3)
    return random.sample(_PILLARS, n)


def _create_assessment(client: Any) -> str | None:
    with client.post(
        "/v1/assessments",
        json={
            "subscription_ids": [SUBSCRIPTION_ID],
            "pillar_filter": _random_pillar_filter(),
            "tag_filter": {},
        },
        headers=_AUTH_HEADERS,
        catch_response=True,
        name="/v1/assessments [POST]",
    ) as resp:
        if resp.status_code == 201:
            data = resp.json()
            aid = data.get("assessment_id")
            if aid:
                _known_assessment_ids.append(aid)
            return aid
        elif resp.status_code == 429:
            resp.success()  # Rate-limited — not a failure, mark as expected
            return None
        else:
            resp.failure(f"Unexpected {resp.status_code}")
            return None


# ---------------------------------------------------------------------------
# Mixed-traffic user — representative production load
# ---------------------------------------------------------------------------


class WafApiUser(HttpUser):
    """Simulates a realistic mix of API calls.

    Task weights reflect approximate production traffic:
      - Health checks:    3×  (monitoring probes every 10s)
      - Assessment GET:   5×  (polling for status updates)
      - Findings list:    3×  (dashboard loading)
      - Assessment POST:  1×  (actual new assessments are rare)
    """

    wait_time = between(1, 5)

    def on_start(self) -> None:
        # Pre-populate with a known assessment so GET tasks have something to query
        _create_assessment(self.client)

    @task(3)
    def health_check(self) -> None:
        self.client.get("/healthz", name="/healthz")

    @task(5)
    def get_assessment_status(self) -> None:
        if not _known_assessment_ids:
            return
        aid = random.choice(_known_assessment_ids)
        self.client.get(
            f"/v1/assessments/{aid}",
            headers=_AUTH_HEADERS,
            name="/v1/assessments/{id} [GET]",
        )

    @task(3)
    def list_findings(self) -> None:
        if not _known_assessment_ids:
            return
        aid = random.choice(_known_assessment_ids)
        self.client.get(
            f"/v1/assessments/{aid}/findings?page=1&page_size=25",
            headers=_AUTH_HEADERS,
            name="/v1/assessments/{id}/findings [GET]",
        )

    @task(1)
    def create_assessment(self) -> None:
        _create_assessment(self.client)

    @task(2)
    def list_assessments(self) -> None:
        self.client.get(
            "/v1/assessments?page=1&page_size=10",
            headers=_AUTH_HEADERS,
            name="/v1/assessments [GET]",
        )


# ---------------------------------------------------------------------------
# Create-only workload — throughput stress test
# ---------------------------------------------------------------------------


class AssessmentCreator(HttpUser):
    """Hammers the assessment creation endpoint to measure throughput ceiling."""

    wait_time = between(2, 10)

    @task
    def create_assessment(self) -> None:
        _create_assessment(self.client)


# ---------------------------------------------------------------------------
# Read-only workload — database read scalability
# ---------------------------------------------------------------------------


class FindingsFetcher(HttpUser):
    """Reads findings and assessment details in a tight loop to stress the DB read path."""

    wait_time = between(0.5, 2)

    def on_start(self) -> None:
        if not _known_assessment_ids:
            _create_assessment(self.client)

    @task(4)
    def get_findings_page_1(self) -> None:
        if not _known_assessment_ids:
            return
        aid = random.choice(_known_assessment_ids)
        self.client.get(
            f"/v1/assessments/{aid}/findings?page=1&page_size=50&severity=critical",
            headers=_AUTH_HEADERS,
            name="/v1/assessments/{id}/findings?sev=critical",
        )

    @task(2)
    def get_findings_page_2(self) -> None:
        if not _known_assessment_ids:
            return
        aid = random.choice(_known_assessment_ids)
        self.client.get(
            f"/v1/assessments/{aid}/findings?page=2&page_size=50",
            headers=_AUTH_HEADERS,
            name="/v1/assessments/{id}/findings [page2]",
        )

    @task(1)
    def get_assessment_detail(self) -> None:
        if not _known_assessment_ids:
            return
        aid = random.choice(_known_assessment_ids)
        self.client.get(
            f"/v1/assessments/{aid}",
            headers=_AUTH_HEADERS,
            name="/v1/assessments/{id} [GET]",
        )


# ---------------------------------------------------------------------------
# Unauth stress test — verify 401 rejection overhead is acceptable
# ---------------------------------------------------------------------------


class UnauthUser(HttpUser):
    """Sends unauthenticated requests to measure auth middleware overhead."""

    wait_time = between(0.1, 0.5)

    @task
    def unauthenticated_get(self) -> None:
        with self.client.get(
            "/v1/assessments",
            catch_response=True,
            name="/v1/assessments [unauth]",
        ) as resp:
            if resp.status_code == 401:
                resp.success()  # 401 is the expected outcome — not a failure
            else:
                resp.failure(f"Expected 401, got {resp.status_code}")


# ---------------------------------------------------------------------------
# SLO assertions (executed at end of run via event)
# ---------------------------------------------------------------------------


@events.quitting.add_listener
def _assert_slos(environment: Any, **_: Any) -> None:
    """Assert performance SLOs are met.

    Targets:
      - p95 response time ≤ 500ms for GET endpoints
      - p99 response time ≤ 2000ms for POST /assessments
      - Error rate ≤ 1%
    """
    stats = environment.stats

    # Overall error rate
    total = sum(s.num_requests for s in stats.entries.values())
    failures = sum(s.num_failures for s in stats.entries.values())
    if total > 0:
        error_rate = failures / total
        if error_rate > 0.01:
            print(f"SLO VIOLATION: Error rate {error_rate:.1%} exceeds 1% threshold")
            environment.process_exit_code = 1

    # p95 for health endpoint
    health_stats = stats.get("/healthz", "GET")
    if health_stats and health_stats.get_response_time_percentile(0.95) > 200:
        print("SLO VIOLATION: /healthz p95 > 200ms")
        environment.process_exit_code = 1

    # p95 for assessment GET
    for name in stats.entries:
        if "/v1/assessments/{id} [GET]" in str(name):
            entry_stats = stats.entries[name]
            p95 = entry_stats.get_response_time_percentile(0.95)
            if p95 > 500:
                print(f"SLO VIOLATION: Assessment GET p95 {p95}ms > 500ms")
                environment.process_exit_code = 1
