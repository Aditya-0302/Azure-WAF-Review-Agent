"""Unit tests for WebhookService — SSRF validation, HMAC signing, retry logic.

All HTTP calls are mocked via aiohttp patching so no network I/O occurs.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from waf_reporting.webhook_service import (
    WebhookDeliveryError,
    WebhookService,
    _compute_signature,
    _validate_webhook_url,
)
from waf_shared.db.repositories.webhook_repository import WebhookRepository
from waf_shared.telemetry.logging import StructuredLogger


# ---------------------------------------------------------------------------
# _validate_webhook_url — SSRF prevention
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestValidateWebhookUrl:
    # ── Must pass ─────────────────────────────────────────────────────────────

    def test_valid_https_public_hostname(self) -> None:
        _validate_webhook_url("https://hooks.example.com/waf")

    def test_valid_https_with_path_and_query(self) -> None:
        _validate_webhook_url("https://api.example.com/webhook?token=abc&v=2")

    def test_valid_https_ip_public(self) -> None:
        # 8.8.8.8 is a public IP — should be allowed
        _validate_webhook_url("https://8.8.8.8/webhook")

    def test_valid_https_ipv6_public(self) -> None:
        _validate_webhook_url("https://[2001:db8::1]/webhook")

    # ── Must reject — non-HTTPS ───────────────────────────────────────────────

    def test_rejects_http_scheme(self) -> None:
        with pytest.raises(ValueError, match="HTTPS"):
            _validate_webhook_url("http://example.com/webhook")

    def test_rejects_ftp_scheme(self) -> None:
        with pytest.raises(ValueError, match="HTTPS"):
            _validate_webhook_url("ftp://example.com/webhook")

    def test_rejects_no_scheme(self) -> None:
        with pytest.raises(ValueError):
            _validate_webhook_url("example.com/webhook")

    # ── Must reject — loopback hostnames ─────────────────────────────────────

    def test_rejects_localhost(self) -> None:
        with pytest.raises(ValueError, match="not allowed"):
            _validate_webhook_url("https://localhost/webhook")

    def test_rejects_ip6_localhost(self) -> None:
        with pytest.raises(ValueError, match="not allowed"):
            _validate_webhook_url("https://ip6-localhost/webhook")

    # ── Must reject — RFC 1918 private ranges ────────────────────────────────

    def test_rejects_10_x_x_x(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://10.0.0.1/webhook")

    def test_rejects_172_16_x_x(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://172.16.0.1/webhook")

    def test_rejects_172_31_x_x(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://172.31.255.255/webhook")

    def test_rejects_192_168_x_x(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://192.168.1.1/webhook")

    # ── Must reject — loopback IP ─────────────────────────────────────────────

    def test_rejects_127_0_0_1(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://127.0.0.1/webhook")

    def test_rejects_127_0_0_255(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://127.255.255.255/webhook")

    # ── Must reject — IMDS endpoint (critical security test) ─────────────────

    def test_rejects_azure_imds_169_254_169_254(self) -> None:
        """CRITICAL: must block the Azure IMDS endpoint to prevent token theft."""
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://169.254.169.254/metadata/identity/oauth2/token")

    def test_rejects_link_local_range(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://169.254.0.1/webhook")

    # ── Must reject — IPv6 private ────────────────────────────────────────────

    def test_rejects_ipv6_loopback(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://[::1]/webhook")

    def test_rejects_ipv6_ula(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://[fc00::1]/webhook")

    def test_rejects_ipv6_link_local(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_webhook_url("https://[fe80::1]/webhook")

    def test_rejects_missing_hostname(self) -> None:
        with pytest.raises(ValueError, match="no hostname"):
            _validate_webhook_url("https:///path")


# ---------------------------------------------------------------------------
# _compute_signature
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestComputeSignature:
    def test_produces_hex_string(self) -> None:
        sig = _compute_signature(b"hello", b"secret")
        assert all(c in "0123456789abcdef" for c in sig)
        assert len(sig) == 64  # SHA-256 → 32 bytes → 64 hex chars

    def test_deterministic(self) -> None:
        body = b'{"key": "value"}'
        secret = b"my-hmac-secret"
        assert _compute_signature(body, secret) == _compute_signature(body, secret)

    def test_different_secrets_differ(self) -> None:
        body = b"payload"
        assert _compute_signature(body, b"secret1") != _compute_signature(body, b"secret2")

    def test_different_bodies_differ(self) -> None:
        secret = b"secret"
        assert _compute_signature(b"body1", secret) != _compute_signature(b"body2", secret)

    def test_matches_reference_implementation(self) -> None:
        body = b"test body"
        secret = b"test secret"
        expected = hmac.new(secret, body, hashlib.sha256).hexdigest()
        assert _compute_signature(body, secret) == expected

    def test_empty_body(self) -> None:
        sig = _compute_signature(b"", b"secret")
        assert len(sig) == 64


# ---------------------------------------------------------------------------
# WebhookService.deliver — success path
# ---------------------------------------------------------------------------


def _make_service() -> tuple[WebhookService, MagicMock, MagicMock]:
    repo = AsyncMock(spec=WebhookRepository)
    repo.record_delivery = AsyncMock(return_value=None)
    logger = MagicMock(spec=StructuredLogger)
    logger.bind = MagicMock(return_value=logger)
    logger.info = MagicMock()
    logger.warning = MagicMock()
    logger.error = MagicMock()
    return WebhookService(webhook_repo=repo, logger=logger), repo, logger


def _make_session_mock(status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    resp.status = status_code

    post_ctx = MagicMock()
    post_ctx.__aenter__ = AsyncMock(return_value=resp)
    post_ctx.__aexit__ = AsyncMock(return_value=False)

    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session.post = MagicMock(return_value=post_ctx)
    return session


@pytest.mark.unit
class TestWebhookServiceDeliver:
    async def test_successful_delivery_on_first_attempt(self) -> None:
        service, repo, _ = _make_service()
        session = _make_session_mock(200)

        with patch("waf_reporting.webhook_service.aiohttp.ClientSession", return_value=session):
            await service.deliver(
                tenant_id=uuid.uuid4(),
                assessment_id=uuid.uuid4(),
                webhook_url="https://example.com/wh",
                webhook_secret=b"secret",
                payload={"status": "completed"},
            )

        repo.record_delivery.assert_called_once()
        call_kwargs = repo.record_delivery.call_args[1]
        assert call_kwargs["success"] is True
        assert call_kwargs["attempt"] == 1

    async def test_invalid_url_raises_webhook_delivery_error(self) -> None:
        service, repo, _ = _make_service()

        with pytest.raises(WebhookDeliveryError):
            await service.deliver(
                tenant_id=uuid.uuid4(),
                assessment_id=uuid.uuid4(),
                webhook_url="http://example.com/wh",  # HTTP not HTTPS
                webhook_secret=b"secret",
                payload={},
            )

        repo.record_delivery.assert_not_called()

    async def test_ssrf_url_raises_webhook_delivery_error(self) -> None:
        service, repo, _ = _make_service()

        with pytest.raises(WebhookDeliveryError):
            await service.deliver(
                tenant_id=uuid.uuid4(),
                assessment_id=uuid.uuid4(),
                webhook_url="https://169.254.169.254/metadata/identity/oauth2/token",
                webhook_secret=b"secret",
                payload={},
            )

    async def test_request_includes_hmac_signature_header(self) -> None:
        service, repo, _ = _make_service()
        session = _make_session_mock(200)

        payload = {"status": "completed", "assessment_id": "abc"}
        secret = b"test-secret"

        with patch("waf_reporting.webhook_service.aiohttp.ClientSession", return_value=session):
            await service.deliver(
                tenant_id=uuid.uuid4(),
                assessment_id=uuid.uuid4(),
                webhook_url="https://example.com/wh",
                webhook_secret=secret,
                payload=payload,
            )

        call_kwargs = session.post.call_args[1]
        headers = call_kwargs["headers"]
        assert "X-WAF-Signature" in headers

        # Verify the HMAC is correct
        body = call_kwargs["data"]
        expected_sig = "sha256=" + _compute_signature(body, secret)
        assert headers["X-WAF-Signature"] == expected_sig

    async def test_http_4xx_records_failure(self) -> None:
        service, repo, _ = _make_service()
        # All 4 attempts return 400
        sessions = [_make_session_mock(400) for _ in range(4)]
        session_iter = iter(sessions)

        with (
            patch("waf_reporting.webhook_service.aiohttp.ClientSession", side_effect=lambda: next(session_iter)),
            patch("waf_reporting.webhook_service.asyncio.sleep", new=AsyncMock()),
        ):
            with pytest.raises(WebhookDeliveryError):
                await service.deliver(
                    tenant_id=uuid.uuid4(),
                    assessment_id=uuid.uuid4(),
                    webhook_url="https://example.com/wh",
                    webhook_secret=b"secret",
                    payload={},
                )

        # All 4 attempts recorded
        assert repo.record_delivery.call_count == 4
        for call in repo.record_delivery.call_args_list:
            assert call[1]["success"] is False

    async def test_session_scoped_to_all_attempts(self) -> None:
        """Verify a single ClientSession is used across the retry loop."""
        service, _, _ = _make_service()
        session = _make_session_mock(200)
        session_count = {"n": 0}
        original_class = session.__class__

        def _count_sessions():
            session_count["n"] += 1
            return session

        with patch("waf_reporting.webhook_service.aiohttp.ClientSession", side_effect=_count_sessions):
            await service.deliver(
                tenant_id=uuid.uuid4(),
                assessment_id=uuid.uuid4(),
                webhook_url="https://example.com/wh",
                webhook_secret=b"secret",
                payload={},
            )

        # Only one ClientSession should have been created
        assert session_count["n"] == 1

    async def test_delivery_log_failure_does_not_block_retry(self) -> None:
        """DB failure in record_delivery must not abort the delivery loop."""
        service, repo, _ = _make_service()
        repo.record_delivery = AsyncMock(side_effect=Exception("DB down"))
        session = _make_session_mock(200)

        with patch("waf_reporting.webhook_service.aiohttp.ClientSession", return_value=session):
            # Should not raise even though record_delivery fails
            await service.deliver(
                tenant_id=uuid.uuid4(),
                assessment_id=uuid.uuid4(),
                webhook_url="https://example.com/wh",
                webhook_secret=b"secret",
                payload={},
            )

    async def test_retry_with_eventual_success(self) -> None:
        """First two attempts fail with 503, third succeeds with 200."""
        service, repo, _ = _make_service()

        attempt_count = {"n": 0}

        async def _fake_enter(self):
            attempt_count["n"] += 1
            resp = MagicMock()
            resp.status = 200 if attempt_count["n"] >= 3 else 503
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=False)
            return resp

        session = MagicMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=False)

        post_ctx = MagicMock()
        post_ctx.__aenter__ = _fake_enter.__get__(post_ctx, type(post_ctx))
        post_ctx.__aexit__ = AsyncMock(return_value=False)
        session.post = MagicMock(return_value=post_ctx)

        with (
            patch("waf_reporting.webhook_service.aiohttp.ClientSession", return_value=session),
            patch("waf_reporting.webhook_service.asyncio.sleep", new=AsyncMock()),
        ):
            await service.deliver(
                tenant_id=uuid.uuid4(),
                assessment_id=uuid.uuid4(),
                webhook_url="https://example.com/wh",
                webhook_secret=b"secret",
                payload={},
            )

        # 3 attempts recorded; last one is success
        assert repo.record_delivery.call_count == 3
        last_call = repo.record_delivery.call_args_list[-1][1]
        assert last_call["success"] is True
        assert last_call["attempt"] == 3


# ---------------------------------------------------------------------------
# WebhookDeliveryError
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestWebhookDeliveryError:
    def test_attributes(self) -> None:
        err = WebhookDeliveryError("https://example.com/wh", 4)
        assert err.webhook_url == "https://example.com/wh"
        assert err.attempts == 4
        assert "4 attempts" in str(err)
