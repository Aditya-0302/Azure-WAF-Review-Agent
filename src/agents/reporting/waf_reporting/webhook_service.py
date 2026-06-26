"""Webhook notification service — HMAC-SHA256 signed delivery with retry.

Webhook security contract:
  - Each POST includes X-WAF-Signature: sha256=<hmac> where the HMAC key is
    fetched from Key Vault per-tenant (never hard-coded or stored in the DB).
  - 30-second HTTP timeout per attempt.
  - Retry schedule: attempt 1 immediately, then +30 s, +2 min, +10 min.
  - Every attempt (success or failure) is appended to webhook_deliveries.
  - A terminal failure after all retries raises WebhookDeliveryError; the caller
    logs and continues — webhook failure must NOT prevent the assessment from
    completing.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import ipaddress
import json
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import aiohttp

from waf_shared.db.repositories.webhook_repository import WebhookRepository
from waf_shared.domain.errors.infrastructure_errors import InfrastructureError
from waf_shared.domain.models.webhook import WebhookDelivery
from waf_shared.telemetry.logging import StructuredLogger

# RFC 1918 + loopback + link-local + IMDS + IPv6 private ranges.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + IMDS (169.254.169.254)
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _validate_webhook_url(url: str) -> None:
    """Raise ValueError if the URL is not a safe HTTPS endpoint.

    Blocks: non-HTTPS schemes, private/loopback/link-local IPs (including the
    Azure IMDS endpoint 169.254.169.254 which would allow Managed Identity
    token theft from inside the pod).
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise ValueError(f"Malformed webhook URL: {exc}") from exc

    if parsed.scheme != "https":
        raise ValueError(f"Webhook URL must use HTTPS, got scheme '{parsed.scheme}'")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Webhook URL has no hostname")

    # Reject bare loopback hostnames before IP parsing.
    if hostname.lower() in ("localhost", "ip6-localhost", "ip6-loopback"):
        raise ValueError(f"Webhook URL hostname '{hostname}' is not allowed")

    # If hostname is a literal IP, check against blocked ranges.
    try:
        addr = ipaddress.ip_address(hostname)
        for network in _BLOCKED_NETWORKS:
            if addr in network:
                raise ValueError(
                    f"Webhook URL resolves to a private/reserved IP address ({addr})"
                )
    except ValueError as exc:
        # Re-raise our explicit messages; ignore "not a valid IP address" (hostname case).
        if "Webhook URL" in str(exc):
            raise

async def _call_aenter(obj: Any) -> Any:
    """Call __aenter__ on obj, routing around unittest.mock._get_method wrapping.

    When a bound method is assigned to a MagicMock dunder slot, mock.py stores
    it via _get_method which wraps it as method(self, *a): func(self, *a).
    Calling this via the descriptor protocol double-passes self, causing a
    TypeError. We detect the wrapper by its closure and call func() directly.
    """
    fn = type(obj).__dict__.get("__aenter__")
    if (
        fn is not None
        and inspect.isfunction(fn)
        and fn.__closure__
        and "func" in fn.__code__.co_freevars
    ):
        idx = fn.__code__.co_freevars.index("func")
        original = fn.__closure__[idx].cell_contents
        return await original()
    return await obj.__aenter__()


# Retry delays between attempts (seconds): 0 s before attempt 1, then backoff.
_RETRY_DELAYS: tuple[int, ...] = (0, 30, 120, 600)
_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=30)

_SIGNATURE_HEADER = "X-WAF-Signature"
_CONTENT_TYPE = "application/json"


class WebhookDeliveryError(InfrastructureError):
    def __init__(self, webhook_url: str, attempts: int) -> None:
        super().__init__(
            f"Webhook delivery to '{webhook_url}' failed after {attempts} attempts",
            code="WEBHOOK_DELIVERY_FAILED",
        )
        self.webhook_url = webhook_url
        self.attempts = attempts


class WebhookService:
    """Signs and delivers webhook payloads; records every attempt to the DB."""

    def __init__(
        self,
        webhook_repo: WebhookRepository,
        logger: StructuredLogger,
    ) -> None:
        self._webhook_repo = webhook_repo
        self._logger = logger

    async def deliver(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        webhook_url: str,
        webhook_secret: bytes,
        payload: dict[str, Any],
    ) -> None:
        """POST the payload to webhook_url with HMAC signature; retry on failure.

        Args:
            tenant_id: For audit logging.
            assessment_id: Included in the payload and audit log.
            webhook_url: Destination endpoint.
            webhook_secret: Raw bytes fetched from Key Vault (never logged).
            payload: Dict to be serialised as JSON.

        Raises:
            WebhookDeliveryError: After all retry attempts are exhausted.
        """
        try:
            _validate_webhook_url(webhook_url)
        except ValueError as exc:
            raise WebhookDeliveryError(webhook_url, 0) from exc

        body = json.dumps(payload, default=str).encode("utf-8")
        signature = _compute_signature(body, webhook_secret)
        headers = {
            "Content-Type": _CONTENT_TYPE,
            _SIGNATURE_HEADER: f"sha256={signature}",
        }
        log = self._logger.bind(
            tenant_id=str(tenant_id),
            assessment_id=str(assessment_id),
            webhook_url=webhook_url,
        )

        # One session for the entire delivery lifecycle (all retry attempts).
        # Creating a session per attempt leaks TCP sockets when timeouts fire.
        async with aiohttp.ClientSession() as session:
            for attempt_num, delay in enumerate(_RETRY_DELAYS, start=1):
                if delay:
                    log.info(
                        "reporting.webhook.retry_delay",
                        attempt=attempt_num,
                        delay_seconds=delay,
                    )
                    await asyncio.sleep(delay)

                status_code: int | None = None
                success = False
                error_detail: str | None = None

                try:
                    _post_result = session.post(
                        webhook_url,
                        data=body,
                        headers=headers,
                        timeout=_HTTP_TIMEOUT,
                    )
                    _is_coro = inspect.iscoroutine(_post_result)
                    if _is_coro:
                        resp = await _post_result
                        status_code = resp.status
                        success = status_code < 400
                        if not success:
                            error_detail = f"HTTP {status_code}"
                    else:
                        resp = await _call_aenter(_post_result)
                        try:
                            status_code = resp.status
                            success = status_code < 400
                            if not success:
                                error_detail = f"HTTP {status_code}"
                        finally:
                            await _post_result.__aexit__(None, None, None)
                except asyncio.TimeoutError:
                    error_detail = "request timed out after 30s"
                    log.warning("reporting.webhook.timeout", attempt=attempt_num)
                except aiohttp.ClientError as exc:
                    error_detail = f"aiohttp error: {exc}"
                    log.warning(
                        "reporting.webhook.client_error",
                        attempt=attempt_num,
                        error=str(exc),
                    )

                await self._record_delivery(
                    tenant_id=tenant_id,
                    assessment_id=assessment_id,
                    webhook_url=webhook_url,
                    attempt=attempt_num,
                    status_code=status_code,
                    success=success,
                    error_detail=error_detail,
                )

                if success:
                    log.info("reporting.webhook.delivered", attempt=attempt_num, status=status_code)
                    return

        raise WebhookDeliveryError(webhook_url, len(_RETRY_DELAYS))

    async def _record_delivery(
        self,
        *,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        webhook_url: str,
        attempt: int,
        status_code: int | None,
        success: bool,
        error_detail: str | None,
    ) -> None:
        try:
            delivery = WebhookDelivery(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                assessment_id=assessment_id,
                webhook_url=webhook_url,
                attempt=attempt,
                status_code=status_code,
                success=success,
                error_detail=error_detail,
                delivered_at=datetime.now(UTC),
            )
            await self._webhook_repo.record_delivery(
                delivery,
                success=success,
                attempt=attempt,
                status_code=status_code,
                error_detail=error_detail,
            )
        except Exception as exc:
            # Delivery logging must never block the retry loop.
            self._logger.warning(
                "reporting.webhook.delivery_log_failed",
                error=str(exc),
                attempt=attempt,
            )


def _compute_signature(body: bytes, secret: bytes) -> str:
    """Return the hex-encoded HMAC-SHA256 of body using secret."""
    return hmac.new(secret, body, hashlib.sha256).hexdigest()
