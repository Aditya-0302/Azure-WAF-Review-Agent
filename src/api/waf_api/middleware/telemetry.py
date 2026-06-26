"""OTel request tracing middleware — creates root span per HTTP request."""

from __future__ import annotations

import time
import uuid

from fastapi import Request, Response
from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from waf_shared.telemetry.logging import set_log_context

_tracer = trace.get_tracer("waf_api")


class TelemetryMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        span_name = f"{request.method} {request.url.path}"

        with _tracer.start_as_current_span(
            span_name,
            kind=SpanKind.SERVER,
        ) as span:
            span.set_attribute("http.method", request.method)
            span.set_attribute("http.url", str(request.url))
            span.set_attribute("http.request_id", request_id)

            if hasattr(request.state, "auth"):
                tenant_id = str(request.state.auth.tenant_id)
                span.set_attribute("waf.tenant_id", tenant_id)
                set_log_context(tenant_id=tenant_id)

            start = time.perf_counter()
            try:
                response: Response = await call_next(request)
                duration_ms = (time.perf_counter() - start) * 1000

                span.set_attribute("http.status_code", response.status_code)
                span.set_attribute("http.duration_ms", duration_ms)

                if response.status_code >= 500:  # noqa: PLR2004
                    span.set_status(StatusCode.ERROR)

                response.headers["X-Request-ID"] = request_id
                return response

            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise
