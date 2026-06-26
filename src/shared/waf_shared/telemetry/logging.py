"""StructuredLogger — 10-field mandatory schema, automatic OTel context injection.

Direct use of Python logging or print() is forbidden in production code.
Always obtain a logger via get_logger() or StructuredLogger().
"""

from __future__ import annotations

import contextvars
import re
from typing import Any

import structlog
from opentelemetry import trace

_SENSITIVE_FIELD_PATTERN = re.compile(
    r"(?:secret|password|key|token|credential)", re.IGNORECASE
)
_SUBSCRIPTION_ID_PATTERN = re.compile(
    r"/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)
_SAS_QUERY_PATTERN = re.compile(r"\?sv=.*", re.IGNORECASE)

_ctx_tenant_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "log_tenant_id", default="system"
)
_ctx_assessment_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "log_assessment_id", default=None
)


def set_log_context(
    tenant_id: str | None = None,
    assessment_id: str | None = None,
) -> None:
    if tenant_id is not None:
        _ctx_tenant_id.set(tenant_id)
    if assessment_id is not None:
        _ctx_assessment_id.set(assessment_id)


def _scrub_value(key: str, value: Any) -> Any:
    if isinstance(value, str):
        if _SENSITIVE_FIELD_PATTERN.search(key):
            return "[REDACTED]"
        value = _SUBSCRIPTION_ID_PATTERN.sub("/subscriptions/[SUB-REDACTED]", value)
        value = _SAS_QUERY_PATTERN.sub("[SAS-REDACTED]", value)
    return value


def _scrub_event(
    _logger: Any,
    _method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    return {k: _scrub_value(k, v) for k, v in event_dict.items()}


def _inject_otel_context(
    _logger: Any,
    _method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if ctx.is_valid:
        event_dict["trace_id"] = format(ctx.trace_id, "032x")
        event_dict["span_id"] = format(ctx.span_id, "016x")
    else:
        event_dict.setdefault("trace_id", "")
        event_dict.setdefault("span_id", "")
    event_dict.setdefault("tenant_id", _ctx_tenant_id.get())
    event_dict.setdefault("assessment_id", _ctx_assessment_id.get())
    return event_dict


def configure_structlog(json_output: bool = True) -> None:
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _inject_otel_context,
        _scrub_event,
        # Render exc_info=True into a formatted "exception" string so the
        # actual traceback appears in JSON output rather than `{"exc_info": true}`.
        structlog.processors.ExceptionRenderer(),
    ]
    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(__import__("logging").INFO),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


class StructuredLogger:
    """Thin facade over structlog with mandatory 10-field schema enforcement."""

    def __init__(self, service: str, version: str) -> None:
        self._log = structlog.get_logger().bind(service=service, version=version)

    def debug(self, event: str, **kwargs: Any) -> None:
        self._log.debug(event, **kwargs)

    def info(self, event: str, **kwargs: Any) -> None:
        self._log.info(event, **kwargs)

    def warning(self, event: str, **kwargs: Any) -> None:
        self._log.warning(event, **kwargs)

    def error(self, event: str, exc_info: bool = False, **kwargs: Any) -> None:
        self._log.error(event, exc_info=exc_info, **kwargs)

    def critical(self, event: str, exc_info: bool = False, **kwargs: Any) -> None:
        self._log.critical(event, exc_info=exc_info, **kwargs)

    def bind(self, **kwargs: Any) -> "StructuredLogger":
        copy = object.__new__(StructuredLogger)
        copy._log = self._log.bind(**kwargs)  # noqa: SLF001
        return copy


def get_logger(service: str, version: str = "unknown") -> StructuredLogger:
    return StructuredLogger(service=service, version=version)
