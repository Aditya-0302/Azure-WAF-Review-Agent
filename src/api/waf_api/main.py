"""FastAPI application entrypoint.

Lifecycle:
  startup  → configure telemetry → connect DB pool → wire DI container
  shutdown → disconnect DB pool

Exception handlers are registered here so routers never catch exceptions
and construct HTTP responses manually.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from dependency_injector import providers
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from waf_shared.domain.errors.application_errors import (
    ApplicationError,
    CancellationRequestedError,
    IdempotencyConflictError,
)
from waf_shared.domain.errors.domain_errors import (
    AssessmentNotFoundError,
    DSLValidationError,
    DomainError,
    HumanReviewControlNotFoundError,
    HumanReviewNotFoundError,
    InvalidAssessmentScopeError,
    QuotaExceededException,
    WafAgentError,
)
from waf_shared.domain.errors.infrastructure_errors import (
    AzureRateLimitError,
    CredentialUnavailableError,
    DatabaseError,
    InfrastructureError,
    LLMQuotaExhaustedError,
    LLMRateLimitError,
)
from waf_shared.messaging.service_bus import ServiceBusPublisher
from waf_shared.telemetry.logging import configure_structlog, get_logger
from waf_shared.telemetry.otel import configure_telemetry

from waf_api.config import AppEnvironment, Settings
from waf_api.container import Container
from waf_api.middleware.auth import AuthMiddleware
from waf_api.middleware.security_headers import SecurityHeadersMiddleware
from waf_api.middleware.telemetry import TelemetryMiddleware
from waf_api.routers import assessments, health, human_review, system
from waf_api.schemas.responses.error_response import ErrorDetail, ErrorResponse

_settings = Settings()
_logger = get_logger(service="waf-api", version=_settings.app_version)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    configure_structlog(json_output=_settings.is_production)

    configure_telemetry(
        service_name=_settings.otel_service_name,
        service_version=_settings.app_version,
        connection_string=(
            _settings.applicationinsights_connection_string.get_secret_value()
            if _settings.applicationinsights_connection_string
            else None
        ),
        enabled=_settings.otel_exporter_enabled,
    )

    container = Container()
    # Share the module-level Settings instance with the container so that
    # Settings() is called exactly once per process.  providers.Object wraps
    # a pre-created value; all downstream Singleton providers that reference
    # config.provided.xxx will resolve against this same instance.
    container.config.override(providers.Object(_settings))
    container.wire(
        modules=[
            "waf_api.dependencies.db",
            "waf_api.dependencies.rbac",
            "waf_api.dependencies.services",
            "waf_api.routers.health",
            "waf_api.routers.assessments",
            "waf_api.routers.human_review",
        ]
    )
    app.state.container = container

    db_pool = container.db_pool()
    await db_pool.connect()
    app.state.db_pool = db_pool

    if _settings.api_auth_mode == "development":
        from waf_api.dev_bootstrap import ensure_dev_tenant
        await ensure_dev_tenant(db_pool)

    # ── Service Bus publisher ────────────────────────────────────────────────
    if _settings.servicebus_connection_string:
        publisher = ServiceBusPublisher(
            connection_string=_settings.servicebus_connection_string.get_secret_value()
        )
    else:
        platform_credential = await container.platform_credential_provider().get_credential()
        publisher = ServiceBusPublisher(
            fully_qualified_namespace=_settings.servicebus_namespace,
            credential=platform_credential,
        )
    app.state.publisher = publisher

    if _settings.api_auth_mode == "development":
        _logger.warning(
            "api.startup.dev_auth_enabled",
            message="Development authentication enabled. "
                    "JWT validation is disabled. "
                    "Never deploy with API_AUTH_MODE=development.",
        )

    _logger.info("api.startup.complete", environment=_settings.app_env.value)

    yield

    await publisher.close()
    await db_pool.disconnect()
    _logger.info("api.shutdown.complete")


def _make_error_response(
    request: Request,
    code: str,
    message: str,
    status_code: int,
    detail: dict | None = None,
) -> JSONResponse:
    from opentelemetry import trace

    span = trace.get_current_span()
    ctx = span.get_span_context()
    trace_id = format(ctx.trace_id, "032x") if ctx.is_valid else ""
    request_id = request.headers.get("X-Request-ID", "")

    body = ErrorResponse(
        error=ErrorDetail(
            code=code,
            message=message,
            detail=detail,
            trace_id=trace_id,
            request_id=request_id,
        )
    )
    return JSONResponse(status_code=status_code, content=body.model_dump())


def create_app() -> FastAPI:
    app = FastAPI(
        title="WAF Review Agent API",
        version=_settings.app_version,
        docs_url="/docs" if _settings.app_env == AppEnvironment.DEVELOPMENT else None,
        redoc_url="/redoc" if _settings.app_env == AppEnvironment.DEVELOPMENT else None,
        openapi_url="/openapi.json" if _settings.app_env == AppEnvironment.DEVELOPMENT else None,
        lifespan=lifespan,
    )

    # ── Middleware (applied bottom-up: last-added = outermost) ───────────────
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(TelemetryMiddleware)
    app.add_middleware(AuthMiddleware, settings=_settings)

    # ── Routers ───────────────────────────────────────────────────────────────
    app.include_router(health.router)
    app.include_router(assessments.router)
    app.include_router(human_review.router)
    app.include_router(system.router)

    # ── Exception handlers ────────────────────────────────────────────────────
    @app.exception_handler(AssessmentNotFoundError)
    async def handle_not_found(request: Request, exc: AssessmentNotFoundError) -> JSONResponse:
        return _make_error_response(request, exc.code, exc.message, 404)

    @app.exception_handler(HumanReviewNotFoundError)
    async def handle_human_review_not_found(
        request: Request, exc: HumanReviewNotFoundError
    ) -> JSONResponse:
        return _make_error_response(request, exc.code, exc.message, 404)

    @app.exception_handler(HumanReviewControlNotFoundError)
    async def handle_human_review_control_not_found(
        request: Request, exc: HumanReviewControlNotFoundError
    ) -> JSONResponse:
        return _make_error_response(request, exc.code, exc.message, 404)

    @app.exception_handler(QuotaExceededException)
    async def handle_quota(request: Request, exc: QuotaExceededException) -> JSONResponse:
        return _make_error_response(
            request,
            exc.code,
            exc.message,
            429,
            detail={"quota_name": exc.quota_name, "limit": exc.limit, "current": exc.current},
        )

    @app.exception_handler(IdempotencyConflictError)
    async def handle_idempotency(
        request: Request, exc: IdempotencyConflictError
    ) -> JSONResponse:
        return _make_error_response(request, exc.code, exc.message, 409)

    @app.exception_handler(InvalidAssessmentScopeError)
    async def handle_invalid_scope(
        request: Request, exc: InvalidAssessmentScopeError
    ) -> JSONResponse:
        return _make_error_response(request, exc.code, exc.message, 422)

    @app.exception_handler(DSLValidationError)
    async def handle_dsl(request: Request, exc: DSLValidationError) -> JSONResponse:
        return _make_error_response(request, exc.code, exc.message, 422)

    @app.exception_handler(CancellationRequestedError)
    async def handle_cancellation(
        request: Request, exc: CancellationRequestedError
    ) -> JSONResponse:
        return _make_error_response(request, exc.code, exc.message, 409)

    @app.exception_handler(CredentialUnavailableError)
    async def handle_credential(
        request: Request, exc: CredentialUnavailableError
    ) -> JSONResponse:
        return _make_error_response(request, exc.code, "A required credential is temporarily unavailable", 503)

    @app.exception_handler(AzureRateLimitError)
    async def handle_azure_rate_limit(
        request: Request, exc: AzureRateLimitError
    ) -> JSONResponse:
        return _make_error_response(request, exc.code, "Azure service rate limit reached; try again later", 503)

    @app.exception_handler(LLMRateLimitError)
    async def handle_llm_rate_limit(
        request: Request, exc: LLMRateLimitError
    ) -> JSONResponse:
        return _make_error_response(request, exc.code, "LLM rate limit reached; try again later", 503)

    @app.exception_handler(LLMQuotaExhaustedError)
    async def handle_llm_quota(
        request: Request, exc: LLMQuotaExhaustedError
    ) -> JSONResponse:
        return _make_error_response(request, exc.code, "LLM monthly quota exhausted", 503)

    @app.exception_handler(DatabaseError)
    async def handle_db_error(request: Request, exc: DatabaseError) -> JSONResponse:
        _logger.error("db.error.unhandled", exc_info=True)
        return _make_error_response(request, "DATABASE_ERROR", "A database error occurred", 503)

    @app.exception_handler(InfrastructureError)
    async def handle_infra(request: Request, exc: InfrastructureError) -> JSONResponse:
        _logger.error("infrastructure.error.unhandled", exc_info=True)
        return _make_error_response(request, exc.code, "An infrastructure error occurred", 503)

    @app.exception_handler(DomainError)
    async def handle_domain(request: Request, exc: DomainError) -> JSONResponse:
        return _make_error_response(request, exc.code, exc.message, 400)

    @app.exception_handler(ApplicationError)
    async def handle_application(request: Request, exc: ApplicationError) -> JSONResponse:
        return _make_error_response(request, exc.code, exc.message, 400)

    @app.exception_handler(WafAgentError)
    async def handle_waf_base(request: Request, exc: WafAgentError) -> JSONResponse:
        _logger.error("error.unclassified", exc_info=True, error_code=exc.code)
        return _make_error_response(request, exc.code, "An unexpected error occurred", 500)

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        _logger.error("error.unexpected", exc_info=True)
        return _make_error_response(request, "INTERNAL_ERROR", "An unexpected error occurred", 500)

    return app


app = create_app()
