# syntax=docker/dockerfile:1.7
# Multi-stage: build → distroless runtime.
# The runtime image has no shell, no package manager, no root user.

# ── Stage 1: build ───────────────────────────────────────────────────────────
FROM python:3.12-bookworm AS build

WORKDIR /build

# Install build toolchain
RUN pip install --no-cache-dir hatchling==1.24.2

# Copy shared package first (better layer cache utilisation)
COPY src/shared/pyproject.toml src/shared/
COPY src/shared/waf_shared/ src/shared/waf_shared/
COPY src/shared/waf_catalog/ src/shared/waf_catalog/
RUN pip install --no-cache-dir --prefix=/install "src/shared/"

# Expose the prefix so pip can find waf-agent-shared when resolving
# consumer-package dependencies below (--prefix is not on sys.path by default).
ENV PYTHONPATH=/install/lib/python3.12/site-packages

# Copy API package
COPY src/api/pyproject.toml src/api/
COPY src/api/waf_api/ src/api/waf_api/
RUN pip install --no-cache-dir --prefix=/install "src/api/"

# ── Stage 2: development (uvicorn reload, debugger) ──────────────────────────
FROM python:3.12-slim-bookworm AS development

WORKDIR /app
COPY --from=build /install /usr/local

# Development extras
RUN pip install --no-cache-dir pytest pytest-asyncio httpx fakeredis

COPY src/ /app/src/
ENV PYTHONPATH=/app/src/shared:/app/src/api
USER nobody

EXPOSE 8000
CMD ["uvicorn", "waf_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ── Stage 3: production (distroless, no shell) ────────────────────────────────
FROM gcr.io/distroless/python3-debian12:nonroot AS production

WORKDIR /app
COPY --from=build /install/lib /usr/lib/python3/dist-packages
COPY --from=build /install/lib/python3.12/site-packages /usr/local/lib/python3.12/dist-packages

ENV PYTHONPATH=/usr/local/lib/python3.12/dist-packages
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

ENTRYPOINT ["python", "-m", "uvicorn", "waf_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
