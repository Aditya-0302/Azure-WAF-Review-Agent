# syntax=docker/dockerfile:1.7
# Multi-stage: build → distroless runtime.
# The runtime image has no shell, no package manager, no root user.
#
# Resource requests: 1 vCPU, 2Gi memory; limits: 2 vCPU, 4Gi.
# reportlab PDF generation is CPU-intensive; the limits reflect this.

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM python:3.12-bookworm AS build

WORKDIR /build

RUN pip install --no-cache-dir hatchling==1.24.2

# Install shared library first for better layer caching.
COPY src/shared/pyproject.toml src/shared/
COPY src/shared/waf_shared/ src/shared/waf_shared/
COPY src/shared/waf_catalog/ src/shared/waf_catalog/
RUN pip install --no-cache-dir --prefix=/install "src/shared/"

ENV PYTHONPATH=/install/lib/python3.12/site-packages

# Install reporting agent package.
COPY src/agents/reporting/pyproject.toml src/agents/reporting/
COPY src/agents/reporting/waf_reporting/ src/agents/reporting/waf_reporting/
RUN pip install --no-cache-dir --prefix=/install "src/agents/reporting/"

# ── Stage 2: development (debugger, live-reload) ──────────────────────────────
FROM python:3.12-slim-bookworm AS development

WORKDIR /app
COPY --from=build /install /usr/local

RUN pip install --no-cache-dir pytest pytest-asyncio

COPY src/ /app/src/
ENV PYTHONPATH=/app/src/shared:/app/src/agents/reporting
USER nobody

CMD ["python", "-m", "waf_reporting.main"]

# ── Stage 3: production (distroless, no shell, nonroot) ──────────────────────
FROM gcr.io/distroless/python3-debian12:nonroot AS production

WORKDIR /app

COPY --from=build /install/lib/python3.12/site-packages \
     /usr/local/lib/python3.12/dist-packages

ENV PYTHONPATH=/usr/local/lib/python3.12/dist-packages
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Reporting agent runs as a long-lived consumer loop; no port exposed.
ENTRYPOINT ["python", "-m", "waf_reporting.main"]
