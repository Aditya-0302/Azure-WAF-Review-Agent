# syntax=docker/dockerfile:1.7
# Multi-stage: build → distroless runtime.
# Extraction Agent: queries ARM APIs for resource properties across all WAF pillars.
# Network-bound; many concurrent ARM calls — 500m CPU / 1Gi memory in production.

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM python:3.12-bookworm AS build

WORKDIR /build

RUN pip install --no-cache-dir hatchling==1.24.2

COPY src/shared/pyproject.toml src/shared/
COPY src/shared/waf_shared/ src/shared/waf_shared/
COPY src/shared/waf_catalog/ src/shared/waf_catalog/
RUN pip install --no-cache-dir --prefix=/install "src/shared/"

ENV PYTHONPATH=/install/lib/python3.12/site-packages

COPY src/agents/extraction/pyproject.toml src/agents/extraction/
COPY src/agents/extraction/waf_extraction/ src/agents/extraction/waf_extraction/
RUN pip install --no-cache-dir --prefix=/install "src/agents/extraction/"

# ── Stage 2: development ──────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS development

WORKDIR /app
COPY --from=build /install /usr/local

RUN pip install --no-cache-dir pytest pytest-asyncio pytest-mock respx

COPY src/ /app/src/
ENV PYTHONPATH=/app/src/shared:/app/src/agents/extraction
USER nobody

CMD ["python", "-m", "waf_extraction.main"]

# ── Stage 3: production (distroless, nonroot) ─────────────────────────────────
FROM gcr.io/distroless/python3-debian12:nonroot AS production

WORKDIR /app

COPY --from=build /install/lib/python3.12/site-packages \
     /usr/local/lib/python3.12/dist-packages

ENV PYTHONPATH=/usr/local/lib/python3.12/dist-packages
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "waf_extraction.main"]
