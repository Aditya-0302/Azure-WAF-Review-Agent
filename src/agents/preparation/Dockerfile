# syntax=docker/dockerfile:1.7
# Multi-stage: build → distroless runtime.
# Preparation Agent: validates and enqueues assessment requests.
# Lightweight workload — 250m CPU / 512Mi memory in production.

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM python:3.12-bookworm AS build

WORKDIR /build

RUN pip install --no-cache-dir hatchling==1.24.2

COPY src/shared/pyproject.toml src/shared/
COPY src/shared/waf_shared/ src/shared/waf_shared/
COPY src/shared/waf_catalog/ src/shared/waf_catalog/
RUN pip install --no-cache-dir --prefix=/install "src/shared/"

ENV PYTHONPATH=/install/lib/python3.12/site-packages

COPY src/agents/preparation/pyproject.toml src/agents/preparation/
COPY src/agents/preparation/waf_preparation/ src/agents/preparation/waf_preparation/
RUN pip install --no-cache-dir --prefix=/install "src/agents/preparation/"

# ── Stage 2: development ──────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS development

WORKDIR /app
COPY --from=build /install /usr/local

RUN pip install --no-cache-dir pytest pytest-asyncio pytest-mock

COPY src/ /app/src/
ENV PYTHONPATH=/app/src/shared:/app/src/agents/preparation
USER nobody

CMD ["python", "-m", "waf_preparation.main"]

# ── Stage 3: production (distroless, nonroot) ─────────────────────────────────
FROM gcr.io/distroless/python3-debian12:nonroot AS production

WORKDIR /app

COPY --from=build /install/lib/python3.12/site-packages \
     /usr/local/lib/python3.12/dist-packages

ENV PYTHONPATH=/usr/local/lib/python3.12/dist-packages
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "waf_preparation.main"]
