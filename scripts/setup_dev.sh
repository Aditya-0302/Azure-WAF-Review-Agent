#!/usr/bin/env bash
# setup_dev.sh — bootstrap a local development environment
# Run once after cloning the repository.

set -euo pipefail

echo "==> WAF Review Agent — Dev Setup"

# ── Python version check ──────────────────────────────────────────────────────
REQUIRED_MAJOR=3
REQUIRED_MINOR=12
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [[ "$MAJOR" -lt "$REQUIRED_MAJOR" ]] || \
   { [[ "$MAJOR" -eq "$REQUIRED_MAJOR" ]] && [[ "$MINOR" -lt "$REQUIRED_MINOR" ]]; }; then
    echo "ERROR: Python $REQUIRED_MAJOR.$REQUIRED_MINOR+ required. Found: $PYTHON_VERSION"
    exit 1
fi
echo "  Python $PYTHON_VERSION — OK"

# ── Virtual environment ───────────────────────────────────────────────────────
if [[ ! -d ".venv" ]]; then
    python3 -m venv .venv
    echo "  Created .venv"
fi
source .venv/bin/activate
pip install --quiet --upgrade pip

# ── Install packages in editable mode ────────────────────────────────────────
pip install --quiet -e "src/shared[dev]"
pip install --quiet -e "src/api[dev]"
echo "  Installed waf-agent-shared and waf-api"

# ── Pre-commit hooks ──────────────────────────────────────────────────────────
pip install --quiet pre-commit
pre-commit install
echo "  Pre-commit hooks installed"

# ── Create .env from example ──────────────────────────────────────────────────
if [[ ! -f ".env" ]]; then
    cp .env.example .env
    echo "  Created .env from .env.example — update values before running"
else
    echo "  .env already exists — skipping"
fi

# ── Detect secrets baseline ───────────────────────────────────────────────────
if [[ ! -f ".secrets.baseline" ]]; then
    pip install --quiet detect-secrets
    detect-secrets scan > .secrets.baseline
    echo "  Created .secrets.baseline"
fi

# ── Docker Compose services ───────────────────────────────────────────────────
if command -v docker &>/dev/null && command -v docker-compose &>/dev/null; then
    echo "  Starting Docker Compose services (postgres, redis, servicebus-emulator)..."
    docker-compose -f docker-compose.dev.yml up -d postgres redis servicebus-emulator
    echo "  Waiting for postgres to be ready..."
    until docker-compose -f docker-compose.dev.yml exec -T postgres pg_isready -U wafagent &>/dev/null; do
        sleep 1
    done
    echo "  postgres ready"
else
    echo "  WARN: Docker not found — start postgres/redis manually"
fi

# ── Run migrations ────────────────────────────────────────────────────────────
echo "  Running Alembic migrations..."
alembic upgrade head
echo "  Migrations applied"

echo ""
echo "==> Dev setup complete. Activate the venv: source .venv/bin/activate"
echo "    Run API: uvicorn waf_api.main:app --reload"
echo "    Run tests: pytest tests/unit/ -v"
