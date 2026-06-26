"""Preparation Agent runtime configuration.

Inherits all platform settings from AgentSettings.  The shared variables
DB_*, SERVICEBUS_NAMESPACE, and KEYVAULT_URI from the project .env are
reused directly — no PREPARATION_* duplicates are required.

Agent-specific variables (all optional; sensible defaults apply):
  BATCH_SIZE                    — resources per DB batch (default 50)
  MAX_CONCURRENT_SUBSCRIPTIONS  — parallel subscription discovery (default 5)
"""

from __future__ import annotations

from pydantic import Field

from waf_shared.agents.settings import AgentSettings


class PreparationConfig(AgentSettings):
    batch_size: int = Field(default=50, ge=1)
    max_concurrent_subscriptions: int = Field(default=5, ge=1)
