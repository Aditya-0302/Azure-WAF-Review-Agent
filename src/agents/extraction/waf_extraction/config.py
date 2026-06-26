"""Extraction Agent runtime configuration.

Inherits all platform settings from AgentSettings.  The shared variables
DB_*, SERVICEBUS_NAMESPACE, and KEYVAULT_URI from the project .env are
reused directly — no EXTRACTION_* duplicates are required.

No agent-specific variables — all required configuration comes from the
shared platform settings.
"""

from __future__ import annotations

from waf_shared.agents.settings import AgentSettings


class ExtractionConfig(AgentSettings):
    pass
