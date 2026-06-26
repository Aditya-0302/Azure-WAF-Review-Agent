"""Reporting Agent runtime configuration.

Inherits platform settings (DB_*, SERVICEBUS_NAMESPACE, KEYVAULT_URI) from
AgentSettings.  The storage fields reuse STORAGE_* variables already present
in the project .env — no REPORTING_* duplicates are required.

Agent-specific variables:
  STORAGE_ACCOUNT_NAME      — Azure Storage account name (e.g. "stwafagentdev")
  STORAGE_REPORTS_CONTAINER — Blob container for generated reports (default "reports")
"""

from __future__ import annotations

from waf_shared.agents.settings import AgentSettings


class ReportingConfig(AgentSettings):
    storage_account_name: str = ""
    storage_reports_container: str = "reports"

    @property
    def storage_account_url(self) -> str:
        """Full Blob Service URL derived from storage_account_name."""
        return f"https://{self.storage_account_name}.blob.core.windows.net"
