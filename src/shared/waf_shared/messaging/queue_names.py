"""Azure Service Bus queue name constants.

Import from this module instead of scattering string literals across agents.
"""

from __future__ import annotations

ASSESSMENT_CREATED: str = "assessment.created"
EXTRACTION_REQUESTED: str = "extraction.requested"
REASONING_REQUESTED: str = "reasoning.requested"
REPORTING_REQUESTED: str = "reporting.requested"
ASSESSMENT_CANCELLED: str = "assessment.cancelled"
WEBHOOK_DELIVERY: str = "webhook.delivery"
CREDENTIAL_HEALTH_CHECK: str = "credential.health-check"
DLQ_REPROCESS: str = "dlq-reprocess"
