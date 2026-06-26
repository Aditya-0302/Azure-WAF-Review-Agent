"""Repository implementations — one class per aggregate root."""

from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.db.repositories.credential_repository import CredentialRepository
from waf_shared.db.repositories.finding_repository import FindingRepository
from waf_shared.db.repositories.rule_repository import WafRuleRepository
from waf_shared.db.repositories.tenant_repository import TenantRepository

__all__ = [
    "AssessmentRepository",
    "CredentialRepository",
    "FindingRepository",
    "TenantRepository",
    "WafRuleRepository",
]
