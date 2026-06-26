"""Domain repository interfaces — contracts that infrastructure must implement."""

from waf_shared.domain.repositories.i_assessment_repository import IAssessmentRepository
from waf_shared.domain.repositories.i_credential_repository import ICredentialRepository
from waf_shared.domain.repositories.i_finding_repository import IFindingRepository
from waf_shared.domain.repositories.i_rule_repository import IWafRuleRepository
from waf_shared.domain.repositories.i_tenant_repository import ITenantRepository

__all__ = [
    "IAssessmentRepository",
    "ICredentialRepository",
    "IFindingRepository",
    "IWafRuleRepository",
    "ITenantRepository",
]
