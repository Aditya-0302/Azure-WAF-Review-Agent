"""SQLAlchemy ORM models — imported here so Alembic autogenerate sees all tables.

Import order matters: dependent tables must follow their references.
"""

from waf_shared.db.models.assessment import (
    AssessmentBatchORM,
    AssessmentORM,
    AssessmentResourceORM,
)
from waf_shared.db.models.base import AuditMixin, Base, TimestampMixin
from waf_shared.db.models.credential import SubscriptionCredentialORM
from waf_shared.db.models.finding import AssessmentFindingORM
from waf_shared.db.models.human_review import HumanReviewAssessmentORM
from waf_shared.db.models.rule import WafRuleORM
from waf_shared.db.models.tenant import TenantORM, TenantQuotaORM, TenantUserORM

__all__ = [
    "AuditMixin",
    "AssessmentBatchORM",
    "AssessmentFindingORM",
    "AssessmentORM",
    "AssessmentResourceORM",
    "Base",
    "HumanReviewAssessmentORM",
    "SubscriptionCredentialORM",
    "TimestampMixin",
    "TenantORM",
    "TenantQuotaORM",
    "TenantUserORM",
    "WafRuleORM",
]
