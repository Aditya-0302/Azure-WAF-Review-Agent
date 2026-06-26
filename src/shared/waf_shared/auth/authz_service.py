"""Authorization service — object-level permission checks.

Role-based access (route-level) is enforced by the RBAC FastAPI dependency.
This service handles finer-grained checks on domain objects: can this specific
user read this specific assessment, manage credentials for this tenant, etc.

All methods are pure static — no I/O, no state. Callers can import the class
or individual check helpers. The require_* variants raise PermissionDeniedError
so callers can propagate a structured 403 without writing their own if-raise.
"""

from __future__ import annotations

import uuid

from waf_shared.auth.models import AuthContext
from waf_shared.domain.errors.domain_errors import PermissionDeniedError
from waf_shared.domain.models.assessment import Assessment
from waf_shared.domain.models.tenant import UserRole


class AuthorizationService:
    """Fine-grained (object-level) authorization checks."""

    # ── Assessment ────────────────────────────────────────────────────────────

    @staticmethod
    def can_read_assessment(auth: AuthContext, assessment: Assessment) -> bool:
        if auth.role == UserRole.PLATFORM_ADMIN:
            return True
        return auth.tenant_id == assessment.tenant_id

    @staticmethod
    def can_write_assessment(auth: AuthContext, assessment: Assessment) -> bool:
        if auth.role == UserRole.TENANT_VIEWER:
            return False
        return AuthorizationService.can_read_assessment(auth, assessment)

    @staticmethod
    def can_cancel_assessment(auth: AuthContext, assessment: Assessment) -> bool:
        if auth.role == UserRole.TENANT_VIEWER:
            return False
        return AuthorizationService.can_read_assessment(auth, assessment)

    @staticmethod
    def require_read_assessment(auth: AuthContext, assessment: Assessment) -> None:
        if not AuthorizationService.can_read_assessment(auth, assessment):
            raise PermissionDeniedError(
                principal_id=auth.user_id,
                action="read_assessment",
                resource_id=assessment.id,
            )

    @staticmethod
    def require_write_assessment(auth: AuthContext, assessment: Assessment) -> None:
        if not AuthorizationService.can_write_assessment(auth, assessment):
            raise PermissionDeniedError(
                principal_id=auth.user_id,
                action="write_assessment",
                resource_id=assessment.id,
            )

    @staticmethod
    def require_cancel_assessment(auth: AuthContext, assessment: Assessment) -> None:
        if not AuthorizationService.can_cancel_assessment(auth, assessment):
            raise PermissionDeniedError(
                principal_id=auth.user_id,
                action="cancel_assessment",
                resource_id=assessment.id,
            )

    # ── Findings ──────────────────────────────────────────────────────────────

    @staticmethod
    def can_view_findings(auth: AuthContext, tenant_id: uuid.UUID) -> bool:
        if auth.role == UserRole.PLATFORM_ADMIN:
            return True
        return auth.tenant_id == tenant_id

    @staticmethod
    def can_acknowledge_finding(auth: AuthContext, tenant_id: uuid.UUID) -> bool:
        if auth.role == UserRole.TENANT_VIEWER:
            return False
        return AuthorizationService.can_view_findings(auth, tenant_id)

    @staticmethod
    def require_view_findings(auth: AuthContext, tenant_id: uuid.UUID) -> None:
        if not AuthorizationService.can_view_findings(auth, tenant_id):
            raise PermissionDeniedError(
                principal_id=auth.user_id,
                action="view_findings",
                resource_id=tenant_id,
            )

    @staticmethod
    def require_acknowledge_finding(auth: AuthContext, tenant_id: uuid.UUID) -> None:
        if not AuthorizationService.can_acknowledge_finding(auth, tenant_id):
            raise PermissionDeniedError(
                principal_id=auth.user_id,
                action="acknowledge_finding",
                resource_id=tenant_id,
            )

    # ── Credentials ───────────────────────────────────────────────────────────

    @staticmethod
    def can_manage_credentials(auth: AuthContext, tenant_id: uuid.UUID) -> bool:
        """Tenant admins for their own tenant, or platform admins for any tenant."""
        if auth.role == UserRole.PLATFORM_ADMIN:
            return True
        if auth.role == UserRole.TENANT_ADMIN and auth.tenant_id == tenant_id:
            return True
        return False

    @staticmethod
    def require_manage_credentials(auth: AuthContext, tenant_id: uuid.UUID) -> None:
        if not AuthorizationService.can_manage_credentials(auth, tenant_id):
            raise PermissionDeniedError(
                principal_id=auth.user_id,
                action="manage_credentials",
                resource_id=tenant_id,
            )

    # ── Tenant management ─────────────────────────────────────────────────────

    @staticmethod
    def can_manage_tenant(auth: AuthContext, target_tenant_id: uuid.UUID) -> bool:  # noqa: ARG004
        return auth.role == UserRole.PLATFORM_ADMIN

    @staticmethod
    def require_manage_tenant(auth: AuthContext, target_tenant_id: uuid.UUID) -> None:
        if not AuthorizationService.can_manage_tenant(auth, target_tenant_id):
            raise PermissionDeniedError(
                principal_id=auth.user_id,
                action="manage_tenant",
                resource_id=target_tenant_id,
            )
