"""Unit tests for AuthorizationService."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from waf_shared.auth.authz_service import AuthorizationService
from waf_shared.auth.models import AuthContext
from waf_shared.domain.errors.domain_errors import PermissionDeniedError
from waf_shared.domain.models.assessment import Assessment, AssessmentStatus
from waf_shared.domain.models.tenant import UserRole


def _ctx(role: UserRole, tenant_id: uuid.UUID | None = None) -> AuthContext:
    tid = tenant_id or uuid.uuid4()
    return AuthContext(
        tenant_id=tid,
        user_id=uuid.uuid4(),
        role=role,
        entra_oid=uuid.uuid4(),
    )


def _assessment(tenant_id: uuid.UUID) -> Assessment:
    now = datetime.now(UTC)
    return Assessment(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        idempotency_key="key-001",
        status=AssessmentStatus.PENDING,
        subscription_ids=[uuid.uuid4()],
        pillar_filter=None,
        tag_filter=None,
        requested_by_oid=uuid.uuid4(),
        total_batches=None,
        completed_batches=0,
        cancellation_requested_at=None,
        created_at=now,
        updated_at=now,
    )


@pytest.mark.unit
class TestAuthorizationServiceAssessments:
    def test_platform_admin_can_read_any_assessment(self) -> None:
        auth = _ctx(UserRole.PLATFORM_ADMIN)
        assessment = _assessment(uuid.uuid4())
        assert AuthorizationService.can_read_assessment(auth, assessment) is True

    def test_tenant_admin_can_read_own_tenant_assessment(self) -> None:
        tenant_id = uuid.uuid4()
        auth = _ctx(UserRole.TENANT_ADMIN, tenant_id)
        assessment = _assessment(tenant_id)
        assert AuthorizationService.can_read_assessment(auth, assessment) is True

    def test_tenant_admin_cannot_read_other_tenant_assessment(self) -> None:
        auth = _ctx(UserRole.TENANT_ADMIN)
        assessment = _assessment(uuid.uuid4())
        assert AuthorizationService.can_read_assessment(auth, assessment) is False

    def test_viewer_can_read_own_tenant_assessment(self) -> None:
        tenant_id = uuid.uuid4()
        auth = _ctx(UserRole.TENANT_VIEWER, tenant_id)
        assessment = _assessment(tenant_id)
        assert AuthorizationService.can_read_assessment(auth, assessment) is True

    def test_viewer_cannot_write_assessment(self) -> None:
        tenant_id = uuid.uuid4()
        auth = _ctx(UserRole.TENANT_VIEWER, tenant_id)
        assessment = _assessment(tenant_id)
        assert AuthorizationService.can_write_assessment(auth, assessment) is False

    def test_admin_can_write_assessment(self) -> None:
        tenant_id = uuid.uuid4()
        auth = _ctx(UserRole.TENANT_ADMIN, tenant_id)
        assessment = _assessment(tenant_id)
        assert AuthorizationService.can_write_assessment(auth, assessment) is True

    def test_viewer_cannot_cancel_assessment(self) -> None:
        tenant_id = uuid.uuid4()
        auth = _ctx(UserRole.TENANT_VIEWER, tenant_id)
        assessment = _assessment(tenant_id)
        assert AuthorizationService.can_cancel_assessment(auth, assessment) is False

    def test_require_read_raises_for_wrong_tenant(self) -> None:
        auth = _ctx(UserRole.TENANT_ADMIN)
        assessment = _assessment(uuid.uuid4())
        with pytest.raises(PermissionDeniedError) as exc_info:
            AuthorizationService.require_read_assessment(auth, assessment)
        assert exc_info.value.action == "read_assessment"
        assert exc_info.value.principal_id == auth.user_id

    def test_require_write_raises_for_viewer(self) -> None:
        tenant_id = uuid.uuid4()
        auth = _ctx(UserRole.TENANT_VIEWER, tenant_id)
        assessment = _assessment(tenant_id)
        with pytest.raises(PermissionDeniedError) as exc_info:
            AuthorizationService.require_write_assessment(auth, assessment)
        assert exc_info.value.action == "write_assessment"


@pytest.mark.unit
class TestAuthorizationServiceFindings:
    def test_platform_admin_can_view_any_findings(self) -> None:
        auth = _ctx(UserRole.PLATFORM_ADMIN)
        assert AuthorizationService.can_view_findings(auth, uuid.uuid4()) is True

    def test_viewer_can_view_own_tenant_findings(self) -> None:
        tenant_id = uuid.uuid4()
        auth = _ctx(UserRole.TENANT_VIEWER, tenant_id)
        assert AuthorizationService.can_view_findings(auth, tenant_id) is True

    def test_viewer_cannot_view_other_tenant_findings(self) -> None:
        auth = _ctx(UserRole.TENANT_VIEWER)
        assert AuthorizationService.can_view_findings(auth, uuid.uuid4()) is False

    def test_viewer_cannot_acknowledge_finding(self) -> None:
        tenant_id = uuid.uuid4()
        auth = _ctx(UserRole.TENANT_VIEWER, tenant_id)
        assert AuthorizationService.can_acknowledge_finding(auth, tenant_id) is False

    def test_admin_can_acknowledge_finding(self) -> None:
        tenant_id = uuid.uuid4()
        auth = _ctx(UserRole.TENANT_ADMIN, tenant_id)
        assert AuthorizationService.can_acknowledge_finding(auth, tenant_id) is True

    def test_require_view_raises_for_wrong_tenant(self) -> None:
        auth = _ctx(UserRole.TENANT_ADMIN)
        with pytest.raises(PermissionDeniedError) as exc_info:
            AuthorizationService.require_view_findings(auth, uuid.uuid4())
        assert exc_info.value.action == "view_findings"


@pytest.mark.unit
class TestAuthorizationServiceCredentials:
    def test_platform_admin_can_manage_any_tenant_credentials(self) -> None:
        auth = _ctx(UserRole.PLATFORM_ADMIN)
        assert AuthorizationService.can_manage_credentials(auth, uuid.uuid4()) is True

    def test_tenant_admin_can_manage_own_credentials(self) -> None:
        tenant_id = uuid.uuid4()
        auth = _ctx(UserRole.TENANT_ADMIN, tenant_id)
        assert AuthorizationService.can_manage_credentials(auth, tenant_id) is True

    def test_tenant_admin_cannot_manage_other_tenant_credentials(self) -> None:
        auth = _ctx(UserRole.TENANT_ADMIN)
        assert AuthorizationService.can_manage_credentials(auth, uuid.uuid4()) is False

    def test_viewer_cannot_manage_credentials(self) -> None:
        tenant_id = uuid.uuid4()
        auth = _ctx(UserRole.TENANT_VIEWER, tenant_id)
        assert AuthorizationService.can_manage_credentials(auth, tenant_id) is False

    def test_require_manage_raises_for_viewer(self) -> None:
        tenant_id = uuid.uuid4()
        auth = _ctx(UserRole.TENANT_VIEWER, tenant_id)
        with pytest.raises(PermissionDeniedError) as exc_info:
            AuthorizationService.require_manage_credentials(auth, tenant_id)
        assert exc_info.value.action == "manage_credentials"


@pytest.mark.unit
class TestAuthorizationServiceTenants:
    def test_platform_admin_can_manage_tenant(self) -> None:
        auth = _ctx(UserRole.PLATFORM_ADMIN)
        assert AuthorizationService.can_manage_tenant(auth, uuid.uuid4()) is True

    def test_tenant_admin_cannot_manage_tenant(self) -> None:
        tenant_id = uuid.uuid4()
        auth = _ctx(UserRole.TENANT_ADMIN, tenant_id)
        assert AuthorizationService.can_manage_tenant(auth, tenant_id) is False

    def test_require_manage_tenant_raises_for_non_platform_admin(self) -> None:
        tenant_id = uuid.uuid4()
        auth = _ctx(UserRole.TENANT_ADMIN, tenant_id)
        with pytest.raises(PermissionDeniedError) as exc_info:
            AuthorizationService.require_manage_tenant(auth, tenant_id)
        assert exc_info.value.action == "manage_tenant"
