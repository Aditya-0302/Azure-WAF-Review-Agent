"""Auth domain models — shared between middleware, services, and authz layer."""

from __future__ import annotations

import dataclasses
import uuid

from waf_shared.domain.models.tenant import UserRole


@dataclasses.dataclass(frozen=True)
class AuthContext:
    """Populated by the JWT middleware; consumed by RBAC and authz service."""

    tenant_id: uuid.UUID
    user_id: uuid.UUID
    role: UserRole
    entra_oid: uuid.UUID
