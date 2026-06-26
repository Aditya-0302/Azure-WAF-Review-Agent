"""Azure authentication and authorization layer."""

from waf_shared.auth.auth_service import AuthenticationService
from waf_shared.auth.authz_service import AuthorizationService
from waf_shared.auth.config import (
    AuthMode,
    ManagedIdentityConfig,
    PlatformAuthConfig,
    ServicePrincipalConfig,
    WorkloadIdentityConfig,
)
from waf_shared.auth.credential_provider import (
    CredentialProvider,
    CrossTenantCredentialProvider,
    ManagedIdentityCredentialProvider,
    ServicePrincipalCredentialProvider,
    WorkloadIdentityCredentialProvider,
    create_platform_provider,
)
from waf_shared.auth.models import AuthContext
from waf_shared.auth.token_provider import TokenProvider

__all__ = [
    # Models
    "AuthContext",
    # Config
    "AuthMode",
    "ManagedIdentityConfig",
    "PlatformAuthConfig",
    "ServicePrincipalConfig",
    "WorkloadIdentityConfig",
    # Providers
    "CredentialProvider",
    "CrossTenantCredentialProvider",
    "ManagedIdentityCredentialProvider",
    "ServicePrincipalCredentialProvider",
    "WorkloadIdentityCredentialProvider",
    "create_platform_provider",
    # Token
    "TokenProvider",
    # Services
    "AuthenticationService",
    "AuthorizationService",
]
