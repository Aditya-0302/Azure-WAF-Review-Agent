"""Infrastructure-layer exceptions — I/O failures."""

from __future__ import annotations

import uuid

from waf_shared.domain.errors.domain_errors import WafAgentError


class InfrastructureError(WafAgentError):
    """Raised when an I/O operation fails."""


class DatabaseError(InfrastructureError):
    """Base class for database-related failures."""


class ConnectionPoolExhaustedError(DatabaseError):
    def __init__(self, pool_name: str, timeout_seconds: float) -> None:
        super().__init__(
            f"Database pool '{pool_name}' exhausted after waiting {timeout_seconds}s",
            code="CONNECTION_POOL_EXHAUSTED",
        )
        self.pool_name = pool_name
        self.timeout_seconds = timeout_seconds


class QueryTimeoutError(DatabaseError):
    def __init__(self, query_description: str, timeout_seconds: float) -> None:
        super().__init__(
            f"Query '{query_description}' timed out after {timeout_seconds}s",
            code="QUERY_TIMEOUT",
        )
        self.query_description = query_description
        self.timeout_seconds = timeout_seconds


class CredentialUnavailableError(InfrastructureError):
    def __init__(self, reason: str) -> None:
        super().__init__(
            f"Azure credential unavailable: {reason}",
            code="CREDENTIAL_UNAVAILABLE",
        )
        self.reason = reason


class AzureRateLimitError(InfrastructureError):
    def __init__(self, service: str, retry_after_seconds: int | None = None) -> None:
        msg = f"Azure service '{service}' rate limit reached"
        if retry_after_seconds is not None:
            msg += f"; retry after {retry_after_seconds}s"
        super().__init__(msg, code="AZURE_RATE_LIMIT")
        self.service = service
        self.retry_after_seconds = retry_after_seconds


class LLMRateLimitError(InfrastructureError):
    def __init__(self, retry_after_seconds: int | None = None) -> None:
        msg = "Azure OpenAI rate limit reached (TPM/RPM)"
        if retry_after_seconds is not None:
            msg += f"; retry after {retry_after_seconds}s"
        super().__init__(msg, code="LLM_RATE_LIMIT")
        self.retry_after_seconds = retry_after_seconds


class LLMQuotaExhaustedError(InfrastructureError):
    def __init__(self, deployment: str) -> None:
        super().__init__(
            f"Azure OpenAI monthly token quota exhausted for deployment '{deployment}'",
            code="LLM_QUOTA_EXHAUSTED",
        )
        self.deployment = deployment


class ServiceBusDeliveryError(InfrastructureError):
    def __init__(self, queue_name: str, reason: str) -> None:
        super().__init__(
            f"Service Bus delivery failed on queue '{queue_name}': {reason}",
            code="SERVICEBUS_DELIVERY_ERROR",
        )
        self.queue_name = queue_name
        self.reason = reason


class KeyVaultAccessError(InfrastructureError):
    def __init__(self, secret_name: str, reason: str) -> None:
        super().__init__(
            f"Failed to access Key Vault secret '{secret_name}': {reason}",
            code="KEYVAULT_ACCESS_ERROR",
        )
        self.secret_name = secret_name
        self.reason = reason


class CrossTenantAuthError(InfrastructureError):
    def __init__(self, subscription_id: uuid.UUID, reason: str) -> None:
        super().__init__(
            f"Cross-tenant authentication failed for subscription {subscription_id}: {reason}",
            code="CROSS_TENANT_AUTH_ERROR",
        )
        self.subscription_id = subscription_id
        self.reason = reason


class ResourceDiscoveryError(InfrastructureError):
    def __init__(self, service: str, reason: str) -> None:
        super().__init__(
            f"Azure resource discovery failed for service '{service}': {reason}",
            code="RESOURCE_DISCOVERY_ERROR",
        )
        self.service = service
        self.reason = reason


class AdvisorAccessError(InfrastructureError):
    def __init__(self, subscription_id: uuid.UUID, reason: str) -> None:
        super().__init__(
            f"Azure Advisor access failed for subscription {subscription_id}: {reason}",
            code="ADVISOR_ACCESS_ERROR",
        )
        self.subscription_id = subscription_id
        self.reason = reason


class AgentError(InfrastructureError):
    def __init__(self, agent_name: str, reason: str) -> None:
        super().__init__(
            f"Agent '{agent_name}' failed: {reason}",
            code="AGENT_ERROR",
        )
        self.agent_name = agent_name
        self.reason = reason


class AgentTimeoutError(AgentError):
    def __init__(self, agent_name: str, timeout_seconds: float) -> None:
        super().__init__(
            agent_name=agent_name,
            reason=f"execution timed out after {timeout_seconds}s",
        )
        self.code = "AGENT_TIMEOUT"
        self.timeout_seconds = timeout_seconds


class PipelineError(InfrastructureError):
    def __init__(self, pipeline_name: str, stage_name: str, reason: str) -> None:
        super().__init__(
            f"Pipeline '{pipeline_name}' failed at stage '{stage_name}': {reason}",
            code="PIPELINE_ERROR",
        )
        self.pipeline_name = pipeline_name
        self.stage_name = stage_name
        self.reason = reason


class WorkflowError(InfrastructureError):
    def __init__(self, workflow_id: uuid.UUID, reason: str) -> None:
        super().__init__(
            f"Workflow {workflow_id} failed: {reason}",
            code="WORKFLOW_ERROR",
        )
        self.workflow_id = workflow_id
        self.reason = reason
