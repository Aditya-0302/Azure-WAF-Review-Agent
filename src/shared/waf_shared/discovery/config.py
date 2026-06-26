"""Configuration for Azure discovery operations."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DiscoveryConfig(BaseModel):
    """Tuning parameters for Azure management API calls during discovery."""

    page_size: int = Field(default=100, ge=1, le=1000)
    max_pages: int = Field(default=50, ge=1)
    request_timeout_seconds: float = Field(default=30.0, gt=0)
    max_concurrent_subscriptions: int = Field(default=5, ge=1)

    # Retry policy
    retry_max_attempts: int = Field(default=3, ge=1)
    retry_initial_wait_seconds: float = Field(default=1.0, gt=0)
    retry_backoff_factor: float = Field(default=2.0, gt=1)
    retry_max_wait_seconds: float = Field(default=30.0, gt=0)

    # Which resource types to include when no explicit filter is given (empty = all)
    default_resource_types: list[str] = []
