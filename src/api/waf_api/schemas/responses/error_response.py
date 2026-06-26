"""Standardised error response schema.

Every error returned by the API conforms to this structure.
Routers never construct error responses manually — exception handlers do.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ErrorDetail(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    message: str
    detail: dict | None = None
    trace_id: str
    request_id: str


class ErrorResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    error: ErrorDetail
