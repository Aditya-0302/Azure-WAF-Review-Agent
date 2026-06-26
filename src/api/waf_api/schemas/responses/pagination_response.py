"""Cursor-based pagination response wrapper.

All list endpoints return a PaginatedResponse[T].
Cursor is an opaque base64-encoded string — clients must not parse it.
"""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class PaginationMeta(BaseModel):
    model_config = ConfigDict(frozen=True)

    total: int | None = None
    next_cursor: str | None = None
    has_more: bool


class PaginatedResponse(BaseModel, Generic[T]):
    model_config = ConfigDict(frozen=True)

    items: list[T]
    pagination: PaginationMeta
