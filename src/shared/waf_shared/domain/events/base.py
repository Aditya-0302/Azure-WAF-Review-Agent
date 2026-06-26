"""CloudEvents 1.0 envelope base class."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T", bound=BaseModel)


class CloudEventEnvelope(BaseModel, Generic[T]):
    """Conforms to CloudEvents 1.0 specification."""

    model_config = ConfigDict(frozen=True)

    specversion: str = Field(default="1.0")
    type: str
    source: str
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    datacontenttype: str = Field(default="application/json")
    data: T

    @classmethod
    def wrap(cls, event_type: str, source: str, data: T) -> "CloudEventEnvelope[T]":
        return cls(type=event_type, source=source, data=data)

    def to_json_bytes(self) -> bytes:
        return self.model_dump_json().encode("utf-8")

    @classmethod
    def from_json_bytes(cls, raw: bytes, data_type: type[T]) -> "CloudEventEnvelope[T]":
        payload: dict[str, Any] = json.loads(raw)
        payload["data"] = data_type.model_validate(payload["data"])
        return cls.model_validate(payload)
