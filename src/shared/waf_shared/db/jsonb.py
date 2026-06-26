"""normalize_jsonb — safe JSONB value normalizer for asyncpg row mappers.

asyncpg may return JSONB columns as:
  - Python dict / list  (when a native codec is registered, or in some asyncpg
                         versions with built-in JSON support active)
  - Raw JSON string     (when no codec is registered and the column value was
                         sent as text with a ::jsonb server-side cast — the
                         most common case in this project, which uses no init
                         codec in pool.py)
  - None                (SQL NULL)

Using dict(row["column"]) blindly treats a JSON string as a sequence of
single-character items, producing the misleading:
    ValueError: dictionary update sequence element #0 has length 1; 2 is required

This module provides the single canonical conversion function used by every
repository row mapper.  Import it instead of calling dict() / json.loads()
directly on JSONB columns.
"""

from __future__ import annotations

import json
from typing import Any


def normalize_jsonb(value: Any) -> dict[str, Any] | list[Any] | None:
    """Safely convert a JSONB column value from asyncpg to a Python object.

    Args:
        value: The raw value returned by asyncpg for a JSONB column.

    Returns:
        A Python dict, list, or None — never a raw string.

    Raises:
        TypeError: If the value is a type that cannot be interpreted as JSON
                   (e.g. int, bytes without JSON content).  This is intentional
                   fail-fast behaviour: silent coercion would hide data bugs.
        json.JSONDecodeError: If the value is a string but not valid JSON.
    """
    if value is None:
        return None
    if isinstance(value, dict | list):
        return value
    if isinstance(value, str):
        return json.loads(value)
    if hasattr(value, "items"):
        # asyncpg Record or any other dict-like mapping
        return dict(value)
    raise TypeError(
        f"normalize_jsonb received unsupported type {type(value).__name__!r} "
        f"for a JSONB column — expected dict, list, str, or None; "
        f"got {repr(value)[:200]}"
    )
