"""Database pool dependency — yields shared pool from application state."""

from __future__ import annotations

from fastapi import Request

from waf_shared.db.pool import DatabasePool


def get_db_pool(request: Request) -> DatabasePool:
    """Return the application-wide DatabasePool.

    The pool is created once in lifespan() and stored in app.state.
    Never create new connections per request.
    """
    return request.app.state.db_pool  # type: ignore[no-any-return]
