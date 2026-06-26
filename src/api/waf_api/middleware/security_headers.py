"""Security response headers middleware.

Applies OWASP-recommended HTTP security headers to every response.
Must be added to the app after the telemetry middleware so it runs
on the outermost layer and cannot be stripped by inner middleware.
"""

from __future__ import annotations

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        # Enforce HTTPS for 2 years; include subdomains and preload list.
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )

        # Prevent MIME-type sniffing (XSS via content-type confusion).
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Deny embedding in frames/iframes to prevent clickjacking.
        response.headers["X-Frame-Options"] = "DENY"

        # Do not send Referer header to third-party sites.
        response.headers["Referrer-Policy"] = "no-referrer"

        # Restrict browser feature access.
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )

        # API responses must never be cached by proxies or browsers.
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"

        # Remove the Server header to avoid leaking framework/version info.
        # MutableHeaders has no .pop(); use guarded del (raises KeyError if absent).
        if "server" in response.headers:
            del response.headers["server"]

        return response
