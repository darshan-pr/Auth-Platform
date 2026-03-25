"""
CSRF Protection Middleware — Double-Submit Cookie Pattern.

- On any request, if no csrf_token cookie is present, set one.
- On state-changing requests (POST/PUT/DELETE), validate that the
  X-CSRF-Token header matches the csrf_token cookie.
- Skipped for:
    • Requests with a Bearer Authorization header (API-to-API / SDK calls)
    • The /oauth/token endpoint (protected by PKCE)
    • Non-state-changing methods (GET, HEAD, OPTIONS)
"""

import hmac
import secrets
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from app.config import settings

logger = logging.getLogger(__name__)

# Paths that are exempt from CSRF validation
_CSRF_EXEMPT_PATHS = {
    "/oauth/token",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/health",
}

# Path prefixes that are exempt (API-only endpoints authenticated via Bearer)
_CSRF_EXEMPT_PREFIXES = (
    "/token/",    # Token endpoints use Bearer auth
)


class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit cookie CSRF protection."""

    async def dispatch(self, request: Request, call_next) -> Response:
        method = request.method.upper()

        # Only enforce on state-changing methods
        if method in ("GET", "HEAD", "OPTIONS"):
            response = await call_next(request)
            # Set CSRF cookie if not present
            if "csrf_token" not in request.cookies:
                token = secrets.token_urlsafe(32)
                response.set_cookie(
                    key="csrf_token",
                    value=token,
                    httponly=False,  # JS must read this to send in header
                    samesite="lax",
                    secure=settings.CSRF_COOKIE_SECURE,
                    path="/",
                )
            return response

        # --- State-changing request (POST / PUT / DELETE) ---

        # Skip if the request carries a Bearer token (API-to-API)
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            return await call_next(request)

        # Skip for JSON API requests — CSRF only applies to form submissions
        # Browsers cannot cross-origin POST application/json without CORS preflight
        content_type = request.headers.get("content-type", "")
        if settings.CSRF_SKIP_JSON and "application/json" in content_type:
            return await call_next(request)

        # Skip exempt paths
        path = request.url.path.rstrip("/")
        if path in _CSRF_EXEMPT_PATHS:
            return await call_next(request)
        for prefix in _CSRF_EXEMPT_PREFIXES:
            if path.startswith(prefix):
                return await call_next(request)

        # Validate CSRF: header must match cookie
        cookie_token = request.cookies.get("csrf_token")
        header_token = request.headers.get("x-csrf-token")

        if not cookie_token or not header_token or not hmac.compare_digest(cookie_token, header_token):
            logger.warning(f"CSRF validation failed for {method} {path}")
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token missing or invalid"},
            )

        return await call_next(request)
