from __future__ import annotations

from datetime import timedelta
from typing import Optional

from app.models.app import App
from app.models.user import User
from app.services.jwt_service import (
    clear_user_blacklist,
    create_access_token,
    create_refresh_token,
    mark_user_online,
)


def generate_tokens_for_user(user: User, app: Optional[App], cnf: Optional[dict] = None, scope: Optional[str] = None) -> tuple[str, str]:
    """Generate access/refresh tokens with app-specific TTL and claims.

    Token claims follow RFC 7519:
      - sub: opaque, immutable user identifier (never PII like email)
      - email: user email as a regular claim
      - aud: client_id of the requesting application
      - scope: granted OAuth scope
    """
    # RFC 7519 §4.1.2: sub MUST be a locally unique, immutable, non-PII identifier.
    # Using "usr_{id}" — opaque, stable, never changes even if user changes email.
    token_data = {
        "sub": f"usr_{user.id}",
        "email": user.email,
        "user_id": user.id,
    }
    if cnf:
        token_data["cnf"] = cnf
    if scope:
        token_data["scope"] = scope

    if app:
        token_data["app_id"] = app.app_id
        token_data["tenant_id"] = app.tenant_id
        token_data["aud"] = app.app_id  # RFC 7519 §4.1.3: audience restriction

    if app:
        access_expires = timedelta(minutes=app.access_token_expiry_minutes)
        refresh_expires = timedelta(days=app.refresh_token_expiry_days)
    else:
        access_expires = None
        refresh_expires = None

    access_token = create_access_token(token_data, access_expires)
    refresh_token = create_refresh_token(token_data, refresh_expires)

    if app:
        ttl = int(app.access_token_expiry_minutes * 60) + 60
        mark_user_online(user.id, app.tenant_id, ttl_seconds=ttl)
        clear_user_blacklist(user.id, app.tenant_id)

    return access_token, refresh_token
