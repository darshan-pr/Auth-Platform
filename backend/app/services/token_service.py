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


def generate_tokens_for_user(user: User, app: Optional[App], cnf: Optional[dict] = None) -> tuple[str, str]:
    """Generate access/refresh tokens with app-specific TTL and claims."""
    token_data = {"sub": user.email, "user_id": user.id}
    if cnf:
        token_data["cnf"] = cnf

    if app:
        token_data["app_id"] = app.app_id
        token_data["tenant_id"] = app.tenant_id

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
