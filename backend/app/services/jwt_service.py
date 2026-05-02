import jwt
from datetime import datetime, timedelta
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from app.config import settings
import os
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

JWT_ALGORITHM = settings.JWT_ALGORITHM or "RS256"

# Key storage directory - defaults to repo `backend/keys`, with Railway fallback.
_DEFAULT_KEYS_DIR = Path(__file__).resolve().parent.parent.parent / "keys"


def _resolve_keys_dir() -> Path:
    configured = (getattr(settings, "JWT_KEYS_DIR", None) or "").strip()
    if configured:
        return Path(configured).expanduser()
    if os.getenv("RAILWAY_ENVIRONMENT"):
        return Path("/tmp/keys")
    return _DEFAULT_KEYS_DIR


KEYS_DIR = _resolve_keys_dir()
PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"


def _load_keys_from_env() -> Optional[tuple[object, object]]:
    private_pem = (getattr(settings, "JWT_PRIVATE_KEY_PEM", None) or "").strip()
    public_pem = (getattr(settings, "JWT_PUBLIC_KEY_PEM", None) or "").strip()

    if not private_pem and not public_pem:
        return None
    if not private_pem or not public_pem:
        raise RuntimeError("Both JWT_PRIVATE_KEY_PEM and JWT_PUBLIC_KEY_PEM must be provided together.")

    private_key = serialization.load_pem_private_key(
        private_pem.encode("utf-8"),
        password=None,
        backend=default_backend(),
    )
    public_key = serialization.load_pem_public_key(
        public_pem.encode("utf-8"),
        backend=default_backend(),
    )
    logger.info("Loaded JWT signing keys from environment variables.")
    return private_key, public_key


def _load_keys_from_disk() -> Optional[tuple[object, object]]:
    if not (PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists()):
        return None

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )
    logger.info("Loaded JWT signing keys from %s", KEYS_DIR)
    return private_key, public_key


def _load_required_keys():
    """Load keys from env or disk; do not auto-generate."""
    env_keys = _load_keys_from_env()
    if env_keys:
        return env_keys

    disk_keys = _load_keys_from_disk()
    if disk_keys:
        return disk_keys

    raise RuntimeError(
        "No JWT key material found. Configure JWT_PRIVATE_KEY_PEM/JWT_PUBLIC_KEY_PEM "
        "or mount key files (private_key.pem/public_key.pem) in JWT_KEYS_DIR."
    )


PRIVATE_KEY, PUBLIC_KEY = _load_required_keys()
SIGNING_KEY = PRIVATE_KEY
VERIFY_KEY = PUBLIC_KEY

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a new access token"""
    payload = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    payload.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "iss": settings.JWT_ISSUER,
    })
    payload.setdefault("type", "access")
    return jwt.encode(payload, SIGNING_KEY, algorithm=settings.JWT_ALGORITHM)

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a new refresh token"""
    payload = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
    payload.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "iss": settings.JWT_ISSUER,
    })
    payload.setdefault("type", "refresh")
    return jwt.encode(payload, SIGNING_KEY, algorithm=settings.JWT_ALGORITHM)

def verify_token(token: str) -> Optional[dict]:
    """Verify a token and return the payload.

    Note: `aud` claim validation is skipped because the auth server itself is not
    the audience — the `aud` claim (client_id) is for downstream app validation.
    """
    try:
        payload = jwt.decode(
            token, 
            VERIFY_KEY, 
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.JWT_ISSUER,
            options={"verify_aud": False},  # aud is for client-side validation
        )
        # If this is a user token, check if admin has force-logged-out this user
        uid = payload.get("user_id")
        tid = payload.get("tenant_id")
        if uid and tid and is_user_blacklisted(uid, tid):
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def refresh_token(db, refresh_token_str: str) -> dict:
    """Generate a new access token using a refresh token"""
    payload = verify_token(refresh_token_str)
    if not payload or payload.get("type") != "refresh":
        raise ValueError("Invalid refresh token")
    
    # Check if user has been force-logged-out by admin
    uid = payload.get("user_id")
    tid = payload.get("tenant_id")
    if uid and tid and is_user_blacklisted(uid, tid):
        raise ValueError("Session has been revoked by administrator")
    
    # Get app-specific settings if app_id is in the token
    access_expires = None
    app_id = payload.get("app_id")
    if app_id:
        from app.models.app import App
        app = db.query(App).filter(App.app_id == app_id).first()
        if app:
            from datetime import timedelta
            access_expires = timedelta(minutes=app.access_token_expiry_minutes)
    
    # Create new access token with app-specific or default expiry.
    # Propagate all identity claims from the refresh token.
    new_token_data = {
        "sub": payload["sub"],         # opaque user ID (usr_xxx)
        "user_id": payload.get("user_id"),
        "tenant_id": payload.get("tenant_id"),
        "app_id": app_id,
    }
    # Preserve email, audience, and scope claims from original token
    if payload.get("email"):
        new_token_data["email"] = payload["email"]
    if payload.get("aud"):
        new_token_data["aud"] = payload["aud"]
    if payload.get("scope"):
        new_token_data["scope"] = payload["scope"]
    new_access_token = create_access_token(new_token_data, access_expires)
    
    return {
        "access_token": new_access_token,
        "token_type": "bearer"
    }

def revoke_token(db, token: str) -> dict:
    """Revoke a token — blacklists the user so all their tokens are rejected.

    Decodes the token WITHOUT expiry verification so we can still extract
    user_id/tenant_id and call force_user_offline() even for expired tokens.
    This prevents the bug where an expired token returns None from verify_token()
    and the user never gets blacklisted.
    """
    try:
        # Decode ignoring expiry to always get the claims
        payload = jwt.decode(
            token,
            VERIFY_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={
                "verify_exp": False,
                "verify_aud": False,
            },
            issuer=settings.JWT_ISSUER,
        )
    except jwt.InvalidTokenError:
        # Token is malformed (bad signature, wrong format, etc.) — truly invalid
        return {"message": "Token already invalid"}

    uid = payload.get("user_id")
    tid = payload.get("tenant_id")
    if uid and tid:
        force_user_offline(uid, tid)
        return {"message": "Token revoked — user has been force-logged-out"}

    return {"message": "Token revoked"}


# ============== Online Presence (Redis) ==============

def mark_user_online(user_id: int, tenant_id: int, ttl_seconds: int = 1800):
    """Set a Redis key to mark the user as online. TTL defaults to 30 min."""
    try:
        from app.redis import redis_client
        key = f"user_online:{tenant_id}:{user_id}"
        redis_client.setex(key, ttl_seconds, "1")
    except Exception:
        pass  # fail silently – presence is best-effort


def is_user_online(user_id: int, tenant_id: int) -> bool:
    """Check if the user has an active presence key in Redis."""
    try:
        from app.redis import redis_client
        key = f"user_online:{tenant_id}:{user_id}"
        return redis_client.exists(key) == 1
    except Exception:
        return False


def get_online_status_map(user_ids: list[int], tenant_id: int) -> dict[int, bool]:
    """Return online status for many users with a single Redis round-trip when possible."""
    if not user_ids:
        return {}

    try:
        from app.redis import redis_client
        keys = [f"user_online:{tenant_id}:{uid}" for uid in user_ids]
        mget = getattr(redis_client, "mget", None)
        if callable(mget):
            values = mget(keys)
            return {
                uid: bool(value)
                for uid, value in zip(user_ids, values)
            }
        return {uid: redis_client.exists(key) == 1 for uid, key in zip(user_ids, keys)}
    except Exception:
        return {uid: False for uid in user_ids}


def count_online_users(user_ids: list[int], tenant_id: int) -> int:
    """Count online users for a tenant from a list of user IDs."""
    status_map = get_online_status_map(user_ids, tenant_id)
    return sum(1 for is_online in status_map.values() if is_online)


def force_user_offline(user_id: int, tenant_id: int):
    """Remove the user's online presence key – effectively a force logout signal."""
    try:
        from app.redis import redis_client
        key = f"user_online:{tenant_id}:{user_id}"
        redis_client.delete(key)
        # Also set a blacklist flag so token verify can reject
        bl_key = f"user_blacklist:{tenant_id}:{user_id}"
        redis_client.setex(bl_key, 86400, "1")  # blacklisted for 24h
        # Publish to Redis pub/sub for real-time SSE notification
        redis_client.publish(f"force_logout:{tenant_id}:{user_id}", "revoked")
    except Exception:
        pass


def is_user_blacklisted(user_id: int, tenant_id: int) -> bool:
    """Check if a user's sessions have been force-revoked."""
    try:
        from app.redis import redis_client
        bl_key = f"user_blacklist:{tenant_id}:{user_id}"
        return redis_client.exists(bl_key) == 1
    except Exception:
        return False


def clear_user_blacklist(user_id: int, tenant_id: int):
    """Clear the blacklist flag when a user logs in again."""
    try:
        from app.redis import redis_client
        bl_key = f"user_blacklist:{tenant_id}:{user_id}"
        redis_client.delete(bl_key)
    except Exception:
        pass
