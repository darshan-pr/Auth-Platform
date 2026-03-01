import jwt
from datetime import datetime, timedelta
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from app.config import settings
import os
from pathlib import Path

# Key storage directory - use /tmp on Railway (read-only filesystem)
_default_keys_dir = Path(__file__).resolve().parent.parent.parent / "keys"
if os.getenv("RAILWAY_ENVIRONMENT"):
    KEYS_DIR = Path("/tmp/keys")
else:
    KEYS_DIR = _default_keys_dir
PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"

def _load_or_generate_keys():
    """Load existing keys or generate new ones"""
    KEYS_DIR.mkdir(exist_ok=True)
    
    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        # Load existing keys
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )
    else:
        # Generate new keys
        private_key = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Save keys
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    return private_key, public_key

PRIVATE_KEY, PUBLIC_KEY = _load_or_generate_keys()

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
    return jwt.encode(payload, PRIVATE_KEY, algorithm=settings.JWT_ALGORITHM)

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
    return jwt.encode(payload, PRIVATE_KEY, algorithm=settings.JWT_ALGORITHM)

def verify_token(token: str) -> Optional[dict]:
    """Verify a token and return the payload"""
    try:
        payload = jwt.decode(
            token, 
            PUBLIC_KEY, 
            algorithms=[settings.JWT_ALGORITHM],
            issuer=settings.JWT_ISSUER
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
    
    # Get app-specific settings if app_id is in the token
    access_expires = None
    app_id = payload.get("app_id")
    if app_id:
        from app.models.app import App
        app = db.query(App).filter(App.app_id == app_id).first()
        if app:
            from datetime import timedelta
            access_expires = timedelta(minutes=app.access_token_expiry_minutes)
    
    # Create new access token with app-specific or default expiry
    new_access_token = create_access_token({
        "sub": payload["sub"],
        "user_id": payload.get("user_id"),
        "tenant_id": payload.get("tenant_id"),
        "app_id": app_id
    }, access_expires)
    
    return {
        "access_token": new_access_token,
        "token_type": "bearer"
    }

def revoke_token(db, token: str) -> dict:
    """Revoke a token (placeholder - implement with Redis blacklist)"""
    # TODO: Implement token blacklisting with Redis
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


def force_user_offline(user_id: int, tenant_id: int):
    """Remove the user's online presence key – effectively a force logout signal."""
    try:
        from app.redis import redis_client
        key = f"user_online:{tenant_id}:{user_id}"
        redis_client.delete(key)
        # Also set a blacklist flag so token verify can reject
        bl_key = f"user_blacklist:{tenant_id}:{user_id}"
        redis_client.setex(bl_key, 86400, "1")  # blacklisted for 24h
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

