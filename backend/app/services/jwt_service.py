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
        "type": "access"
    })
    return jwt.encode(payload, PRIVATE_KEY, algorithm=settings.JWT_ALGORITHM)

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a new refresh token"""
    payload = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
    payload.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "iss": settings.JWT_ISSUER,
        "type": "refresh"
    })
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

