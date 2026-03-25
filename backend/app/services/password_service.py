import bcrypt
import secrets
from app.redis import redis_client
import logging
from typing import Optional

logger = logging.getLogger(__name__)

RESET_TOKEN_EXPIRY_SECONDS = 600  # 10 minutes


def validate_password_strength(password: str) -> Optional[str]:
    """Return a validation error message if password is weak, else None."""
    if len(password) < 8:
        return "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one digit"
    return None


def enforce_password_strength(password: str) -> None:
    """Raise ValueError when password does not meet policy."""
    error = validate_password_strength(password)
    if error:
        raise ValueError(error)

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    # Encode the password and hash it
    password_bytes = password.encode('utf-8')
    # Truncate to 72 bytes (bcrypt limit)
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a hash"""
    password_bytes = password.encode('utf-8')
    # Truncate to 72 bytes (bcrypt limit)
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    hashed_bytes = hashed.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

def generate_reset_token(email: str, app_id: str) -> str:
    """Generate a secure password reset token and store it in Redis"""
    token = secrets.token_urlsafe(32)
    key = f"reset_token:{email}:{app_id}"
    redis_client.setex(key, RESET_TOKEN_EXPIRY_SECONDS, token)
    logger.info(f"Password reset token generated for {email} (app: {app_id})")
    return token

def verify_reset_token(email: str, app_id: str, token: str) -> bool:
    """Verify the password reset token against stored value"""
    key = f"reset_token:{email}:{app_id}"
    stored = redis_client.get(key)
    
    if stored is None:
        logger.warning(f"Reset token not found or expired for {email} (app: {app_id})")
        return False
    
    if stored == token:
        # Delete token after successful verification (one-time use)
        redis_client.delete(key)
        logger.info(f"Reset token verified successfully for {email} (app: {app_id})")
        return True
    
    logger.warning(f"Invalid reset token attempt for {email} (app: {app_id})")
    return False
