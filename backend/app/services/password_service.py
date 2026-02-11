import bcrypt
import secrets
from app.redis import redis_client
import logging

logger = logging.getLogger(__name__)

RESET_TOKEN_EXPIRY_SECONDS = 600  # 10 minutes

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
