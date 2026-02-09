import random
import secrets
from app.redis import redis_client
import logging

logger = logging.getLogger(__name__)

OTP_EXPIRY_SECONDS = 180  # 3 minutes

def generate_otp(email: str) -> str:
    """Generate a secure 6-digit OTP and store it in Redis"""
    otp = str(random.SystemRandom().randint(100000, 999999))
    key = f"otp:{email}"
    redis_client.setex(key, OTP_EXPIRY_SECONDS, otp)
    logger.info(f"OTP generated for {email}")
    return otp

def verify_otp(email: str, otp: str) -> bool:
    """Verify the OTP against stored value"""
    key = f"otp:{email}"
    stored = redis_client.get(key)
    
    if stored is None:
        logger.warning(f"OTP not found or expired for {email}")
        return False
    
    if stored == otp:
        # Delete OTP after successful verification (one-time use)
        redis_client.delete(key)
        logger.info(f"OTP verified successfully for {email}")
        return True
    
    logger.warning(f"Invalid OTP attempt for {email}")
    return False

