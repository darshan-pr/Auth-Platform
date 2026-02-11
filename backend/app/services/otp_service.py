import random
import secrets
from app.redis import redis_client
import logging

logger = logging.getLogger(__name__)

OTP_EXPIRY_SECONDS = 180  # 3 minutes
PASSWORD_RESET_OTP_EXPIRY_SECONDS = 600  # 10 minutes

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


def generate_password_reset_otp(email: str, app_id: str) -> str:
    """Generate a secure 6-digit OTP for password reset and store it in Redis with longer expiry"""
    otp = str(random.SystemRandom().randint(100000, 999999))
    key = f"password_reset_otp:{email}:{app_id}"
    redis_client.setex(key, PASSWORD_RESET_OTP_EXPIRY_SECONDS, otp)
    logger.info(f"Password reset OTP generated for {email} (app: {app_id})")
    return otp

def verify_password_reset_otp(email: str, app_id: str, otp: str) -> bool:
    """Verify the password reset OTP against stored value"""
    key = f"password_reset_otp:{email}:{app_id}"
    stored = redis_client.get(key)
    
    if stored is None:
        logger.warning(f"Password reset OTP not found or expired for {email} (app: {app_id})")
        return False
    
    if stored == otp:
        # Delete OTP after successful verification (one-time use)
        redis_client.delete(key)
        logger.info(f"Password reset OTP verified successfully for {email} (app: {app_id})")
        return True
    
    logger.warning(f"Invalid password reset OTP attempt for {email} (app: {app_id})")
    return False
