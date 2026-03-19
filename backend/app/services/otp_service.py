import random
import secrets
from app.redis import redis_client
import logging

logger = logging.getLogger(__name__)

OTP_EXPIRY_SECONDS = 180  # 3 minutes
PASSWORD_RESET_OTP_EXPIRY_SECONDS = 600  # 10 minutes

# Brute-force protection
MAX_OTP_ATTEMPTS = 5
OTP_LOCKOUT_SECONDS = 900  # 15 minutes


def _get_otp_attempts_key(email: str) -> str:
    return f"otp_attempts:{email}"


def _get_otp_lockout_key(email: str) -> str:
    return f"otp_lockout:{email}"


def _check_otp_lockout(email: str) -> bool:
    """Check if OTP verification is locked out for this email. Returns True if locked."""
    try:
        lockout_key = _get_otp_lockout_key(email)
        ttl = redis_client.ttl(lockout_key)
        return ttl is not None and ttl > 0
    except Exception:
        return False  # Redis down — fail open


def _record_failed_otp_attempt(email: str):
    """Record a failed OTP attempt. Deletes OTP and locks out after MAX_OTP_ATTEMPTS."""
    try:
        attempts_key = _get_otp_attempts_key(email)
        count = redis_client.incr(attempts_key)
        redis_client.expire(attempts_key, OTP_LOCKOUT_SECONDS)
        if count >= MAX_OTP_ATTEMPTS:
            # Lock out and delete the OTP (force re-generation)
            lockout_key = _get_otp_lockout_key(email)
            redis_client.setex(lockout_key, OTP_LOCKOUT_SECONDS, "1")
            redis_client.delete(attempts_key)
            redis_client.delete(f"otp:{email}")
            logger.warning(f"OTP verification locked out for {email} after {count} failed attempts")
    except Exception:
        pass  # Redis down — fail open


def _clear_otp_attempts(email: str):
    """Clear OTP attempt counter on successful verification."""
    try:
        redis_client.delete(_get_otp_attempts_key(email))
        redis_client.delete(_get_otp_lockout_key(email))
    except Exception:
        pass


def generate_otp(email: str) -> str:
    """Generate a secure 6-digit OTP and store it in Redis"""
    otp = str(random.SystemRandom().randint(100000, 999999))
    key = f"otp:{email}"
    redis_client.setex(key, OTP_EXPIRY_SECONDS, otp)
    logger.info(f"OTP generated for {email}")
    return otp

def verify_otp(email: str, otp: str) -> bool:
    """Verify the OTP against stored value with brute-force protection"""
    # Check lockout first
    if _check_otp_lockout(email):
        logger.warning(f"OTP verification blocked — account locked for {email}")
        return False

    key = f"otp:{email}"
    stored = redis_client.get(key)
    
    if stored is None:
        logger.warning(f"OTP not found or expired for {email}")
        return False
    
    if stored == otp:
        # Delete OTP after successful verification (one-time use)
        redis_client.delete(key)
        _clear_otp_attempts(email)
        logger.info(f"OTP verified successfully for {email}")
        return True
    
    # Wrong OTP — record failed attempt
    _record_failed_otp_attempt(email)
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
    """Verify the password reset OTP against stored value with brute-force protection"""
    reset_lockout_key = f"otp_lockout:reset:{email}:{app_id}"
    reset_attempts_key = f"otp_attempts:reset:{email}:{app_id}"

    # Check lockout
    try:
        ttl = redis_client.ttl(reset_lockout_key)
        if ttl and ttl > 0:
            logger.warning(f"Password reset OTP locked for {email}")
            return False
    except Exception:
        pass

    key = f"password_reset_otp:{email}:{app_id}"
    stored = redis_client.get(key)
    
    if stored is None:
        logger.warning(f"Password reset OTP not found or expired for {email} (app: {app_id})")
        return False
    
    if stored == otp:
        # Delete OTP after successful verification (one-time use)
        redis_client.delete(key)
        try:
            redis_client.delete(reset_attempts_key)
            redis_client.delete(reset_lockout_key)
        except Exception:
            pass
        logger.info(f"Password reset OTP verified successfully for {email} (app: {app_id})")
        return True
    
    # Wrong OTP — record failed attempt
    try:
        count = redis_client.incr(reset_attempts_key)
        redis_client.expire(reset_attempts_key, OTP_LOCKOUT_SECONDS)
        if count >= MAX_OTP_ATTEMPTS:
            redis_client.setex(reset_lockout_key, OTP_LOCKOUT_SECONDS, "1")
            redis_client.delete(reset_attempts_key)
            redis_client.delete(key)  # Force re-generation
            logger.warning(f"Password reset OTP locked for {email} after {count} failed attempts")
    except Exception:
        pass

    logger.warning(f"Invalid password reset OTP attempt for {email} (app: {app_id})")
    return False


def _get_password_reset_verified_key(email: str, app_id: str) -> str:
    return f"password_reset_verified:{email}:{app_id}"


def mark_password_reset_otp_verified(email: str, app_id: str) -> None:
    """Mark a password reset OTP as verified for a short window."""
    key = _get_password_reset_verified_key(email, app_id)
    redis_client.setex(key, PASSWORD_RESET_OTP_EXPIRY_SECONDS, "1")


def is_password_reset_otp_verified(email: str, app_id: str) -> bool:
    """Check whether password reset OTP was verified recently."""
    key = _get_password_reset_verified_key(email, app_id)
    value = redis_client.get(key)
    return value == "1" or value == b"1"


def clear_password_reset_otp_verified(email: str, app_id: str) -> None:
    """Clear the password reset OTP verification marker."""
    key = _get_password_reset_verified_key(email, app_id)
    redis_client.delete(key)
