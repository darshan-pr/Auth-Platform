import smtplib
from email.message import EmailMessage
from app.config import settings
import logging
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Set to False to enable actual email sending
DEV_MODE = False

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


def _load_template(template_name: str, **kwargs) -> str:
    """Load an HTML template and substitute {{ key }} placeholders."""
    template_path = TEMPLATES_DIR / template_name
    html = template_path.read_text(encoding="utf-8")
    for key, value in kwargs.items():
        html = html.replace("{{ " + key + " }}", str(value))
    return html


def _send_email(to: str, subject: str, body_text: str, body_html: str = None) -> bool:
    """Low-level helper to send an email via SMTP."""
    if not settings.SMTP_EMAIL or not settings.SMTP_PASSWORD:
        raise ValueError("SMTP credentials not configured")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_EMAIL
    msg["To"] = to
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(settings.SMTP_EMAIL, settings.SMTP_PASSWORD)
        server.send_message(msg)

    return True

def send_otp_email(to: str, otp: str, app_name: str = "Auth Platform") -> bool:
    """Send OTP email to the specified address"""
    
    if DEV_MODE:
        logger.info(f"[DEV MODE] OTP for {to}: {otp}")
        print(f"\n{'='*50}")
        print(f"[DEV MODE] OTP for {to}: {otp}")
        print(f"{'='*50}\n")
        return True
    
    try:
        plain = (
            f"Hello,\n\n"
            f"Your OTP code is: {otp}\n\n"
            f"This code will expire in 3 minutes.\n\n"
            f"If you didn't request this code, please ignore this email.\n\n"
            f"Best regards,\n{app_name} Team\n\nSecured by Auth Platform !"
        )
        html = _load_template("otp.html", app_name=app_name, otp=otp)

        _send_email(to, f"Your OTP Code - {app_name}", plain, html)
        logger.info(f"OTP email sent to {to}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email to {to}: {str(e)}")
        raise


def send_password_reset_email(to: str, otp: str, app_name: str = "Auth Platform") -> bool:
    """Send password reset OTP email with HTML template"""
    
    if DEV_MODE:
        logger.info(f"[DEV MODE] Password Reset OTP for {to}: {otp}")
        print(f"\n{'='*50}")
        print(f"[DEV MODE] Password Reset OTP for {to}: {otp}")
        print(f"{'='*50}\n")
        return True
    
    try:
        plain = (
            f"Hello,\n\n"
            f"We received a request to reset your password.\n\n"
            f"Your password reset OTP code is: {otp}\n\n"
            f"This code will expire in 10 minutes.\n\n"
            f"If you didn't request a password reset, please ignore this email.\n\n"
            f"Best regards,\n{app_name} Team\nSecured by Auth Platform !"
        )
        html = _load_template("forgot_password_otp.html", app_name=app_name, otp=otp)

        _send_email(to, f"Password Reset Request - {app_name}", plain, html)
        logger.info(f"Password reset OTP email sent to {to}")
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email to {to}: {str(e)}")
        raise


def send_password_reset_token_email(to: str, token: str, app_name: str = "Auth Platform") -> bool:
    """Send password reset token/link email with HTML template (when OTP is disabled)"""
    
    if DEV_MODE:
        logger.info(f"[DEV MODE] Password Reset Token for {to}: {token}")
        print(f"\n{'='*50}")
        print(f"[DEV MODE] Password Reset Token for {to}: {token}")
        print(f"{'='*50}\n")
        return True
    
    try:
        plain = (
            f"Hello,\n\n"
            f"We received a request to reset your password.\n\n"
            f"Your password reset token is: {token}\n\n"
            f"This token will expire in 10 minutes.\n\n"
            f"If you didn't request a password reset, please ignore this email.\n\n"
            f"Best regards,\n{app_name} Team\nSecured by Auth Platform !"
        )
        html = _load_template("forgot_password_token.html", app_name=app_name, token=token)

        _send_email(to, f"Password Reset Request - {app_name}", plain, html)
        logger.info(f"Password reset token email sent to {to}")
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset token email to {to}: {str(e)}")
        raise


def send_login_notification_email(
    to: str,
    app_name: str = "Auth Platform",
    access_token_expiry_minutes: int = 30,
    refresh_token_expiry_days: int = 7,
) -> bool:
    """Send login notification email with session expiry details"""
    
    if DEV_MODE:
        logger.info(f"[DEV MODE] Login notification for {to} on {app_name}")
        print(f"\n{'='*50}")
        print(f"[DEV MODE] Login notification for {to} on {app_name}")
        print(f"{'='*50}\n")
        return True
    
    try:
        now = datetime.utcnow()
        login_time = now.strftime("%B %d, %Y at %I:%M %p UTC")
        session_expiry_dt = now + timedelta(days=refresh_token_expiry_days)
        session_expiry = session_expiry_dt.strftime("%B %d, %Y at %I:%M %p UTC")

        plain = (
            f"Hello,\n\n"
            f"A successful login was detected on your account at {app_name}.\n\n"
            f"Email: {to}\n"
            f"Login Time: {login_time}\n"
            f"Session Expiry: {session_expiry}\n"
            f"Access Token: Expires in {access_token_expiry_minutes} minutes\n"
            f"Refresh Token: Expires in {refresh_token_expiry_days} days\n\n"
            f"If this wasn't you, please reset your password immediately.\n\n"
            f"Best regards,\n{app_name} Team\nSecured by Auth Platform !"
        )
        html = _load_template(
            "login_notification.html",
            app_name=app_name,
            email=to,
            login_time=login_time,
            session_expiry=session_expiry,
            access_token_expiry_minutes=str(access_token_expiry_minutes),
            refresh_token_expiry_days=str(refresh_token_expiry_days),
        )

        _send_email(to, f"New Login Detected - {app_name}", plain, html)
        logger.info(f"Login notification email sent to {to}")
        return True
    except Exception as e:
        logger.error(f"Failed to send login notification email to {to}: {str(e)}")
        # Don't raise — login notification is non-critical
        return False
