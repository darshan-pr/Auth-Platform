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


def _get_logo_url() -> str:
    """Return a public logo URL that email clients can always load."""
    return "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRrugJcpnwgDvPDr6Gr41KzsEcfImRD9kpn45FCA-InPo42p8ht"


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

    smtp_server = settings.SMTP_SERVER or "smtp.gmail.com"
    smtp_port = settings.SMTP_PORT or 587

    try:
        if smtp_port == 465:
            # Port 465: implicit SSL
            with smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10) as server:
                server.login(settings.SMTP_EMAIL, settings.SMTP_PASSWORD)
                server.send_message(msg)
        else:
            # Port 587 (or other): STARTTLS
            try:
                with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
                    # Upgrade to TLS
                    server.starttls()
                    server.login(settings.SMTP_EMAIL, settings.SMTP_PASSWORD)
                    server.send_message(msg)
            except OSError as e:
                # Fallback for "Network is unreachable" (often IPv6 issues) or connection timeouts
                # Try Port 465 (Implicit SSL) as a backup
                if "unreachable" in str(e) or "101" in str(e):
                    logger.warning(f"Port {smtp_port} failed ({e}), retrying with Port 465 SSL...")
                    with smtplib.SMTP_SSL(smtp_server, 465, timeout=10) as server:
                        server.login(settings.SMTP_EMAIL, settings.SMTP_PASSWORD)
                        server.send_message(msg)
                else:
                    raise e
                    
    except Exception as e:
        logger.error(f"SMTP Error: {str(e)}")
        # If it's the login notification, just log and continue (don't crash the request)
        if "Login notification" in subject:
             return False
        raise

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
        html = _load_template("otp.html", app_name=app_name, otp=otp, logo_url=_get_logo_url())

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
        html = _load_template(
            "forgot_password_otp.html",
            app_name=app_name,
            otp=otp,
            logo_url=_get_logo_url(),
        )

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
        html = _load_template(
            "forgot_password_token.html",
            app_name=app_name,
            token=token,
            logo_url=_get_logo_url(),
        )

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
    location: str = "Unavailable",
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
            f"Location: {location}\n"
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
            location=location,
            session_expiry=session_expiry,
            access_token_expiry_minutes=str(access_token_expiry_minutes),
            refresh_token_expiry_days=str(refresh_token_expiry_days),
            logo_url=_get_logo_url(),
        )

        _send_email(to, f"New Login Detected - {app_name}", plain, html)
        logger.info(f"Login notification email sent to {to}")
        return True
    except Exception as e:
        logger.error(f"Failed to send login notification email to {to}: {str(e)}")
        # Don't raise — login notification is non-critical
        return False


def send_admin_welcome_email(to: str, tenant_name: str, app_name: str = "Auth Platform") -> bool:
    """Send welcome email after first-time admin signup."""

    if DEV_MODE:
        logger.info(f"[DEV MODE] Admin welcome email for {to} in tenant {tenant_name}")
        print(f"\n{'='*50}")
        print(f"[DEV MODE] Admin welcome email for {to} in tenant {tenant_name}")
        print(f"{'='*50}\n")
        return True

    try:
        plain = (
            f"Hello,\n\n"
            f"Welcome to {app_name}. Your admin account is now active for tenant: {tenant_name}.\n\n"
            f"Services available:\n"
            f"- Multi-tenant app and user management\n"
            f"- OAuth 2.0 with PKCE\n"
            f"- OTP and passkey authentication\n"
            f"- Security notifications and login event tracking\n"
            f"- Token lifecycle and session controls\n\n"
            f"You can now sign in to the admin console and configure your first application.\n\n"
            f"Best regards,\n{app_name} Team\n"
        )
        html = _load_template(
            "admin_welcome.html",
            app_name=app_name,
            tenant_name=tenant_name,
            admin_email=to,
            logo_url=_get_logo_url(),
        )

        _send_email(to, f"Welcome to {app_name}", plain, html)
        logger.info(f"Admin welcome email sent to {to}")
        return True
    except Exception as e:
        logger.error(f"Failed to send admin welcome email to {to}: {str(e)}")
        return False


def send_set_password_email(to: str, reset_link: str, app_name: str = "Auth Platform") -> bool:
    """Send a 'set your password' invitation email when an admin creates a user"""
    
    if DEV_MODE:
        logger.info(f"[DEV MODE] Set Password link for {to}: {reset_link}")
        print(f"\n{'='*50}")
        print(f"[DEV MODE] Set Password link for {to}: {reset_link}")
        print(f"{'='*50}\n")
        return True
    
    try:
        plain = (
            f"Hello,\n\n"
            f"An account has been created for you on {app_name}.\n\n"
            f"Please set your password by visiting the following link:\n"
            f"{reset_link}\n\n"
            f"This link will expire in 10 minutes.\n\n"
            f"If you didn't expect this email, you can safely ignore it.\n\n"
            f"Best regards,\n{app_name} Team\nSecured by Auth Platform !"
        )
        html = _load_template(
            "set_password.html",
            app_name=app_name,
            reset_link=reset_link,
            logo_url=_get_logo_url(),
        )

        _send_email(to, f"Set Your Password - {app_name}", plain, html)
        logger.info(f"Set password email sent to {to}")
        return True
    except Exception as e:
        logger.error(f"Failed to send set password email to {to}: {str(e)}")
        raise


def send_force_logout_email(to: str, app_name: str = "Auth Platform") -> bool:
    """Send a notification email when an admin force-logouts a user"""

    if DEV_MODE:
        logger.info(f"[DEV MODE] Force logout notification for {to} on {app_name}")
        print(f"\n{'='*50}")
        print(f"[DEV MODE] Force logout notification for {to} on {app_name}")
        print(f"{'='*50}\n")
        return True

    try:
        now = datetime.utcnow()
        revoked_at = now.strftime("%B %d, %Y at %I:%M %p UTC")

        plain = (
            f"Hello,\n\n"
            f"Your active session on {app_name} has been revoked by an administrator.\n\n"
            f"Account: {to}\n"
            f"Revoked At: {revoked_at}\n"
            f"Action: Force Logout by Admin\n\n"
            f"All your active tokens have been invalidated. "
            f"You will need to sign in again to continue using {app_name}.\n\n"
            f"If you believe this was done in error, please contact your administrator.\n\n"
            f"Best regards,\n{app_name} Team\nSecured by Auth Platform !"
        )
        html = _load_template(
            "force_logout.html",
            app_name=app_name,
            email=to,
            revoked_at=revoked_at,
            logo_url=_get_logo_url(),
        )

        _send_email(to, f"Session Revoked - {app_name}", plain, html)
        logger.info(f"Force logout notification email sent to {to}")
        return True
    except Exception as e:
        logger.error(f"Failed to send force logout email to {to}: {str(e)}")
        # Don't raise — this is non-critical, the force-logout itself already succeeded
        return False
