import smtplib
from email.message import EmailMessage
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# Set to False to enable actual email sending
DEV_MODE = False

def send_otp_email(to: str, otp: str) -> bool:
    """Send OTP email to the specified address"""
    
    if DEV_MODE:
        # In development mode, just log the OTP instead of sending email
        logger.info(f"[DEV MODE] OTP for {to}: {otp}")
        print(f"\n{'='*50}")
        print(f"[DEV MODE] OTP for {to}: {otp}")
        print(f"{'='*50}\n")
        return True
    
    try:
        if not settings.SMTP_EMAIL or not settings.SMTP_PASSWORD:
            raise ValueError("SMTP credentials not configured")
        
        msg = EmailMessage()
        msg["Subject"] = "Your OTP Code - Auth Platform"
        msg["From"] = settings.SMTP_EMAIL
        msg["To"] = to
        msg.set_content(f"""
Hello,

Your OTP code is: {otp}

This code will expire in 3 minutes.

If you didn't request this code, please ignore this email.

Best regards,
Auth Platform Team
        """)

        # Simple Gmail SMTP - works like other projects
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(settings.SMTP_EMAIL, settings.SMTP_PASSWORD)
            server.send_message(msg)
        
        logger.info(f"OTP email sent to {to}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email to {to}: {str(e)}")
        raise

