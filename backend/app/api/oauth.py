"""
OAuth 2.0 Authorization Code Flow with PKCE

Endpoints:
  GET  /oauth/authorize    — Renders the hosted login page (like Google's login screen)
  POST /oauth/authenticate — Internal API for the login page to verify credentials
  POST /oauth/token        — Token exchange: authorization_code + PKCE → access/refresh tokens
"""

from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from pathlib import Path
from urllib.parse import urlparse

from app.db import get_db
from app.models.app import App
from app.models.user import User
from app.models.admin import Admin
from app.models.passkey import PasskeyCredential
from app.services.oauth_service import (
    create_oauth_session,
    get_oauth_session,
    delete_oauth_session,
    generate_authorization_code,
    validate_authorization_code,
)
from app.services.password_service import hash_password, verify_password
from app.services.otp_service import (
    generate_otp,
    verify_otp,
    generate_password_reset_otp,
    verify_password_reset_otp,
    mark_password_reset_otp_verified,
    is_password_reset_otp_verified,
    clear_password_reset_otp_verified,
)
from app.services.mail_service import send_otp_email, send_login_notification_email, send_password_reset_email
from app.services.passkey_service import (
    generate_passkey_registration_challenge,
    verify_passkey_registration,
    generate_passkey_auth_challenge,
    verify_passkey_authentication,
    generate_passkey_registration_otp,
    verify_passkey_registration_otp,
    is_passkey_registration_verified,
    clear_passkey_registration_verified,
)
from app.api.auth import generate_tokens_for_user
from app.services.jwt_service import mark_user_online, is_user_blacklisted, clear_user_blacklist
from app.services.rate_limiter import create_rate_limit_dependency
from app.services.geo_service import record_login_event, get_client_ip, get_location
from app.services.dpop_service import validate_dpop_proof, create_dpop_thumbprint
from app.config import settings
import logging


logger = logging.getLogger(__name__)


def _get_admin_contact_email(db: Session, tenant_id: int) -> str:
    """Look up the admin email for a tenant so users know whom to contact."""
    admin = db.query(Admin).filter(Admin.tenant_id == tenant_id).first()
    return admin.email if admin else "your administrator"

router = APIRouter(prefix="/oauth")

# Rate limit dependencies
_rl_oauth_auth = create_rate_limit_dependency("oauth_auth", max_requests=settings.RATE_LIMIT_LOGIN)
_rl_oauth_token = create_rate_limit_dependency("oauth_token", max_requests=settings.RATE_LIMIT_GENERAL)

templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates")
)


# ==================== Redirect URI Validation ====================

def validate_redirect_uri(app: App, redirect_uri: str) -> bool:
    """
    Validate that redirect_uri is registered for this app.
    - If app has redirect_uris configured: strict match required
    - If no redirect_uris configured: allow localhost only (dev mode)
    """
    if app.redirect_uris:
        allowed = [uri.strip() for uri in app.redirect_uris.split(",")]
        return redirect_uri in allowed

    # Dev mode fallback: allow localhost when no URIs configured
    parsed = urlparse(redirect_uri)
    return parsed.hostname in ("localhost", "127.0.0.1")


# ==================== GET /oauth/authorize ====================

@router.get("/authorize", response_class=HTMLResponse)
def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    state: str = None,
    code_challenge: str = None,
    code_challenge_method: str = "S256",
    db: Session = Depends(get_db),
):
    """
    OAuth 2.0 Authorization Endpoint.
    
    Validates all parameters and renders the auth platform's hosted login page.
    This is the equivalent of Google's login screen — the auth platform owns this UI.
    
    Client apps redirect here; they never see user credentials.
    """
    error_ctx = {
        "request": request,
        "error": None,
        "session_id": None,
        "app_name": "",
        "app_logo_url": "/assets/logo.png",
        "app_id": "",
        "otp_enabled": False,
        "auth_platform_url": settings.AUTH_PLATFORM_URL,
    }

    # Validate response_type
    if response_type != "code":
        error_ctx["error"] = "Unsupported response_type. Only 'code' is supported."
        return templates.TemplateResponse("auth.html", error_ctx)

    # Validate client_id
    app = db.query(App).filter(App.app_id == client_id).first()
    if not app:
        error_ctx["error"] = "Invalid client_id. This application is not registered."
        return templates.TemplateResponse("auth.html", error_ctx)

    # Validate redirect_uri
    if not validate_redirect_uri(app, redirect_uri):
        error_ctx["error"] = "Invalid redirect_uri. This URI is not registered for this application."
        return templates.TemplateResponse("auth.html", error_ctx)

    # PKCE is mandatory for security
    if not code_challenge:
        error_ctx["error"] = "PKCE code_challenge is required. Public clients must use PKCE."
        return templates.TemplateResponse("auth.html", error_ctx)

    # State is mandatory for CSRF protection
    if not state:
        error_ctx["error"] = "state parameter is required for CSRF protection."
        return templates.TemplateResponse("auth.html", error_ctx)

    # Create OAuth session in Redis
    session_id = create_oauth_session(
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

    return templates.TemplateResponse("auth.html", {
        "request": request,
        "session_id": session_id,
        "app_name": app.name or "Application",
        "app_logo_url": app.logo_url or "/assets/logo.png",
        "app_id": client_id,
        "otp_enabled": app.otp_enabled,
        "passkey_enabled": app.passkey_enabled,
        "auth_platform_url": settings.AUTH_PLATFORM_URL,
        "error": None,
    })


# ==================== POST /oauth/authenticate ====================

class AuthenticateRequest(BaseModel):
    session_id: str
    action: str  # "login", "signup", "verify_otp", "verify_signup_otp", "forgot_password", "verify_reset_otp", "reset_password", "passkey_register_begin", "passkey_register_verify_otp", "passkey_register_complete", "passkey_auth_begin", "passkey_auth_complete"
    email: Optional[str] = None
    password: Optional[str] = None
    otp: Optional[str] = None
    new_password: Optional[str] = None
    # Passkey fields
    credential: Optional[dict] = None
    rp_id: Optional[str] = None


@router.post("/authenticate", dependencies=[Depends(_rl_oauth_auth)])
def authenticate(req: AuthenticateRequest, request: Request = None, db: Session = Depends(get_db)):
    """
    Internal API called by the hosted login page.
    
    Handles three actions:
      - signup:     Create account → always require email OTP verification
      - login:      Verify credentials → return auth code (or ask for OTP)
      - verify_otp: Verify OTP → return auth code
      - verify_signup_otp: Verify OTP → complete signup only (no sign-in)
      - verify_reset_otp: Verify reset OTP only (before showing password form)
    
    On successful auth, returns { action: "redirect", redirect_url: "..." }
    The login page JavaScript then navigates to that URL.
    """
    # Validate OAuth session
    session = get_oauth_session(req.session_id)
    if not session:
        raise HTTPException(
            status_code=400,
            detail="Session expired. Please go back and try again."
        )

    app = db.query(App).filter(App.app_id == session["client_id"]).first()
    if not app:
        raise HTTPException(status_code=400, detail="Invalid application")

    if req.action == "signup":
        return _handle_signup(req, session, app, db)
    elif req.action == "login":
        return _handle_login(req, session, app, db, request)
    elif req.action == "verify_otp":
        return _handle_verify_otp(req, session, app, db, request)
    elif req.action == "verify_signup_otp":
        return _handle_verify_signup_otp(req, session, app, db)
    elif req.action == "forgot_password":
        return _handle_forgot_password(req, session, app, db)
    elif req.action == "verify_reset_otp":
        return _handle_verify_reset_otp(req, session, app, db)
    elif req.action == "reset_password":
        return _handle_reset_password(req, session, app, db)
    elif req.action == "passkey_register_begin":
        return _handle_passkey_register_begin(req, session, app, db)
    elif req.action == "passkey_register_verify_otp":
        return _handle_passkey_register_verify_otp(req, session, app, db)
    elif req.action == "passkey_register_complete":
        return _handle_passkey_register_complete(req, session, app, db)
    elif req.action == "passkey_auth_begin":
        return _handle_passkey_auth_begin(req, session, app, db)
    elif req.action == "passkey_auth_complete":
        return _handle_passkey_auth_complete(req, session, app, db, request)
    elif req.action == "passkey_check":
        return _handle_passkey_check(req, session, app, db)
    else:
        raise HTTPException(status_code=400, detail="Invalid action")


def _handle_signup(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Create a new user account and require signup OTP verification."""
    # Check if user exists for this specific app within tenant
    existing = db.query(User).filter(
        User.email == req.email,
        User.tenant_id == app.tenant_id,
        User.app_id == session["client_id"]
    ).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail="An account with this email already exists. Please login instead."
        )

    # Validate password strength
    if not req.password or len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not any(c.isupper() for c in req.password):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter")
    if not any(c.islower() for c in req.password):
        raise HTTPException(status_code=400, detail="Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in req.password):
        raise HTTPException(status_code=400, detail="Password must contain at least one digit")

    # Create user
    hashed = hash_password(req.password)
    user = User(
        email=req.email,
        password_hash=hashed,
        app_id=session["client_id"],
        tenant_id=app.tenant_id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    try:
        otp = generate_otp(req.email)
        send_otp_email(req.email, otp, app.name or "Auth Platform", app.logo_url)
        return {
            "action": "show_signup_otp",
            "message": "Account created. A verification code has been sent to your email."
        }
    except Exception:
        logger.exception("Failed to send signup verification code for %s", req.email)
        # Signup email verification is mandatory; remove the just-created account on failure.
        db.delete(user)
        db.commit()
        raise HTTPException(
            status_code=500,
            detail="Failed to send verification code. Please try again."
        )


def _handle_login(req: AuthenticateRequest, session: dict, app: App, db: Session, http_request: Request = None):
    """Verify email + password, then either issue code or request OTP"""
    user = db.query(User).filter(
        User.email == req.email,
        User.tenant_id == app.tenant_id,
        User.app_id == session["client_id"]
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.password_hash:
        raise HTTPException(status_code=400, detail="User does not have a password set. Please sign up first.")

    if not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")

    if not user.is_active:
        admin_email = _get_admin_contact_email(db, app.tenant_id)
        raise HTTPException(
            status_code=403,
            detail=f"Your account has been temporarily deactivated by the administrator. "
                   f"Please contact {admin_email} for further assistance."
        )

    # If user was force-logged-out, clear the blacklist now — they're proving identity again
    if is_user_blacklisted(user.id, app.tenant_id):
        clear_user_blacklist(user.id, app.tenant_id)

    # Check if OTP is required
    if app.otp_enabled:
        try:
            otp = generate_otp(req.email)
            send_otp_email(req.email, otp, app.name or "Auth Platform", app.logo_url)
            return {
                "action": "show_otp",
                "message": "A verification code has been sent to your email."
            }
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to send verification code: {str(e)}"
            )
    else:
        # No OTP needed — complete authentication
        return _complete_auth(session, user, req.session_id, app, db=db, http_request=http_request)


def _handle_verify_otp(req: AuthenticateRequest, session: dict, app: App, db: Session, http_request: Request = None):
    """Verify OTP and complete authentication"""
    if not req.otp:
        raise HTTPException(status_code=400, detail="Verification code is required")

    if not verify_otp(req.email, req.otp):
        raise HTTPException(status_code=401, detail="Invalid or expired verification code")

    user = db.query(User).filter(
        User.email == req.email,
        User.tenant_id == app.tenant_id,
        User.app_id == session["client_id"]
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return _complete_auth(session, user, req.session_id, app, db=db, http_request=http_request)


def _handle_verify_signup_otp(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Verify OTP for signup completion only (no automatic sign-in)."""
    if not req.otp:
        raise HTTPException(status_code=400, detail="Verification code is required")

    if not verify_otp(req.email, req.otp):
        raise HTTPException(status_code=401, detail="Invalid or expired verification code")

    user = db.query(User).filter(
        User.email == req.email,
        User.tenant_id == app.tenant_id,
        User.app_id == session["client_id"]
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "action": "show_login",
        "message": "Email verified. Sign up complete. Please sign in."
    }


def _handle_forgot_password(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Send password reset OTP to user's email (no email enumeration)"""
    user = db.query(User).filter(
        User.email == req.email,
        User.tenant_id == app.tenant_id,
        User.app_id == session["client_id"]
    ).first()
    if not user or not user.password_hash:
        # Don't reveal whether user exists — return generic success
        import logging
        logging.getLogger(__name__).info(f"Forgot password requested for unknown/passwordless user via OAuth: {req.email}")
        return {
            "action": "show_reset_otp",
            "message": "If an account exists with this email, a password reset code has been sent."
        }

    try:
        otp = generate_password_reset_otp(req.email, session["client_id"])
        send_password_reset_email(req.email, otp, app.name or "Auth Platform", app.logo_url)
        return {
            "action": "show_reset_otp",
            "message": "A password reset code has been sent to your email."
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send reset code: {str(e)}"
        )


def _handle_verify_reset_otp(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Verify reset OTP and mark reset flow as verified for a short period."""
    if not req.otp:
        raise HTTPException(status_code=400, detail="Verification code is required")

    if not verify_password_reset_otp(req.email, session["client_id"], req.otp):
        raise HTTPException(status_code=401, detail="Invalid or expired verification code")

    user = db.query(User).filter(
        User.email == req.email,
        User.tenant_id == app.tenant_id,
        User.app_id == session["client_id"]
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    mark_password_reset_otp_verified(req.email, session["client_id"])
    return {
        "action": "show_reset_password_form",
        "message": "Code verified. You can now set a new password."
    }


def _handle_reset_password(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Verify OTP and reset the user's password"""
    if not req.new_password or len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")

    if req.otp:
        if not verify_password_reset_otp(req.email, session["client_id"], req.otp):
            raise HTTPException(status_code=401, detail="Invalid or expired verification code")
    elif not is_password_reset_otp_verified(req.email, session["client_id"]):
        raise HTTPException(status_code=400, detail="Please verify your reset code first")

    user = db.query(User).filter(
        User.email == req.email,
        User.tenant_id == app.tenant_id,
        User.app_id == session["client_id"]
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.password_hash = hash_password(req.new_password)
    db.commit()
    clear_password_reset_otp_verified(req.email, session["client_id"])

    return {
        "action": "password_reset_success",
        "message": "Password reset successfully. Please sign in with your new password."
    }


# ==================== Passkey Handlers ====================

def _handle_passkey_register_begin(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Start passkey registration - send OTP to verify email ownership first"""
    logger.info("passkey_register_begin requested for email=%s app_id=%s", req.email, session.get("client_id"))
    if not app.passkey_enabled:
        raise HTTPException(status_code=400, detail="Passkeys are not enabled for this application")

    if not req.email:
        raise HTTPException(status_code=400, detail="Email is required")

    user = db.query(User).filter(
        User.email == req.email,
        User.tenant_id == app.tenant_id,
        User.app_id == session["client_id"]
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found. Please sign up first.")

    # Send OTP to verify email ownership before allowing passkey registration
    try:
        otp = generate_passkey_registration_otp(req.email, session["client_id"])
        send_otp_email(req.email, otp, app.name or "Auth Platform", app.logo_url)
        return {
            "action": "passkey_register_otp",
            "message": "A verification code has been sent to your email. Please enter it to proceed with passkey registration."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send verification code: {str(e)}")


def _handle_passkey_register_verify_otp(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Verify OTP and then return the WebAuthn registration challenge"""
    logger.info("passkey_register_verify_otp requested for email=%s app_id=%s", req.email, session.get("client_id"))
    if not app.passkey_enabled:
        raise HTTPException(status_code=400, detail="Passkeys are not enabled for this application")

    if not req.email or not req.otp:
        raise HTTPException(status_code=400, detail="Email and OTP are required")

    if not verify_passkey_registration_otp(req.email, session["client_id"], req.otp):
        raise HTTPException(status_code=401, detail="Invalid or expired verification code")

    user = db.query(User).filter(
        User.email == req.email,
        User.tenant_id == app.tenant_id,
        User.app_id == session["client_id"]
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    rp_id = req.rp_id or "localhost"
    options = generate_passkey_registration_challenge(req.email, session["client_id"], rp_id)

    # Include existing credential IDs to exclude
    existing_creds = db.query(PasskeyCredential).filter(
        PasskeyCredential.user_id == user.id,
        PasskeyCredential.app_id == session["client_id"]
    ).all()
    if existing_creds:
        options["excludeCredentials"] = [
            {"type": "public-key", "id": cred.credential_id}
            for cred in existing_creds
        ]

    return {"action": "passkey_register_options", "options": options}


def _handle_passkey_register_complete(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Complete passkey registration - verify OTP flag, verify credential, and store"""
    logger.info("passkey_register_complete requested for email=%s app_id=%s", req.email, session.get("client_id"))
    if not app.passkey_enabled:
        raise HTTPException(status_code=400, detail="Passkeys are not enabled for this application")

    if not req.email or not req.credential:
        raise HTTPException(status_code=400, detail="Email and credential data are required")

    # Ensure the email was OTP-verified for passkey registration
    if not is_passkey_registration_verified(req.email, session["client_id"]):
        raise HTTPException(
            status_code=403,
            detail="Email verification required before registering a passkey. Please complete OTP verification first."
        )

    user = db.query(User).filter(
        User.email == req.email,
        User.tenant_id == app.tenant_id,
        User.app_id == session["client_id"]
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    rp_id = req.rp_id or "localhost"
    cred = req.credential

    result = verify_passkey_registration(
        user_email=req.email,
        app_id=session["client_id"],
        rp_id=rp_id,
        credential_id=cred.get("id", ""),
        client_data_json_b64=cred.get("clientDataJSON", ""),
        attestation_object_b64=cred.get("attestationObject", ""),
    )

    if not result:
        raise HTTPException(status_code=400, detail="Passkey registration verification failed")

    # Clear the OTP verification flag (one-time use)
    clear_passkey_registration_verified(req.email, session["client_id"])

    # Store the credential with algorithm info for future signature verification
    passkey = PasskeyCredential(
        user_id=user.id,
        app_id=session["client_id"],
        tenant_id=app.tenant_id,
        credential_id=result["credential_id"],
        public_key=result["public_key"],
        sign_count=result["sign_count"],
        algorithm=result.get("algorithm", -7),
        device_name=cred.get("deviceName", "Unknown Device"),
    )
    db.add(passkey)
    db.commit()

    return {
        "action": "passkey_registered",
        "message": "Passkey registered successfully! You can now use it to sign in."
    }


def _handle_passkey_check(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Check if a user has any passkeys registered"""
    if not app.passkey_enabled:
        return {"has_passkey": False}

    if not req.email:
        return {"has_passkey": False}

    user = db.query(User).filter(
        User.email == req.email,
        User.tenant_id == app.tenant_id,
        User.app_id == session["client_id"]
    ).first()
    if not user:
        return {"has_passkey": False}

    count = db.query(PasskeyCredential).filter(
        PasskeyCredential.user_id == user.id,
        PasskeyCredential.app_id == session["client_id"]
    ).count()

    return {"has_passkey": count > 0}


def _handle_passkey_auth_begin(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Start passkey authentication - generate challenge with allowed credentials"""
    if not app.passkey_enabled:
        raise HTTPException(status_code=400, detail="Passkeys are not enabled for this application")

    if not req.email:
        raise HTTPException(status_code=400, detail="Email is required for passkey sign-in")

    user = db.query(User).filter(
        User.email == req.email,
        User.tenant_id == app.tenant_id,
        User.app_id == session["client_id"]
    ).first()

    if not user:
        return {
            "action": "no_passkey_for_account",
            "message": "No passkey is linked to this account yet."
        }

    rp_id = req.rp_id or "localhost"

    # Limit auth to credentials linked to the provided account
    user_creds = db.query(PasskeyCredential).filter(
        PasskeyCredential.user_id == user.id,
        PasskeyCredential.app_id == session["client_id"]
    ).all()

    if not user_creds:
        return {
            "action": "no_passkey_for_account",
            "message": "No passkey is linked to this account yet."
        }

    credential_ids = [cred.credential_id for cred in user_creds]
    options = generate_passkey_auth_challenge(session["client_id"], rp_id, credential_ids=credential_ids)

    return {"action": "passkey_auth_options", "options": options}


def _handle_passkey_auth_complete(req: AuthenticateRequest, session: dict, app: App, db: Session, http_request: Request = None):
    """Complete passkey authentication - verify assertion"""
    if not app.passkey_enabled:
        raise HTTPException(status_code=400, detail="Passkeys are not enabled for this application")

    if not req.email or not req.credential:
        raise HTTPException(status_code=400, detail="Email and credential data are required")

    user = db.query(User).filter(
        User.email == req.email,
        User.tenant_id == app.tenant_id,
        User.app_id == session["client_id"]
    ).first()

    if not user:
        raise HTTPException(status_code=401, detail="Passkey does not match this account")

    cred = req.credential
    credential_id = cred.get("id", "")

    # Find the stored credential
    stored_cred = db.query(PasskeyCredential).filter(
        PasskeyCredential.credential_id == credential_id,
        PasskeyCredential.app_id == session["client_id"]
    ).first()

    if not stored_cred or stored_cred.user_id != user.id:
        raise HTTPException(status_code=401, detail="Passkey does not match this account")

    rp_id = req.rp_id or "localhost"

    new_sign_count = verify_passkey_authentication(
        app_id=session["client_id"],
        rp_id=rp_id,
        credential_id=credential_id,
        client_data_json_b64=cred.get("clientDataJSON", ""),
        authenticator_data_b64=cred.get("authenticatorData", ""),
        signature_b64=cred.get("signature", ""),
        stored_public_key_b64=stored_cred.public_key,
        stored_sign_count=stored_cred.sign_count,
        stored_algorithm=getattr(stored_cred, 'algorithm', -7),
    )

    if new_sign_count is None:
        raise HTTPException(status_code=401, detail="Passkey verification failed")

    # Update sign count and last used
    stored_cred.sign_count = new_sign_count
    from datetime import datetime, timezone
    stored_cred.last_used_at = datetime.now(timezone.utc)
    db.commit()

    if not user.is_active:
        admin_email = _get_admin_contact_email(db, app.tenant_id)
        raise HTTPException(
            status_code=403,
            detail=f"Your account has been temporarily deactivated by the administrator. "
                   f"Please contact {admin_email} for further assistance."
        )

    return _complete_auth(session, user, req.session_id, app, db=db, http_request=http_request)


def _complete_auth(session: dict, user: User, session_id: str, app: App = None, db: Session = None, http_request: Request = None):
    """
    Generate authorization code and return redirect URL.
    This is the final step — the login page redirects the user back to the client app.
    """
    code = generate_authorization_code(
        client_id=session["client_id"],
        redirect_uri=session["redirect_uri"],
        user_email=user.email,
        user_id=user.id,
        code_challenge=session["code_challenge"],
        code_challenge_method=session["code_challenge_method"],
    )

    # Clean up the OAuth session
    delete_oauth_session(session_id)

    # Mark user online in Redis
    if app:
        ttl = int(app.access_token_expiry_minutes * 60) + 60
        mark_user_online(user.id, app.tenant_id, ttl_seconds=ttl)
        clear_user_blacklist(user.id, app.tenant_id)

    # Send login notification if enabled
    if app and app.login_notification_enabled:
        location_str = "Unavailable"
        if http_request:
            ip = get_client_ip(http_request)
            geo = get_location(ip)
            parts = [geo.get("city"), geo.get("region"), geo.get("country")]
            location_str = ", ".join([p for p in parts if p]) or "Unavailable"
        send_login_notification_email(
            to=user.email,
            app_name=app.name or "Auth Platform",
            access_token_expiry_minutes=app.access_token_expiry_minutes,
            refresh_token_expiry_days=app.refresh_token_expiry_days,
            location=location_str,
            app_logo_url=app.logo_url,
        )

    # Record login event with IP/location
    if db and http_request and app:
        record_login_event(db, user.id, session["client_id"], app.tenant_id, http_request, "oauth_login")

    # Build redirect URL with code and state
    redirect_uri = session["redirect_uri"]
    separator = "&" if "?" in redirect_uri else "?"
    redirect_url = f"{redirect_uri}{separator}code={code}&state={session['state']}"

    return {"action": "redirect", "redirect_url": redirect_url}


# ==================== POST /oauth/token ====================

class TokenExchangeRequest(BaseModel):
    grant_type: str  # Must be "authorization_code"
    code: str
    client_id: str
    redirect_uri: str
    code_verifier: str  # PKCE proof — proves this is the same client that started the flow
    client_secret: Optional[str] = None  # Optional: for confidential clients (backend apps)


@router.post("/token", dependencies=[Depends(_rl_oauth_token)])
def token_exchange(req: TokenExchangeRequest, request: Request = None, db: Session = Depends(get_db)):
    """
    OAuth 2.0 Token Endpoint.
    
    Exchanges an authorization code + PKCE code_verifier for access/refresh tokens.
    
    Security:
    - Authorization code is single-use (deleted from Redis on first use)
    - PKCE code_verifier must match the code_challenge from the authorize request
    - No app_secret required — PKCE replaces it for public clients (SPAs)
    - client_id and redirect_uri must match the original authorize request
    """
    if req.grant_type != "authorization_code":
        raise HTTPException(
            status_code=400,
            detail="Unsupported grant_type. Only 'authorization_code' is supported."
        )

    # Validate code + PKCE
    code_data = validate_authorization_code(
        code=req.code,
        client_id=req.client_id,
        redirect_uri=req.redirect_uri,
        code_verifier=req.code_verifier,
    )

    if not code_data:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authorization code, or PKCE verification failed."
        )

    # Get app for token expiry settings and tenant context
    app = db.query(App).filter(App.app_id == req.client_id).first()

    # --- Client Authentication (confidential clients) ---
    if req.client_secret:
        if not app:
            raise HTTPException(status_code=401, detail="Invalid client_id")
        # Use hash comparison for secrets
        import hashlib, hmac
        if len(app.app_secret) == 64:
            provided_hash = hashlib.sha256(req.client_secret.encode()).hexdigest()
            if not hmac.compare_digest(provided_hash, app.app_secret):
                raise HTTPException(status_code=401, detail="Invalid client_secret")
        else:
            if app.app_secret != req.client_secret:
                raise HTTPException(status_code=401, detail="Invalid client_secret")

    # Get user for this tenant and app
    user = db.query(User).filter(
        User.email == code_data["user_email"],
        User.tenant_id == app.tenant_id,
        User.app_id == req.client_id
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # --- DPoP (Sender-Constrained Tokens) ---
    dpop_header = None
    cnf_claim = None
    if request:
        dpop_header = request.headers.get("DPoP")
    if dpop_header:
        http_uri = str(request.url).split("?")[0]  # Strip query params
        dpop_result = validate_dpop_proof(dpop_header, "POST", http_uri)
        if not dpop_result:
            raise HTTPException(status_code=400, detail="Invalid DPoP proof")
        cnf_claim = {"jkt": dpop_result["jkt"]}

    # Generate tokens (with optional DPoP binding)
    access_token, refresh_token = generate_tokens_for_user(user, app, cnf=cnf_claim)

    # Record login event
    if request and app:
        record_login_event(db, user.id, req.client_id, app.tenant_id, request, "oauth_token_exchange")

    token_type = "DPoP" if cnf_claim else "bearer"

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": token_type,
        "expires_in": (app.access_token_expiry_minutes if app else 30) * 60,
    }
