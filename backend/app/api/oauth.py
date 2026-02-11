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
from app.services.oauth_service import (
    create_oauth_session,
    get_oauth_session,
    delete_oauth_session,
    generate_authorization_code,
    validate_authorization_code,
)
from app.services.password_service import hash_password, verify_password
from app.services.otp_service import generate_otp, verify_otp, generate_password_reset_otp, verify_password_reset_otp
from app.services.mail_service import send_otp_email, send_login_notification_email, send_password_reset_email
from app.api.auth import generate_tokens_for_user

router = APIRouter(prefix="/oauth")

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
    error_ctx = {"request": request, "error": None, "session_id": None, "app_name": "", "app_id": "", "otp_enabled": False}

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
        "app_id": client_id,
        "otp_enabled": app.otp_enabled,
        "error": None,
    })


# ==================== POST /oauth/authenticate ====================

class AuthenticateRequest(BaseModel):
    session_id: str
    action: str  # "login", "signup", "verify_otp", "forgot_password", "reset_password"
    email: str
    password: Optional[str] = None
    otp: Optional[str] = None
    new_password: Optional[str] = None


@router.post("/authenticate")
def authenticate(req: AuthenticateRequest, db: Session = Depends(get_db)):
    """
    Internal API called by the hosted login page.
    
    Handles three actions:
      - signup:     Create account → ask user to login
      - login:      Verify credentials → return auth code (or ask for OTP)
      - verify_otp: Verify OTP → return auth code
    
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
        return _handle_login(req, session, app, db)
    elif req.action == "verify_otp":
        return _handle_verify_otp(req, session, app, db)
    elif req.action == "forgot_password":
        return _handle_forgot_password(req, session, app, db)
    elif req.action == "reset_password":
        return _handle_reset_password(req, session, app, db)
    else:
        raise HTTPException(status_code=400, detail="Invalid action")


def _handle_signup(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Create a new user account"""
    # Check if user exists for this specific app
    existing = db.query(User).filter(
        User.email == req.email,
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
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "action": "show_login",
        "message": "Account created successfully! Please sign in."
    }


def _handle_login(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Verify email + password, then either issue code or request OTP"""
    user = db.query(User).filter(
        User.email == req.email,
        User.app_id == session["client_id"]
    ).first()
    if not user or not user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="This account has been deactivated")

    # Check if OTP is required
    if app.otp_enabled:
        try:
            otp = generate_otp(req.email)
            send_otp_email(req.email, otp, app.name or "Auth Platform")
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
        return _complete_auth(session, user, req.session_id, app)


def _handle_verify_otp(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Verify OTP and complete authentication"""
    if not req.otp:
        raise HTTPException(status_code=400, detail="Verification code is required")

    if not verify_otp(req.email, req.otp):
        raise HTTPException(status_code=401, detail="Invalid or expired verification code")

    user = db.query(User).filter(
        User.email == req.email,
        User.app_id == session["client_id"]
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return _complete_auth(session, user, req.session_id, app)


def _handle_forgot_password(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Send password reset OTP to user's email"""
    user = db.query(User).filter(
        User.email == req.email,
        User.app_id == session["client_id"]
    ).first()
    if not user or not user.password_hash:
        raise HTTPException(
            status_code=404,
            detail="No account found with this email address."
        )

    try:
        otp = generate_password_reset_otp(req.email, session["client_id"])
        send_password_reset_email(req.email, otp, app.name or "Auth Platform")
        return {
            "action": "show_reset_otp",
            "message": "A password reset code has been sent to your email."
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send reset code: {str(e)}"
        )


def _handle_reset_password(req: AuthenticateRequest, session: dict, app: App, db: Session):
    """Verify OTP and reset the user's password"""
    if not req.otp:
        raise HTTPException(status_code=400, detail="Verification code is required")
    if not req.new_password or len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")

    if not verify_password_reset_otp(req.email, session["client_id"], req.otp):
        raise HTTPException(status_code=401, detail="Invalid or expired verification code")

    user = db.query(User).filter(
        User.email == req.email,
        User.app_id == session["client_id"]
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.password_hash = hash_password(req.new_password)
    db.commit()

    return {
        "action": "password_reset_success",
        "message": "Password reset successfully. Please sign in with your new password."
    }


def _complete_auth(session: dict, user: User, session_id: str, app: App = None):
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

    # Send login notification if enabled
    if app and app.login_notification_enabled:
        send_login_notification_email(
            to=user.email,
            app_name=app.name or "Auth Platform",
            access_token_expiry_minutes=app.access_token_expiry_minutes,
            refresh_token_expiry_days=app.refresh_token_expiry_days,
        )

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


@router.post("/token")
def token_exchange(req: TokenExchangeRequest, db: Session = Depends(get_db)):
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

    # Get user for this specific app
    user = db.query(User).filter(
        User.email == code_data["user_email"],
        User.app_id == req.client_id
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get app for token expiry settings
    app = db.query(App).filter(App.app_id == req.client_id).first()

    # Generate tokens
    access_token, refresh_token = generate_tokens_for_user(user, app)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": (app.access_token_expiry_minutes if app else 30) * 60,
    }
