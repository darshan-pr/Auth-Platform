"""
OAuth 2.0 Authorization Code Flow with PKCE

Endpoints:
  GET  /oauth/authorize    — Renders the hosted login page (like Google's login screen)
  POST /oauth/authenticate — Internal API for the login page to verify credentials
  POST /oauth/token        — Token exchange: authorization_code + PKCE → access/refresh tokens
"""

from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel
from typing import Optional
from pathlib import Path
from urllib.parse import urlparse, urlencode
from datetime import timedelta

from app.db import get_db
from app.models.app import App
from app.models.user import User
from app.models.admin import Admin
from app.models.passkey import PasskeyCredential
from app.models.oauth_consent import OAuthConsent
from app.models.login_event import LoginEvent
from app.services.oauth_service import (
    create_oauth_session,
    get_oauth_session,
    update_oauth_session,
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
from app.services.redirect_url_service import append_query_params, build_auth_platform_login_url
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
from app.services.jwt_service import (
    create_access_token,
    verify_token,
    mark_user_online,
    is_user_blacklisted,
    clear_user_blacklist,
)
from app.services.token_service import generate_tokens_for_user
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


def _with_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


def _build_auth_platform_retry_login_url() -> str:
    return append_query_params(
        build_auth_platform_login_url(settings.AUTH_PLATFORM_URL),
        {"oauth_warning": "retry_oauth"},
    )


PLATFORM_SSO_COOKIE = "platform_sso"
ADMIN_TOKEN_COOKIE = "admin_token"
_MIN_SSO_COOKIE_AGE_SECONDS = 3600


def _issue_platform_sso_cookie_payload(user: User, app: App) -> dict:
    max_age = max(int((app.refresh_token_expiry_days or 1) * 86400), _MIN_SSO_COOKIE_AGE_SECONDS)
    token = create_access_token(
        {
            "sub": user.email,
            "tenant_id": app.tenant_id,
            "source_app_id": app.app_id,
            "type": "platform_sso",
        },
        timedelta(seconds=max_age),
    )
    return {"token": token, "max_age": max_age}


def _set_platform_sso_cookie(response, request: Request, token: str, max_age: int) -> None:
    response.set_cookie(
        key=PLATFORM_SSO_COOKIE,
        value=token,
        max_age=max_age,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/",
    )


def _get_platform_sso_payload(request: Request) -> Optional[dict]:
    token = request.cookies.get(PLATFORM_SSO_COOKIE)
    if not token:
        return None

    payload = verify_token(token)
    if not payload or payload.get("type") != "platform_sso":
        return None

    if not payload.get("sub") or not payload.get("tenant_id"):
        return None

    # Backward-compat safety: ignore legacy cookies that were issued by admin portal login.
    # OAuth SSO cookies must be minted through OAuth authorize/authenticate flow.
    if payload.get("source_app_id") == "admin_portal":
        return None

    return payload


def _find_or_provision_app_user(db: Session, app: App, email: str) -> Optional[User]:
    target_user = db.query(User).filter(
        User.email == email,
        User.tenant_id == app.tenant_id,
        User.app_id == app.app_id,
    ).first()
    if target_user:
        return target_user

    target_user = User(
        email=email,
        app_id=app.app_id,
        tenant_id=app.tenant_id,
        is_active=True,
    )
    db.add(target_user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return db.query(User).filter(
            User.email == email,
            User.tenant_id == app.tenant_id,
            User.app_id == app.app_id,
        ).first()

    db.refresh(target_user)
    return target_user


def _resolve_admin_from_dashboard_session(request: Request, db: Session, app: App) -> Optional[Admin]:
    token = request.cookies.get(ADMIN_TOKEN_COOKIE)
    if not token:
        return None

    payload = verify_token(token)
    if not payload or payload.get("type") != "admin_access":
        return None

    admin_id = payload.get("admin_id")
    tenant_id = payload.get("tenant_id")
    if not admin_id or not tenant_id:
        return None
    if tenant_id != app.tenant_id:
        return None

    return db.query(Admin).filter(
        Admin.id == admin_id,
        Admin.tenant_id == tenant_id,
    ).first()


def _resolve_admin_user_for_app(request: Request, db: Session, app: App) -> Optional[User]:
    admin = _resolve_admin_from_dashboard_session(request, db, app)
    if not admin:
        return None
    return _find_or_provision_app_user(db, app, admin.email)


def _resolve_sso_user_for_app(request: Request, db: Session, app: App) -> Optional[User]:
    payload = _get_platform_sso_payload(request)
    if not payload:
        return None

    if payload.get("tenant_id") != app.tenant_id:
        return None

    email = payload.get("sub")
    if not email:
        return None

    # Ensure this email still exists in tenant identity records (user or admin).
    identity_user = db.query(User).filter(
        User.email == email,
        User.tenant_id == app.tenant_id,
    ).first()
    identity_admin = db.query(Admin).filter(
        Admin.email == email,
        Admin.tenant_id == app.tenant_id,
    ).first()
    if not identity_user and not identity_admin:
        return None
    return _find_or_provision_app_user(db, app, email)


def _has_granted_consent(db: Session, user: User, app: App) -> bool:
    consent = db.query(OAuthConsent).filter(
        OAuthConsent.tenant_id == app.tenant_id,
        OAuthConsent.user_id == user.id,
        OAuthConsent.client_id == app.app_id,
    ).first()
    return bool(consent and consent.granted)


def _upsert_granted_consent(db: Session, user: User, app: App) -> None:
    consent = db.query(OAuthConsent).filter(
        OAuthConsent.tenant_id == app.tenant_id,
        OAuthConsent.user_id == user.id,
        OAuthConsent.client_id == app.app_id,
    ).first()
    if consent:
        consent.granted = True
        consent.scope = "email"
    else:
        consent = OAuthConsent(
            tenant_id=app.tenant_id,
            user_id=user.id,
            client_id=app.app_id,
            scope="email",
            granted=True,
        )
        db.add(consent)
    db.commit()


def _build_consent_url(session_id: str, client_id: str) -> str:
    return f"/oauth/consent?session_id={session_id}&client_id={client_id}"


def _build_bootstrap_url(session_id: str, client_id: str) -> str:
    return f"/oauth/session/bootstrap?session_id={session_id}&client_id={client_id}"


def _build_oauth_error_redirect(session: dict, error: str, error_description: str) -> str:
    redirect_uri = session["redirect_uri"]
    separator = "&" if "?" in redirect_uri else "?"
    query = urlencode({
        "error": error,
        "error_description": error_description,
        "state": session["state"],
    })
    return f"{redirect_uri}{separator}{query}"


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

@router.get("/logout")
def oauth_logout(
    request: Request,
    post_logout_redirect_uri: Optional[str] = None,
):
    """
    RP-Initiated Logout (simplified).

    Clears the platform_sso HttpOnly cookie so the next /oauth/authorize call
    will NOT silently re-authenticate the user. This is the correct logout flow:
    the 3rd-party app calls this endpoint after invalidating its own local session.

    ?post_logout_redirect_uri=https://yourapp.com/  — where to redirect after clearing.
    """
    redirect_to = post_logout_redirect_uri or settings.AUTH_PLATFORM_URL or "/"
    response = RedirectResponse(url=redirect_to, status_code=302)
    response.delete_cookie(key=PLATFORM_SSO_COOKIE, path="/")
    _with_no_cache_headers(response)
    return response


@router.get("/authorize", response_class=HTMLResponse)
def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    state: str = None,
    code_challenge: str = None,
    code_challenge_method: str = "S256",
    prompt: Optional[str] = None,
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
        return _with_no_cache_headers(templates.TemplateResponse(request, "auth.html", error_ctx))

    # Validate client_id
    app = db.query(App).filter(App.app_id == client_id).first()
    if not app:
        error_ctx["error"] = "Invalid client_id. This application is not registered."
        return _with_no_cache_headers(templates.TemplateResponse(request, "auth.html", error_ctx))

    # Validate redirect_uri
    if not validate_redirect_uri(app, redirect_uri):
        error_ctx["error"] = "Invalid redirect_uri. This URI is not registered for this application."
        return _with_no_cache_headers(templates.TemplateResponse(request, "auth.html", error_ctx))

    # PKCE is mandatory for security
    if not code_challenge:
        error_ctx["error"] = "PKCE code_challenge is required. Public clients must use PKCE."
        return _with_no_cache_headers(templates.TemplateResponse(request, "auth.html", error_ctx))

    # State is mandatory for CSRF protection
    if not state:
        error_ctx["error"] = "state parameter is required for CSRF protection."
        return _with_no_cache_headers(templates.TemplateResponse(request, "auth.html", error_ctx))

    # Create OAuth session in Redis
    session_id = create_oauth_session(
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

    # Silent SSO: if a valid platform session cookie exists, authorize without prompting.
    # prompt=login/select_account must bypass silent SSO and show authentication UI.
    # prompt=consent should keep SSO identity but force consent UI.
    # oauth_enabled controls SSO/consent behavior; when disabled we still allow
    # explicit credential-based sign-in for compatibility with non-SSO flows.
    sso_enabled = bool(app.oauth_enabled)
    prompt_mode = (prompt or "").strip().lower() if prompt else None
    if prompt_mode in ("login", "consent", "select_account"):
        update_oauth_session(session_id, {"prompt": prompt_mode})

    force_login = prompt_mode in ("login", "select_account")
    skip_sso = force_login or not sso_enabled
    silent_user = None

    if sso_enabled and not skip_sso:
        # Only platform_sso cookie is valid for silent OAuth SSO.
        # Admin dashboard sessions must not implicitly authenticate OAuth apps.
        silent_user = _resolve_sso_user_for_app(request, db, app)

    if silent_user:
        if not silent_user.is_active:
            admin_email = _get_admin_contact_email(db, app.tenant_id)
            error_ctx["error"] = (
                "Your account has been temporarily deactivated by the administrator. "
                f"Please contact {admin_email} for further assistance."
            )
            delete_oauth_session(session_id)
            return _with_no_cache_headers(templates.TemplateResponse(request, "auth.html", error_ctx))
        update_oauth_session(
            session_id,
            {"authenticated_user_id": silent_user.id, "authenticated_email": silent_user.email},
        )

        consent_redirect = RedirectResponse(
            url=_build_consent_url(session_id, client_id=client_id),
            status_code=302,
        )
        return _with_no_cache_headers(consent_redirect)

    # Bootstrap OAuth SSO from existing dashboard admin session, but only when /oauth/authorize is invoked.
    # This mints platform_sso cookie on-demand via a dedicated OAuth route.
    if sso_enabled and not skip_sso:
        if _resolve_admin_from_dashboard_session(request, db, app):
            bootstrap_redirect = RedirectResponse(
                url=_build_bootstrap_url(session_id=session_id, client_id=client_id),
                status_code=302,
            )
            return _with_no_cache_headers(bootstrap_redirect)

        # OAuth-enabled apps require an existing Auth Platform session.
        # If absent, send users to the admin login screen with a retry hint.
        delete_oauth_session(session_id)
        login_redirect = RedirectResponse(
            url=_build_auth_platform_retry_login_url(),
            status_code=302,
        )
        return _with_no_cache_headers(login_redirect)

    return _with_no_cache_headers(templates.TemplateResponse(request, "auth.html", {
        "request": request,
        "session_id": session_id,
        "app_name": app.name or "Application",
        "app_logo_url": app.logo_url or "/assets/logo.png",
        "app_id": client_id,
        "otp_enabled": app.otp_enabled,
        "passkey_enabled": app.passkey_enabled,
        "auth_platform_url": settings.AUTH_PLATFORM_URL,
        "error": None,
    }))


@router.get("/session/bootstrap")
def bootstrap_oauth_session(
    request: Request,
    session_id: str,
    client_id: str,
    db: Session = Depends(get_db),
):
    """
    Dedicated OAuth bootstrap route.
    If a valid admin dashboard session exists, bind OAuth session to that identity.
    platform_sso is minted only when authorization completes (consent approve or silent auto-approve).
    """
    session = get_oauth_session(session_id)
    if not session:
        return _with_no_cache_headers(
            templates.TemplateResponse(
                request,
                "auth.html",
                {
                    "request": request,
                    "session_id": None,
                    "app_name": "Application",
                    "app_logo_url": "/assets/logo.png",
                    "app_id": client_id,
                    "otp_enabled": False,
                    "passkey_enabled": False,
                    "auth_platform_url": settings.AUTH_PLATFORM_URL,
                    "error": "Authorization session expired. Please restart sign in.",
                },
            )
        )

    if session.get("client_id") != client_id:
        return _with_no_cache_headers(
            templates.TemplateResponse(
                request,
                "auth.html",
                {
                    "request": request,
                    "session_id": None,
                    "app_name": "Application",
                    "app_logo_url": "/assets/logo.png",
                    "app_id": client_id,
                    "otp_enabled": False,
                    "passkey_enabled": False,
                    "auth_platform_url": settings.AUTH_PLATFORM_URL,
                    "error": "Invalid authorization session for this client.",
                },
            )
        )

    app = db.query(App).filter(App.app_id == client_id).first()
    if not app or not app.oauth_enabled:
        return _with_no_cache_headers(
            templates.TemplateResponse(
                request,
                "auth.html",
                {
                    "request": request,
                    "session_id": None,
                    "app_name": "Application",
                    "app_logo_url": "/assets/logo.png",
                    "app_id": client_id,
                    "otp_enabled": False,
                    "passkey_enabled": False,
                    "auth_platform_url": settings.AUTH_PLATFORM_URL,
                    "error": "OAuth is disabled for this application.",
                },
            )
        )

    admin_user = _resolve_admin_user_for_app(request, db, app)
    if not admin_user:
        # Admin session expired or missing during bootstrap: require re-login.
        delete_oauth_session(session_id)
        login_redirect = RedirectResponse(
            url=_build_auth_platform_retry_login_url(),
            status_code=302,
        )
        return _with_no_cache_headers(login_redirect)

    if not admin_user.is_active:
        admin_email = _get_admin_contact_email(db, app.tenant_id)
        return _with_no_cache_headers(
            templates.TemplateResponse(
                request,
                "auth.html",
                {
                    "request": request,
                    "session_id": session_id,
                    "app_name": app.name or "Application",
                    "app_logo_url": app.logo_url or "/assets/logo.png",
                    "app_id": client_id,
                    "otp_enabled": app.otp_enabled,
                    "passkey_enabled": app.passkey_enabled,
                    "auth_platform_url": settings.AUTH_PLATFORM_URL,
                    "error": (
                        "Your account has been temporarily deactivated by the administrator. "
                        f"Please contact {admin_email} for further assistance."
                    ),
                },
            )
        )

    update_oauth_session(
        session_id,
        {"authenticated_user_id": admin_user.id, "authenticated_email": admin_user.email},
    )

    response = RedirectResponse(
        url=_build_consent_url(session_id, client_id=client_id),
        status_code=302,
    )
    return _with_no_cache_headers(response)


# ==================== POST /oauth/authenticate ====================

class AuthenticateRequest(BaseModel):
    session_id: str
    action: str  # "login", "signup", "verify_otp", "verify_signup_otp", "forgot_password", "verify_reset_otp", "reset_password", "passkey_register_begin", "passkey_register_verify_otp", "passkey_register_complete", "passkey_auth_begin", "passkey_auth_complete"
    email: Optional[str] = None
    password: Optional[str] = None
    otp: Optional[str] = None
    new_password: Optional[str] = None
    # Client-side pre-hashed password flag (PBKDF2-SHA256 before transit)
    # When True, password is a hex-encoded PBKDF2 hash, not the raw plaintext.
    pre_hashed: Optional[bool] = False
    # Passkey fields
    credential: Optional[dict] = None
    rp_id: Optional[str] = None


@router.post("/authenticate", dependencies=[Depends(_rl_oauth_auth)])
def authenticate(req: AuthenticateRequest, request: Request, db: Session = Depends(get_db)):
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
        result = _handle_signup(req, session, app, db)
    elif req.action == "login":
        result = _handle_login(req, session, app, db, request)
    elif req.action == "verify_otp":
        result = _handle_verify_otp(req, session, app, db, request)
    elif req.action == "verify_signup_otp":
        result = _handle_verify_signup_otp(req, session, app, db)
    elif req.action == "forgot_password":
        result = _handle_forgot_password(req, session, app, db)
    elif req.action == "verify_reset_otp":
        result = _handle_verify_reset_otp(req, session, app, db)
    elif req.action == "reset_password":
        result = _handle_reset_password(req, session, app, db)
    elif req.action == "passkey_register_begin":
        result = _handle_passkey_register_begin(req, session, app, db)
    elif req.action == "passkey_register_verify_otp":
        result = _handle_passkey_register_verify_otp(req, session, app, db)
    elif req.action == "passkey_register_complete":
        result = _handle_passkey_register_complete(req, session, app, db)
    elif req.action == "passkey_auth_begin":
        result = _handle_passkey_auth_begin(req, session, app, db)
    elif req.action == "passkey_auth_complete":
        result = _handle_passkey_auth_complete(req, session, app, db, request)
    elif req.action == "passkey_check":
        result = _handle_passkey_check(req, session, app, db)
    else:
        raise HTTPException(status_code=400, detail="Invalid action")

    if isinstance(result, dict):
        sso_cookie_payload = result.pop("_platform_sso", None)
        if sso_cookie_payload:
            response = JSONResponse(content=result)
            _set_platform_sso_cookie(
                response,
                request,
                sso_cookie_payload["token"],
                sso_cookie_payload["max_age"],
            )
            return response

    return result


@router.get("/consent", response_class=HTMLResponse)
def consent_page(
    request: Request,
    session_id: str,
    client_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    session = get_oauth_session(session_id)
    if not session:
        return _with_no_cache_headers(
            templates.TemplateResponse(
                request,
                "oauth_consent.html",
                {
                    "request": request,
                    "error": "Your authorization session expired. Please try signing in again.",
                    "session_id": None,
                    "client_id": "",
                    "app_name": "Application",
                    "app_logo_url": "/assets/logo.png",
                    "user_email": "",
                    "auth_platform_url": settings.AUTH_PLATFORM_URL,
                },
            )
        )

    session_client_id = session["client_id"]
    if client_id and client_id != session_client_id:
        return _with_no_cache_headers(
            templates.TemplateResponse(
                request,
                "oauth_consent.html",
                {
                    "request": request,
                    "error": "Consent request does not match the OAuth client.",
                    "session_id": None,
                    "client_id": "",
                    "app_name": "Application",
                    "app_logo_url": "/assets/logo.png",
                    "user_email": "",
                    "auth_platform_url": settings.AUTH_PLATFORM_URL,
                },
            )
        )

    app = db.query(App).filter(App.app_id == session_client_id).first()
    if not app or not app.oauth_enabled:
        return _with_no_cache_headers(
            templates.TemplateResponse(
                request,
                "oauth_consent.html",
                {
                    "request": request,
                    "error": "OAuth is not available for this application.",
                    "session_id": None,
                    "client_id": "",
                    "app_name": "Application",
                    "app_logo_url": "/assets/logo.png",
                    "user_email": "",
                    "auth_platform_url": settings.AUTH_PLATFORM_URL,
                },
            )
        )

    user_id = session.get("authenticated_user_id")
    user_email = session.get("authenticated_email", "")
    if not user_id:
        delete_oauth_session(session_id)
        login_redirect = RedirectResponse(
            url=_build_auth_platform_retry_login_url(),
            status_code=302,
        )
        return _with_no_cache_headers(login_redirect)

    return _with_no_cache_headers(
        templates.TemplateResponse(
            request,
            "oauth_consent.html",
            {
                "request": request,
                "error": None,
                "session_id": session_id,
                "client_id": session_client_id,
                "app_name": app.name or "Application",
                "app_logo_url": app.logo_url or "/assets/logo.png",
                "user_email": user_email,
                "auth_platform_url": settings.AUTH_PLATFORM_URL,
            },
        )
    )


class ConsentDecisionRequest(BaseModel):
    session_id: str
    decision: str  # "approve" | "deny"
    client_id: Optional[str] = None


@router.post("/consent")
def consent_decision(
    req: ConsentDecisionRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    session = get_oauth_session(req.session_id)
    if not session:
        raise HTTPException(status_code=400, detail="Session expired. Please restart the sign-in flow.")

    if req.client_id and req.client_id != session["client_id"]:
        raise HTTPException(status_code=400, detail="Consent decision does not match the OAuth client")

    app = db.query(App).filter(App.app_id == session["client_id"]).first()
    if not app or not app.oauth_enabled:
        raise HTTPException(status_code=400, detail="Invalid or disabled application")

    user_id = session.get("authenticated_user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="Authentication required before consent")

    user = db.query(User).filter(
        User.id == user_id,
        User.tenant_id == app.tenant_id,
        User.app_id == app.app_id,
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found for this application")

    decision = (req.decision or "").strip().lower()
    if decision not in {"approve", "deny"}:
        raise HTTPException(status_code=400, detail="decision must be 'approve' or 'deny'")

    if decision == "deny":
        delete_oauth_session(req.session_id)
        return {
            "action": "redirect",
            "redirect_url": _build_oauth_error_redirect(
                session,
                "access_denied",
                "User denied consent",
            ),
        }

    _upsert_granted_consent(db, user, app)
    result = _complete_auth(
        session,
        user,
        req.session_id,
        app=app,
        db=db,
        http_request=request,
        event_type="oauth_consent_granted",
    )
    sso_cookie_payload = result.pop("_platform_sso", None)
    response = JSONResponse(content=result)
    if sso_cookie_payload:
        _set_platform_sso_cookie(
            response,
            request,
            sso_cookie_payload["token"],
            sso_cookie_payload["max_age"],
        )
    return response


# ==================== OAuth Consent Management (for users) ====================


def _get_current_user_from_sso(request: Request, db: Session) -> Optional[tuple[str, int]]:
    """
    Get the current user's email and tenant_id from platform_sso cookie.
    Returns (email, tenant_id) or None if no valid session.
    """
    payload = _get_platform_sso_payload(request)
    if payload:
        return (payload.get("sub"), payload.get("tenant_id"))

    return None


@router.get("/my-consents")
def list_my_consents(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    List all OAuth consents granted by the current user.
    Requires a valid platform_sso cookie.
    """
    user_info = _get_current_user_from_sso(request, db)
    if not user_info:
        raise HTTPException(status_code=401, detail="Authentication required")

    email, tenant_id = user_info

    # Find all user records for this email in tenant
    users = db.query(User).filter(
        User.email == email,
        User.tenant_id == tenant_id,
    ).all()

    if not users:
        return {"consents": []}

    user_ids = [u.id for u in users]

    # Find all consents
    consents = db.query(OAuthConsent).filter(
        OAuthConsent.tenant_id == tenant_id,
        OAuthConsent.user_id.in_(user_ids),
        OAuthConsent.granted == True,
    ).all()

    client_ids = sorted({consent.client_id for consent in consents if consent.client_id})
    apps_by_id = {}
    if client_ids:
        apps_by_id = {
            app.app_id: app
            for app in db.query(App).filter(App.app_id.in_(client_ids)).all()
        }

    login_counts: dict[tuple[int, str], int] = {}
    if consents and client_ids:
        login_rows = db.query(
            LoginEvent.user_id,
            LoginEvent.app_id,
            func.count(LoginEvent.id).label("count"),
        ).filter(
            LoginEvent.tenant_id == tenant_id,
            LoginEvent.user_id.in_(user_ids),
            LoginEvent.app_id.in_(client_ids),
        ).group_by(
            LoginEvent.user_id,
            LoginEvent.app_id,
        ).all()
        login_counts = {
            (int(row.user_id), str(row.app_id)): int(row.count or 0)
            for row in login_rows
            if row.user_id is not None and row.app_id is not None
        }

    result = []
    for consent in consents:
        app = apps_by_id.get(consent.client_id)
        login_count = login_counts.get((consent.user_id, consent.client_id), 0)
        result.append({
            "consent_id": consent.id,
            "client_id": consent.client_id,
            "app_name": app.name if app else consent.client_id,
            "app_logo_url": app.logo_url if app else None,
            "scope": consent.scope,
            "granted_at": consent.granted_at.isoformat() if consent.granted_at else None,
            "login_count": login_count,
        })

    return {"consents": result}


@router.delete("/my-consents/{client_id}")
def revoke_my_consent(
    client_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Revoke OAuth consent for a specific app.
    This prevents silent SSO to this app until the user re-grants consent.
    """
    user_info = _get_current_user_from_sso(request, db)
    if not user_info:
        raise HTTPException(status_code=401, detail="Authentication required")

    email, tenant_id = user_info

    # Find user record(s) for this email/tenant
    users = db.query(User).filter(
        User.email == email,
        User.tenant_id == tenant_id,
    ).all()

    if not users:
        raise HTTPException(status_code=404, detail="User not found")

    user_ids = [u.id for u in users]

    # Find and revoke consent
    consent = db.query(OAuthConsent).filter(
        OAuthConsent.tenant_id == tenant_id,
        OAuthConsent.user_id.in_(user_ids),
        OAuthConsent.client_id == client_id,
        OAuthConsent.granted == True,
    ).first()

    if not consent:
        raise HTTPException(status_code=404, detail="Consent not found or already revoked")

    consent.granted = False
    db.commit()

    # Also record the revocation event
    app = db.query(App).filter(App.app_id == client_id).first()

    return {
        "message": "Consent revoked successfully",
        "client_id": client_id,
        "app_name": app.name if app else client_id,
    }


@router.post("/my-consents/revoke-all")
def revoke_all_my_consents(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Revoke all OAuth consents for the current user.
    This prevents silent SSO to all apps until re-granted.
    """
    user_info = _get_current_user_from_sso(request, db)
    if not user_info:
        raise HTTPException(status_code=401, detail="Authentication required")

    email, tenant_id = user_info

    # Find all user records for this email in tenant
    users = db.query(User).filter(
        User.email == email,
        User.tenant_id == tenant_id,
    ).all()

    if not users:
        return {"message": "No consents to revoke", "revoked_count": 0}

    user_ids = [u.id for u in users]

    # Revoke all consents
    revoked_count = db.query(OAuthConsent).filter(
        OAuthConsent.tenant_id == tenant_id,
        OAuthConsent.user_id.in_(user_ids),
        OAuthConsent.granted == True,
    ).update({"granted": False}, synchronize_session=False)

    db.commit()

    return {
        "message": "All consents revoked successfully",
        "revoked_count": revoked_count,
    }



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
        raise HTTPException(
            status_code=400,
            detail="User exists but no password is set yet. You can reset your password to continue."
        )

    # Password verification: support both pre-hashed (client-side PBKDF2) and legacy plaintext.
    # When pre_hashed=True the client sent PBKDF2-SHA256(password, email) instead of the raw password.
    # bcrypt stores bcrypt(hex_hash), so verify_password works identically in both paths.
    password_ok = verify_password(req.password, user.password_hash)
    if not password_ok and req.pre_hashed:
        # Edge case: user was created before client-side hashing was introduced.
        # The stored hash may be bcrypt(plaintext) while we received a hash.
        # We can't reverse the hash, so reject — user should reset password.
        pass  # already False
    if not password_ok:
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
        return _complete_or_request_consent(session, user, req.session_id, app, db=db, http_request=http_request)


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

    return _complete_or_request_consent(session, user, req.session_id, app, db=db, http_request=http_request)


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
    if not user:
        # Don't reveal whether user exists — return generic success
        import logging
        logging.getLogger(__name__).info(f"Forgot password requested for unknown user via OAuth: {req.email}")
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

    return _complete_or_request_consent(session, user, req.session_id, app, db=db, http_request=http_request)


def _complete_or_request_consent(
    session: dict,
    user: User,
    session_id: Optional[str],
    app: App = None,
    db: Session = None,
    http_request: Request = None,
    event_type: str = "oauth_login",
):
    if not app or not db or not session_id:
        return _complete_auth(
            session,
            user,
            session_id,
            app=app,
            db=db,
            http_request=http_request,
            event_type=event_type,
        )

    # When OAuth SSO is disabled for this app, complete auth directly without consent.
    if not app.oauth_enabled:
        return _complete_auth(
            session,
            user,
            session_id,
            app=app,
            db=db,
            http_request=http_request,
            event_type=event_type,
        )

    update_oauth_session(
        session_id,
        {"authenticated_user_id": user.id, "authenticated_email": user.email},
    )
    return {"action": "redirect", "redirect_url": _build_consent_url(session_id, client_id=app.app_id)}


def _complete_auth(
    session: dict,
    user: User,
    session_id: Optional[str],
    app: App = None,
    db: Session = None,
    http_request: Request = None,
    event_type: str = "oauth_login",
):
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
    if session_id:
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
        record_login_event(db, user.id, session["client_id"], app.tenant_id, http_request, event_type)

    # Build redirect URL with code and state
    redirect_uri = session["redirect_uri"]
    separator = "&" if "?" in redirect_uri else "?"
    redirect_url = f"{redirect_uri}{separator}code={code}&state={session['state']}"

    result = {"action": "redirect", "redirect_url": redirect_url}
    if app:
        result["_platform_sso"] = _issue_platform_sso_cookie_payload(user, app)
    return result


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
    if not app:
        raise HTTPException(status_code=401, detail="Invalid client_id")

    # --- Client Authentication (confidential clients) ---
    if req.client_secret:
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
