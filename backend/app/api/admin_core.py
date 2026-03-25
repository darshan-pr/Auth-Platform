from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, func
from app.db import get_db
from app.models.app import App
from app.models.user import User
from app.models.admin import Admin
from app.models.admin_passkey import AdminPasskeyCredential
from app.models.tenant import Tenant
from app.models.passkey import PasskeyCredential
from app.models.admin_session import AdminSession
from app.models.admin_activity_event import AdminActivityEvent
from app.models.login_event import LoginEvent
from app.models.oauth_consent import OAuthConsent
from typing import Optional
from datetime import datetime, timedelta, timezone
import secrets
import hashlib
import hmac
import logging
import re
import base64
import binascii
from pathlib import Path

from app.services.jwt_service import create_access_token, verify_token
from app.services.jwt_service import (
    count_online_users,
    force_user_offline,
    get_online_status_map,
    is_user_online,
)
from app.services.password_service import (
    enforce_password_strength,
    generate_reset_token,
    hash_password,
    verify_password,
)
from app.services.tenant_service import create_tenant
from app.services.mail_service import send_set_password_email, send_force_logout_email
from app.services.mail_service import send_admin_welcome_email
from app.services.mail_service import send_password_reset_email
from app.services.mail_service import send_otp_email
from app.services.passkey_service import (
    generate_passkey_registration_challenge,
    verify_passkey_registration,
    generate_passkey_auth_challenge,
    verify_passkey_authentication,
)
from app.services.rate_limiter import create_rate_limit_dependency
from app.services.admin_activity_service import (
    create_admin_session,
    is_admin_session_active,
    log_admin_activity,
    revoke_admin_session,
    revoke_all_admin_sessions,
    touch_admin_session,
)
from app.config import settings as app_settings
from app.redis import redis_client
from app.schemas.admin import (
    AdminForgotPasswordRequest,
    AdminForgotPasswordVerifyOTPRequest,
    AdminLoginMFAVerifyRequest,
    AdminLoginRequest,
    AdminMFARequestOTPRequest,
    AdminMFASetupVerifyRequest,
    AdminPasskeyCheckRequest,
    AdminPasskeyCredentialPayload,
    AdminPasskeyLoginBeginRequest,
    AdminPasskeyLoginCompleteRequest,
    AdminPasskeyRegisterCompleteRequest,
    AdminProfileUpdateRequest,
    AdminRegisterRequest,
    AdminResetPasswordRequest,
    AdminVerifyOTPRequest,
    AppCreateRequest,
    AppCredentialsResponse,
    AppResponse,
    AppUpdateRequest,
    BulkActionRequest,
    TenantUpdateRequest,
    UserCreateRequest,
    UserResponse,
    UserUpdateRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin")
security = HTTPBearer(auto_error=False)

# Rate limit dependencies
_rl_admin_login = create_rate_limit_dependency("admin_login", max_requests=app_settings.RATE_LIMIT_LOGIN)
_rl_admin_register = create_rate_limit_dependency("admin_register", max_requests=app_settings.RATE_LIMIT_SIGNUP)
_rl_admin_forgot = create_rate_limit_dependency("admin_forgot_password", max_requests=app_settings.RATE_LIMIT_OTP)
_rl_admin_otp = create_rate_limit_dependency("admin_otp", max_requests=app_settings.RATE_LIMIT_OTP)

ADMIN_RESET_SCOPE = "admin_portal"
ADMIN_PASSKEY_SCOPE = "admin_console"
PLATFORM_SSO_COOKIE = "platform_sso"
ADMIN_TOKEN_COOKIE = "admin_token"
ADMIN_SESSION_CLAIM = "admin_session_id"
ADMIN_MFA_SETUP_KEY_PREFIX = "admin_mfa_setup"
ADMIN_MFA_LOGIN_TICKET_PREFIX = "admin_mfa_login_ticket"
ADMIN_EMAIL_LOGO_URL = "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRrugJcpnwgDvPDr6Gr41KzsEcfImRD9kpn45FCA-InPo42p8ht"


def _redis_client():
    # Keep compatibility with tests and monkeypatches that target app.api.admin.redis_client.
    from app.api import admin as admin_module

    return getattr(admin_module, "redis_client", redis_client)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _payload_exp_to_utc_naive(payload: dict) -> Optional[datetime]:
    raw_exp = payload.get("exp")
    if raw_exp is None:
        return None
    if isinstance(raw_exp, datetime):
        if raw_exp.tzinfo is not None:
            return raw_exp.astimezone(timezone.utc).replace(tzinfo=None)
        return raw_exp
    if isinstance(raw_exp, (int, float)):
        return datetime.utcfromtimestamp(raw_exp)
    if isinstance(raw_exp, str):
        exp_txt = raw_exp.strip()
        if not exp_txt:
            return None
        if exp_txt.isdigit():
            return datetime.utcfromtimestamp(int(exp_txt))
        try:
            parsed = datetime.fromisoformat(exp_txt.replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                return parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return parsed
        except Exception:
            return None
    return None


def _resolve_admin_session_id(payload: dict, token: str) -> str:
    explicit = payload.get(ADMIN_SESSION_CLAIM) or payload.get("sid") or payload.get("session_id")
    if explicit:
        return str(explicit)
    # Backward compatibility for tokens issued before admin-session tracking existed.
    legacy = hashlib.sha256(token.encode()).hexdigest()[:40]
    return f"legacy-{legacy}"


def _request_activity_target(request: Request) -> tuple[str, str]:
    method = str(getattr(request, "method", "GET") or "GET").upper()
    path = str(request.url.path) if request and request.url else "/admin"
    return method, path


def _format_location(city: Optional[str], region: Optional[str], country: Optional[str]) -> str:
    chunks = [part for part in [city, region, country] if part]
    return ", ".join(chunks) if chunks else "Unknown"


def _to_utc_naive(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _resolve_rp_id_from_request(request: Request) -> str:
    host = (request.url.hostname or "").strip().lower() if request and request.url else ""
    if not host:
        return "localhost"
    if host in {"127.0.0.1", "0.0.0.0", "::1"}:
        return "localhost"
    return host


def _issue_admin_login_response(
    admin: Admin,
    request: Request,
    db: Session,
    *,
    event_type: str,
    details: str,
    extra_content: Optional[dict] = None,
) -> JSONResponse:
    tenant = db.query(Tenant).filter(Tenant.id == admin.tenant_id).first()

    admin_session_id = secrets.token_urlsafe(24)
    token_data = {
        "admin_id": admin.id,
        "tenant_id": admin.tenant_id,
        "sub": admin.email,
        "type": "admin_access",
        ADMIN_SESSION_CLAIM: admin_session_id,
    }
    session_expires_at = _utc_now() + timedelta(hours=24)
    access_token = create_access_token(token_data, timedelta(hours=24))

    created_session = create_admin_session(
        db=db,
        admin=admin,
        session_id=admin_session_id,
        request=request,
        expires_at=session_expires_at,
    )
    if not created_session:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not initialize admin session",
        )

    log_admin_activity(
        db=db,
        admin=admin,
        request=request,
        event_type=event_type,
        session_id=admin_session_id,
        resource="/admin/login",
        method="POST",
        details=details,
    )

    content = {
        "token_type": "bearer",
        "tenant_id": admin.tenant_id,
        "tenant_name": tenant.name if tenant else "",
    }
    if extra_content:
        content.update(extra_content)

    response = JSONResponse(content=content)
    response.set_cookie(
        key=ADMIN_TOKEN_COOKIE,
        value=access_token,
        httponly=True,
        samesite="lax",
        max_age=86400,  # 24 hours
        path="/",
    )
    return response


CLIENT_SESSION_ID_PREFIX = "client"
_LOGIN_ACTIVITY_EVENT_TYPES = (
    "login",
    "oauth_login",
    "oauth_silent_login",
    "oauth_consent_granted",
    "oauth_token_exchange",
)


def _admin_identity_filter(admin: Admin):
    return func.lower(User.email) == (admin.email or "").lower()


def _related_identity_users(
    db: Session,
    admin: Admin,
    active_only: bool = True,
) -> list[User]:
    query = db.query(User).filter(
        User.tenant_id == admin.tenant_id,
        _admin_identity_filter(admin),
    )
    if active_only:
        query = query.filter(User.is_active == True)
    return query.all()


def _build_client_session_id(user_id: int, app_id: Optional[str]) -> str:
    return f"{CLIENT_SESSION_ID_PREFIX}:{user_id}:{app_id or ''}"


def _parse_client_session_id(session_id: str) -> Optional[tuple[int, str]]:
    parts = str(session_id or "").split(":", 2)
    if len(parts) != 3 or parts[0] != CLIENT_SESSION_ID_PREFIX:
        return None
    if not parts[1].isdigit():
        return None
    return int(parts[1]), parts[2]


def _latest_login_events_by_user_id(
    db: Session,
    tenant_id: int,
    user_ids: list[int],
) -> dict[int, LoginEvent]:
    if not user_ids:
        return {}

    rows = db.query(LoginEvent).filter(
        LoginEvent.tenant_id == tenant_id,
        LoginEvent.user_id.in_(user_ids),
        LoginEvent.event_type.in_(_LOGIN_ACTIVITY_EVENT_TYPES),
    ).order_by(LoginEvent.created_at.desc()).all()

    latest: dict[int, LoginEvent] = {}
    for row in rows:
        uid = row.user_id
        if uid is None or uid in latest:
            continue
        latest[uid] = row
    return latest

# ============== Admin Auth ==============

def get_current_admin(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> Admin:
    """Validate admin JWT from Authorization header or HttpOnly cookie and return the admin"""
    token = None
    
    # 1. Try Authorization header first (explicit, takes precedence)
    if credentials:
        token = credentials.credentials
    
    # 2. Fallback to HttpOnly cookie (browser sessions)
    if not token and request and hasattr(request, 'cookies'):
        token = request.cookies.get(ADMIN_TOKEN_COOKIE)
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    payload = verify_token(token)
    if not payload or payload.get("type") != "admin_access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired admin token"
        )
    admin = db.query(Admin).filter(Admin.id == payload.get("admin_id")).first()
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin not found"
        )

    admin_session_id = _resolve_admin_session_id(payload, token)
    existing_session = db.query(AdminSession).filter(
        AdminSession.admin_id == admin.id,
        AdminSession.session_id == admin_session_id,
    ).first()

    if not existing_session:
        created = create_admin_session(
            db=db,
            admin=admin,
            session_id=admin_session_id,
            request=request,
            expires_at=_payload_exp_to_utc_naive(payload),
        )
        if not created:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin session not found"
            )

    if not is_admin_session_active(db, admin.id, admin_session_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session revoked or expired"
        )

    touch_admin_session(db, admin.id, admin_session_id)
    request.state.admin_session_id = admin_session_id
    request.state.admin_id = admin.id

    method, path = _request_activity_target(request)
    log_admin_activity(
        db=db,
        admin=admin,
        request=request,
        event_type="access",
        session_id=admin_session_id,
        resource=path,
        method=method,
        details=f"{method} {path}",
    )
    return admin


# ============== Brute-Force Protection for Admin Login ==============

MAX_ADMIN_LOGIN_ATTEMPTS = 5
ADMIN_LOCKOUT_SECONDS = 900  # 15 minutes


def _check_admin_lockout(email: str):
    """Check if admin account is locked out."""
    try:
        ttl = _redis_client().ttl(f"admin_lockout:{email}")
        if ttl and ttl > 0:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Account temporarily locked. Try again in {ttl // 60 + 1} minutes."
            )
    except HTTPException:
        raise
    except Exception:
        pass


def _record_admin_failed_login(email: str):
    """Record a failed admin login attempt."""
    try:
        key = f"admin_attempts:{email}"
        count = _redis_client().incr(key)
        _redis_client().expire(key, ADMIN_LOCKOUT_SECONDS)
        if count >= MAX_ADMIN_LOGIN_ATTEMPTS:
            _redis_client().setex(f"admin_lockout:{email}", ADMIN_LOCKOUT_SECONDS, "1")
            _redis_client().delete(key)
            logger.warning(f"Admin account locked: {email} after {count} failed attempts")
    except Exception:
        pass


def _clear_admin_login_attempts(email: str):
    try:
        _redis_client().delete(f"admin_attempts:{email}")
        _redis_client().delete(f"admin_lockout:{email}")
    except Exception:
        pass


# ============== App Secret Hashing ==============

def _hash_app_secret(secret: str) -> str:
    """Hash an app secret using SHA-256 for secure storage."""
    return hashlib.sha256(secret.encode()).hexdigest()


def _verify_app_secret(provided: str, stored_hash: str) -> bool:
    """Verify a provided app secret against its stored hash."""
    return hmac.compare_digest(
        hashlib.sha256(provided.encode()).hexdigest(),
        stored_hash
    )


_APP_LOGO_DIR = Path(__file__).resolve().parent.parent / "assets" / "app-logos"
_APP_LOGO_DIR.mkdir(parents=True, exist_ok=True)
_DATA_URL_RE = re.compile(r"^data:image/(png|jpeg|jpg|webp|gif);base64,(.+)$", re.IGNORECASE | re.DOTALL)
_MAX_LOGO_BYTES = 2 * 1024 * 1024  # 2MB


def _sanitize_logo_url(raw_url: Optional[str], allow_empty: bool = False) -> Optional[str]:
    if raw_url is None:
        return None
    cleaned = raw_url.strip()
    if not cleaned:
        return "" if allow_empty else None
    if cleaned.startswith("/assets/") or cleaned.startswith("https://") or cleaned.startswith("http://"):
        return cleaned
    raise HTTPException(status_code=400, detail="logo_url must start with http://, https://, or /assets/")


def _store_logo_data_url(logo_data_url: str, app_id: str) -> str:
    if not logo_data_url:
        raise HTTPException(status_code=400, detail="logo_data_url is empty")

    match = _DATA_URL_RE.match(logo_data_url.strip())
    if not match:
        raise HTTPException(status_code=400, detail="Invalid logo_data_url format")

    ext = match.group(1).lower()
    ext = "jpg" if ext == "jpeg" else ext
    b64_payload = re.sub(r"\s+", "", match.group(2))
    try:
        raw_bytes = base64.b64decode(b64_payload, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="Invalid base64 image data")

    if len(raw_bytes) > _MAX_LOGO_BYTES:
        raise HTTPException(status_code=400, detail="Logo image is too large (max 2MB)")

    filename = f"{app_id}-{secrets.token_hex(6)}.{ext}"
    file_path = _APP_LOGO_DIR / filename
    file_path.write_bytes(raw_bytes)
    return f"/assets/app-logos/{filename}"


def _cleanup_local_logo(logo_url: Optional[str]) -> None:
    if not logo_url or not logo_url.startswith("/assets/app-logos/"):
        return
    filename = Path(logo_url).name
    if not filename:
        return
    target = _APP_LOGO_DIR / filename
    try:
        if target.exists():
            target.unlink()
    except Exception as e:
        logger.warning(f"Failed to delete old app logo {target}: {e}")


# Route handlers are split into domain modules to keep this file focused on shared
# dependencies, helpers, and auth/session primitives.
from app.api import admin_core_activity_routes  # noqa: F401
from app.api import admin_core_apps_routes  # noqa: F401
from app.api import admin_core_security_routes  # noqa: F401
from app.api import admin_core_users_routes  # noqa: F401
