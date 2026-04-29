from fastapi import APIRouter, HTTPException, status, Depends, Request
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.schemas.auth import (
    OTPRequest, OTPVerifyRequest, AuthResponse,
    SignupRequest, LoginRequest, LoginResponse, LoginOTPVerifyRequest,
    ForgotPasswordRequest, ForgotPasswordResponse, ResetPasswordRequest
)
from app.services.otp_service import generate_otp, verify_otp, generate_password_reset_otp, verify_password_reset_otp
from app.services.mail_service import send_otp_email, send_password_reset_email, send_password_reset_token_email, send_login_notification_email
from app.services.password_service import (
    enforce_password_strength,
    generate_reset_token,
    hash_password,
    verify_password,
    verify_reset_token,
)
from app.services.redirect_url_service import build_server_signin_url, infer_app_signin_url
from app.services.token_service import generate_tokens_for_user
from app.services.tenant_service import get_or_create_default_tenant
from app.services.rate_limiter import create_rate_limit_dependency
from app.services.geo_service import record_login_event, get_client_ip, get_location
from app.config import settings
from app.db import get_db
from app.models.user import User
from app.models.app import App
from app.redis import redis_client
from pydantic import BaseModel
from typing import Optional
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth")

# ============== Brute-Force Protection ==============

MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCKOUT_SECONDS = 900  # 15 minutes


def _get_login_lockout_key(app_id: str, email: str) -> str:
    return f"login_lockout:{app_id}:{email}"


def _get_login_attempts_key(app_id: str, email: str) -> str:
    return f"login_attempts:{app_id}:{email}"


def _check_account_lockout(app_id: str, email: str):
    """Check if an account is locked out. Raises HTTPException if locked."""
    lockout_key = _get_login_lockout_key(app_id, email)
    try:
        ttl = redis_client.ttl(lockout_key)
        if ttl and ttl > 0:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Account temporarily locked due to too many failed attempts. Try again in {ttl // 60 + 1} minutes."
            )
    except HTTPException:
        raise
    except Exception:
        pass  # Redis down — fail open


def _record_failed_login(app_id: str, email: str):
    """Record a failed login attempt. Locks account after MAX_LOGIN_ATTEMPTS."""
    try:
        attempts_key = _get_login_attempts_key(app_id, email)
        count = redis_client.incr(attempts_key)
        redis_client.expire(attempts_key, ACCOUNT_LOCKOUT_SECONDS)
        if count >= MAX_LOGIN_ATTEMPTS:
            lockout_key = _get_login_lockout_key(app_id, email)
            redis_client.setex(lockout_key, ACCOUNT_LOCKOUT_SECONDS, "1")
            redis_client.delete(attempts_key)
            logger.warning(f"Account locked: {email} for app {app_id} after {count} failed attempts")
    except Exception:
        pass  # Redis down — fail open


def _clear_login_attempts(app_id: str, email: str):
    """Clear failed attempt counter on successful login."""
    try:
        redis_client.delete(_get_login_attempts_key(app_id, email))
        redis_client.delete(_get_login_lockout_key(app_id, email))
    except Exception:
        pass

# Rate limit dependencies
_rl_login = create_rate_limit_dependency("login", max_requests=settings.RATE_LIMIT_LOGIN)
_rl_signup = create_rate_limit_dependency("signup", max_requests=settings.RATE_LIMIT_SIGNUP)
_rl_otp = create_rate_limit_dependency("otp", max_requests=settings.RATE_LIMIT_OTP)
_rl_forgot = create_rate_limit_dependency("forgot_password", max_requests=settings.RATE_LIMIT_OTP)


def _find_or_provision_user_for_app_login(
    db: Session,
    app: App,
    email: str,
    app_id: str,
) -> Optional[User]:
    user = db.query(User).filter(
        User.email == email,
        User.tenant_id == app.tenant_id,
        User.app_id == app_id,
    ).first()
    if user:
        return user

    # Support same-tenant multi-app login by provisioning a per-app identity
    # from an existing tenant-level identity record.
    tenant_user = db.query(User).filter(
        User.email == email,
        User.tenant_id == app.tenant_id,
    ).order_by(User.created_at.asc()).first()
    if not tenant_user or not tenant_user.password_hash:
        return None

    clone = User(
        email=tenant_user.email,
        password_hash=tenant_user.password_hash,
        app_id=app_id,
        tenant_id=app.tenant_id,
        is_active=tenant_user.is_active,
    )
    db.add(clone)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return db.query(User).filter(
            User.email == email,
            User.tenant_id == app.tenant_id,
            User.app_id == app_id,
        ).first()

    db.refresh(clone)
    return clone

def validate_app_credentials(db: Session, app_id: str, app_secret: str) -> App:
    """Validate app credentials and return the app if valid.
    Supports both hashed (SHA-256) and legacy plaintext secrets for backward compatibility.
    """
    import hashlib
    import hmac
    
    if not app_id or not app_secret:
        return None
    
    app = db.query(App).filter(App.app_id == app_id).first()
    if not app:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid app credentials"
        )
    
    # Check hashed secret (SHA-256 hex digest = 64 chars)
    if len(app.app_secret) == 64:
        provided_hash = hashlib.sha256(app_secret.encode()).hexdigest()
        if not hmac.compare_digest(provided_hash, app.app_secret):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid app credentials"
            )
    else:
        # Legacy plaintext comparison (for pre-migration apps)
        if app.app_secret != app_secret:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid app credentials"
            )
    return app

# ============== Password-based Auth ==============

@router.post("/signup", dependencies=[Depends(_rl_signup)])
def signup(request: SignupRequest, http_request: Request = None, db: Session = Depends(get_db)):
    """Sign up a new user with email and password"""
    # Validate app credentials
    app = validate_app_credentials(db, request.app_id, request.app_secret)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="App credentials are required for signup"
        )
    
    # Check if user already exists for this app within tenant
    existing_user = db.query(User).filter(
        User.email == request.email,
        User.tenant_id == app.tenant_id,
        User.app_id == request.app_id
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists for this app"
        )
    
    # Create user with hashed password
    hashed_pwd = hash_password(request.password)
    user = User(
        email=request.email,
        password_hash=hashed_pwd,
        app_id=request.app_id,
        tenant_id=app.tenant_id
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Record signup event
    if http_request:
        record_login_event(db, user.id, request.app_id, app.tenant_id, http_request, "signup")
    
    return {
        "message": "User registered successfully",
        "email": user.email,
        "user_id": user.id
    }

@router.post("/login", response_model=LoginResponse, dependencies=[Depends(_rl_login)])
def login(request: LoginRequest, http_request: Request = None, db: Session = Depends(get_db)):
    """
    Login with email and password.
    - If OTP is enabled for the app: verifies password and sends OTP
    - If OTP is disabled: verifies password and returns tokens directly
    """
    # Validate app credentials
    app = validate_app_credentials(db, request.app_id, request.app_secret)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="App credentials are required for login"
        )
    
    # Find (or provision) user for this app within tenant.
    user = _find_or_provision_user_for_app_login(
        db=db,
        app=app,
        email=request.email,
        app_id=request.app_id,
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Check if user has a password set
    if not user.password_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User exists but no password is set yet. You can reset your password to continue."
        )
    
    # Check brute-force lockout BEFORE verifying password
    _check_account_lockout(request.app_id, request.email)
    
    # Verify password
    if not verify_password(request.password, user.password_hash):
        _record_failed_login(request.app_id, request.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password"
        )
    
    # Check if user is active
    if not user.is_active:
        # Look up admin email for this tenant
        from app.models.admin import Admin
        admin = db.query(Admin).filter(Admin.tenant_id == app.tenant_id).first()
        admin_email = admin.email if admin else "your administrator"
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Your account has been temporarily deactivated by the administrator. "
                   f"Please contact {admin_email} for further assistance."
        )
    
    # Check if OTP is enabled for this app
    if app.otp_enabled:
        # Generate and send OTP
        try:
            otp = generate_otp(request.email)
            send_otp_email(request.email, otp, app.name or "Auth Platform", app.logo_url)
            return LoginResponse(
                message="Password verified. OTP sent to your email.",
                email=request.email,
                otp_required=True
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to send OTP: {str(e)}"
            )
    else:
        # OTP disabled - return tokens directly
        access_token, refresh_token = generate_tokens_for_user(user, app)
        # Send login notification if enabled
        if app.login_notification_enabled:
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
        # Record login event
        if http_request:
            record_login_event(db, user.id, request.app_id, app.tenant_id, http_request, "login")
        
        # Clear failed attempt counter on successful login
        _clear_login_attempts(request.app_id, request.email)
        
        return LoginResponse(
            message="Login successful",
            email=request.email,
            otp_required=False,
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

@router.post("/login/verify-otp", response_model=AuthResponse, dependencies=[Depends(_rl_otp)])
def login_verify_otp(request: LoginOTPVerifyRequest, http_request: Request = None, db: Session = Depends(get_db)):
    """Verify OTP after password-based login"""
    # Validate app credentials
    app = validate_app_credentials(db, request.app_id, request.app_secret)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="App credentials are required"
        )
    
    # Verify OTP
    if not verify_otp(request.email, request.otp):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired OTP"
        )
    
    # Get user for this app within tenant
    user = db.query(User).filter(
        User.email == request.email,
        User.tenant_id == app.tenant_id,
        User.app_id == request.app_id
    ).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Generate tokens
    access_token, refresh_token = generate_tokens_for_user(user, app)
    
    # Send login notification if enabled
    if app.login_notification_enabled:
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
    
    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        app_id=request.app_id
    )

# ============== Forgot Password ==============

@router.post("/forgot-password", response_model=ForgotPasswordResponse, dependencies=[Depends(_rl_forgot)])
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """
    Request password reset for a user.
    - If OTP is enabled: sends OTP via email
    - If OTP is disabled: sends reset token via email
    """
    # Validate app credentials
    app = validate_app_credentials(db, request.app_id, request.app_secret)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="App credentials are required"
        )
    
    # Check if user exists for this app within tenant
    user = db.query(User).filter(
        User.email == request.email,
        User.tenant_id == app.tenant_id,
        User.app_id == request.app_id
    ).first()
    
    if not user:
        # Don't reveal if user exists — always return success
        logger.info(f"Forgot password requested for non-existent user: {request.email}")
        return ForgotPasswordResponse(
            message="If an account with this email exists, a password reset has been sent.",
            email=request.email,
            method="otp" if app.otp_enabled else "token"
        )
    
    try:
        if app.otp_enabled:
            # Generate and send OTP
            otp = generate_password_reset_otp(request.email, request.app_id)
            send_password_reset_email(request.email, otp, app.name or "Auth Platform", app.logo_url)
            return ForgotPasswordResponse(
                message="Password reset OTP sent to your email",
                email=request.email,
                method="otp"
            )
        else:
            # Generate and send reset token
            token = generate_reset_token(request.email, request.app_id)
            send_password_reset_token_email(request.email, token, app.name or "Auth Platform", app.logo_url)
            return ForgotPasswordResponse(
                message="Password reset token sent to your email",
                email=request.email,
                method="token"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send password reset email: {str(e)}"
        )

@router.post("/reset-password")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    """
    Reset password using OTP (if enabled) or token (if OTP disabled).
    """
    # Validate app credentials
    app = validate_app_credentials(db, request.app_id, request.app_secret)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="App credentials are required"
        )
    
    # Get user for this app within tenant
    user = db.query(User).filter(
        User.email == request.email,
        User.tenant_id == app.tenant_id,
        User.app_id == request.app_id
    ).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Verify OTP or token based on app settings
    if app.otp_enabled:
        if not request.otp:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP is required for password reset"
            )
        if not verify_password_reset_otp(request.email, request.app_id, request.otp):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired OTP"
            )
    else:
        if not request.token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reset token is required for password reset"
            )
        if not verify_reset_token(request.email, request.app_id, request.token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired reset token"
            )
    
    # Update user's password
    user.password_hash = hash_password(request.new_password)
    db.commit()
    
    return {
        "message": "Password reset successfully",
        "email": user.email
    }

# ============== Set Password (admin-invited users) ==============

class SetPasswordRequest(BaseModel):
    token: str
    email: str
    app_id: str
    new_password: str

@router.post("/set-password")
def set_password(request: SetPasswordRequest, db: Session = Depends(get_db)):
    """
    Set password for a user invited by admin.
    Uses the reset token sent via email link.
    """
    # Validate app exists
    app = db.query(App).filter(App.app_id == request.app_id).first()
    if not app:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid application"
        )

    # Verify the reset token
    if not verify_reset_token(request.email, request.app_id, request.token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired link. Please contact your administrator for a new invite."
        )

    # Find the user within this app
    user = db.query(User).filter(
        User.email == request.email,
        User.tenant_id == app.tenant_id,
        User.app_id == request.app_id
    ).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    try:
        enforce_password_strength(request.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Set the password
    user.password_hash = hash_password(request.new_password)
    db.commit()

    return {
        "message": "Password set successfully. You can now sign in.",
        "email": user.email,
        "server_signin_url": build_server_signin_url(request.app_id),
        "app_signin_url": infer_app_signin_url(app.redirect_uris),
    }

# ============== OTP-only Auth (legacy) ==============

@router.post("/request-otp", dependencies=[Depends(_rl_otp)])
def request_otp(request: OTPRequest, db: Session = Depends(get_db)):
    """Request an OTP to be sent to the provided email"""
    # Validate app credentials if provided
    app = None
    if request.app_id and request.app_secret:
        app = validate_app_credentials(db, request.app_id, request.app_secret)
    
    try:
        otp = generate_otp(request.email)
        app_name = app.name if app else "Auth Platform"
        send_otp_email(request.email, otp, app_name, app.logo_url if app else None)
        return {"message": "OTP sent successfully", "email": request.email}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send OTP: {str(e)}"
        )

@router.post("/verify-otp", response_model=AuthResponse, dependencies=[Depends(_rl_otp)])
def verify(request: OTPVerifyRequest, db: Session = Depends(get_db)):
    """Verify OTP and return access and refresh tokens"""
    # Validate app credentials if provided
    app = None
    if request.app_id and request.app_secret:
        app = validate_app_credentials(db, request.app_id, request.app_secret)
    
    if not verify_otp(request.email, request.otp):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired OTP"
        )
    
    # Check if user exists for this app within tenant, create if not
    if app:
        user = db.query(User).filter(
            User.email == request.email,
            User.tenant_id == app.tenant_id,
            User.app_id == request.app_id
        ).first()
    else:
        user = db.query(User).filter(User.email == request.email).first()
    
    if not user:
        # For legacy flow without app, get or create default tenant
        if app:
            tenant_id = app.tenant_id
        else:
            default_tenant = get_or_create_default_tenant(db)
            tenant_id = default_tenant.id
        user = User(
            email=request.email,
            app_id=request.app_id if app else 'default',
            tenant_id=tenant_id
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    
    # Generate tokens
    access_token, refresh_token = generate_tokens_for_user(user, app)
    
    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        app_id=request.app_id if app else None
    )

# ============== App Settings ==============

@router.get("/app-settings/{app_id}")
def get_app_settings(app_id: str, app_secret: str, db: Session = Depends(get_db)):
    """Get app settings (OTP enabled, etc.) - requires app credentials"""
    app = validate_app_credentials(db, app_id, app_secret)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid app credentials"
        )
    
    return {
        "app_id": app.app_id,
        "name": app.name,
        "otp_enabled": app.otp_enabled,
        "login_notification_enabled": app.login_notification_enabled,
        "access_token_expiry_minutes": app.access_token_expiry_minutes,
        "refresh_token_expiry_days": app.refresh_token_expiry_days
    }
