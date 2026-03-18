from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.db import get_db
from app.models.app import App
from app.models.user import User
from app.models.admin import Admin
from app.models.tenant import Tenant
from app.models.passkey import PasskeyCredential
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
import secrets
import hashlib
import hmac
import logging

from app.services.jwt_service import create_access_token, verify_token
from app.services.jwt_service import is_user_online, force_user_offline
from app.services.password_service import hash_password, verify_password, generate_reset_token
from app.services.tenant_service import create_tenant
from app.services.mail_service import send_set_password_email, send_force_logout_email
from app.services.mail_service import send_admin_welcome_email
from app.services.rate_limiter import create_rate_limit_dependency
from app.config import settings as app_settings
from app.redis import redis_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin")
security = HTTPBearer(auto_error=False)

# Rate limit dependencies
_rl_admin_login = create_rate_limit_dependency("admin_login", max_requests=app_settings.RATE_LIMIT_LOGIN)
_rl_admin_register = create_rate_limit_dependency("admin_register", max_requests=app_settings.RATE_LIMIT_SIGNUP)

# ============== Pydantic Schemas ==============

class AdminRegisterRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_name: str

class AdminLoginRequest(BaseModel):
    email: str
    password: str

class TenantUpdateRequest(BaseModel):
    name: Optional[str] = None

class AppCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    otp_enabled: bool = True
    login_notification_enabled: bool = False
    force_logout_notification_enabled: bool = False
    passkey_enabled: bool = False
    access_token_expiry_minutes: int = 30
    refresh_token_expiry_days: int = 7
    redirect_uris: Optional[str] = None  # Comma-separated allowed redirect URIs

class AppUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    otp_enabled: Optional[bool] = None
    login_notification_enabled: Optional[bool] = None
    force_logout_notification_enabled: Optional[bool] = None
    passkey_enabled: Optional[bool] = None
    access_token_expiry_minutes: Optional[int] = None
    refresh_token_expiry_days: Optional[int] = None
    redirect_uris: Optional[str] = None

class AppResponse(BaseModel):
    id: int
    app_id: str
    name: Optional[str]
    description: Optional[str]
    created_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class AppCredentialsResponse(BaseModel):
    app_id: str
    app_secret_hint: str  # Only shows last 4 characters
    app_secret: Optional[str] = None  # Only populated on create/regenerate (plaintext shown once)

class UserCreateRequest(BaseModel):
    email: EmailStr
    app_id: Optional[str] = None

class UserUpdateRequest(BaseModel):
    is_active: Optional[bool] = None
    app_id: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    email: str
    app_id: Optional[str]
    is_active: bool
    created_at: Optional[datetime]
    
    class Config:
        from_attributes = True

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
        token = request.cookies.get('admin_token')
    
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
    return admin


# ============== Brute-Force Protection for Admin Login ==============

MAX_ADMIN_LOGIN_ATTEMPTS = 5
ADMIN_LOCKOUT_SECONDS = 900  # 15 minutes


def _check_admin_lockout(email: str):
    """Check if admin account is locked out."""
    try:
        ttl = redis_client.ttl(f"admin_lockout:{email}")
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
        count = redis_client.incr(key)
        redis_client.expire(key, ADMIN_LOCKOUT_SECONDS)
        if count >= MAX_ADMIN_LOGIN_ATTEMPTS:
            redis_client.setex(f"admin_lockout:{email}", ADMIN_LOCKOUT_SECONDS, "1")
            redis_client.delete(key)
            logger.warning(f"Admin account locked: {email} after {count} failed attempts")
    except Exception:
        pass


def _clear_admin_login_attempts(email: str):
    try:
        redis_client.delete(f"admin_attempts:{email}")
        redis_client.delete(f"admin_lockout:{email}")
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


@router.post("/register", response_model=dict, dependencies=[Depends(_rl_admin_register)])
def admin_register(request: AdminRegisterRequest, db: Session = Depends(get_db)):
    """Step 1: Validate input and send OTP to admin email for verification"""
    from app.services.otp_service import generate_otp
    from app.services.mail_service import send_otp_email
    
    # Check if admin already exists
    existing = db.query(Admin).filter(Admin.email == request.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An admin with this email already exists"
        )
    
    # Store pending registration data in Redis (expires in 10 minutes)
    import json
    pending_key = f"admin_pending_reg:{request.email}"
    redis_client.setex(pending_key, 600, json.dumps({
        "email": request.email,
        "password": request.password,
        "tenant_name": request.tenant_name
    }))
    
    # Generate and send OTP
    otp = generate_otp(request.email)
    send_otp_email(request.email, otp, "Auth Platform Admin")
    
    return {"message": "OTP sent to your email. Please verify to complete registration.", "email": request.email}


class AdminVerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str


@router.post("/register/verify-otp", response_model=dict)
def admin_register_verify_otp(request: AdminVerifyOTPRequest, db: Session = Depends(get_db)):
    """Step 2: Verify OTP and complete admin registration"""
    from app.services.otp_service import verify_otp
    import json
    
    # Verify OTP
    if not verify_otp(request.email, request.otp):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP"
        )
    
    # Retrieve pending registration data
    pending_key = f"admin_pending_reg:{request.email}"
    pending_data = redis_client.get(pending_key)
    if not pending_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration session expired. Please start again."
        )
    
    data = json.loads(pending_data)
    redis_client.delete(pending_key)
    
    # Double-check admin doesn't exist (race condition guard)
    existing = db.query(Admin).filter(Admin.email == data["email"]).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An admin with this email already exists"
        )
    
    # Create tenant
    tenant = create_tenant(db, data["tenant_name"])
    
    # Create admin
    admin = Admin(
        email=data["email"],
        password_hash=hash_password(data["password"]),
        tenant_id=tenant.id
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)
    db.refresh(tenant)
    
    # Generate admin JWT
    token_data = {
        "admin_id": admin.id,
        "tenant_id": tenant.id,
        "sub": admin.email,
        "type": "admin_access"
    }
    access_token = create_access_token(token_data, timedelta(hours=24))
    
    # Set token as HttpOnly cookie
    response = JSONResponse(content={
        "admin_id": admin.id,
        "tenant_id": tenant.id,
        "tenant_name": tenant.name,
        "token_type": "bearer",
        "message": "Admin registered successfully"
    })
    response.set_cookie(
        key="admin_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        max_age=86400,  # 24 hours
        path="/"
    )

    # Non-blocking welcome email for new admin signup
    send_admin_welcome_email(to=admin.email, tenant_name=tenant.name, app_name="Auth Platform")

    return response


@router.post("/login", response_model=dict, dependencies=[Depends(_rl_admin_login)])
def admin_login(request: AdminLoginRequest, db: Session = Depends(get_db)):
    """Admin login — sets JWT as HttpOnly cookie with brute-force protection"""
    # Check lockout
    _check_admin_lockout(request.email)
    
    admin = db.query(Admin).filter(Admin.email == request.email).first()
    if not admin or not verify_password(request.password, admin.password_hash):
        _record_admin_failed_login(request.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Clear failed attempts on success
    _clear_admin_login_attempts(request.email)
    
    tenant = db.query(Tenant).filter(Tenant.id == admin.tenant_id).first()
    
    token_data = {
        "admin_id": admin.id,
        "tenant_id": admin.tenant_id,
        "sub": admin.email,
        "type": "admin_access"
    }
    access_token = create_access_token(token_data, timedelta(hours=24))
    
    # Set token as HttpOnly cookie
    response = JSONResponse(content={
        "token_type": "bearer",
        "tenant_id": admin.tenant_id,
        "tenant_name": tenant.name if tenant else ""
    })
    response.set_cookie(
        key="admin_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        max_age=86400,  # 24 hours
        path="/"
    )
    return response


@router.post("/logout")
def admin_logout():
    """Admin logout — clears the HttpOnly cookie"""
    response = JSONResponse(content={"message": "Logged out successfully"})
    response.delete_cookie(key="admin_token", path="/")
    return response


# ============== Tenant Management ==============

@router.get("/tenant", response_model=dict)
def get_tenant(admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    """Get the current admin's tenant details"""
    tenant = db.query(Tenant).filter(Tenant.id == admin.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {
        "id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "created_at": tenant.created_at.isoformat() if tenant.created_at else None
    }


@router.put("/tenant", response_model=dict)
def update_tenant(
    request: TenantUpdateRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Update the current admin's tenant"""
    tenant = db.query(Tenant).filter(Tenant.id == admin.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    if request.name is not None:
        tenant.name = request.name
    
    db.commit()
    db.refresh(tenant)
    
    return {
        "id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "message": "Tenant updated successfully"
    }


# ============== App Management ==============

@router.post("/apps", response_model=dict)
def create_app(
    request: AppCreateRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Create a new application under the admin's tenant"""
    try:
        app_id = secrets.token_hex(8)
        app_secret = secrets.token_hex(16)
        app_secret_hash = _hash_app_secret(app_secret)

        app = App(
            app_id=app_id, 
            app_secret=app_secret_hash,
            tenant_id=admin.tenant_id,
            name=request.name,
            description=request.description,
            otp_enabled=request.otp_enabled,
            login_notification_enabled=request.login_notification_enabled,
            force_logout_notification_enabled=request.force_logout_notification_enabled,
            passkey_enabled=request.passkey_enabled,
            access_token_expiry_minutes=request.access_token_expiry_minutes,
            refresh_token_expiry_days=request.refresh_token_expiry_days,
            redirect_uris=request.redirect_uris
        )
        db.add(app)
        db.commit()
        db.refresh(app)

        return {
            "id": app.id,
            "app_id": app_id, 
            "app_secret": app_secret,  # Plaintext shown ONLY on creation
            "name": app.name,
            "tenant_id": app.tenant_id,
            "otp_enabled": app.otp_enabled,
            "login_notification_enabled": app.login_notification_enabled,
            "force_logout_notification_enabled": app.force_logout_notification_enabled,
            "passkey_enabled": app.passkey_enabled,
            "access_token_expiry_minutes": app.access_token_expiry_minutes,
            "refresh_token_expiry_days": app.refresh_token_expiry_days,
            "redirect_uris": app.redirect_uris,
            "message": "App created successfully"
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create app: {str(e)}"
        )

# Keep old endpoint for backward compatibility
@router.post("/create-app", response_model=dict, include_in_schema=False)
def create_app_legacy(
    request: AppCreateRequest = None,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    if request is None:
        request = AppCreateRequest(name="Unnamed App")
    return create_app(request, admin, db)

@router.get("/apps", response_model=List[dict])
def list_apps(
    search: Optional[str] = None,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """List applications for the admin's tenant"""
    query = db.query(App).filter(App.tenant_id == admin.tenant_id)
    
    if search:
        query = query.filter(
            or_(
                App.name.ilike(f"%{search}%"),
                App.app_id.ilike(f"%{search}%")
            )
        )
    
    apps = query.order_by(App.created_at.desc()).all()
    return [{
        "id": app.id,
        "app_id": app.app_id,
        "name": app.name,
        "description": app.description,
        "tenant_id": app.tenant_id,
        "is_active": True,  # All apps are active by default
        "otp_enabled": app.otp_enabled,
        "passkey_enabled": app.passkey_enabled,
        "login_notification_enabled": app.login_notification_enabled,
        "force_logout_notification_enabled": app.force_logout_notification_enabled,
        "access_token_expiry_minutes": app.access_token_expiry_minutes,
        "refresh_token_expiry_days": app.refresh_token_expiry_days,
        "redirect_uris": app.redirect_uris,
        "created_at": app.created_at.isoformat() if app.created_at else None
    } for app in apps]

@router.get("/apps/{app_id}", response_model=dict)
def get_app(
    app_id: str,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Get a specific application by app_id (scoped to admin's tenant)"""
    app = db.query(App).filter(
        App.app_id == app_id,
        App.tenant_id == admin.tenant_id
    ).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    return {
        "id": app.id,
        "app_id": app.app_id,
        "name": app.name,
        "description": app.description,
        "tenant_id": app.tenant_id,
        "otp_enabled": app.otp_enabled,
        "login_notification_enabled": app.login_notification_enabled,
        "force_logout_notification_enabled": app.force_logout_notification_enabled,
        "passkey_enabled": app.passkey_enabled,
        "access_token_expiry_minutes": app.access_token_expiry_minutes,
        "refresh_token_expiry_days": app.refresh_token_expiry_days,
        "redirect_uris": app.redirect_uris,
        "created_at": app.created_at.isoformat() if app.created_at else None,
        "updated_at": app.updated_at.isoformat() if app.updated_at else None
    }

@router.put("/apps/{app_id}", response_model=dict)
def update_app(
    app_id: str,
    request: AppUpdateRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Update an application's properties (scoped to admin's tenant)"""
    app = db.query(App).filter(
        App.app_id == app_id,
        App.tenant_id == admin.tenant_id
    ).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    if request.name is not None:
        app.name = request.name
    if request.description is not None:
        app.description = request.description
    if request.otp_enabled is not None:
        app.otp_enabled = request.otp_enabled
    if request.login_notification_enabled is not None:
        app.login_notification_enabled = request.login_notification_enabled
    if request.force_logout_notification_enabled is not None:
        app.force_logout_notification_enabled = request.force_logout_notification_enabled
    if request.passkey_enabled is not None:
        app.passkey_enabled = request.passkey_enabled
    if request.access_token_expiry_minutes is not None:
        app.access_token_expiry_minutes = request.access_token_expiry_minutes
    if request.refresh_token_expiry_days is not None:
        app.refresh_token_expiry_days = request.refresh_token_expiry_days
    if request.redirect_uris is not None:
        app.redirect_uris = request.redirect_uris
    
    db.commit()
    db.refresh(app)
    
    return {
        "id": app.id,
        "app_id": app.app_id,
        "name": app.name,
        "description": app.description,
        "tenant_id": app.tenant_id,
        "otp_enabled": app.otp_enabled,
        "login_notification_enabled": app.login_notification_enabled,
        "force_logout_notification_enabled": app.force_logout_notification_enabled,
        "passkey_enabled": app.passkey_enabled,
        "access_token_expiry_minutes": app.access_token_expiry_minutes,
        "refresh_token_expiry_days": app.refresh_token_expiry_days,
        "redirect_uris": app.redirect_uris,
        "message": "App updated successfully"
    }

@router.delete("/apps/{app_id}")
def delete_app(
    app_id: str,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Delete an application and all its associated data (scoped to admin's tenant)"""
    app = db.query(App).filter(
        App.app_id == app_id,
        App.tenant_id == admin.tenant_id
    ).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    # Delete passkey credentials for this app within the tenant
    db.query(PasskeyCredential).filter(
        PasskeyCredential.app_id == app_id,
        PasskeyCredential.tenant_id == admin.tenant_id
    ).delete()
    # Delete all users associated with this app within the tenant
    db.query(User).filter(
        User.app_id == app_id,
        User.tenant_id == admin.tenant_id
    ).delete()
    db.delete(app)
    db.commit()
    
    return {"message": "App and its associated data deleted successfully"}

@router.get("/apps/{app_id}/credentials", response_model=AppCredentialsResponse)
def get_app_credentials(
    app_id: str,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Get the credentials for an application (scoped to admin's tenant)"""
    app = db.query(App).filter(
        App.app_id == app_id,
        App.tenant_id == admin.tenant_id
    ).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    return AppCredentialsResponse(app_id=app.app_id, app_secret_hint="****" + app.app_secret[-4:] if len(app.app_secret) > 4 else "****")

@router.post("/apps/{app_id}/regenerate-secret", response_model=AppCredentialsResponse)
def regenerate_app_secret(
    app_id: str,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Regenerate the secret for an application (scoped to admin's tenant)"""
    app = db.query(App).filter(
        App.app_id == app_id,
        App.tenant_id == admin.tenant_id
    ).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    new_secret = secrets.token_hex(16)
    app.app_secret = _hash_app_secret(new_secret)
    db.commit()
    db.refresh(app)
    
    # Return plaintext just this once; also include the hint for display
    return {"app_id": app.app_id, "app_secret": new_secret, "app_secret_hint": "****" + new_secret[-4:]}

# ============== User Management ==============

@router.get("/users", response_model=dict)
def list_users(
    search: Optional[str] = None,
    app_id: Optional[str] = None,
    is_active: Optional[bool] = None,
    limit: int = Query(default=50, le=100),
    offset: int = 0,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """List all users within the admin's tenant"""
    query = db.query(User).filter(User.tenant_id == admin.tenant_id)
    
    if search:
        query = query.filter(User.email.ilike(f"%{search}%"))
    if app_id:
        query = query.filter(User.app_id == app_id)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)
    
    total = query.count()
    users = query.order_by(User.created_at.desc()).offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "users": [{
            "id": user.id,
            "email": user.email,
            "app_id": user.app_id,
            "tenant_id": user.tenant_id,
            "is_active": user.is_active,
            "is_online": is_user_online(user.id, admin.tenant_id),
            "created_at": user.created_at.isoformat() if user.created_at else None
        } for user in users]
    }

@router.post("/users", response_model=dict)
def create_user(
    request: UserCreateRequest,
    http_request: Request = None,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Create a new user within the admin's tenant and send a set-password invite email"""
    if not request.app_id:
        raise HTTPException(status_code=400, detail="app_id is required")
    
    # Validate app belongs to the admin's tenant
    app = db.query(App).filter(
        App.app_id == request.app_id,
        App.tenant_id == admin.tenant_id
    ).first()
    if not app:
        raise HTTPException(status_code=400, detail="App not found in your tenant")
    
    # Check if user already exists in this app (same email can exist in different apps)
    existing = db.query(User).filter(
        User.email == request.email,
        User.tenant_id == admin.tenant_id,
        User.app_id == request.app_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="User with this email already exists in this app")
    
    user = User(
        email=request.email,
        app_id=request.app_id,
        tenant_id=admin.tenant_id,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Generate a reset token and send set-password email
    invite_sent = False
    try:
        token = generate_reset_token(user.email, request.app_id)
        base_url = str(http_request.base_url).rstrip("/") if http_request else ""
        reset_link = f"{base_url}/reset-password?token={token}&email={user.email}&app_id={request.app_id}"
        app_name = app.name or "Application"
        send_set_password_email(user.email, reset_link, app_name)
        invite_sent = True
    except Exception as e:
        logger.warning(f"Failed to send set-password email to {user.email}: {e}")
    
    return {
        "id": user.id,
        "email": user.email,
        "app_id": user.app_id,
        "tenant_id": user.tenant_id,
        "is_active": user.is_active,
        "invite_sent": invite_sent,
        "message": "User created successfully" + (" and invite email sent" if invite_sent else " (invite email failed)")
    }


class BulkActionRequest(BaseModel):
    action: str  # "delete" | "force-logout" | "set-inactive"
    user_ids: list[int]


@router.post("/users/bulk-action")
def bulk_user_action(
    request: BulkActionRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Perform a bulk action on multiple users (scoped to admin's tenant)"""
    if request.action not in ("delete", "force-logout", "set-inactive"):
        raise HTTPException(status_code=400, detail="Invalid action. Must be: delete, force-logout, or set-inactive")

    if not request.user_ids:
        raise HTTPException(status_code=400, detail="No user IDs provided")

    # Fetch all matching users scoped to the admin's tenant
    target_users = db.query(User).filter(
        User.id.in_(request.user_ids),
        User.tenant_id == admin.tenant_id
    ).all()

    if not target_users:
        raise HTTPException(status_code=404, detail="No matching users found in your tenant")

    results = {"processed": 0, "skipped": 0, "emails_sent": 0}

    if request.action == "delete":
        for user in target_users:
            # Revoke session only when the user is currently online.
            if is_user_online(user.id, admin.tenant_id):
                force_user_offline(user.id, admin.tenant_id)
            db.query(PasskeyCredential).filter(
                PasskeyCredential.user_id == user.id,
                PasskeyCredential.tenant_id == admin.tenant_id
            ).delete()
            db.delete(user)
            results["processed"] += 1
        db.commit()

    elif request.action == "force-logout":
        for user in target_users:
            force_user_offline(user.id, admin.tenant_id)
            results["processed"] += 1
            # Send notification email if enabled
            try:
                app_name = "Auth Platform"
                send_email = False
                if user.app_id:
                    app_obj = db.query(App).filter(App.app_id == user.app_id).first()
                    if app_obj:
                        if app_obj.name:
                            app_name = app_obj.name
                        send_email = app_obj.force_logout_notification_enabled
                if send_email:
                    if send_force_logout_email(user.email, app_name):
                        results["emails_sent"] += 1
            except Exception:
                pass

    elif request.action == "set-inactive":
        for user in target_users:
            user.is_active = False
            results["processed"] += 1
        db.commit()

    return {
        "message": f"Bulk {request.action} completed",
        "action": request.action,
        **results,
        "total_requested": len(request.user_ids)
    }


@router.get("/users/{user_id}", response_model=dict)
def get_user(
    user_id: int,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Get a specific user by ID (scoped to admin's tenant)"""
    user = db.query(User).filter(
        User.id == user_id,
        User.tenant_id == admin.tenant_id
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": user.id,
        "email": user.email,
        "app_id": user.app_id,
        "tenant_id": user.tenant_id,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None
    }

@router.put("/users/{user_id}", response_model=dict)
def update_user(
    user_id: int,
    request: UserUpdateRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Update a user's properties (scoped to admin's tenant)"""
    user = db.query(User).filter(
        User.id == user_id,
        User.tenant_id == admin.tenant_id
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if request.is_active is not None:
        user.is_active = request.is_active
    if request.app_id is not None:
        # Validate the target app belongs to the same tenant
        app = db.query(App).filter(
            App.app_id == request.app_id,
            App.tenant_id == admin.tenant_id
        ).first()
        if not app:
            raise HTTPException(status_code=400, detail="Target app not found in your tenant")
        user.app_id = request.app_id
    
    db.commit()
    db.refresh(user)
    
    return {
        "id": user.id,
        "email": user.email,
        "app_id": user.app_id,
        "tenant_id": user.tenant_id,
        "is_active": user.is_active,
        "message": "User updated successfully"
    }

@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Delete a user (scoped to admin's tenant)"""
    user = db.query(User).filter(
        User.id == user_id,
        User.tenant_id == admin.tenant_id
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Revoke active sessions before deleting user data only if user is online.
    if is_user_online(user.id, admin.tenant_id):
        force_user_offline(user.id, admin.tenant_id)
    
    # Delete user's passkey credentials
    db.query(PasskeyCredential).filter(
        PasskeyCredential.user_id == user.id,
        PasskeyCredential.tenant_id == admin.tenant_id
    ).delete()
    
    db.delete(user)
    db.commit()
    
    return {"message": "User deleted successfully"}


@router.post("/users/{user_id}/force-logout")
def force_logout_user(
    user_id: int,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Force a user offline – invalidates their session immediately and sends a notification email"""
    user = db.query(User).filter(
        User.id == user_id,
        User.tenant_id == admin.tenant_id
    ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    force_user_offline(user.id, admin.tenant_id)

    # Send notification email if enabled for this app (non-blocking, best-effort)
    email_sent = False
    try:
        app_name = "Auth Platform"
        send_email = False
        if user.app_id:
            app_obj = db.query(App).filter(App.app_id == user.app_id).first()
            if app_obj:
                if app_obj.name:
                    app_name = app_obj.name
                send_email = app_obj.force_logout_notification_enabled
        if send_email:
            email_sent = send_force_logout_email(user.email, app_name)
    except Exception as e:
        logger.warning(f"Failed to send force-logout email to {user.email}: {e}")
    
    return {
        "message": f"User {user.email} has been forced offline",
        "user_id": user.id,
        "is_online": False,
        "email_sent": email_sent
    }


# ============== Dashboard Stats ==============

@router.get("/stats")
def get_stats(
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics for the admin's tenant"""
    total_apps = db.query(App).filter(App.tenant_id == admin.tenant_id).count()
    total_users = db.query(User).filter(User.tenant_id == admin.tenant_id).count()
    active_users = db.query(User).filter(
        User.tenant_id == admin.tenant_id,
        User.is_active == True
    ).count()

    # Count online users via Redis
    all_users = db.query(User).filter(User.tenant_id == admin.tenant_id).all()
    online_count = sum(1 for u in all_users if is_user_online(u.id, admin.tenant_id))
    
    return {
        "total_apps": total_apps,
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": total_users - active_users,
        "online_users": online_count
    }


@router.get("/login-events")
def get_login_events(
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
    page: int = 1,
    per_page: int = 50,
    event_type: str = None,
    app_id: str = None,
):
    """Get login events for the admin's tenant (paginated, with optional filters)"""
    from app.models.login_event import LoginEvent

    query = db.query(LoginEvent).filter(LoginEvent.tenant_id == admin.tenant_id)

    if event_type:
        query = query.filter(LoginEvent.event_type == event_type)
    if app_id:
        query = query.filter(LoginEvent.app_id == app_id)

    total = query.count()
    events = (
        query.order_by(LoginEvent.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "events": [
            {
                "id": e.id,
                "user_id": e.user_id,
                "app_id": e.app_id,
                "event_type": e.event_type,
                "ip_address": e.ip_address,
                "city": e.city,
                "region": e.region,
                "country": e.country,
                "lat": e.lat,
                "lon": e.lon,
                "isp": e.isp,
                "created_at": str(e.created_at) if e.created_at else None,
            }
            for e in events
        ],
    }
