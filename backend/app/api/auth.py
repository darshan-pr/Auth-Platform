from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.orm import Session
from datetime import timedelta
from app.schemas.auth import (
    OTPRequest, OTPVerifyRequest, AuthResponse,
    SignupRequest, LoginRequest, LoginResponse, LoginOTPVerifyRequest,
    ForgotPasswordRequest, ForgotPasswordResponse, ResetPasswordRequest
)
from app.services.otp_service import generate_otp, verify_otp, generate_password_reset_otp, verify_password_reset_otp
from app.services.mail_service import send_otp_email, send_password_reset_email, send_password_reset_token_email, send_login_notification_email
from app.services.jwt_service import create_access_token, create_refresh_token
from app.services.password_service import hash_password, verify_password, generate_reset_token, verify_reset_token
from app.db import get_db
from app.models.user import User
from app.models.app import App

router = APIRouter(prefix="/auth")

def validate_app_credentials(db: Session, app_id: str, app_secret: str) -> App:
    """Validate app credentials and return the app if valid"""
    if not app_id or not app_secret:
        return None
    
    app = db.query(App).filter(App.app_id == app_id).first()
    if not app:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid app credentials"
        )
    if app.app_secret != app_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid app credentials"
        )
    return app

def generate_tokens_for_user(user: User, app: App):
    """Generate access and refresh tokens for a user with app-specific expiry settings"""
    token_data = {"sub": user.email, "user_id": user.id}
    if app:
        token_data["app_id"] = app.app_id
    
    # Use app-specific expiry settings
    if app:
        access_expires = timedelta(minutes=app.access_token_expiry_minutes)
        refresh_expires = timedelta(days=app.refresh_token_expiry_days)
    else:
        access_expires = None
        refresh_expires = None
    
    access_token = create_access_token(token_data, access_expires)
    refresh_token = create_refresh_token(token_data, refresh_expires)
    
    return access_token, refresh_token

# ============== Password-based Auth ==============

@router.post("/signup")
def signup(request: SignupRequest, db: Session = Depends(get_db)):
    """Sign up a new user with email and password"""
    # Validate app credentials
    app = validate_app_credentials(db, request.app_id, request.app_secret)
    if not app:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="App credentials are required for signup"
        )
    
    # Check if user already exists for this app
    existing_user = db.query(User).filter(
        User.email == request.email,
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
        app_id=request.app_id
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return {
        "message": "User registered successfully",
        "email": user.email,
        "user_id": user.id
    }

@router.post("/login", response_model=LoginResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
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
    
    # Find user for this specific app
    user = db.query(User).filter(
        User.email == request.email,
        User.app_id == request.app_id
    ).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Check if user has a password set
    if not user.password_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User does not have a password set. Please sign up first."
        )
    
    # Verify password
    if not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )
    
    # Check if OTP is enabled for this app
    if app.otp_enabled:
        # Generate and send OTP
        try:
            otp = generate_otp(request.email)
            send_otp_email(request.email, otp, app.name or "Auth Platform")
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
            send_login_notification_email(
                to=user.email,
                app_name=app.name or "Auth Platform",
                access_token_expiry_minutes=app.access_token_expiry_minutes,
                refresh_token_expiry_days=app.refresh_token_expiry_days,
            )
        return LoginResponse(
            message="Login successful",
            email=request.email,
            otp_required=False,
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

@router.post("/login/verify-otp", response_model=AuthResponse)
def login_verify_otp(request: LoginOTPVerifyRequest, db: Session = Depends(get_db)):
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
    
    # Get user for this specific app
    user = db.query(User).filter(
        User.email == request.email,
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
        send_login_notification_email(
            to=user.email,
            app_name=app.name or "Auth Platform",
            access_token_expiry_minutes=app.access_token_expiry_minutes,
            refresh_token_expiry_days=app.refresh_token_expiry_days,
        )
    
    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        app_id=request.app_id
    )

# ============== Forgot Password ==============

@router.post("/forgot-password", response_model=ForgotPasswordResponse)
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
    
    # Check if user exists for this app
    user = db.query(User).filter(
        User.email == request.email,
        User.app_id == request.app_id
    ).first()
    
    if not user:
        # Don't reveal if user exists or not for security
        # But still return success to prevent email enumeration
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if not user.password_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User does not have a password set"
        )
    
    try:
        if app.otp_enabled:
            # Generate and send OTP
            otp = generate_password_reset_otp(request.email, request.app_id)
            send_password_reset_email(request.email, otp, app.name or "Auth Platform")
            return ForgotPasswordResponse(
                message="Password reset OTP sent to your email",
                email=request.email,
                method="otp"
            )
        else:
            # Generate and send reset token
            token = generate_reset_token(request.email, request.app_id)
            send_password_reset_token_email(request.email, token, app.name or "Auth Platform")
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
    
    # Get user for this specific app
    user = db.query(User).filter(
        User.email == request.email,
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

# ============== OTP-only Auth (legacy) ==============

@router.post("/request-otp")
def request_otp(request: OTPRequest, db: Session = Depends(get_db)):
    """Request an OTP to be sent to the provided email"""
    # Validate app credentials if provided
    app = None
    if request.app_id and request.app_secret:
        app = validate_app_credentials(db, request.app_id, request.app_secret)
    
    try:
        otp = generate_otp(request.email)
        app_name = app.name if app else "Auth Platform"
        send_otp_email(request.email, otp, app_name)
        return {"message": "OTP sent successfully", "email": request.email}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send OTP: {str(e)}"
        )

@router.post("/verify-otp", response_model=AuthResponse)
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
    
    # Check if user exists for this app, create if not
    if app:
        user = db.query(User).filter(
            User.email == request.email,
            User.app_id == request.app_id
        ).first()
    else:
        user = db.query(User).filter(User.email == request.email).first()
    
    if not user:
        user = User(
            email=request.email,
            app_id=request.app_id if app else 'default'
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
