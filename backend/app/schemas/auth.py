from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
from app.services.password_service import enforce_password_strength

class OTPRequest(BaseModel):
    email: str
    app_id: Optional[str] = None
    app_secret: Optional[str] = None

class OTPVerifyRequest(BaseModel):
    email: str
    otp: str
    app_id: Optional[str] = None
    app_secret: Optional[str] = None

class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    app_id: Optional[str] = None

# New schemas for password-based auth
class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    app_id: str
    app_secret: str
    
    @field_validator('password')
    @classmethod
    def password_strength(cls, v):
        enforce_password_strength(v)
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    app_id: str
    app_secret: str

class LoginResponse(BaseModel):
    message: str
    email: str
    otp_required: bool
    # Only returned if OTP is not required
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: Optional[str] = None

class LoginOTPVerifyRequest(BaseModel):
    email: str
    otp: str
    app_id: str
    app_secret: str

# Forgot Password schemas
class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    app_id: str
    app_secret: str

class ForgotPasswordResponse(BaseModel):
    message: str
    email: str
    method: str  # "otp" or "token"

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    app_id: str
    app_secret: str
    new_password: str
    otp: Optional[str] = None  # Required if OTP is enabled
    token: Optional[str] = None  # Required if OTP is disabled
    
    @field_validator('new_password')
    @classmethod
    def password_strength(cls, v):
        enforce_password_strength(v)
        return v
