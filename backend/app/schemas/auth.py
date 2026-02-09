from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional

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
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
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