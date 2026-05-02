from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


class AdminRegisterRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_name: str


class AdminLoginRequest(BaseModel):
    email: str
    password: str


class AdminLoginMFAVerifyRequest(BaseModel):
    mfa_ticket: str
    otp: str


class AdminForgotPasswordRequest(BaseModel):
    email: EmailStr


class AdminForgotPasswordVerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str


class AdminResetPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str


class AdminPasskeyCheckRequest(BaseModel):
    email: EmailStr


class AdminPasskeyLoginBeginRequest(BaseModel):
    email: EmailStr


class AdminPasskeyCredentialPayload(BaseModel):
    id: str
    clientDataJSON: str
    attestationObject: Optional[str] = None
    authenticatorData: Optional[str] = None
    signature: Optional[str] = None
    deviceName: Optional[str] = None


class AdminPasskeyLoginCompleteRequest(BaseModel):
    email: EmailStr
    credential: AdminPasskeyCredentialPayload


class AdminPasskeyRegisterCompleteRequest(BaseModel):
    credential: AdminPasskeyCredentialPayload


class AdminMFARequestOTPRequest(BaseModel):
    action: str = "enable"  # enable | disable


class AdminMFASetupVerifyRequest(BaseModel):
    otp: str


class AdminProfileUpdateRequest(BaseModel):
    email: Optional[EmailStr] = None


class TenantUpdateRequest(BaseModel):
    name: Optional[str] = None


class AppCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    logo_url: Optional[str] = None
    logo_data_url: Optional[str] = None
    oauth_enabled: bool = True
    client_type: str = "confidential"  # "confidential" or "public" (RFC 6749 §2.1)
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
    logo_url: Optional[str] = None
    logo_data_url: Optional[str] = None
    oauth_enabled: Optional[bool] = None
    client_type: Optional[str] = None  # "confidential" or "public"
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
    logo_url: Optional[str]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class AppCredentialsResponse(BaseModel):
    app_id: str
    app_secret_hint: str  # Only shows last 4 characters
    app_secret: Optional[str] = None  # Plaintext shown once on create/regenerate


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


class AdminVerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str


class BulkActionRequest(BaseModel):
    action: str  # "delete" | "force-logout" | "set-inactive"
    user_ids: list[int]
