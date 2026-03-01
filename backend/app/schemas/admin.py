from pydantic import BaseModel, EmailStr
from typing import Optional


class AdminLoginRequest(BaseModel):
    email: str
    password: str


class AdminLoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: int
    tenant_name: str


class AdminRegisterRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_name: str


class AdminRegisterResponse(BaseModel):
    admin_id: int
    tenant_id: int
    tenant_name: str
    access_token: str
    token_type: str = "bearer"