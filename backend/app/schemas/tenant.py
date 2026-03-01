from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class TenantResponse(BaseModel):
    id: int
    name: str
    slug: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TenantUpdateRequest(BaseModel):
    name: Optional[str] = None
