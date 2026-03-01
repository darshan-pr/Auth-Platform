from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from ..db import Base


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    user_id = Column(Integer)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    expires_at = Column(DateTime)