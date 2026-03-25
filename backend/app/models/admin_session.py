from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.sql import func
from app.db import Base


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, nullable=False, index=True)
    admin_id = Column(Integer, ForeignKey("admins.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)

    user_agent = Column(String, nullable=True)
    browser = Column(String, nullable=True)
    device = Column(String, nullable=True)

    ip_address = Column(String, nullable=True)
    city = Column(String, nullable=True)
    region = Column(String, nullable=True)
    country = Column(String, nullable=True)
    isp = Column(String, nullable=True)

    login_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)

    is_revoked = Column(Boolean, nullable=False, default=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_reason = Column(String, nullable=True)
