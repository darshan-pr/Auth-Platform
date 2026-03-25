from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.db import Base


class AdminActivityEvent(Base):
    __tablename__ = "admin_activity_events"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("admins.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(String, nullable=True, index=True)

    event_type = Column(String, nullable=False, index=True)
    method = Column(String, nullable=True)
    resource = Column(String, nullable=True)
    details = Column(String, nullable=True)

    user_agent = Column(String, nullable=True)
    browser = Column(String, nullable=True)
    device = Column(String, nullable=True)

    ip_address = Column(String, nullable=True)
    city = Column(String, nullable=True)
    region = Column(String, nullable=True)
    country = Column(String, nullable=True)
    isp = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
