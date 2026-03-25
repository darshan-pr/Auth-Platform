from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.sql import func
from app.db import Base


class OAuthConsent(Base):
    __tablename__ = "oauth_consents"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    client_id = Column(String, nullable=False, index=True)
    scope = Column(String, nullable=False, default="email")
    granted = Column(Boolean, nullable=False, default=True)
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", "client_id", name="uq_oauth_consents_tenant_user_client"),
    )
