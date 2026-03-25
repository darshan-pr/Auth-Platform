from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.sql import func

from app.db import Base


class AdminPasskeyCredential(Base):
    __tablename__ = "admin_passkey_credentials"
    __table_args__ = (
        UniqueConstraint("credential_id", name="uq_admin_passkey_credential_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("admins.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    credential_id = Column(String, nullable=False, index=True)
    public_key = Column(String, nullable=False)
    sign_count = Column(Integer, default=0, nullable=False)
    algorithm = Column(Integer, default=-7, nullable=False)
    device_name = Column(String, default="Admin Device")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True))
