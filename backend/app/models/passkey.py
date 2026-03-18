from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.db import Base


class PasskeyCredential(Base):
    __tablename__ = "passkey_credentials"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    app_id = Column(String, nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    credential_id = Column(String, nullable=False, index=True)
    public_key = Column(String, nullable=False)
    sign_count = Column(Integer, default=0, nullable=False)
    algorithm = Column(Integer, default=-7, nullable=False)  # COSE algorithm: -7=ES256, -257=RS256
    device_name = Column(String, default="Unknown Device")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True))
