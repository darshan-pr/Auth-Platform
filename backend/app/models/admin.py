from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from app.db import Base


class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    password_hash = Column(String)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
