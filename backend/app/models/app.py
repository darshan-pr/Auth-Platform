from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.sql import func
from app.db import Base

class App(Base):
    __tablename__ = "apps"

    id = Column(Integer, primary_key=True, index=True)
    app_id = Column(String, unique=True, index=True, nullable=False)
    app_secret = Column(String, nullable=False)
    name = Column(String, nullable=True)
    description = Column(String, nullable=True)
    # OTP Settings
    otp_enabled = Column(Boolean, default=True, nullable=False)
    # JWT Session Settings
    access_token_expiry_minutes = Column(Integer, default=30, nullable=False)
    refresh_token_expiry_days = Column(Integer, default=7, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
