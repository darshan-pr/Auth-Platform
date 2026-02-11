from sqlalchemy import Column, Integer, String, DateTime, Boolean, UniqueConstraint
from sqlalchemy.sql import func
from app.db import Base

class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint('email', 'app_id', name='uq_user_email_app'),
    )

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True, nullable=False)
    password_hash = Column(String, nullable=True)  # Hashed password (nullable for OTP-only users)
    app_id = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

