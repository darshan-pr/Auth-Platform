from sqlalchemy import Column, Integer, String
from app.db import Base

class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    password_hash = Column(String)
