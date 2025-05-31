"""
User model for SQLAlchemy ORM.
"""
from sqlalchemy import Boolean, Column, Integer, String
from db.database import Base

class DBUser(Base):
    """SQLAlchemy model for the User table."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(128), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(128), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    profile_picture = Column(String(256), nullable=True, default=None)

