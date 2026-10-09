import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Integer
from sqlalchemy.orm import relationship
from backend.app.database import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    plan = Column(String(50), default="enterprise")
    business_hours_start = Column(Integer, default=9)  # 09:00
    business_hours_end = Column(Integer, default=18)    # 18:00
    timezone = Column(String(50), default="UTC")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    employees = relationship("Employee", back_populates="tenant", cascade="all, delete-orphan")
    events = relationship("Event", back_populates="tenant", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="tenant", cascade="all, delete-orphan")
    policies = relationship("Policy", back_populates="tenant", cascade="all, delete-orphan")
    cases = relationship("Case", back_populates="tenant", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="tenant", cascade="all, delete-orphan")

