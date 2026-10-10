import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from backend.app.database import Base


class Employee(Base):
    __tablename__ = "employees"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    employee_id = Column(String(100), nullable=False)  # Organization internal ID or username
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=True)
    department = Column(String(100), nullable=True, default="General")
    title = Column(String(100), nullable=True)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    last_activity = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_tenant_employee_id", "tenant_id", "employee_id", unique=True),
    )

    tenant = relationship("Tenant", back_populates="employees")
    events = relationship("Event", back_populates="employee", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="employee", cascade="all, delete-orphan")
    risk_profile = relationship("RiskProfile", back_populates="employee", uselist=False, cascade="all, delete-orphan")

