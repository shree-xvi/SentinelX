import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.app.database import Base


class RiskProfile(Base):
    __tablename__ = "risk_profiles"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    employee_id = Column(String(36), ForeignKey("employees.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    overall_score = Column(Float, default=0.0)
    behavior_baseline = Column(JSON, default=dict)
    anomaly_history = Column(JSON, default=list)
    last_calculated = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    employee = relationship("Employee", back_populates="risk_profile")

