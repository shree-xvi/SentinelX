import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, JSON, Index
from sqlalchemy.orm import relationship
from backend.app.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    employee_id = Column(String(36), ForeignKey("employees.id", ondelete="SET NULL"), nullable=True, index=True)
    alert_type = Column(String(100), nullable=False, index=True)  # BRUTE_FORCE, AFTER_HOURS, DATA_EXFILTRATION, etc.
    severity = Column(String(20), default="MEDIUM", index=True)   # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, default=50.0)
    risk_level = Column(String(20), default="MEDIUM")
    source_ip = Column(String(45), nullable=True)
    fingerprint = Column(String(64), nullable=False, index=True)  # For deduplication
    status = Column(String(50), default="New", index=True)        # New, Investigating, Resolved, Closed
    evidence = Column(JSON, default=dict)
    detected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_alert_tenant_detected", "tenant_id", "detected_at"),
        Index("ix_alert_fingerprint_time", "tenant_id", "fingerprint", "detected_at"),
    )

    tenant = relationship("Tenant", back_populates="alerts")
    employee = relationship("Employee", back_populates="alerts")
    cases = relationship("Case", back_populates="alert", cascade="all, delete-orphan")

