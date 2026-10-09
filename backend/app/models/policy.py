import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.app.database import Base


class Policy(Base):
    __tablename__ = "policies"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    rule_type = Column(String(100), nullable=False, index=True)  # BRUTE_FORCE, SUSPICIOUS_LOGIN, etc.
    description = Column(String(500), nullable=True)
    severity = Column(String(20), default="MEDIUM")
    enabled = Column(Boolean, default=True)
    conditions = Column(JSON, default=dict)                      # e.g. {"threshold": 5, "window_minutes": 5}
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    tenant = relationship("Tenant", back_populates="policies")

