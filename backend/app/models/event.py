import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Index
from sqlalchemy.orm import relationship
from backend.app.database import Base


class Event(Base):
    __tablename__ = "events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    employee_id = Column(String(36), ForeignKey("employees.id", ondelete="SET NULL"), nullable=True, index=True)
    event_type = Column(String(100), nullable=False, index=True)  # auth_success, auth_failure, file_copy, usb_mount, etc.
    source = Column(String(100), default="agent")                 # agent, syslog, api, cloud
    source_ip = Column(String(45), nullable=True, index=True)
    username = Column(String(255), nullable=True, index=True)
    event_data = Column(JSON, default=dict)                       # Arbitrary payload/details
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_event_tenant_time", "tenant_id", "timestamp"),
        Index("ix_event_tenant_type", "tenant_id", "event_type"),
    )

    tenant = relationship("Tenant", back_populates="events")
    employee = relationship("Employee", back_populates="events")

