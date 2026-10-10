import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from backend.app.database import Base


class Case(Base):
    __tablename__ = "cases"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_id = Column(String(36), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True)
    assigned_to = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), default="New", index=True)        # New, Investigating, Escalated, Resolved, Closed
    priority = Column(String(20), default="MEDIUM")               # LOW, MEDIUM, HIGH, CRITICAL
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_case_tenant_status", "tenant_id", "status"),
    )

    tenant = relationship("Tenant", back_populates="cases")
    alert = relationship("Alert", back_populates="cases")
    assignee = relationship("User", back_populates="assigned_cases", foreign_keys=[assigned_to])
    notes = relationship("CaseNote", back_populates="case", cascade="all, delete-orphan", order_by="CaseNote.created_at.desc()")


class CaseNote(Base):
    __tablename__ = "case_notes"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    author_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    note = Column(Text, nullable=False)
    action_type = Column(String(50), default="comment")  # comment, status_change, reassignment
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    case = relationship("Case", back_populates="notes")
    author = relationship("User", back_populates="notes")

