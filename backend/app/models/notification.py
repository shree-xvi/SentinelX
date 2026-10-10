import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, Integer, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.app.database import Base


class NotificationChannel(Base):
    """A tenant-configured destination for alert notifications.

    Supports webhook delivery today; the ``channel_type`` field leaves room for
    email/Slack/PagerDuty integrations later.
    """

    __tablename__ = "notification_channels"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    channel_type = Column(String(50), default="webhook", nullable=False)  # webhook, email, slack
    target = Column(String(1000), nullable=False)  # webhook URL or address
    # Minimum severity that triggers a notification to this channel.
    min_severity = Column(String(20), default="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL
    enabled = Column(Boolean, default=True)
    # Optional signing secret; when set, outbound payloads include an
    # HMAC-SHA256 signature header for receiver verification.
    secret = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    tenant = relationship("Tenant")


class NotificationLog(Base):
    """Audit record of an outbound notification attempt."""

    __tablename__ = "notification_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    channel_id = Column(String(36), ForeignKey("notification_channels.id", ondelete="CASCADE"), nullable=True, index=True)
    alert_id = Column(String(36), nullable=True)
    status = Column(String(20), default="pending")  # pending, sent, failed
    response_status = Column(Integer, nullable=True)
    error = Column(String(1000), nullable=True)
    payload = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
