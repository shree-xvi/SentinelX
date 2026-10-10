import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer
from sqlalchemy.orm import relationship
from backend.app.database import Base


class SiemIntegration(Base):
    """A tenant-configured SIEM / log-forwarding destination.

    Alerts and events can be forwarded to an external SIEM (Splunk HEC,
    Elastic, a generic webhook, etc.) in either CEF or JSON format.
    """

    __tablename__ = "siem_integrations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    provider = Column(String(50), default="webhook", nullable=False)  # splunk_hec, elastic, webhook, syslog
    endpoint = Column(String(1000), nullable=False)
    # Wire format for forwarded messages: "cef" or "json".
    format = Column(String(20), default="json", nullable=False)
    # Optional auth token (e.g. Splunk HEC token) sent as a bearer/header value.
    auth_token = Column(String(500), nullable=True)
    # What to forward: "alerts", "events", or "all".
    forward_scope = Column(String(20), default="alerts")
    min_severity = Column(String(20), default="MEDIUM")
    enabled = Column(Boolean, default=True)
    last_status = Column(String(20), nullable=True)  # ok, error
    last_error = Column(String(1000), nullable=True)
    last_sent_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    tenant = relationship("Tenant")
