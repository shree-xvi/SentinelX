from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class NotificationChannelCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    channel_type: str = "webhook"
    target: str = Field(..., min_length=3, max_length=1000)
    min_severity: str = "HIGH"
    enabled: bool = True
    secret: Optional[str] = None


class NotificationChannelUpdate(BaseModel):
    name: Optional[str] = None
    target: Optional[str] = None
    min_severity: Optional[str] = None
    enabled: Optional[bool] = None
    secret: Optional[str] = None


class NotificationChannelResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    channel_type: str
    target: str
    min_severity: str
    enabled: bool
    # secret is never echoed back to clients.
    created_at: datetime

    class Config:
        from_attributes = True


class NotificationLogResponse(BaseModel):
    id: str
    channel_id: Optional[str] = None
    alert_id: Optional[str] = None
    status: str
    response_status: Optional[int] = None
    error: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class TestNotificationRequest(BaseModel):
    message: str = "SentinelX test notification"
