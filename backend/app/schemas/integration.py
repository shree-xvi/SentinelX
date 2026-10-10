from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field


class SiemIntegrationCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    provider: str = "webhook"
    endpoint: str = Field(..., min_length=3, max_length=1000)
    format: str = "json"  # cef | json
    auth_token: Optional[str] = None
    forward_scope: str = "alerts"  # alerts | events | all
    min_severity: str = "MEDIUM"
    enabled: bool = True


class SiemIntegrationUpdate(BaseModel):
    name: Optional[str] = None
    endpoint: Optional[str] = None
    format: Optional[str] = None
    auth_token: Optional[str] = None
    forward_scope: Optional[str] = None
    min_severity: Optional[str] = None
    enabled: Optional[bool] = None


class SiemIntegrationResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    provider: str
    endpoint: str
    format: str
    forward_scope: str
    min_severity: str
    enabled: bool
    last_status: Optional[str] = None
    last_error: Optional[str] = None
    last_sent_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class TestIntegrationResponse(BaseModel):
    ok: bool
    status_code: Optional[int] = None
    error: Optional[str] = None
