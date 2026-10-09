from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field


class EventCreate(BaseModel):
    event_type: str = Field(..., description="e.g. auth_success, auth_failure, file_copy, usb_mount")
    employee_id: Optional[str] = Field(None, description="Organization internal employee ID or username")
    username: Optional[str] = None
    source: Optional[str] = "agent"
    source_ip: Optional[str] = None
    event_data: Optional[Dict[str, Any]] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class BatchEventCreate(BaseModel):
    events: List[EventCreate] = Field(..., min_length=1, max_length=1000)


class EventResponse(BaseModel):
    id: str
    tenant_id: str
    employee_id: Optional[str] = None
    event_type: str
    source: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_data: Dict[str, Any]
    timestamp: datetime
    created_at: datetime

    class Config:
        from_attributes = True

