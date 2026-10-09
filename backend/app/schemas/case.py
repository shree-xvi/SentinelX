from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field


class CaseNoteCreate(BaseModel):
    note: str = Field(..., min_length=1, max_length=5000)
    action_type: Optional[str] = "comment"


class CaseNoteResponse(BaseModel):
    id: str
    case_id: str
    author_id: Optional[str] = None
    note: str
    action_type: str
    created_at: datetime

    class Config:
        from_attributes = True


class CaseCreate(BaseModel):
    alert_id: Optional[str] = None
    title: str = Field(..., min_length=2, max_length=255)
    description: Optional[str] = None
    priority: Optional[str] = "MEDIUM"
    assigned_to: Optional[str] = None


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(New|Investigating|Escalated|Resolved|Closed)$")
    priority: Optional[str] = Field(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    assigned_to: Optional[str] = None


class CaseResponse(BaseModel):
    id: str
    tenant_id: str
    alert_id: Optional[str] = None
    assigned_to: Optional[str] = None
    title: str
    description: Optional[str] = None
    status: str
    priority: str
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    notes: List[CaseNoteResponse] = []

    class Config:
        from_attributes = True

