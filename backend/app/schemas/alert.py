from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class AlertResponse(BaseModel):
    id: str
    tenant_id: str
    employee_id: Optional[str] = None
    alert_type: str
    severity: str
    risk_score: float
    risk_level: str
    source_ip: Optional[str] = None
    fingerprint: str
    status: str
    evidence: Dict[str, Any]
    detected_at: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    status: Optional[str] = Field(None, pattern="^(New|Investigating|Resolved|Closed)$")

