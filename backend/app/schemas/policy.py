from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class PolicyCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    rule_type: str = Field(..., description="e.g. BRUTE_FORCE, AFTER_HOURS, DATA_EXFILTRATION")
    description: Optional[str] = None
    severity: Optional[str] = "MEDIUM"
    enabled: Optional[bool] = True
    conditions: Optional[Dict[str, Any]] = Field(default_factory=dict)


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None
    conditions: Optional[Dict[str, Any]] = None


class PolicyResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    rule_type: str
    description: Optional[str] = None
    severity: str
    enabled: bool
    conditions: Dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True

