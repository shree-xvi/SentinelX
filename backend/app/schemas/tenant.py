from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field


class TenantResponse(BaseModel):
    id: str
    name: str
    domain: str
    plan: str
    business_hours_start: int
    business_hours_end: int
    timezone: str
    created_at: datetime

    class Config:
        from_attributes = True


class TenantUpdate(BaseModel):
    name: Optional[str] = None
    business_hours_start: Optional[int] = Field(None, ge=0, le=23)
    business_hours_end: Optional[int] = Field(None, ge=0, le=23)
    timezone: Optional[str] = None

