from typing import Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


class EmployeeCreate(BaseModel):
    employee_id: str = Field(..., min_length=1, max_length=100)
    name: str = Field(..., min_length=1, max_length=255)
    email: Optional[EmailStr] = None
    department: Optional[str] = "General"
    title: Optional[str] = None


class EmployeeUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    department: Optional[str] = None
    title: Optional[str] = None


class EmployeeResponse(BaseModel):
    id: str
    tenant_id: str
    employee_id: str
    name: str
    email: Optional[str] = None
    department: Optional[str] = None
    title: Optional[str] = None
    risk_score: float
    risk_level: str
    last_activity: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True

