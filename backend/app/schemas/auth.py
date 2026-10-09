from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    company_name: str = Field(..., min_length=2, max_length=255)
    domain: str = Field(..., min_length=3, max_length=255)
    full_name: str = Field(..., min_length=2, max_length=255)
    email: EmailStr
    password: str = Field(..., min_length=8)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    tenant_id: str
    role: str
    email: str


class UserResponse(BaseModel):
    id: str
    tenant_id: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool

    class Config:
        from_attributes = True


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    created_at: str
    raw_key: Optional[str] = None  # Only returned on creation

