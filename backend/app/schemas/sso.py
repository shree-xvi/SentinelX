from typing import Optional
from pydantic import BaseModel


class SsoConfigResponse(BaseModel):
    enabled: bool
    authorization_url: Optional[str] = None
    state: Optional[str] = None
    nonce: Optional[str] = None


class SsoCallbackRequest(BaseModel):
    code: str
    state: str
