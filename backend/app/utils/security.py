import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import bcrypt
import jwt
from backend.app.config import settings


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Generate a signed JWT access token."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "iat": now})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.
    Returns: (raw_key, prefix, sha256_hash)
    Example raw_key: snx_live_a1b2c3d4e5f6...
    """
    random_part = secrets.token_urlsafe(32)
    raw_key = f"snx_live_{random_part}"
    prefix = raw_key[:12]
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    return raw_key, prefix, key_hash


def hash_api_key(raw_key: str) -> str:
    """Compute sha256 hash of an API key for lookup."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

