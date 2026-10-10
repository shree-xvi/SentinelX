import os
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelX Insider Threat Detection Platform"
    API_V1_PREFIX: str = "/api/v1"
    SECRET_KEY: str = Field(default="sentinelx-super-secret-key-change-in-production-2026", validation_alias="SECRET_KEY")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day

    DATABASE_URL: str = Field(
        default="sqlite:///./sentinelx.db",
        validation_alias="DATABASE_URL"
    )

    ENVIRONMENT: str = "development"

    # Rate limiting defaults
    DEFAULT_RATE_LIMIT_PER_MINUTE: int = 300

    # ------------------------------------------------------------------
    # Production hardening
    # ------------------------------------------------------------------
    # Emit strict security headers (HSTS, X-Content-Type-Options, etc.).
    # Disabled by default so local development is unaffected.
    ENABLE_SECURITY_HEADERS: bool = True
    # Trusted origins for CORS. "*" keeps local development frictionless;
    # override with a comma-separated list in production.
    CORS_ORIGINS: str = "*"
    # Enable simple per-client rate limiting middleware.
    ENABLE_RATE_LIMIT: bool = True
    # Log level for the structured JSON logger.
    LOG_LEVEL: str = "INFO"

    # ------------------------------------------------------------------
    # SSO / OpenID Connect (optional; disabled when unset)
    # ------------------------------------------------------------------
    SSO_ENABLED: bool = False
    OIDC_ISSUER: str = ""
    OIDC_CLIENT_ID: str = ""
    OIDC_CLIENT_SECRET: str = ""
    OIDC_REDIRECT_URI: str = "http://localhost:5173/auth/callback"
    OIDC_SCOPE: str = "openid email profile"

    @property
    def cors_origin_list(self) -> list[str]:
        raw = self.CORS_ORIGINS.strip()
        if raw == "*":
            return ["*"]
        return [origin.strip() for origin in raw.split(",") if origin.strip()]

    class Config:
        env_file = ".env"
        extra = "allow"


settings = Settings()


