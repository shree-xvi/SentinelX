"""Production-hardening middleware: security headers + simple rate limiting."""
import time
from collections import defaultdict, deque
from typing import Deque, Dict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from backend.app.config import settings

# Paths exempt from rate limiting (health checks, docs, root).
_RATE_LIMIT_EXEMPT_PATHS = {"/health", "/", "/docs", "/redoc", "/openapi.json"}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-XSS-Protection": "1; mode=block",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # Only send HSTS over HTTPS to avoid breaking local HTTP development.
    # Starlette populates this conditionally in SecurityHeadersMiddleware.
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach defensive HTTP security headers to every response."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if request.url.scheme == "https":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window-per-minute rate limiter keyed by client identity.

    Identity preference: authenticated tenant (from the JWT ``tenant_id`` when
    present) falling back to the client IP. State is kept in-memory, which is
    appropriate for a single-instance deployment; a shared store (e.g. Redis)
    would back a horizontally-scaled cluster.
    """

    def __init__(self, app, limit_per_minute: int | None = None):
        super().__init__(app)
        self.limit = limit_per_minute or settings.DEFAULT_RATE_LIMIT_PER_MINUTE
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def _client_key(self, request: Request) -> str:
        # Best-effort tenant extraction without full auth validation.
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:]
            # The tenant id is embedded in the token payload; decode leniently.
            try:
                import base64

                payload_part = token.split(".")[1]
                padded = payload_part + "=" * (-len(payload_part) % 4)
                claims = __import__("json").loads(base64.urlsafe_b64decode(padded))
                tenant_id = claims.get("tenant_id")
                if tenant_id:
                    return f"tenant:{tenant_id}"
            except Exception:
                pass
        client = request.client.host if request.client else "unknown"
        return f"ip:{client}"

    async def dispatch(self, request: Request, call_next):
        if request.url.path in _RATE_LIMIT_EXEMPT_PATHS:
            return await call_next(request)

        now = time.time()
        window_start = now - 60
        key = self._client_key(request)
        hits = self._hits[key]

        while hits and hits[0] < window_start:
            hits.popleft()

        if len(hits) >= self.limit:
            retry_after = int(60 - (now - hits[0])) + 1
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": str(max(retry_after, 1))},
            )

        hits.append(now)
        return await call_next(request)
