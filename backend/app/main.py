from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from backend.app.config import settings
from backend.app.database import engine, Base
from backend.app.middleware import SecurityHeadersMiddleware, RateLimitMiddleware
from backend.app.utils.logging import configure_logging
import backend.app.models  # Ensure all models are registered

# Import API Routers
from backend.app.api.auth import router as auth_router
from backend.app.api.tenants import router as tenants_router
from backend.app.api.employees import router as employees_router
from backend.app.api.events import router as events_router
from backend.app.api.alerts import router as alerts_router
from backend.app.api.cases import router as cases_router
from backend.app.api.policies import router as policies_router
from backend.app.api.dashboard import router as dashboard_router
from backend.app.api.notifications import router as notifications_router
from backend.app.api.siem import router as siem_router
from backend.app.api.reports import router as reports_router
from backend.app.api.sso import router as sso_router

logger = configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables automatically if using SQLite / first run
    Base.metadata.create_all(bind=engine)
    logger.info("SentinelX backend started", extra={"environment": settings.ENVIRONMENT})
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="SentinelX Multi-Tenant Insider Threat Detection SaaS Platform",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Production hardening middleware.
if settings.ENABLE_SECURITY_HEADERS:
    app.add_middleware(SecurityHeadersMiddleware)
if settings.ENABLE_RATE_LIMIT:
    app.add_middleware(RateLimitMiddleware)


# Mount API Routers
api_v1_prefix = settings.API_V1_PREFIX
app.include_router(auth_router, prefix=api_v1_prefix)
app.include_router(tenants_router, prefix=api_v1_prefix)
app.include_router(employees_router, prefix=api_v1_prefix)
app.include_router(events_router, prefix=api_v1_prefix)
app.include_router(alerts_router, prefix=api_v1_prefix)
app.include_router(cases_router, prefix=api_v1_prefix)
app.include_router(policies_router, prefix=api_v1_prefix)
app.include_router(dashboard_router, prefix=api_v1_prefix)
app.include_router(notifications_router, prefix=api_v1_prefix)
app.include_router(siem_router, prefix=api_v1_prefix)
app.include_router(reports_router, prefix=api_v1_prefix)
app.include_router(sso_router, prefix=api_v1_prefix)


@app.get("/health", tags=["System"])
def health_check():
    """System health check endpoint."""
    return {
        "status": "ok",
        "service": "SentinelX SaaS Platform",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT
    }


@app.get("/", tags=["System"])
def root():
    return {
        "message": "Welcome to SentinelX Insider Threat Detection Platform API",
        "documentation": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)

