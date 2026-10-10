from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.tenant import Tenant
from backend.app.models.user import User
from backend.app.schemas.tenant import TenantResponse, TenantUpdate
from backend.app.utils.dependencies import get_current_tenant, require_role

router = APIRouter(prefix="/tenant", tags=["Tenant Settings"])


@router.get("", response_model=TenantResponse)
def get_tenant_details(tenant: Tenant = Depends(get_current_tenant)):
    """Retrieve details and business hour policies for current organization."""
    return tenant


@router.put("", response_model=TenantResponse)
def update_tenant_settings(
    req: TenantUpdate,
    current_user: User = Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """Update organization settings, working hours, or timezone."""
    if req.name is not None:
        tenant.name = req.name
    if req.business_hours_start is not None:
        tenant.business_hours_start = req.business_hours_start
    if req.business_hours_end is not None:
        tenant.business_hours_end = req.business_hours_end
    if req.timezone is not None:
        tenant.timezone = req.timezone

    db.commit()
    db.refresh(tenant)
    return tenant

