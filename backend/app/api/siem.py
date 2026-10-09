from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.tenant import Tenant
from backend.app.models.integration import SiemIntegration
from backend.app.schemas.integration import (
    SiemIntegrationCreate,
    SiemIntegrationResponse,
    SiemIntegrationUpdate,
    TestIntegrationResponse,
)
from backend.app.services.siem_service import forward_alert
from backend.app.utils.dependencies import get_current_tenant, require_role

router = APIRouter(prefix="/siem", tags=["SIEM Integration"])


@router.get("/integrations", response_model=List[SiemIntegrationResponse])
def list_integrations(
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """List configured SIEM forwarding destinations."""
    return (
        db.query(SiemIntegration)
        .filter(SiemIntegration.tenant_id == tenant.id)
        .order_by(SiemIntegration.created_at.desc())
        .all()
    )


@router.post(
    "/integrations",
    response_model=SiemIntegrationResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_integration(
    req: SiemIntegrationCreate,
    current_user=Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Register a SIEM forwarding integration (admin only)."""
    integration = SiemIntegration(
        tenant_id=tenant.id,
        name=req.name,
        provider=req.provider,
        endpoint=req.endpoint,
        format=req.format.lower(),
        auth_token=req.auth_token,
        forward_scope=req.forward_scope,
        min_severity=req.min_severity.upper(),
        enabled=req.enabled,
    )
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


@router.patch("/integrations/{integration_id}", response_model=SiemIntegrationResponse)
def update_integration(
    integration_id: str,
    req: SiemIntegrationUpdate,
    current_user=Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Update or toggle a SIEM integration (admin only)."""
    integration = (
        db.query(SiemIntegration)
        .filter(SiemIntegration.id == integration_id, SiemIntegration.tenant_id == tenant.id)
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="SIEM integration not found.")

    if req.name is not None:
        integration.name = req.name
    if req.endpoint is not None:
        integration.endpoint = req.endpoint
    if req.format is not None:
        integration.format = req.format.lower()
    if req.auth_token is not None:
        integration.auth_token = req.auth_token
    if req.forward_scope is not None:
        integration.forward_scope = req.forward_scope
    if req.min_severity is not None:
        integration.min_severity = req.min_severity.upper()
    if req.enabled is not None:
        integration.enabled = req.enabled

    db.commit()
    db.refresh(integration)
    return integration


@router.delete("/integrations/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_integration(
    integration_id: str,
    current_user=Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Remove a SIEM integration (admin only)."""
    integration = (
        db.query(SiemIntegration)
        .filter(SiemIntegration.id == integration_id, SiemIntegration.tenant_id == tenant.id)
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="SIEM integration not found.")
    db.delete(integration)
    db.commit()
    return None


@router.post("/integrations/{integration_id}/test", response_model=TestIntegrationResponse)
def test_integration(
    integration_id: str,
    current_user=Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Send a synthetic alert to verify SIEM connectivity (admin only)."""
    integration = (
        db.query(SiemIntegration)
        .filter(SiemIntegration.id == integration_id, SiemIntegration.tenant_id == tenant.id)
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="SIEM integration not found.")

    from datetime import datetime, timezone

    class _SyntheticAlert:
        id = "test-alert"
        alert_type = "TEST"
        severity = "HIGH"
        risk_score = 90.0
        risk_level = "HIGH"
        source_ip = "203.0.113.200"
        status = "New"
        detected_at = datetime.now(timezone.utc)
        evidence = {"note": "SIEM connectivity test"}

    ok = forward_alert(db, integration, _SyntheticAlert())
    return TestIntegrationResponse(
        ok=ok,
        status_code=None,
        error=None if ok else integration.last_error,
    )

