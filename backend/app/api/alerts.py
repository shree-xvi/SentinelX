from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.tenant import Tenant
from backend.app.models.alert import Alert
from backend.app.schemas.alert import AlertResponse, AlertUpdate
from backend.app.utils.dependencies import get_current_tenant

router = APIRouter(prefix="/alerts", tags=["Threat Alerts"])


@router.get("", response_model=List[AlertResponse])
def list_alerts(
    severity: Optional[str] = Query(None, description="Filter by LOW, MEDIUM, HIGH, CRITICAL"),
    status: Optional[str] = Query(None, description="Filter by New, Investigating, Resolved, Closed"),
    alert_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """Retrieve security alerts filtered by severity, status, or detection rule."""
    query = db.query(Alert).filter(Alert.tenant_id == tenant.id)

    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if status:
        query = query.filter(Alert.status == status)
    if alert_type:
        query = query.filter(Alert.alert_type == alert_type)

    alerts = query.order_by(Alert.detected_at.desc()).offset(offset).limit(limit).all()
    return alerts


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_detail(
    alert_id: str,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """Get single alert details and evidence."""
    alert = db.query(Alert).filter(
        Alert.id == alert_id,
        Alert.tenant_id == tenant.id
    ).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert_status(
    alert_id: str,
    req: AlertUpdate,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """Update investigation status of an alert."""
    alert = db.query(Alert).filter(
        Alert.id == alert_id,
        Alert.tenant_id == tenant.id
    ).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    if req.status:
        alert.status = req.status

    db.commit()
    db.refresh(alert)
    return alert

