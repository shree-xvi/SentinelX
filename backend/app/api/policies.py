from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.tenant import Tenant
from backend.app.models.policy import Policy
from backend.app.models.user import User
from backend.app.schemas.policy import PolicyCreate, PolicyUpdate, PolicyResponse
from backend.app.utils.dependencies import get_current_tenant, require_role

router = APIRouter(prefix="/policies", tags=["Detection Policies"])


@router.get("", response_model=List[PolicyResponse])
def list_policies(
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """List threat detection policies configured for this organization."""
    return db.query(Policy).filter(Policy.tenant_id == tenant.id).all()


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
def create_policy(
    req: PolicyCreate,
    current_user: User = Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """Add a custom threat detection policy or rule override."""
    policy = Policy(
        tenant_id=tenant.id,
        name=req.name,
        rule_type=req.rule_type,
        description=req.description,
        severity=req.severity or "MEDIUM",
        enabled=req.enabled if req.enabled is not None else True,
        conditions=req.conditions or {}
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


@router.patch("/{policy_id}", response_model=PolicyResponse)
def update_policy(
    policy_id: str,
    req: PolicyUpdate,
    current_user: User = Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """Update policy thresholds or toggle enable/disable."""
    policy = db.query(Policy).filter(
        Policy.id == policy_id,
        Policy.tenant_id == tenant.id
    ).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found.")

    if req.name is not None:
        policy.name = req.name
    if req.description is not None:
        policy.description = req.description
    if req.severity is not None:
        policy.severity = req.severity
    if req.enabled is not None:
        policy.enabled = req.enabled
    if req.conditions is not None:
        policy.conditions = req.conditions

    db.commit()
    db.refresh(policy)
    return policy

