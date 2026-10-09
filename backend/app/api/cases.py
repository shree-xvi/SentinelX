from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.tenant import Tenant
from backend.app.models.case import Case, CaseNote
from backend.app.models.alert import Alert
from backend.app.models.user import User
from backend.app.schemas.case import (
    CaseCreate,
    CaseUpdate,
    CaseResponse,
    CaseNoteCreate,
    CaseNoteResponse
)
from backend.app.utils.dependencies import get_current_tenant, get_current_user

router = APIRouter(prefix="/cases", tags=["Investigation Case Management"])


@router.get("", response_model=List[CaseResponse])
def list_cases(
    status_filter: Optional[str] = Query(None, alias="status"),
    priority: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """List investigation cases."""
    query = db.query(Case).filter(Case.tenant_id == tenant.id)
    if status_filter:
        query = query.filter(Case.status == status_filter)
    if priority:
        query = query.filter(Case.priority == priority.upper())

    cases = query.order_by(Case.created_at.desc()).offset(offset).limit(limit).all()
    return cases


@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
def create_case(
    req: CaseCreate,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Escalate an alert or incident into an investigation case."""
    if req.alert_id:
        alert = db.query(Alert).filter(Alert.id == req.alert_id, Alert.tenant_id == tenant.id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Referenced alert not found.")
        alert.status = "Investigating"

    case = Case(
        tenant_id=tenant.id,
        alert_id=req.alert_id,
        assigned_to=req.assigned_to or current_user.id,
        title=req.title,
        description=req.description,
        priority=req.priority or "MEDIUM",
        status="New"
    )
    db.add(case)
    db.flush()

    # Initial creation note
    initial_note = CaseNote(
        case_id=case.id,
        author_id=current_user.id,
        note=f"Case opened by {current_user.email}.",
        action_type="status_change"
    )
    db.add(initial_note)

    db.commit()
    db.refresh(case)
    return case


@router.get("/{case_id}", response_model=CaseResponse)
def get_case(
    case_id: str,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """Get full case details including audit trail notes."""
    case = db.query(Case).filter(Case.id == case_id, Case.tenant_id == tenant.id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    return case


@router.patch("/{case_id}", response_model=CaseResponse)
def update_case(
    case_id: str,
    req: CaseUpdate,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update case status, assignee, or priority."""
    case = db.query(Case).filter(Case.id == case_id, Case.tenant_id == tenant.id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    changes = []
    if req.status and req.status != case.status:
        changes.append(f"Status changed from {case.status} to {req.status}")
        case.status = req.status
        if req.status in ("Resolved", "Closed"):
            case.resolved_at = datetime.now(timezone.utc)

    if req.priority and req.priority != case.priority:
        changes.append(f"Priority changed from {case.priority} to {req.priority}")
        case.priority = req.priority

    if req.assigned_to and req.assigned_to != case.assigned_to:
        changes.append(f"Assigned to {req.assigned_to}")
        case.assigned_to = req.assigned_to

    if req.title:
        case.title = req.title
    if req.description is not None:
        case.description = req.description

    case.updated_at = datetime.now(timezone.utc)

    if changes:
        note = CaseNote(
            case_id=case.id,
            author_id=current_user.id,
            note="; ".join(changes),
            action_type="status_change"
        )
        db.add(note)

    db.commit()
    db.refresh(case)
    return case


@router.post("/{case_id}/notes", response_model=CaseNoteResponse, status_code=status.HTTP_201_CREATED)
def add_case_note(
    case_id: str,
    req: CaseNoteCreate,
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Add an analyst finding or update note to the investigation audit log."""
    case = db.query(Case).filter(Case.id == case_id, Case.tenant_id == tenant.id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    note = CaseNote(
        case_id=case.id,
        author_id=current_user.id,
        note=req.note,
        action_type=req.action_type or "comment"
    )
    db.add(note)
    case.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(note)
    return note

