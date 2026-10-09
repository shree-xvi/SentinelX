from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.tenant import Tenant
from backend.app.models.employee import Employee
from backend.app.models.user import User
from backend.app.schemas.employee import EmployeeCreate, EmployeeUpdate, EmployeeResponse
from backend.app.utils.dependencies import get_current_tenant, require_role

router = APIRouter(prefix="/employees", tags=["Employees & Risk Profiles"])


@router.get("", response_model=List[EmployeeResponse])
def list_employees(
    search: Optional[str] = Query(None, description="Search by name, employee_id, or email"),
    department: Optional[str] = Query(None),
    min_risk: Optional[float] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """List monitored employees within the tenant with risk levels and filter options."""
    query = db.query(Employee).filter(Employee.tenant_id == tenant.id)

    if search:
        s = f"%{search}%"
        query = query.filter(
            (Employee.name.ilike(s)) |
            (Employee.employee_id.ilike(s)) |
            (Employee.email.ilike(s))
        )
    if department:
        query = query.filter(Employee.department == department)
    if min_risk is not None:
        query = query.filter(Employee.risk_score >= min_risk)

    employees = query.order_by(Employee.risk_score.desc()).offset(offset).limit(limit).all()
    return employees


@router.post("", response_model=EmployeeResponse, status_code=status.HTTP_201_CREATED)
def create_employee(
    req: EmployeeCreate,
    current_user: User = Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """Add a new employee to the monitoring roster."""
    existing = db.query(Employee).filter(
        Employee.tenant_id == tenant.id,
        Employee.employee_id == req.employee_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Employee with this ID already exists.")

    emp = Employee(
        tenant_id=tenant.id,
        employee_id=req.employee_id,
        name=req.name,
        email=req.email,
        department=req.department or "General",
        title=req.title,
        risk_score=0.0,
        risk_level="LOW"
    )
    db.add(emp)
    db.commit()
    db.refresh(emp)
    return emp


@router.get("/{employee_id}", response_model=EmployeeResponse)
def get_employee(
    employee_id: str,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """Retrieve an employee and their current risk score."""
    emp = db.query(Employee).filter(
        Employee.id == employee_id,
        Employee.tenant_id == tenant.id
    ).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found.")
    return emp


@router.put("/{employee_id}", response_model=EmployeeResponse)
def update_employee(
    employee_id: str,
    req: EmployeeUpdate,
    current_user: User = Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """Update employee metadata."""
    emp = db.query(Employee).filter(
        Employee.id == employee_id,
        Employee.tenant_id == tenant.id
    ).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found.")

    if req.name is not None:
        emp.name = req.name
    if req.email is not None:
        emp.email = req.email
    if req.department is not None:
        emp.department = req.department
    if req.title is not None:
        emp.title = req.title

    db.commit()
    db.refresh(emp)
    return emp


@router.get("/{employee_id}/baseline")
def get_employee_behavioral_baseline(
    employee_id: str,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """Retrieve UEBA behavioral baseline and activity profile for an employee."""
    emp = db.query(Employee).filter(
        Employee.id == employee_id,
        Employee.tenant_id == tenant.id
    ).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found.")

    from backend.app.models.risk_profile import RiskProfile
    from backend.app.models.event import Event
    from backend.app.detection.ueba import sync_employee_risk_profile

    profile = db.query(RiskProfile).filter(
        RiskProfile.employee_id == emp.id,
        RiskProfile.tenant_id == tenant.id
    ).first()

    if not profile or not profile.behavior_baseline:
        # Generate baseline from historical events
        events = db.query(Event).filter(
            Event.employee_id == emp.id,
            Event.tenant_id == tenant.id
        ).all()
        events_dicts = [
            {"timestamp": ev.timestamp, "source_ip": ev.source_ip, "event_type": ev.event_type}
            for ev in events
        ]
        profile = sync_employee_risk_profile(db, emp.id, tenant.id, events_dicts)

    return {
        "employee_id": emp.employee_id,
        "name": emp.name,
        "overall_score": emp.risk_score,
        "risk_level": emp.risk_level,
        "baseline": profile.behavior_baseline if profile else {},
        "last_calculated": profile.last_calculated.isoformat() if profile and profile.last_calculated else None,
    }

