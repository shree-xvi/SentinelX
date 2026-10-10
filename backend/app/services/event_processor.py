from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.app.models.event import Event
from backend.app.models.employee import Employee
from backend.app.models.policy import Policy
from backend.app.models.alert import Alert
from backend.app.schemas.event import EventCreate
from backend.app.detection.engine import engine
from backend.app.services.alert_service import save_alert


def get_or_create_employee(
    db: Session,
    tenant_id: str,
    employee_identifier: Optional[str],
    username: Optional[str] = None
) -> Optional[Employee]:
    """
    Look up employee by organization employee_id or username.
    If not found, auto-provision an employee record.
    """
    ident = employee_identifier or username
    if not ident:
        return None

    emp = db.query(Employee).filter(
        Employee.tenant_id == tenant_id,
        Employee.employee_id == ident
    ).first()

    if not emp:
        emp = Employee(
            tenant_id=tenant_id,
            employee_id=ident,
            name=username or ident,
            department="Unassigned",
            risk_score=0.0,
            risk_level="LOW"
        )
        db.add(emp)
        db.flush()

    return emp


def process_events(
    db: Session,
    tenant_id: str,
    event_inputs: List[EventCreate]
) -> List[Alert]:
    """
    1. Ingest events into the database
    2. Load recent events for detection window
    3. Run detection rules against active tenant policies
    4. Save generated alerts with deduplication
    """
    now = datetime.now(timezone.utc)
    new_db_events = []

    for item in event_inputs:
        ts = item.timestamp or now
        # Auto-create or resolve employee
        emp = get_or_create_employee(db, tenant_id, item.employee_id, item.username)
        if emp:
            emp.last_activity = ts

        event_rec = Event(
            tenant_id=tenant_id,
            employee_id=emp.id if emp else None,
            event_type=item.event_type,
            source=item.source or "agent",
            source_ip=item.source_ip,
            username=item.username or (emp.employee_id if emp else None),
            event_data=item.event_data or {},
            timestamp=ts,
        )
        db.add(event_rec)
        new_db_events.append(event_rec)

    db.commit()

    # Load recent events for this tenant within detection window (e.g. last 60 minutes)
    window_start = now - timedelta(minutes=60)
    recent_db_events = db.query(Event).filter(
        Event.tenant_id == tenant_id,
        Event.timestamp >= window_start
    ).order_by(Event.timestamp.asc()).all()

    # Convert to dict for detection engine
    events_payload = []
    for ev in recent_db_events:
        events_payload.append({
            "id": ev.id,
            "event_type": ev.event_type,
            "source_ip": ev.source_ip,
            "username": ev.username,
            "employee_id": ev.employee_id,
            "timestamp": ev.timestamp,
            "data": ev.event_data
        })

    # Fetch tenant policies
    db_policies = db.query(Policy).filter(
        Policy.tenant_id == tenant_id,
        Policy.enabled == True
    ).all()

    policies_payload = [
        {
            "rule_type": p.rule_type,
            "severity": p.severity,
            "enabled": p.enabled,
            "conditions": p.conditions or {}
        }
        for p in db_policies
    ]

    # Run detection rules
    detected_alerts = engine.run(events_payload, policies=policies_payload)

    saved_alerts = []
    for alert_dict in detected_alerts:
        saved = save_alert(db, tenant_id, alert_dict)
        if saved:
            saved_alerts.append(saved)

    # Fan out new alerts to configured notification channels. Delivery is
    # best-effort and never interrupts ingestion.
    if saved_alerts:
        try:
            from backend.app.services.notification_service import notify_for_alert

            for alert in saved_alerts:
                notify_for_alert(db, tenant_id, alert)
        except Exception:  # noqa: BLE001 - notifications must not break ingestion
            pass

    return saved_alerts

