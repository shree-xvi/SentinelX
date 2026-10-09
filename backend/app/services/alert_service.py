from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.app.models.alert import Alert
from backend.app.models.employee import Employee


DEDUPLICATION_WINDOW_MINUTES = 30


def save_alert(
    db: Session,
    tenant_id: str,
    alert_dict: Dict[str, Any]
) -> Optional[Alert]:
    """
    Save an alert with deduplication and update employee risk score.
    Returns Alert instance if newly saved, or None if skipped as duplicate.
    """
    fingerprint = alert_dict.get("fingerprint")
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=DEDUPLICATION_WINDOW_MINUTES)

    # Check for duplicate alert in the same tenant within window
    existing = db.query(Alert).filter(
        Alert.tenant_id == tenant_id,
        Alert.fingerprint == fingerprint,
        Alert.detected_at >= cutoff
    ).first()

    if existing:
        return None  # Duplicate suppressed

    new_alert = Alert(
        tenant_id=tenant_id,
        employee_id=alert_dict.get("employee_id"),
        alert_type=alert_dict.get("alert_type"),
        severity=alert_dict.get("severity", "MEDIUM"),
        risk_score=alert_dict.get("risk_score", 50.0),
        risk_level=alert_dict.get("risk_level", "MEDIUM"),
        source_ip=alert_dict.get("source_ip"),
        fingerprint=fingerprint,
        status="New",
        evidence=alert_dict.get("evidence", {}),
        detected_at=alert_dict.get("detected_at", now),
    )

    db.add(new_alert)

    # Update employee risk score if tied to an employee
    if new_alert.employee_id:
        employee = db.query(Employee).filter(
            Employee.id == new_alert.employee_id,
            Employee.tenant_id == tenant_id
        ).first()
        if employee:
            # Weighted update of employee risk score
            current_score = employee.risk_score or 0.0
            new_score = min(100.0, max(current_score, new_alert.risk_score))
            employee.risk_score = new_score
            if new_score >= 80:
                employee.risk_level = "CRITICAL"
            elif new_score >= 60:
                employee.risk_level = "HIGH"
            elif new_score >= 30:
                employee.risk_level = "MEDIUM"
            else:
                employee.risk_level = "LOW"

    db.commit()
    db.refresh(new_alert)
    return new_alert

