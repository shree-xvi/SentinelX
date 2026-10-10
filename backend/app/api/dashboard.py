from datetime import datetime, timedelta, timezone
from collections import Counter
from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.database import get_db
from backend.app.models.tenant import Tenant
from backend.app.models.alert import Alert
from backend.app.models.case import Case
from backend.app.models.employee import Employee
from backend.app.utils.dependencies import get_current_tenant

router = APIRouter(prefix="/dashboard", tags=["Dashboard Analytics"])


@router.get("/overview")
def get_dashboard_overview(
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Retrieve high-level insider threat overview metrics for the organization."""
    total_alerts = db.query(Alert).filter(Alert.tenant_id == tenant.id).count()

    alerts = db.query(Alert.severity, Alert.risk_level, Alert.risk_score).filter(
        Alert.tenant_id == tenant.id
    ).all()

    severity_counts = Counter()
    risk_level_counts = Counter()
    total_score = 0.0

    for sev, rlevel, score in alerts:
        severity_counts[sev or "UNKNOWN"] += 1
        risk_level_counts[rlevel or "LOW"] += 1
        total_score += (score or 0.0)

    avg_risk = round(total_score / total_alerts, 1) if total_alerts > 0 else 0.0

    open_cases = db.query(Case).filter(
        Case.tenant_id == tenant.id,
        Case.status.in_(["New", "Investigating", "Escalated"])
    ).count()

    resolved_cases = db.query(Case).filter(
        Case.tenant_id == tenant.id,
        Case.status.in_(["Resolved", "Closed"])
    ).count()

    return {
        "total_alerts": total_alerts,
        "average_risk_score": avg_risk,
        "severities": {
            "CRITICAL": severity_counts.get("CRITICAL", 0),
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
        },
        "risk_levels": dict(risk_level_counts),
        "cases": {
            "open": open_cases,
            "resolved": resolved_cases
        }
    }


@router.get("/top-risks")
def get_top_risky_employees(
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
) -> List[Dict[str, Any]]:
    """Get top 10 monitored employees with highest risk scores."""
    employees = db.query(Employee).filter(
        Employee.tenant_id == tenant.id
    ).order_by(Employee.risk_score.desc()).limit(10).all()

    return [
        {
            "id": e.id,
            "employee_id": e.employee_id,
            "name": e.name,
            "department": e.department,
            "risk_score": e.risk_score,
            "risk_level": e.risk_level,
            "last_activity": e.last_activity.isoformat() if e.last_activity else None,
        }
        for e in employees
    ]


@router.get("/rule-stats")
def get_detection_rule_stats(
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
) -> Dict[str, int]:
    """Get alert counts grouped by detection rule."""
    results = db.query(
        Alert.alert_type, func.count(Alert.id)
    ).filter(
        Alert.tenant_id == tenant.id
    ).group_by(Alert.alert_type).all()

    return {alert_type: count for alert_type, count in results}


@router.get("/timeline")
def get_alert_timeline(
    days: int = 7,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
) -> List[Dict[str, Any]]:
    """Get daily threat detection counts for the past N days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    alerts = db.query(Alert.detected_at, Alert.severity).filter(
        Alert.tenant_id == tenant.id,
        Alert.detected_at >= cutoff
    ).all()

    daily_buckets: Dict[str, Counter] = {}
    for dt, sev in alerts:
        if dt:
            day_str = dt.strftime("%Y-%m-%d")
            daily_buckets.setdefault(day_str, Counter())[sev or "MEDIUM"] += 1

    timeline = []
    for day, counts in sorted(daily_buckets.items()):
        timeline.append({
            "date": day,
            "total": sum(counts.values()),
            "by_severity": dict(counts)
        })

    return timeline

