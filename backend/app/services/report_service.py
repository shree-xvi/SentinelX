"""Generate exportable security reports (CSV / JSON) for a tenant.

Reports are computed on demand from the alerts, cases, and employees tables so
they always reflect the current state without a background job.
"""
import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from backend.app.models.tenant import Tenant
from backend.app.models.alert import Alert
from backend.app.models.case import Case
from backend.app.models.employee import Employee


def _alert_row(alert: Alert) -> Dict[str, Any]:
    return {
        "id": alert.id,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "risk_level": alert.risk_level,
        "status": alert.status,
        "source_ip": alert.source_ip,
        "detected_at": alert.detected_at.isoformat() if alert.detected_at else None,
    }


def _case_row(case: Case) -> Dict[str, Any]:
    return {
        "id": case.id,
        "title": case.title,
        "status": case.status,
        "priority": case.priority,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "resolved_at": case.resolved_at.isoformat() if case.resolved_at else None,
    }


def _employee_row(emp: Employee) -> Dict[str, Any]:
    return {
        "employee_id": emp.employee_id,
        "name": emp.name,
        "department": emp.department,
        "risk_score": emp.risk_score,
        "risk_level": emp.risk_level,
    }


def build_summary(db: Session, tenant: Tenant, days: int = 30) -> Dict[str, Any]:
    """Build a structured summary report across alerts, cases, and employees."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    alerts = (
        db.query(Alert)
        .filter(Alert.tenant_id == tenant.id, Alert.detected_at >= cutoff)
        .order_by(Alert.detected_at.desc())
        .all()
    )
    cases = db.query(Case).filter(Case.tenant_id == tenant.id).all()
    employees = (
        db.query(Employee)
        .filter(Employee.tenant_id == tenant.id)
        .order_by(Employee.risk_score.desc())
        .all()
    )

    severity_counts: Dict[str, int] = {}
    type_counts: Dict[str, int] = {}
    for alert in alerts:
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
        type_counts[alert.alert_type] = type_counts.get(alert.alert_type, 0) + 1

    open_cases = sum(1 for c in cases if c.status in ("New", "Investigating", "Escalated"))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "organization": {"name": tenant.name, "domain": tenant.domain},
        "period_days": days,
        "totals": {
            "alerts": len(alerts),
            "cases": len(cases),
            "open_cases": open_cases,
            "employees": len(employees),
        },
        "alerts_by_severity": severity_counts,
        "alerts_by_type": type_counts,
        "alerts": [_alert_row(a) for a in alerts],
        "cases": [_case_row(c) for c in cases],
        "top_risk_employees": [_employee_row(e) for e in employees[:20]],
    }


def summary_to_csv(summary: Dict[str, Any]) -> str:
    """Render the alert rows of a summary as CSV text."""
    output = io.StringIO()
    rows: List[Dict[str, Any]] = summary.get("alerts", [])
    if not rows:
        return "id,alert_type,severity,risk_score,risk_level,status,source_ip,detected_at\n"
    writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def summary_to_json(summary: Dict[str, Any]) -> str:
    return json.dumps(summary, indent=2, default=str)
